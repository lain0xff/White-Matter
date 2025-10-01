#ifndef SSH_UTILS_H
#define SSH_UTILS_H

#include <libssh/libssh.h>
#include <libssh/sftp.h>

#define BUFFER_SIZE 4096

// Core SSH functions
int initialize_ssh_session(ssh_session *session, const char *target, const char *username, int port);
int authenticate_ssh_session(ssh_session session, const char *password_file);
int authenticate_ssh_session_auto(ssh_session session, const char *password_file);
void cleanup_ssh_session(ssh_session session);
int try_connection(const char *host, int port, const char *username, const char *password);
void brute_force_passwords(const char *host, int port, const char *username, const char *password_file);

// File operations
void upload_file(ssh_session session, const char *local_path, const char *remote_path);
int upload_file_data(ssh_session session, const void *data, size_t size, const char *remote_path);

// Interactive shell
void interactive_shell(ssh_session session);

#endif // SSH_UTILS_H
