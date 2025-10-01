#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *global_password = NULL;
int password_loaded = 0;

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

void set_global_password(const char *password_file) {
    if (global_password) {
        free(global_password);
        global_password = NULL;
    }
    
    if (!password_file) return;
    
    FILE *fp = fopen(password_file, "r");
    if (!fp) {
        fprintf(stderr, "[-] Cannot open password file: %s\n", password_file);
        return;
    }
    
    char password[256];
    // Берем только первый пароль из файла
    if (fgets(password, sizeof(password), fp)) {
        password[strcspn(password, "\n")] = 0; // Убираем перевод строки
        global_password = strdup(password);
        printf("[+] Set global password from file: %s\n", password_file);
    }
    
    fclose(fp);
}

void cleanup_password() {
    if (global_password) {
        memset(global_password, 0, strlen(global_password));
        free(global_password);
        global_password = NULL;
    }
    password_loaded = 0;
}
