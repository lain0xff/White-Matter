#ifndef UTILS_H
#define UTILS_H

extern char *global_password;
extern int password_loaded;

int load_password_from_file(const char *password_file);
void cleanup_password(void);

#endif // UTILS_H
