#ifndef RSA_CRYPTO_H
#define RSA_CRYPTO_H

#include <openssl/rsa.h>
#include <libssh/libssh.h>

#define RSA_KEY_SIZE 4096
#define MAX_PATH_LENGTH 4096

typedef struct {
    RSA *public_key;
    RSA *private_key;
    char public_key_path[MAX_PATH_LENGTH];
    char private_key_path[MAX_PATH_LENGTH];
} rsa_keys_t;

extern rsa_keys_t global_rsa_keys;

int initialize_rsa_keys(rsa_keys_t *keys);
void cleanup_rsa_keys(rsa_keys_t *keys);
int generate_rsa_key_pair(const char *public_key_file, const char *private_key_file);
RSA *load_public_key(const char *public_key_file);
RSA *load_private_key(const char *private_key_file);
int encrypt_file(const char *input_file, const char *output_file, RSA *rsa);
int decrypt_file(const char *input_file, const char *output_file, RSA *rsa);

// Remote encryption (прототипы)
void encrypt_remote_file(ssh_session session, const char *remote_file);
void decrypt_remote_file(ssh_session session, const char *remote_file);
void encrypt_remote_directory(ssh_session session, const char *remote_dir);
void decrypt_remote_directory(ssh_session session, const char *remote_dir);

#endif // RSA_CRYPTO_H
