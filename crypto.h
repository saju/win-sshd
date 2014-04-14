#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef CRYPTO_INTERNAL
#include "mpir.h"

#define HMAC_BLOCK_SIZE 64

gmp_randstate_t *crypto_randctx();

typedef struct {
	mpz_t seed;
	mpz_t p; /* prime modulus */
	mpz_t q; /* prime divisor */
	mpz_t g;
	mpz_t x; /* public key */
	mpz_t y; /* private key */
	unsigned int k_len; /* key length in bits */
} dsa_ctx;

typedef struct {
    unsigned long *rk;
    int nrounds;
    unsigned char *iv;
} aes_ctx;

typedef struct {
    unsigned char key[HMAC_BLOCK_SIZE];
} hmac_ctx;

long long_swap(long l);
void show_hex(char *, int lenbytes);
int dsa_compare_keys(void *a, void *b);
dsa_ctx *dsa_load_keys(FILE *pub, FILE *priv, char **err);
dsa_ctx *dsa_store_keys(FILE *pub, FILE *priv, char **err);
unsigned char *sha1(const unsigned char *data, unsigned int len);
unsigned char *hmac(hmac_ctx *ctx, const unsigned char *data, unsigned int len);
void *(*crypto_alloc)(size_t sz, char *file, int line);
void (*crypto_free)(void *ptr, char *file, int line);
aes_ctx *aes_key_schedule(unsigned char *key, int keylenbits, unsigned char *iv, int mode); 
void hmac_init();
hmac_ctx *hmac_ctx_init(unsigned char *key, int len);
void dsa_free(dsa_ctx *ctx);
int dh_kex(mpz_t *e, int algo, unsigned long want_keylen, mpz_t *f, mpz_t *K);
void dsa_sign(dsa_ctx *ctx, unsigned char *msg, unsigned int length, mpz_t *r, mpz_t *sign);
int dsa_verify(dsa_ctx *ctx, unsigned char *msg, int length, mpz_t *r, mpz_t *s);
void aes_ctx_free(aes_ctx *ctx);
void aes_cbc_decrypt(aes_ctx *ctx, unsigned char *cipher, unsigned char *plain);
void aes_cbc_encrypt(aes_ctx *ctx, unsigned char *plain, unsigned char *cipher);
void hmac_free(hmac_ctx *ctx);
void dh_init();
unsigned char *sha1(const unsigned char *data, unsigned int len);

#endif /* CRYPTO_INTERNAL ends - public apis follow */

/* these are our bignums, 4 byte bigendian lengths followed by length bytes of data */
typedef unsigned char mpint; 

#define SHA1 1
#define DSS  2
#define RSA  3
#define DH   4
#define DH1  5
#define DH14  6
#define HMAC 7
#define HMAC96 8
#define TRIPLE_DES_CBC 9
#define AES128_CBC 10
#define AES192_CBC 11
#define AES256_CBC 12

#define CBC_DECRYPT 0
#define CBC_ENCRYPT 1

#define SHA1_DIGEST_SIZE 20 /* bytes */
#define AES_BLOCK_SIZE 16 /* bytes */

#define CRYPTO_MALLOC(a) (void *)malloc((a))
#define CRYPTO_FREE(a) free((a))

int crypto_init();
char *crypto_hash(int algo, const char *data, unsigned int *datalen, char **err);
mpint *crypto_kex(int algo, mpint *client_key, mpint **public_key, unsigned int keylen, char **err);
unsigned char *crypto_sign(int algo, const char *data, unsigned int *datalen, void *keys, char **err);
void *crypto_create_key_pair();
int crypto_store_key_pair(void *key, FILE *pub_key, FILE *priv_key);
void *crypto_load_key_pair(FILE *pub_key, FILE *priv_key, int algo, char **err);
int crypto_write_key_pair(FILE *pub_key, FILE *priv_key, int algo, char **err);
unsigned char *crypto_rand(unsigned int bits);
unsigned char *crypto_flatten_key(int keytype, void *key, int *outl);
void *crypto_setup_cipher_context(int cipher, unsigned char *key, unsigned char *iv, int mode);
void crypto_cbc_decrypt(void *ctx, int cipher, unsigned char *ciphertxt, unsigned char *plaintxt);
void crypto_cbc_encrypt(void *ctx, int cipher, unsigned char *plaintxt, unsigned char *ciphertxt);
void *crypto_setup_mac_context(int mac, unsigned char *key, int keylen);
unsigned char *crypto_mac(void *ctx, int mac, unsigned char *data, int dlen);
void crypto_free_cipher_context(void *ctx, int cipher);
void crypto_free_mac_context(void *ctx, int mac);
size_t crypto_cipher_key_size(unsigned char cipher);
unsigned int crypto_cipher_block_size(unsigned char cipher);

#endif /* __CRYPTO_H__ */


