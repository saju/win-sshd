#define CRYPTO_INTERNAL

#include <stdio.h>
#define _CRT_RAND_S
#include <stdlib.h>

#include "log.h"
#include "mpir.h"
#include "ssh.h"
#include "crypto.h"

#define PUBKEY_FILE "dsa_key.pub"
#define PRIVKEY_FILE "dsa_key.prv"

gmp_randstate_t r_state;

/* endianess swapper for long*/
long long_swap(long l) {
	_asm {
		mov eax, l
		bswap eax
	}
}

size_t crypto_cipher_key_size(byte cipher) {
	if (cipher == AES128_CBC) return 128;
	else if (cipher == AES192_CBC) return 192;
	else if (cipher == AES256_CBC) return 256;
	else if (cipher == TRIPLE_DES_CBC) return 192;
	else return 0;
}

unsigned int crypto_cipher_block_size(byte cipher) {
    if (cipher == AES128_CBC ||
        cipher == AES192_CBC ||
        cipher == AES256_CBC)
        return 128;
    else
        return 0;
}

gmp_randstate_t *crypto_randctx() {
	return &r_state;
}

void make_mpi_from_mpint(mpint *a, mpz_t *b) {
	uint32 size = long_swap(*(uint32 *)a);
	mpz_import(*b, size, 1, 1, 1, 0, a + sizeof(uint32));
}

mpint *make_mpint_from_mpi(mpz_t *a) {
	unsigned int count;
	mpint *mp, *b;
	
	b = mpz_export(NULL, &count, 1, 1, 1, 0, *a);
	mp = CRYPTO_MALLOC(count + 1 + sizeof(uint32));
	if (mpz_tstbit(*a, count*8 -1)) {
		memset(mp, 0x0, sizeof(uint32) + 1);
		memcpy(mp + sizeof(uint32) + 1, b, count);
		count++;
	} else 
		memcpy(mp + sizeof(uint32), b, count);
	CRYPTO_FREE(b);
	count = long_swap(count);
	memcpy(mp, &count, sizeof(uint32));
	return mp;
}

void *crypto_load_key_pair(FILE *pub_key, FILE *priv_key, int algo, char **err) {
	if ((algo != DSS) && (algo != RSA)) {
		*err = "Unknown key algo";
		return NULL;
	}
	if (algo == DSS) 
		return dsa_load_keys(pub_key, priv_key, err);
	else {
		*err = "RSA key supported not implemented";
		return NULL;
	}
}

int crypto_write_key_pair(FILE *pub_key, FILE *priv_key, int algo, char **err) {
	dsa_ctx *ctx, *t_ctx;

	if ((algo != DSS) && (algo != RSA)) {
		*err = "Unknown key algo";
		return 1;
	}
	if (algo == DSS) {
		ctx = dsa_store_keys(pub_key, priv_key, err);
		rewind(pub_key);
		rewind(priv_key);
		t_ctx = dsa_load_keys(pub_key, priv_key, err);
		if (!t_ctx) {
			*err = "Couldn't read keys written to disk! Verification failed";
			dsa_free(ctx);
			return 1;
		}
		if (dsa_compare_keys(ctx, t_ctx)) {
			dsa_free(t_ctx);
			dsa_free(ctx);
			*err = "Possibly corrupted keys on disk. Verification failed";
			return 1;
		}
		dsa_free(t_ctx);
		dsa_free(ctx);
	} else if (algo == RSA) {
		*err = "RSA key support not implemented";
		return 1;
	}
	return 0;
}

mpint *crypto_kex(int algo, mpint *client_key, mpint **pub_key, unsigned int keylen, char **err) {
	mpz_t pkey, secret, ckey;
	mpint *skey;
	
	mpz_init(ckey);
	mpz_init(pkey);
	mpz_init(secret);

	make_mpi_from_mpint(client_key, &ckey);
	if ((algo != DH1) && (algo != DH14)) {
		*err = "Unknown kex algo requested";
		return NULL;
	}
	dh_kex(&ckey, algo, keylen, &pkey, &secret);
	*pub_key = make_mpint_from_mpi(&pkey);
	skey = make_mpint_from_mpi(&secret);
	mpz_clear(ckey);
	mpz_clear(secret);
	mpz_clear(pkey);
	return skey;
}

char *crypto_hash(int algo, const char *msg, unsigned int *length, char **err) {
	char *digest;

	if (algo != SHA1) {
		*err = "Unknown hashing algo requested";
		return NULL;
	}
    digest = sha1(msg, *length);
	*length = SHA1_DIGEST_SIZE;
	return digest;
}

byte *crypto_sign(int algo, const char *data, unsigned int *len, void *keys, char **err) {
	mpz_t r, sign;
	byte *signature = CRYPTO_MALLOC(sizeof(byte) * (20 + 20));
	size_t count = 0;

	if (algo != DSS) {
		*err = "Unknown signing algo requested";
		return NULL;
	}
	mpz_init(r);
	mpz_init(sign);
	dsa_sign(keys, (unsigned char *)data, *len, &r, &sign);
	if (dsa_verify(keys, (unsigned char *)data, *len, &r, &sign)) {
		*err = "DSS signing failed";
		mpz_clear(r);
		mpz_clear(sign);
		return NULL;
	}
	
//__GMP_DECLSPEC void *mpz_export __GMP_PROTO ((void *, size_t *, int, size_t, int, size_t, mpz_srcptr));
	mpz_export(signature, &count, 1, 1, 1, 0, r);
	mpz_export(signature + count, NULL, 1, 1, 1, 0, sign);
	mpz_clear(r);
	mpz_clear(sign);
	*len = 20 + 20;
	return signature;
}

byte *crypto_flatten_key(int keytype, void *key, int *outl) {
	dsa_ctx *ctx;
	mpint *p[4];
	uint32 klen[4], pos = 0;
	byte *s;
	int i;

	if (keytype != DSS) {
		return NULL;
	}
	ctx = (dsa_ctx *)key;
	p[0] = make_mpint_from_mpi(&ctx->p);
	klen[0] = long_swap(*(uint32 *)p[0]) + sizeof(uint32);
	p[1] = make_mpint_from_mpi(&ctx->q);
	klen[1] = long_swap(*(uint32 *)p[1]) + sizeof(uint32);
	p[2] = make_mpint_from_mpi(&ctx->g);
	klen[2] = long_swap(*(uint32 *)p[2]) + sizeof(uint32);
	p[3] = make_mpint_from_mpi(&ctx->y);
	klen[3] = long_swap(*(uint32 *)p[3]) + sizeof(uint32);
	
	s = CRYPTO_MALLOC(klen[0] + klen[1] + klen[2] + klen[3]);
	for (i = 0; i < 4; i++) {
		memcpy(s + pos, p[i], klen[i]);
		pos += klen[i];
		CRYPTO_FREE(p[i]);
	}
	*outl = pos;
	return s;
}

void *crypto_setup_cipher_context(int cipher, unsigned char *key, unsigned char *iv, int mode) {
    switch(cipher) {
    case AES128_CBC: return aes_key_schedule(key, 128, iv, mode);
    case AES192_CBC: return aes_key_schedule(key, 192, iv, mode);
    case AES256_CBC: return aes_key_schedule(key, 256, iv, mode);
    default: return NULL;
    }
}

void crypto_free_cipher_context(void *ctx, int cipher) {
    switch(cipher) {
    case AES128_CBC: 
    case AES192_CBC: 
    case AES256_CBC: aes_ctx_free(ctx);
    }
}

void crypto_cbc_decrypt(void *ctx, int cipher, unsigned char *ciphertxt, unsigned char *plaintxt) {
    switch (cipher) {
    case AES128_CBC:
    case AES192_CBC:
    case AES256_CBC:
        aes_cbc_decrypt(ctx, ciphertxt, plaintxt);
        break;
    }
}

void crypto_cbc_encrypt(void *ctx, int cipher, unsigned char *plaintxt, unsigned char *ciphertxt) {
    switch (cipher) {
    case AES128_CBC:
    case AES192_CBC:
    case AES256_CBC:
        aes_cbc_encrypt(ctx, plaintxt, ciphertxt);
        break;
    }
}

void *crypto_setup_mac_context(int mac, unsigned char *key, int keylen) {
    /* we only support hmac-sha1 right now */
    return hmac_ctx_init(key, keylen);
}

void crypto_free_mac_context(void *ctx, int mac) {
    switch(mac) {
    case HMAC_SHA1: 
    case HMAC_SHA1_96: hmac_free(ctx);
    }
}

unsigned char *crypto_mac(void *ctx, int mac, unsigned char *data, int dlen) {
    return hmac(ctx, data, dlen);
}

unsigned char *crypto_rand(unsigned int bits) {
    mpz_t temp;
    unsigned char *random;
    size_t count;

    mpz_init(temp);
    mpz_urandomb(temp, r_state, bits);
    random = mpz_export(NULL, &count, 1, 1, 1, 0, temp);
    mpz_clear(temp);

    return random;
}

void rand_init() {
	/* We will use win32 rand_s() to generate a cryptographically secure
	   32 bit random value to seed the gmp mersenne twister PRNG. The MT PRNG
	   can generate arbitrarily big MPI random numbers.
	*/
	unsigned int win32_rand;

	rand_s(&win32_rand);
	gmp_randinit_mt(r_state);
	gmp_randseed_ui(r_state, win32_rand);
}

int crypto_init() {
	rand_init();
	dh_init();
        hmac_init();
	return 0;
}

void crypto_printf(mpint *a) {
    mpz_t b;
    mpz_init(b);
    make_mpi_from_mpint(a, &b);
    gmp_printf("%Zd\n...................\n", b);
    mpz_clear(b);
}
