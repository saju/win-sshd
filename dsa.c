/*
  FIPS 186-2 DSA 
*/
#define CRYPTO_INTERNAL

#include <stdlib.h>
#include "ssh.h"
#include "crypto.h"

void dsa_free(dsa_ctx *ctx) {
	if (ctx->seed)
		mpz_clear(ctx->seed);
	if (ctx->p)
		mpz_clear(ctx->p);
	if (ctx->q)
		mpz_clear(ctx->q);
	if (ctx->g)
		mpz_clear(ctx->g);
	if (ctx->x)
		mpz_clear(ctx->x);
	if (ctx->y)
		mpz_clear(ctx->y);
	CRYPTO_FREE(ctx);
}

int param_gen(dsa_ctx *ctx) {
	gmp_randstate_t *rand_t = crypto_randctx();
	size_t count;
	unsigned long size;
	unsigned char *digest, rand[20]; /* 160 bits of randomness */
	int counter = 0, offset = 2, k, n, b;
	mpz_t W, X, c, two_exp_b, two_exp_L_1, two_q, temp, temp_1, temp_2, two_exp_g;
	
	mpz_init(temp_1);
	mpz_init(temp_2);
	mpz_init(two_exp_g);
	mpz_init(two_exp_b);
	mpz_init(temp);
	mpz_init(W);
	mpz_init(X);
	mpz_init(c);
	mpz_init(two_q);
	mpz_init(two_exp_L_1);

	/* this is what openssl's dsa impl does */
	n = (ctx->k_len - 1) / 160;
	b = (ctx->k_len - 1) - (n * 160);

	mpz_ui_pow_ui(two_exp_b, 2, b);
	mpz_ui_pow_ui(two_exp_L_1, 2, ctx->k_len - 1);
	mpz_ui_pow_ui(two_exp_g, 2, 160);
	

 generate_q:
	/* Generate q */
	for (;;) {
		/* SHA-1(SEED) */
		mpz_urandomb(ctx->seed, *rand_t, 159);
		mpz_export(rand, &count, 1, 1, 1, 0, ctx->seed);
		digest = sha1(rand, 20);
		mpz_import(temp_1, 20, 1, 1, 1, 0, digest);
		CRYPTO_FREE(digest);
		
		/* SHA-1((SEED + 1) mod 2^g) */
		mpz_add_ui(temp_2, ctx->seed, 1);
		mpz_mod(temp_2, temp_2, two_exp_g);
		mpz_export(rand, &count, 1, 1, 1, 0, temp_2);
		digest = sha1(rand, 20);
		mpz_import(temp_2, 20, 1, 1, 1, 0, digest);
		CRYPTO_FREE(digest);
		
		mpz_xor(ctx->q, temp_1, temp_2);
		mpz_setbit(ctx->q, 0);
		mpz_setbit(ctx->q, 159);
		
		if (mpz_probab_prime_p(ctx->q, 10)) 
			break;
	}

	mpz_mul_ui(two_q, ctx->q, 2);

 generate_p:
	mpz_set_ui(W, 0UL);
	for (k = 0; k <= n; k++) {
		mpz_t V,Vk;
		unsigned char *r;

		mpz_init(Vk);
		mpz_init(V);
		
		mpz_add_ui(Vk, ctx->seed, offset + k);
		mpz_mod(Vk, Vk, two_exp_g);
		r = mpz_export(NULL, &count, 1, 1, 1, 0, Vk);
		digest = sha1(r, (unsigned int)count);
		CRYPTO_FREE(r);
		mpz_import(V, 20, 1, 1, 1, 0, digest);
		CRYPTO_FREE(digest);
		mpz_mod(V, V, two_exp_b);
		mpz_mul_2exp(V, V, k * 160);
		mpz_add(W, W, V);
		mpz_clear(Vk);
		mpz_clear(V);
	}

	
	mpz_add(X, W, two_exp_L_1);
	mpz_mod(c, X, two_q);
	mpz_sub_ui(c, c, 1UL);
	mpz_sub(ctx->p, X, c);
	{
		/* congruency test */
		mpz_set_ui(temp, 1UL);
		if (!mpz_congruent_p(ctx->p, temp, two_q)) {
			gmp_printf("Error ! p=%Zd is not congruent to 1 modulo 2q\n", ctx->p);
			return 0;
		}
	}
	if (mpz_cmp(ctx->p, two_exp_L_1) > 0) {
		/* check if p is a robust prime */
		if (mpz_probab_prime_p(ctx->p, 10)) {
			/* got it */
			goto done;
		}
	}
	
	counter++;
	offset += n + 1;
	if (counter < 4096) 
		goto generate_p;
	else {
		counter = 0;
		offset = 2;
		goto generate_q;
	}

 done:
	mpz_clear(temp_1);
	mpz_clear(temp_2);
	mpz_clear(two_exp_g);
	mpz_clear(two_exp_b);
	mpz_clear(W);
	mpz_clear(X);
	mpz_clear(c);
	mpz_clear(two_q);
	mpz_clear(two_exp_L_1);

	/* generate g */
	{
		mpz_t h;
		mpz_init(h);

	generate_g:
		mpz_sub_ui(temp, ctx->p, 1UL);
		size = (unsigned long)mpz_sizeinbase(temp, 2);
		mpz_cdiv_q(temp, temp, ctx->q);
		mpz_urandomb(h, *rand_t, size);
		mpz_clrbit(h, size -1);
		mpz_powm(ctx->g, h, temp, ctx->p);
		if (mpz_cmp_ui(ctx->g, 1) <= 0)
			goto generate_g;
		mpz_clear(h);
	}

	/* generate x */
	mpz_urandomb(ctx->x, *rand_t, 159);

	/* generate y */
	mpz_powm(ctx->y, ctx->g, ctx->x, ctx->p);
	return 1;
}

dsa_ctx *dsa_ctx_init(unsigned int key_length) {
	dsa_ctx *ctx = CRYPTO_MALLOC(sizeof(*ctx));

	ctx->k_len = key_length ? key_length : 1024;
	mpz_init(ctx->seed);
	mpz_init(ctx->p);
	mpz_init(ctx->q);
	mpz_init(ctx->g);
	mpz_init(ctx->x);
	mpz_init(ctx->y);

	return ctx;
}

void dsa_sign(dsa_ctx *ctx, unsigned char *msg, unsigned int length, mpz_t *r, mpz_t *sign) {
	unsigned char *digest;
	mpz_t k, k_1, temp;
	gmp_randstate_t *rand_t = crypto_randctx();
	
	mpz_init(k);
	mpz_init(k_1);
	mpz_init(temp);
	
 generate_K:
	mpz_urandomb(k, *rand_t, 159);

	if (!mpz_invert(k_1, k, ctx->q)) 
		goto generate_K; /* no inverse exists for this K */

	if (mpz_cmp(k_1, ctx->q) >= 0) 
		goto generate_K; /* K_1 should be smaller than q */
	
	mpz_powm(*r, ctx->g, k, ctx->p);
	mpz_mod(*r, *r, ctx->q);
	
	digest = sha1(msg, length);
		
	mpz_import(*sign, 20, 1, 1, 1, 0, digest);
	CRYPTO_FREE(digest);
		
	mpz_mul(temp, ctx->x, *r);
	mpz_add(*sign, *sign, temp);
	mpz_mul(*sign, k_1, *sign);
	mpz_mod(*sign, *sign, ctx->q);
	mpz_clear(k);
	mpz_clear(k_1);
	mpz_clear(temp);
}

int dsa_verify(dsa_ctx *ctx, unsigned char *msg, int length, mpz_t *r, mpz_t *s) {
	mpz_t w, u1, u2;
	unsigned char *digest;
	int res;

	mpz_init(w);

	/* w = inverse(s) mod q */
	mpz_invert(w, *s, ctx->q);

	digest = sha1(msg, length);

	mpz_init(u1);
	mpz_import(u1, 20, 1, 1, 1, 0, digest);
	CRYPTO_FREE(digest);
	
	/* u1 = digest * w mod q */
	mpz_mul(u1, u1, w);
	mpz_mod(u1, u1, ctx->q);

	mpz_init(u2);
	/* u2 = r * w mod q */
	mpz_mul(u2, *r, w);
	mpz_mod(u2, u2, ctx->q);

	/* We really want to do ((g**u1 * g**u2) mod p) mod q, but gmplib doesn't have a 
	   mpz_pow(mpz_t, mpz_t, mpz_t) method. So we use (A*B) mod p = ((A mod p) * (B mod p)) * mod p 
	*/
	mpz_powm(u1, ctx->g, u1, ctx->p);
	mpz_powm(u2, ctx->y, u2, ctx->p);
	mpz_mul(u1, u1, u2);
	mpz_mod(u1, u1, ctx->p);

	mpz_mod(u1, u1, ctx->q);

	res = mpz_cmp(u1, *r);
	mpz_clear(u1);
	mpz_clear(u2);
	mpz_clear(w);
	return res;
}

void *dsa_make_ctx() {
	dsa_ctx *ctx;
	mpz_t r, s;
	unsigned char *garbage = NULL;

	ctx = dsa_ctx_init(1024);
	param_gen(ctx);
	/* 
	   test if the generated keys are good. We will sign & verify a random message
	*/
	mpz_init(r);
	mpz_init(s);
	garbage = crypto_rand(4096);
	dsa_sign(ctx, garbage, 4096/8, &r, &s);
	if (dsa_verify(ctx, garbage, 4096/8, &r, &s)) {
		dsa_free(ctx);
		ctx = NULL;
	}
	mpz_clear(r);
	mpz_clear(s);
	CRYPTO_FREE(garbage);
	return ctx;
}


/*
 * (optionally) generate and store public & private DSA keys to disk 
 */
dsa_ctx *dsa_store_keys(FILE *pub_fp, FILE *priv_fp, char **err) {
	dsa_ctx *ctx = dsa_make_ctx();

	if (!ctx) 
		return NULL;
	if (pub_fp) {
		mpz_out_raw(pub_fp, ctx->p);
		mpz_out_raw(pub_fp, ctx->q);
		mpz_out_raw(pub_fp, ctx->g);
		mpz_out_raw(pub_fp, ctx->y);
	}
	if (priv_fp) {
		mpz_out_raw(priv_fp, ctx->x);
	}
	return ctx;
}

/* load dsa keys from a file on disk which should be written by dsa_store_keys */
dsa_ctx *dsa_load_keys(FILE *pub_fp, FILE *priv_fp, char **err) {
	dsa_ctx *ctx = dsa_ctx_init(1024);

	if (pub_fp) {
		mpz_inp_raw(ctx->p, pub_fp);
		mpz_inp_raw(ctx->q, pub_fp);
		mpz_inp_raw(ctx->g, pub_fp);
		mpz_inp_raw(ctx->y, pub_fp);
	}
	if (priv_fp) {
		mpz_inp_raw(ctx->x, priv_fp);
	}

	return ctx;
}

/*
int dsa_make_key_pair(byte **pub, byte **priv, dsa_ctx *octx) {
	dsa_ctx *ctx = octx ? octx : dsa_make_ctx();
	if (!ctx) 
		return 1;

	pub[0] = make_mpint_from_mpi(&ctx->p);
	pub[1] = make_mpint_from_mpi(&ctx->q);
	pub[2] = make_mpint_from_mpi(&ctx->g);
	pub[3] = make_mpint_from_mpi(&ctx->y);
	if (priv)
		*priv  = make_mpint_from_mpi(&ctx->x);

	if (!octx)
		dsa_free(ctx);
	return 0;
}
*/
int dsa_compare_keys(dsa_ctx *a, dsa_ctx *b) {
	if (mpz_cmp(a->p, b->p) ||
		mpz_cmp(a->q, b->q) ||
		mpz_cmp(a->g, b->g) ||
		mpz_cmp(a->y, b->y) ||
		mpz_cmp(a->x, b->x))
		return 1;
	return 0;
}

/*
int main(int argc, char **argv) {
	dsa_ctx *ctx;
	mpz_t r, s, temp;

	mpz_init(r);
	mpz_init(s);
	mpz_init(temp);

	crypto_init();
	ctx = dsa_ctx_init(1024);
	param_gen(ctx);
	mpz_sub_ui(temp, ctx->p, 1UL);
	mpz_cdiv_r(temp, temp, ctx->q);

	dsa_sign(ctx, argv[1], strlen(argv[1]), &r, &s);

	dsa_verify(ctx, &s, &r, argv[2], strlen(argv[2]));
	gmp_printf("p=%Zd\nq=%Zd\n", ctx->p, ctx->q);
	dsa_free(ctx);
}
*/
