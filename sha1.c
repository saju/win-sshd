#include <stdlib.h>

#define CRYPTO_INTERNAL
#include "crypto.h"

#define SHA_BLOCK_SIZE 64 /* 512 bits */
#define shift(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define u64_swap(a) \
  (((a) << 56)                                          \
   | (((a) << 40) & 0xFF000000000000ui64)		\
   | (((a) << 24) & 0xFF0000000000ui64)                         \
   | (((a) << 8) & 0xFF00000000ui64)                                    \
   | (((a) >> 8) & 0xFF000000ui64)                                      \
   | (((a) >> 24) & 0xFF0000ui64)					\
   | (((a) >> 40) & 0xFF00ui64)                                         \
   | ((a) >> 56))

typedef struct {
  unsigned __int64 datalen;
  int len;
  const char *data;
  const char *next;
  char overflow;
  unsigned int H[5];
  unsigned char block[128];
} sha1_ctx;

void pad_block(sha1_ctx *ctx) {
  int num_zeros;
  unsigned __int64 l;
  
  if (ctx->len > SHA_BLOCK_SIZE)  {
    memcpy(ctx->block, ctx->next, SHA_BLOCK_SIZE);
    ctx->len -= SHA_BLOCK_SIZE;
    ctx->next += SHA_BLOCK_SIZE;
    return;
  }
  
  /* ok we need to pad */
  memcpy(ctx->block, ctx->next, ctx->len);
  
  ctx->block[ctx->len] = 0x80;
  
  if (SHA_BLOCK_SIZE - ctx->len - 9 > 0) 
    num_zeros = (long long)SHA_BLOCK_SIZE - ctx->len - 9;
  else if (SHA_BLOCK_SIZE - ctx->len -9 == 0)
    num_zeros = 0;
  else {
    num_zeros = SHA_BLOCK_SIZE - ctx->len + 55; 
    ctx->overflow = 1;
  }
  
  if (num_zeros) 
    memset(ctx->block + ctx->len + 1, 0x0, num_zeros);
  
  l = u64_swap(ctx->datalen);
  memcpy(ctx->block + ctx->len + 1 + num_zeros, (void *)&l, 8);
  ctx->len = 0; 
}

unsigned long f(int t, unsigned int B, unsigned int C, unsigned int D) {
  if (t < 20) 
    return ((B & C) | ((~B) & D));
  else if (t < 40) 
    return (B ^ C ^ D);
  else if (t < 60)
    return ((B & C) | (B & D) | (C & D));
  return (B ^ C ^ D);
}

unsigned int K(int t) {
  if (t < 20) return 0x5A827999;
  else if (t < 40) return 0x6ED9EBA1;
  else if (t < 60) return 0x8F1BBCDC;
  return 0xCA62C1D6;
}

void sha1_core(sha1_ctx *ctx) {
  unsigned int W[80], *w, A, B, C, D, E, TEMP;
  int t;
  
  w = (int *)ctx->block;
  for (t = 0; t < 16; t++) {
    W[t] = long_swap((unsigned int)w[t]);
	//W[t] = long_swap(*tmp);
  }

  for (t = 16; t <= 79; t++) 
    W[t] = shift(W[t-3] ^ W[t-8] ^ W[t-14] ^W[t-16], 1);
  
  A = ctx->H[0];
  B = ctx->H[1];
  C = ctx->H[2];
  D = ctx->H[3];
  E = ctx->H[4];
  for (t = 0; t <= 79; t++) {
    TEMP = shift(A, 5) + f(t, B,C,D) + E+ W[t] + K(t);
    E = D; D = C; C = shift(B, 30); B = A; A= TEMP;
  }
  ctx->H[0] += A;
  ctx->H[1] += B;
  ctx->H[2] += C;
  ctx->H[3] += D;
  ctx->H[4] += E;
}

void process_block(sha1_ctx *ctx) {
  pad_block(ctx);
  sha1_core(ctx);
  if (ctx->overflow) {
    memmove(ctx->block, ctx->block + SHA_BLOCK_SIZE, SHA_BLOCK_SIZE);
    ctx->overflow = 0;
    sha1_core(ctx);
  }
}

unsigned char *sha1(const unsigned char *data, unsigned int len) {
	sha1_ctx *ctx = CRYPTO_MALLOC(sizeof(*ctx));
	char *hash = CRYPTO_MALLOC(20);
	int i;

	ctx->overflow = 0;
	ctx->data = data;
	ctx->len = len;
	ctx->datalen = len * 8;
	ctx->next = data;
	ctx->H[0] = 0x67452301;
	ctx->H[1] = 0xEFCDAB89; 
	ctx->H[2] = 0x98BADCFE;
	ctx->H[3] = 0x10325476;
	ctx->H[4] = 0xC3D2E1F0;
	do {
          process_block(ctx);
	} while (ctx->len > 0);
	for (i = 0; i < 5; i++) {
          unsigned int l = long_swap(ctx->H[i]);
          memcpy(hash + i*sizeof(unsigned int), (void *)&l, sizeof(unsigned int));
	}
	CRYPTO_FREE(ctx);
	return hash;
}
/*
int main2(int argc, char **argv) {
	char *digest = sha1(argv[1], strlen(argv[1]));
	show_hex(digest, 20);
	return 0;
}
*/
