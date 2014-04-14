/* HMAC-SHA1 */
#define CRYPTO_INTERNAL
#include "crypto.h"

unsigned char ipad[HMAC_BLOCK_SIZE], opad[HMAC_BLOCK_SIZE];

void hmac_init() {
  memset(ipad, 0x36, HMAC_BLOCK_SIZE);
  memset(opad, 0x5C, HMAC_BLOCK_SIZE);
}

hmac_ctx *hmac_ctx_init(unsigned char *key, int len) {
  unsigned char *K = key;
  hmac_ctx *ctx = CRYPTO_MALLOC(sizeof(*ctx));

 check_len:
  if (len <= HMAC_BLOCK_SIZE) {
    memcpy(ctx->key, K, len);
    memset(ctx->key + len, 0x0, HMAC_BLOCK_SIZE - len);
  } else {
    K = sha1(key, len);
    len = 20;
    goto check_len;
  }
  return ctx;
}

void hmac_free(hmac_ctx *ctx) {
  CRYPTO_FREE(ctx);
}

unsigned char *hmac(hmac_ctx *ctx, const unsigned char *data, unsigned int dlen) {
  unsigned char temp[HMAC_BLOCK_SIZE], *stream, *hash;
  int i;
  
  for (i = 0; i < HMAC_BLOCK_SIZE; i += sizeof(unsigned int)) 
    *(unsigned int *)(temp + i) = *(unsigned int *)(ctx->key + i) ^ *(unsigned int *)(ipad + i);

  stream = CRYPTO_MALLOC(HMAC_BLOCK_SIZE + dlen);
  memcpy(stream, temp, HMAC_BLOCK_SIZE);
  memcpy(stream + HMAC_BLOCK_SIZE, data, dlen);

  hash = sha1(stream, HMAC_BLOCK_SIZE + dlen);
  CRYPTO_FREE(stream);

  for (i = 0; i < HMAC_BLOCK_SIZE; i += sizeof(unsigned int)) 
    *(unsigned int *)(temp + i) = *(unsigned int *)(ctx->key + i) ^ *(unsigned int *)(opad + i);
  
  stream = CRYPTO_MALLOC(20 /* sha1 o/p */ + HMAC_BLOCK_SIZE);
  memcpy(stream, temp, HMAC_BLOCK_SIZE);
  memcpy(stream + HMAC_BLOCK_SIZE, hash, 20);
  CRYPTO_FREE(hash);

  hash = sha1(stream, 20 + HMAC_BLOCK_SIZE);
  CRYPTO_FREE(stream);
  return hash;
}


