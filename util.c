#include <stdlib.h>
#include "log.h"
#include "mpir.h"
#include "ssh.h"
#include "crypto.h"

#define u64_swap(a) \
    (((unsigned __int64)(a) << 56)					\
   | (((unsigned __int64)(a) << 40) & 0xFF000000000000ui64)		\
   | (((unsigned __int64)(a) << 24) & 0xFF0000000000ui64)			\
   | (((unsigned __int64)(a) << 8) & 0xFF00000000ui64)			\
   | (((unsigned __int64)(a) >> 8) & 0xFF000000ui64)			\
   | (((unsigned __int64)(a) >> 24) & 0xFF0000ui64)				\
   | (((unsigned __int64) (a) >> 40) & 0xFF00ui64)				\
   | ((unsigned __int64) (a) >> 56))

void sshd_free(void *ptr, char *file, int line) {
	if (!ptr) {
		ERR(NOERR, "%s:%d called free on NULL pointer");
		exit(-1);
		return;
	}
	//BAKBAK("%s:%d free(%p)", file, line, ptr);
	//DEBUG("freed (%s:%d) %p\n", file, line, ptr);
	free(ptr);
}

void *sshd_malloc(size_t size, char *file, int line) {
	void *ptr = malloc(size);
	//BAKBAK("%s:%d %p = malloc(%d)", file, line, ptr, size);
	//DEBUG("malloc (%s:%d) %p\n", file, line, ptr);
	return ptr;
}


void show_hex(unsigned char *d, int len) {
	int i;
	
	for (i = 0; i < len; i++) {
		printf("%02X ", d[i]);
	}
        printf("\n.................................\n");
}

uint32 make_uint32(void *addr) {
	return long_swap(*(long *)addr);
}


string *make_string_b(char *b, uint32 len, uint32 *outb) {
    uint32 tlen;
    string *out;
    
    tlen = len + sizeof(uint32);
    out = MALLOC(tlen);
    memcpy(out + sizeof(uint32), b, len);
    len = long_swap(len);
    memcpy(out, &len, sizeof(uint32));
    if (outb)
        *outb = tlen;
    return out;
}

string *make_string(char *in, uint32 *outb) {
    return make_string_b(in, (uint32)strlen(in), outb);
}

char *make_cstring(string *b) {
    /* convert a SSH string into a C string */
    int len = long_swap(*(uint32 *)b);
    char *cstring = MALLOC(len + 1);

    memcpy(cstring, b + sizeof(uint32), len);
    cstring[len] = '\0';
    return cstring;
}

byte *do_sign(int algo, const char *msg, int *len, session *s, char **err) {
    byte *t, *out, *sign;
    uint32 bytes, count;
    void *keys;
    
    t = make_string("ssh-dss", &bytes);
    out = malloc(bytes + sizeof(uint32) + 40);
    memcpy(out, t, bytes);
    FREE(t);
    keys = (algo == DSS) ? s->server_ctx->dsa_keys : s->server_ctx->rsa_keys;
    sign = crypto_sign(algo, msg, len, keys, err);
    if (!sign) {
        FATAL(NOERR, "crypto_sign failed. %s", err);
        return NULL;
    }
    t = make_string_b(sign, *len, &count);
    memcpy(out + bytes, t, count);
    FREE(t);
    FREE(sign);
    *len = count + bytes;
    return out;
}

byte *make_ssh_key(int keytype, void *key, int *outlen) {
    int bytes;
    byte *t, *s;
    
    if (keytype == DSS) {
        int j;
        byte *temp;
        
        t = make_string("ssh-dss", &j);
        temp = crypto_flatten_key(keytype, key, &bytes);
        s = MALLOC(sizeof(byte) * (j + bytes));
        memcpy(s, t, j);
        memcpy(s + j, temp, bytes);
        FREE(t);
		FREE(temp);
        *outlen = j + bytes;
        return s;
    }
    return NULL;
}

char *read_next_string(ssh_packet *p) {
    char *cstring;
    byte *b = p->data + p->pos;
    
    cstring = make_cstring(b);
    
    p->pos += long_swap(*(uint32 *)b) + sizeof(uint32);
    return cstring;
}

byte *read_next_buffer(ssh_packet *p, uint32 *len) {
    byte *buffer, *b = p->data + p->pos;
    *len = long_swap(*(uint32 *)b);
    buffer = malloc(*len);
    memcpy(buffer, b + sizeof(uint32), *len);
    p->pos += *len + sizeof(uint32);
    return buffer;
}

byte read_next_byte(ssh_packet *p) {
    byte b = p->data[p->pos];
    p->pos += 1;
    return b;
}

uint32 read_next_uint32(ssh_packet *p){
    uint32 i = long_swap(*(uint32 *)(p->data + p->pos));
    p->pos += sizeof(uint32);
    return i;
}

unsigned __int64 read_next_uint64(ssh_packet *p) {
    unsigned __int64 i = u64_swap(*(unsigned __int64 *)(p->data + p->pos));
    p->pos += sizeof(unsigned __int64);
    return i;
}
