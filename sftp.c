/**
   SFTP - portions of http://tools.ietf.org/html/draft-ietf-secsh-filexfer-13
**/

#include "log.h"
#include "ssh.h"
#include "fs.h"
#include "win.h"

#define SFTP_VERSION 3
#define SFTP_PITA_VERSION 3
#define SFTP_REAL_VERSION "6"

#define SFTP_MAX_SIZE 35000 /* fixme should be < max_ssh_payload */

#define SSH_FXP_INIT     1
#define SSH_FXP_VERSION  2
#define SSH_FXP_OPEN     3
#define SSH_FXP_CLOSE    4
#define SSH_FXP_WRITE    6
#define SSH_FXP_LSTAT    7
#define SSH_FXP_SETSTAT  8
#define SSH_FXP_REMOVE   13
#define SSH_FXP_MKDIR    14
#define SSH_FXP_RMDIR    15
#define SSH_FXP_REALPATH 16
#define SSH_FXP_STAT     17
#define SSH_FXP_STATUS   101
#define SSH_FXP_HANDLE   102
#define SSH_FXP_NAME     104
#define SSH_FXP_ATTRS    105


typedef struct {
    void *p;
    uint32 length;
    byte   type;
    uint32 request_id;
} sftp_packet;

typedef struct {
    int pos;
    byte *data;
} sftp_plain;

typedef struct {
    void *channel;
    void *session;
    write_cb outgoing;
    wchar_t *user;
    wchar_t *domain;
    uint32 version;
    wchar_t *pwd; 
    void *user_token;
    char *root;
    /* FIXME: only 1 file handle can be open at a time in 
       1 session. This should be a linked list of handles
       but it is not - this is broken
    */
    void *handle;
} sftp_ctx;

unsigned __int64 wtf(unsigned __int64 i) {
    unsigned char c;
    union {
	unsigned __int64 num;
	unsigned char c[8];
    } x;

    x.num = i;
    c = x.c[0]; x.c[0] = x.c[7]; x.c[7] = c;
    c = x.c[1]; x.c[1] = x.c[6]; x.c[6] = c;
    c = x.c[2]; x.c[2] = x.c[5]; x.c[5] = c;
    c = x.c[3]; x.c[3] = x.c[4]; x.c[4] = c;
    return x.num;
}

void sftp_packet_begin(sftp_plain **p, byte type) {
    sftp_plain *pk = malloc(sizeof(*pk));
    pk->data = malloc(SFTP_MAX_SIZE);
    pk->pos = sizeof(uint32);
    pk->data[pk->pos] = type;
    pk->pos++;
    if (type != SSH_FXP_VERSION)
	pk->pos += sizeof(uint32); /* storage for request id */
    *p = pk;
}

void sftp_packet_add_uint32(sftp_plain *p, uint32 num) {
    uint32 l = long_swap(num);
    memcpy(p->data + p->pos, (void *)&l, sizeof(l));
    p->pos += sizeof(l);
}

void sftp_packet_add_cstring(sftp_plain *p, char *s) {
    char *tmp = make_string(s, NULL);
    uint32 bytes = long_swap(*(uint32 *)tmp) + sizeof(uint32);
    memcpy(p->data + p->pos, tmp, bytes);
    free(tmp);
    p->pos += bytes;
}

void sftp_packet_add_utf8(sftp_plain *p, wchar_t *s) {
    char *temp = wchar_to_utf8(s);
    sftp_packet_add_cstring(p, temp);
    free(temp);
}

void sftp_packet_add_byte(sftp_plain *p, byte b) {
    p->data[p->pos] = b;
    p->pos++;
}

void sftp_packet_add_uint64(sftp_plain *p, unsigned __int64 i) {
    unsigned __int64 j = u64_swap(i);
    memcpy(p->data + p->pos, (void *)&j, sizeof(j));
    p->pos += sizeof(j);
}

void sftp_packet_add_int64(sftp_plain *p, __int64 i) {
    __int64 j = u64_swap(i);
    memcpy(p->data + p->pos, (void *)&j, sizeof(j));
    p->pos += sizeof(j);
}

void sftp_packet_finalize(sftp_plain *p, uint32 request_id, int ver) {
    /* subtract the length field */
    uint32 size = long_swap(p->pos - sizeof(uint32));
    memcpy(p->data, (void *)&size, sizeof(uint32));
    if (!ver) {
	size = long_swap(request_id);
	memcpy(p->data + sizeof(uint32) + sizeof(byte), (void *)&size, sizeof(uint32));
    }
}

int sftp_packet_write(sftp_ctx *ctx, sftp_plain *plain) {
    int out =  ctx->outgoing(ctx->session, ctx->channel, plain->data, plain->pos);
    free(plain->data);
    free(plain);
    return out;
}

int sftp_send_status(int error_code, char *emsg, sftp_packet *sp, sftp_ctx *ctx) {
    sftp_plain *p;
    
    sftp_packet_begin(&p, SSH_FXP_STATUS);
    sftp_packet_add_uint32(p, error_code);
    sftp_packet_add_cstring(p, emsg ? emsg : "");
    sftp_packet_add_cstring(p, "");
    sftp_packet_finalize(p, sp->request_id, 0);
    return sftp_packet_write(ctx, p);
}

int sftp_send_attrs(stat_b *st, uint32 give, sftp_packet *sp, sftp_ctx *ctx) {
    sftp_plain *p;
    
    sftp_packet_begin(&p, SSH_FXP_ATTRS); 
    sftp_packet_add_uint32(p, give); 
    sftp_packet_add_uint64(p, st->size);
    sftp_packet_add_uint32(p, st->uid);
    sftp_packet_add_uint32(p, st->gid);
    sftp_packet_add_uint32(p, st->perms);
    sftp_packet_add_uint32(p, st->atime);
    sftp_packet_add_uint32(p, st->mtime);
    sftp_packet_finalize(p, sp->request_id, 0);
    return sftp_packet_write(ctx, p);
}

int sftp_stat(sftp_packet *sp, sftp_ctx *ctx) {
    char *emsg = NULL, *path, *upath = read_next_string(sp->p);
    uint32 give, flags = read_next_uint32(sp->p);
    int ecode;
    stat_b *st;

    path = win_concat_path(ctx->root, upath);
    free(upath);
	
    if (!win_switch_user(ctx->user_token)) {
		free(path);
		return 0;
    }
	
    st = malloc(sizeof(*st));
    ecode = win_filestat(st, path, flags, &give, &emsg);
    if (ecode != FX_OK) {
		int ret;
		
		free(st);
		win_switch_user(NULL);
		free(path);
		ret = sftp_send_status(ecode, emsg, sp, ctx);
		free(emsg);
		return ret;
    }
    win_switch_user(NULL);
	
    ecode = sftp_send_attrs(st, give, sp, ctx);
    free(st);
    free(path);
    return ecode;
}

int sftp_mkdir(sftp_packet *sp, sftp_ctx *ctx) {
    int ecode, ret;
    char *emsg = NULL, *path, *upath = read_next_string(sp->p);
    
    path = win_concat_path(ctx->root, upath);
    free(upath);
    if (!win_switch_user(ctx->user_token)) {
		free(path);
		return 0;
    }
    ecode = win_makedir(path, &emsg);
    win_switch_user(NULL);
    free(path);
    ret = sftp_send_status(ecode, emsg, sp, ctx);
    if (ecode != FX_OK) 
		free(emsg);
    return ret;
}

int sftp_realpath(sftp_packet *sp, sftp_ctx *ctx) {
    /*
      XXX: this is completely broken. We should call
       some API that can return the true canonical path
       to us
    */
    sftp_plain *p;
    char *path, *upath = read_next_string(sp->p);
    
    path = win_concat_path(ctx->root, upath);
    free(upath);
    
    sftp_packet_begin(&p, SSH_FXP_NAME);
    sftp_packet_add_uint32(p, 1L);
    sftp_packet_add_cstring(p, path);
    sftp_packet_add_cstring(p, path);
    sftp_packet_finalize(p, sp->request_id, 0);
    free(path);
    return sftp_packet_write(ctx, p);
}

int sftp_open(sftp_packet *sp, sftp_ctx *ctx) {
    sftp_plain *p;
    int ecode;
    char *emsg = NULL, *path, *upath = read_next_string(sp->p);
    uint32 flags = read_next_uint32(sp->p);
    
    path = win_concat_path(ctx->root, upath);
    free(upath);
    
    if (!win_switch_user(ctx->user_token)) {
		free(path);
		return 0;
    }
	
    ecode = win_createfile(path, flags, &ctx->handle, &emsg);
    if (ecode != FX_OK) {
		int ret;
		win_switch_user(NULL);
		free(path);
		ERR(ecode, "open(%s) failed", path);
		ret = sftp_send_status(ecode, emsg, sp, ctx);
		free(emsg);
		return ret;
    }
	DEBUG("open(%s) succeeded", path);
    win_switch_user(NULL);
    free(path);
    
    sftp_packet_begin(&p, SSH_FXP_HANDLE);
    sftp_packet_add_cstring(p, "handle");
    sftp_packet_finalize(p, sp->request_id, 0);
    return sftp_packet_write(ctx, p);
}

int sftp_close(sftp_packet *sp, sftp_ctx *ctx) {
    win_free_token(ctx->handle);
	ctx->handle = NULL;
    return sftp_send_status(FX_OK, NULL, sp, ctx);
}

int sftp_write(sftp_packet *sp, sftp_ctx *ctx) {
    uint32 ecode, len, ret;
    char *emsg = NULL, *handle = read_next_string(sp->p);
    unsigned __int64 offset = read_next_uint64(sp->p);
    byte *data = read_next_buffer(sp->p, &len);
    
    free(handle);

    if (!win_switch_user(ctx->user_token)) {
		free(data);
		return 0;
    }
    ecode = win_writefile(ctx->handle, data, len, offset, &emsg);
    free(data);
    win_switch_user(NULL);
    ret = sftp_send_status(ecode, emsg, sp, ctx);
    if (emsg) free(emsg);
    return ret;
}

int sftp_chmod(sftp_packet *sp, sftp_ctx *ctx) {
    /* FIXME stub */
    return sftp_send_status(FX_OK, NULL, sp, ctx);
}

int sftp_remove(sftp_packet *sp, sftp_ctx *ctx) {
    char *upath = read_next_string(sp->p);
    char *emsg = NULL, *path = win_concat_path(ctx->root, upath);
    int ecode;
    
    free(upath);
    if (!win_switch_user(ctx->user_token)) {
	free(path);
	return 0;
    }

    ecode = win_deletefile(path, &emsg);

    win_switch_user(NULL);
    free(path);
    ecode = sftp_send_status(ecode, emsg, sp, ctx);
    if (emsg) free(emsg);
    return ecode;
}

int sftp_rmdir(sftp_packet *sp, sftp_ctx *ctx) {
    char *upath = read_next_string(sp->p);
    char *emsg = NULL, *path = win_concat_path(ctx->root, upath);
    int ecode;
    
    free(upath);
    if (!win_switch_user(ctx->user_token)) {
	free(path);
	return 0;
    }

    ecode = win_rmdir(path, &emsg);

    win_switch_user(NULL);
    free(path);
    ecode = sftp_send_status(ecode, emsg, sp, ctx);
    if (emsg) free(emsg);
    return ecode;
}

int sftp_init(sftp_packet *sp, sftp_ctx *ctx) {
    sftp_plain *p;

    ctx->version = read_next_uint32(sp->p);
    sftp_packet_begin(&p, SSH_FXP_VERSION);

    sftp_packet_add_uint32(p, SFTP_VERSION);
    sftp_packet_finalize(p, 0, 1);
    return sftp_packet_write(ctx, p);
}

/**
  decode incoming data to a sftp_packet
  dispatch to the correct handler
*/
int sftp_incoming(void *p, sftp_ctx *ctx) {
    int ret;
    sftp_packet *sp = malloc(sizeof(*sp));
    
    sp->p = p;
    sp->length = read_next_uint32(p);
    sp->type = read_next_byte(p);

    if (sp->type != SSH_FXP_INIT)
	sp->request_id = read_next_uint32(p);
    
    switch (sp->type) {
    case SSH_FXP_INIT:     ret = sftp_init(sp, ctx); break;
    case SSH_FXP_STAT:
    case SSH_FXP_LSTAT:    ret = sftp_stat(sp, ctx); break;
    case SSH_FXP_MKDIR:    ret = sftp_mkdir(sp, ctx); break;
    case SSH_FXP_REALPATH: ret = sftp_realpath(sp, ctx); break;
    case SSH_FXP_OPEN:     ret = sftp_open(sp, ctx); break;
    case SSH_FXP_CLOSE:    ret = sftp_close(sp, ctx); break;
    case SSH_FXP_WRITE:    ret = sftp_write(sp, ctx); break;
    case SSH_FXP_SETSTAT:  ret = sftp_chmod(sp, ctx); break;
    case SSH_FXP_REMOVE:   ret = sftp_remove(sp, ctx); break;
    case SSH_FXP_RMDIR:    ret = sftp_rmdir(sp, ctx); break;
    }
    free(sp);
    return ret;
}

/** shutdown this ftp session */
void sftp_shutdown(sftp_ctx *ctx) {
	if (ctx->handle) {
		win_free_token(ctx->handle);
	}
    free(ctx->root);
    free(ctx);
}

/** 
    boot this sftp session 
    transport layer will pass in their context objects (session & channel)
    the user & domain name, a callback function to write out sftp data.
    SFTP layer will return an opaque context and a function that accepts incoming data
**/
void *sftp_boot(void *session, void *channel, wchar_t *user, wchar_t *domain, void *token,
		write_cb outgoing, read_cb *incoming, cleanup_cb *cleanup) {
    sftp_ctx *ctx = malloc(sizeof(*ctx));

    ctx->outgoing = outgoing;
    ctx->channel = channel;
    ctx->session = session;
    ctx->user = user;
    ctx->domain = domain;
    ctx->user_token = token;
    *incoming = sftp_incoming;
    *cleanup = sftp_shutdown;

    /* this sftp session is rooted at the user's profile directory
       C:\Users\saju\ (for eg) */
    ctx->root = win_get_homedir(ctx->user_token);
    return ctx;
}
