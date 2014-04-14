/**************
   RFC 4252 - SSH2 Auth protocol
   - only portions of the protocol are implemented. 
   publickey & hostbased authentication, banner & password change portions are not implemented
****************/
#include <string.h>
#include "ssh.h"
#include "win.h"
#include "log.h"

typedef struct{
    wchar_t *user;
    wchar_t *password;
    wchar_t *domain;
    void *user_token;
} auth_ctx;

void auth_get_user_creds(session *s, wchar_t **user, wchar_t **password, wchar_t **domain, void **token) {
    auth_ctx *ctx = (auth_ctx *)s->auth;
    *user = ctx->user;
    *password = ctx->password;
    *domain = ctx->domain;
    *token = ctx->user_token;
}

void cleanup_auth(session *s) {
    auth_ctx *ctx = (auth_ctx *)s->auth;
    if (!ctx) 
        return;
    if (ctx->user)
        FREE(ctx->user);
    if (ctx->domain)
        FREE(ctx->domain);
    if (ctx->password)
        FREE(ctx->password);
    FREE(ctx);
}

void auth_failure(session *s) {
    void *packet;

    plain_ssh_packet_begin(&packet, SSH_MSG_USERAUTH_FAILURE);
    plain_ssh_packet_add_name_list(packet, "password");
    plain_ssh_packet_add_byte(packet, 0);
    plain_ssh_packet_finalize(s, packet);
    write_encrypted_ssh_packet(s, packet);
}

int auth_userauth_request(session *s, ssh_packet *p) {
    wchar_t *username, *password, *domain;
    char *service, *method, *temp;
    byte discard;
    void *packet, *token;
    auth_ctx *ctx;
	char *loguser;
    
    if (!s->enc) /* we are not on a
        return 0; 

    if (s->authenticated) /* already authenticated */
        return 1;
    /* username in utf-8. We will convert to wide chars */
    temp = read_next_string(p);
	loguser = _strdup(temp);
    username = utf8_to_wchar(temp);
    FREE(temp);
    service = read_next_string(p);
    FREE(service);
    method = read_next_string(p);
    if (strcmp("password", method)) {
        /* we only support password based authentication */
        FREE(method);
        auth_failure(s);
        return 1;
    }
    FREE(method);
    discard = read_next_byte(p);
    temp = read_next_string(p);
    password = utf8_to_wchar(temp);
    FREE(temp);

    if (!win_authenticate(username, password, &domain, &token)) {
        FREE(password);
        auth_failure(s);
		ERR(NOERR, "Authentication failed for \"%s\"",loguser);
		free(loguser);
        return 0;
    }
	INFO(NOERR, "\"%s\" logged in successfully", loguser);
	free(loguser);
    plain_ssh_packet_begin(&packet, SSH_MSG_USERAUTH_SUCCESS);
    plain_ssh_packet_finalize(s, packet);
    write_encrypted_ssh_packet(s, packet);
    s->authenticated = 1;
    s->cleanup_auth = cleanup_auth;
    ctx = MALLOC(sizeof(*ctx));
    ctx->user = username;
    ctx->password = password;
    ctx->domain = domain;
    ctx->user_token = token;
    s->auth = ctx;
    return 1;
}

void auth_init() {
    handler[SSH_MSG_USERAUTH_REQUEST] = auth_userauth_request;
}
