#ifndef __SSH_H__
#define __SSH_H__

#define _CRT_SECURE_NO_WARNINGS
//#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
//#include <crtdbg.h>
#include <string.h>
#include "ssh_msg.h"

#define HMAC_SHA1     1
#define HMAC_SHA1_96  2
/* supported compression */
#define NONE 1
#define ZLIB 2

/* states */
#define KEX_INIT 1 << 0
#define DH_INIT  1 << 1
#define AUTH     1 << 2

#define DEFAULT_PORT 22
#define READ_ALL 1

#define NETWORK_OK 0
#define NETWORK_CLOSE 1
#define NETWORK_ERROR 2

#define MAX_SSH_PAYLOAD_SIZE 32768
#define MAX_SSH_PACKET_SIZE 35000

#ifndef SSHD_NAME
#define SSHD_NAME "ZERO"
#endif

#define SSH_IDENT "SSH-2.0-" SSHD_NAME

#define RECV_TIMEOUT (1000 * 60)

//#define FREE(a) sshd_free((a), __FILE__, __LINE__)
//#define MALLOC(a) sshd_malloc((a), __FILE__, __LINE__)

#define FREE(a) free(a)
#define MALLOC(a) malloc(a)

#define MPINT_SIZE(a) long_swap(*(uint32 *)(a))
#define MPINT_DATA(a) ((a) + sizeof(uint32))

#define CIPHER_BLOCK_SIZE(a)

typedef unsigned char byte; 
typedef byte boolean;
typedef unsigned int uint32;
typedef unsigned char mpint;
typedef unsigned char string;

typedef void (*ssh_func)(void *);

typedef struct {
  uint32 count;
  char **names;
} name_list;

typedef struct {
	void *dsa_keys;
	void *rsa_keys;
	wchar_t *shell;
	void *lock; 
} ssh_server;

typedef struct {
    int kex_algo;
    int host_key;
    int e_s2c;   /* outgoing cipher */
    int e_c2s;
    int mac_s2c;  /* outgoing mac algo */
    int mac_c2s;
    int comp_s2c;
    int comp_c2s;
    byte enc;      /* is this session encrypted */
    char *client_version;
    void *transport;
    ssh_func cleanup_transport;
    void *kex;
    ssh_func cleanup_kex;
    void *auth;
    ssh_func cleanup_auth;
    void *channel;         /* linked list of channels associated with this session */
    ssh_func cleanup_channel;
    mpint *secret_key;
    byte *session_id;
    uint32 session_id_len;
    byte *keys[6];           /* all secrets */
    ssh_server *server_ctx;
    void *dec_ctx;       /* decryption context */
    void *enc_ctx;
    void *s2c_mac_ctx;   /* outgoing mac context */
    void *c2s_mac_ctx;
    uint32 in_sequence;  /* the mac sequence for the incoming stream */
    uint32 out_sequence; 
    byte authenticated;  /* is this session authenticated  */
    
    /* 
       FIXME ! - the following is a hack 
       
       This session can have multiple writer threads (1 per channel)! If a writer takes a long time
       to write data, the recv() thread will timeout and kill the session & associated channels - yes, yuck !
       We will use the socket_writers count to make sure that recv() timeouts are 
       disabled while writers are working.
    */
    int socket_writers;
    /* we really need a read-write lock - channels being readers and main transport thread the writer ! (for session close msgs while channels are still there */ 
    void *lock;
    void *channel_lock; /* to sanely modify the channel linked list for this session */
} session;

typedef struct {
    byte type;
    uint32 payload_length;
    uint32 packet_length;
    byte padding_length;
    byte *payload; /* points to start of payload in the blob, this will always be blob[5] */
    byte *data; /* points to start of data */
    byte *padding; /* points to start of padding in the blob */
    byte *mac;     /* points to the start of MAC in the blob */
    uint32 pos;
    byte blob[35000]; /* all the SSH bits */
} ssh_packet;


int (*handler[255])(session *, ssh_packet *p);

void sshd_free(void *ptr, char *file, int line);
void *sshd_malloc(size_t size, char *file, int line);

long long_swap(long);
void *network_init(unsigned int port);
ssh_server *sshd_server_ctx();

typedef unsigned int (*iofunc)(void *, void *, int *, int, char **);
typedef void (*clfunc)(void *);

void process_client(void *client, void *fns);
void plain_ssh_packet_begin(void **p, byte type);
void plain_ssh_packet_add_name_list(void *p, char *names);
void plain_ssh_packet_add_byte(void *p, byte b);
void plain_ssh_packet_add_mpint(void *p, mpint *s);
void plain_ssh_packet_add_string(void *p, string *s);
void plain_ssh_packet_add_uint32(void *packet, uint32 i);
void plain_ssh_packet_peek(void *packet, char **data, int *len);
void plain_ssh_packet_add_randomness(void *packet, int bytes);
int plain_ssh_packet_write(session *s, void *p);
void plain_ssh_packet_finalize(session *s, void *packet);
byte *read_ssh_payload(void *t, boolean encrypted);
int write_encrypted_ssh_packet(session *s, void *packet);

string *make_string(char *in, uint32 *outb);
string *make_string_b(char *in, uint32 len, uint32 *outb);
char *make_cstring(string *in);
uint32 make_uint32(void *addr);

char *read_next_string(ssh_packet *p);
byte read_next_byte(ssh_packet *p);
uint32 read_next_uint32(ssh_packet *p);
unsigned __int64 read_next_uint64(ssh_packet *p);
byte *read_next_buffer(ssh_packet *p, uint32 *len);

byte *do_sign(int algo, const char *msg, int *len, session *s, char **err);
char *make_err_str(char *msg, int ecode);
byte *make_ssh_key(int algo, void *key, int *outlen);

typedef int(*write_cb)(void *, void *, byte *, uint32);
typedef int(*read_cb)(void *, void *);
typedef void(*cleanup_cb)(void *);

void transport_init();
void kex_init();
void auth_init();
void channel_init();

void start_server(void *srv, int (*quit)());

void auth_get_user_creds(session *s, wchar_t **user, wchar_t **password, wchar_t **domain, void **token);

void *sftp_boot(void *session, void *channel, wchar_t *user, wchar_t *domain, void *token, write_cb outgoing, read_cb *incoming, cleanup_cb *cleanup);
#endif /* __SSH_H__ */
