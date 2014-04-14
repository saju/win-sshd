/*
 * rfc4253 - SSH Transport Layer Protocol implementation
 */
#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <string.h>
#include "ssh.h"
#include "log.h"
#include "crypto.h"
#include "win.h"

#define SOCKET unsigned
#define OK   1
#define FAIL 2

#define STRICT 1

typedef struct {
    int pos;
    int plain_packet_len;
    int encrypted_packet_len;
    byte *data;
} plain_packet; /* ok, starts life as a plain packet but gets encrypted in time */

typedef struct {
    void *client;
    iofunc read;
    iofunc write;
    clfunc close;
    char rbuff[MAX_SSH_PACKET_SIZE];
    unsigned int _pos;
    unsigned int _cur;
    unsigned long bytes_read;
    unsigned long bytes_write;
    uint32 ctr;
} tr_client;

int __fill_buffer(tr_client *t, int bytes, int fl, char **emsg) {
    int ecode;
	
    if (t->_pos < MAX_SSH_PACKET_SIZE) 
	bytes = MAX_SSH_PACKET_SIZE - t->_pos;
    else
	t->_pos = t->_cur = 0;

    ecode = t->read(t->client, t->rbuff + t->_pos, &bytes, fl, emsg);
    if (ecode != NETWORK_OK)
	return ecode;
    t->_pos += bytes;
    return NETWORK_OK;
}

void reset_buffer(tr_client *t) {
    t->_pos = t->_cur = 0;
}

int read_data2(tr_client *t, char *buff, int *size, unsigned int want_all, char **emsg) {
    int status = 0, tbytes = 0, rbytes = *size;
    do {
		status = t->read(t->client, buff + tbytes, &rbytes, 0, emsg);
		if (status != NETWORK_OK) 
			return status;
		tbytes += rbytes;
		if (!want_all) 
			break;
		if (tbytes == *size)
			break;
		else
			rbytes = *size - tbytes;
    } while (1);
    *size = tbytes;
    return NETWORK_OK;
}

int read_data(tr_client *t, char *buff, unsigned int *size, unsigned int want_all, char **emsg) {
    int ecode;
	
    /* if there is nothing available to read in our local buffers, fill them from the client */
    if (t->_cur == t->_pos) {
		ecode = __fill_buffer(t, MAX_SSH_PACKET_SIZE, 0, emsg);
		if (ecode != NETWORK_OK) 
			return ecode;
    }
	
    /* we have data in our local buffers */
    if (*size <= t->_pos - t->_cur) {
		/*  we can satisfy the full requirement from our local buffer */
		memcpy(buff, t->rbuff + t->_cur, *size);
		t->_cur += *size;
		return NETWORK_OK;
    } else { 
	/* buffer doesn't have *size bytes of data. If the caller doesn't strictly want *size bytes,
	   we will just send him what we have */
		if (!want_all) {
			*size = t->_pos - t->_cur;
			memcpy(buff, t->rbuff + t->_cur, t->_pos - t->_cur);
			t->_cur = t->_pos;
			return NETWORK_OK;
	} else {
	    /* caller strictly wants *size bytes, we will have to read data from the client 
	       to get enough bytes */
	    int old_pos = t->_pos - t->_cur, remaining;
	    memcpy(buff, t->rbuff + t->_cur, t->_pos - t->_cur);
	    remaining = *size - (t->_pos - t->_cur);
	    t->_cur = t->_pos;
	    ecode = __fill_buffer(t, remaining, READ_ALL, emsg);
	    if (ecode != NETWORK_OK)
			return ecode;
	    memcpy(buff + old_pos, t->rbuff + t->_cur, remaining);
	    t->_cur += remaining;
	    return NETWORK_OK;
	}
    }
}

int push_back(tr_client *t, unsigned int howmuch, int fl) {
    if (howmuch > (t->_cur + 1)) {
		if (fl & STRICT) 
			return -1;
		else {
			int old = t->_cur;
			t->_cur = 0;
			return old+1;
		}
    }
    t->_cur -= howmuch;
    return howmuch;
}

int seek(tr_client *t, int newpos) {
    if (newpos > -1 && newpos < MAX_SSH_PACKET_SIZE) {
		t->_cur = newpos;
		return newpos;
    }
    return -1;
}

int write_data(tr_client *t, char *buff, int *size, char **emsg) {
    /* write_data() is always write_all */
    int ecode, total_written = 0, bytes = *size;
    do {
		ecode = t->write(t->client, buff + total_written, &bytes, 0, emsg);
		if (ecode != NETWORK_OK)
			return ecode;
		total_written += bytes;
		bytes = *size - total_written;	
    } while (bytes > 0);
    *size = total_written;
    return NETWORK_OK;
}

void cleanup_transport(session *s) {
    tr_client *t = s->transport;
    t->close(t->client);
    FREE(t);
}

void destroy_ssh_packet(ssh_packet *p) {
    FREE(p);
}

void plain_ssh_packet_begin(plain_packet **p, byte type) {
    plain_packet *packet;

    packet = MALLOC(sizeof(*packet));
    packet->data = MALLOC(MAX_SSH_PAYLOAD_SIZE);
    packet->pos = 0;
    packet->data[packet->pos] = type;
    packet->pos++;
    *p = packet;
}

void plain_ssh_packet_add_randomness(plain_packet *packet, int bytes) {
    char *garbage = crypto_rand(bytes * 8);
    memcpy(packet->data + packet->pos, garbage, bytes);
    packet->pos += bytes;
    FREE(garbage);
}

void plain_ssh_packet_add_uint32(plain_packet *packet, uint32 i) {
    uint32 l = long_swap(i);

    memcpy(packet->data + packet->pos, (void *)&l, sizeof(l));
    packet->pos += sizeof(l);
}

void plain_ssh_packet_add_name_list(plain_packet *packet, char *names) {
    uint32 len = (uint32)strlen(names);
	
    plain_ssh_packet_add_uint32(packet, len);
    memcpy(packet->data + packet->pos, names, len);
    packet->pos += len;
}

void plain_ssh_packet_add_byte(plain_packet *packet, byte b) {
    packet->data[packet->pos] = b;
    packet->pos++;
}

void plain_ssh_packet_peek(plain_packet *packet, char **data, int *len) {
    *data = packet->data;
    *len = packet->pos;
}

void plain_ssh_packet_add_string(plain_packet *packet, string *s) {
    uint32 bytes = long_swap(*(uint32 *)s) + sizeof(uint32);
    memcpy(packet->data + packet->pos, s, bytes);
    packet->pos += bytes;
}

void plain_ssh_packet_add_mpint(plain_packet *packet, mpint *s) {
    plain_ssh_packet_add_string(packet, s);
}

void plain_ssh_packet_finalize(session *s, plain_packet *p) {
    int total, pk_length, upk_length;
    byte padding_len, *outbuff, *g;

    total = p->pos + sizeof(uint32) + sizeof(byte);
    if (!s->enc) {
        padding_len = 8 - total % 8;
        if (padding_len < 4) 
            padding_len += 8;
    } else {
        int block_size = crypto_cipher_block_size(s->e_c2s) / 8;
        padding_len = block_size - total % block_size;
        if (padding_len < 4) 
            padding_len += block_size;
    }
    pk_length = p->pos + sizeof(padding_len) + padding_len;
    upk_length = long_swap(pk_length);
    outbuff = MALLOC(MAX_SSH_PACKET_SIZE);
    memcpy(outbuff, (void *)&upk_length, sizeof(upk_length));
    memcpy(outbuff + sizeof(upk_length), (void *)&padding_len, sizeof(padding_len));
    memcpy(outbuff + sizeof(upk_length) + sizeof(padding_len), p->data, p->pos);
    g = crypto_rand(padding_len * 8);
    memcpy(outbuff + sizeof(upk_length) + sizeof(padding_len) + p->pos, g, padding_len);
    FREE(g);
    FREE(p->data);

    p->data = outbuff;
    p->plain_packet_len = pk_length + sizeof(pk_length);
}

int plain_ssh_packet_write(session *s, plain_packet *p) {
    tr_client *t;
    int total;
    char *error;
    
    t = s->transport;
    total = p->plain_packet_len;
    if (write_data(t, p->data, &total, &error) != NETWORK_OK) {
        ERR(NOERR, "Failed to write plain ssh packet to client. %s", error);
        FREE(p->data);
        FREE(p);
        return 0;
    }
    FREE(p->data);
    FREE(p);
    s->out_sequence++;
    return 1;
}

/*
 * Section 4.2 - Protocol version exchange 
 */
int protocol_version_exchange(session *s) {
    char buffer[255];
    int total_size, size, ecode = FAIL;
    char *error;
    tr_client *t = s->transport;
    
    /* hello world */
    DEBUG("Protocol Version Exchange started with our version=%s", SSH_IDENT);
    
    sprintf(buffer, "%s\r\n",SSH_IDENT);
    size = (int)strlen(buffer);
    ecode = write_data(t, buffer, &size, &error);
    if (ecode != NETWORK_OK) {
        ERR(NOERR, "Could not write to client. %s", error);
        return 1;
    }
    
    /* parse the client version */
    memset(buffer, 0, 255);
    size = 255;
    total_size = 0;
    do {
        int i, parsed = 0;
        ecode = read_data(t, buffer + total_size, &size, 0, &error);
        if (ecode != NETWORK_OK) {
            ERR(NOERR, "Could not read client's protocol version. %s", error);
            return 0;
        } 
        for (i = total_size+1; i < total_size + size; i++) {
            if (buffer[i] == '\n' ) {
                if (buffer[i-1] == '\r') {
                    buffer[i-1] = '\0';
                    parsed = i;
                    break;
                } else { /* some clients may only send a \n instead of \r\n */
                    buffer[i] = '\0';
                    parsed = i;
                    break;
                }
            }
        }
        total_size += size;
        size = 255 - total_size;
        if (parsed) {
            seek(t, parsed+1);
            ecode = OK;
            break;
        }
    } while (total_size < 255);
    
    if (ecode != OK) {
        ERR(NOERR, "Could not parse client version. Maybe this is not a SSH2 client ?");
        return 0;
    }
    if (!strstr(buffer, "SSH-2.0")) {
        ERR(NOERR, "Sorry. Not a SSH 2.0 client(%s)", buffer);
        return 0;
    }
    s->client_version = _strdup(buffer);
    s->in_sequence = s->out_sequence = -1;
    INFO(NOERR, "Client \"%s\" connected", s->client_version);
    return 1;
}

int verify_mac(session *s, ssh_packet *p) {
    byte temp[MAX_SSH_PACKET_SIZE + sizeof(uint32)];
    uint32 seq = long_swap(s->in_sequence);
    byte *hmac;
    int i;

    memcpy(temp, &seq, sizeof(uint32));
    memcpy(temp + sizeof(uint32), p->blob, p->packet_length + sizeof(p->packet_length));
    hmac = crypto_mac(s->c2s_mac_ctx, s->mac_c2s, temp, p->packet_length + 2*sizeof(uint32));
    for (i = 0; i < 20; i++) {
        if (hmac[i] != ((byte *)p->mac)[i]) {
            DEBUG("MAC mismatch");
            FREE(hmac);
            return 0;
        }
    }
    FREE(hmac);
    return 1;
}

ssh_packet *read_encrypted_ssh_packet(session *s) {
    int i;
    char *error;
    tr_client *t = s->transport;
    int ecode, bytes, csize, total_bytes = 0;
    ssh_packet *p = MALLOC(sizeof(*p));
    byte temp[MAX_SSH_PACKET_SIZE];

    p->pos = 0;
    /* Read upto the block size for the cipher in use */
    csize = bytes = crypto_cipher_block_size(s->e_c2s) / 8;
    ecode = read_data(t, temp, &bytes, 1, &error);
    if (ecode != NETWORK_OK) {
	//ERR(NOERR, "Could not read cipher block size of data. %s", error);
	FREE(p);
	return NULL;
    }
    total_bytes += bytes;

    /* decrypt the packet length to figure out how much data remains to be read */
    crypto_cbc_decrypt(s->dec_ctx, s->e_c2s, temp, p->blob);
  
    p->packet_length = long_swap(*(unsigned long *)p->blob);
    bytes = p->packet_length + 4 /* size of packet_length uint32 */ - csize /* cipher size we already read */;
    if (bytes != 0) {
	ecode = read_data(t, temp + total_bytes, &bytes, 1, &error);
	if (ecode != NETWORK_OK) {
	    ERR(NOERR, "Could not read %d bytes of encrypted packet. %s", bytes, error);
	    FREE(p);
	    return NULL;
	}
    }
    total_bytes += bytes;

    /* the full packet is in 'temp', the first cipher block size is decrypted in 'block'. We will decrypt the rest now */
    for (i = csize; i < total_bytes; i += csize) 
	crypto_cbc_decrypt(s->dec_ctx, s->e_c2s, temp + i, p->blob + i);

    p->padding_length = *(byte *)(p->blob + sizeof(p->packet_length));
    p->payload = p->blob + sizeof(p->padding_length) + sizeof(p->packet_length);
    p->data = (byte *)p->payload + sizeof(p->type);
    p->padding = (char *)p->payload + p->packet_length - p->padding_length - sizeof(p->packet_length);
    p->type = ((byte *)(p->payload))[0];

    /* read & verify the 20 byte MAC */
    bytes = 20;
    ecode = read_data(t, p->blob + total_bytes, &bytes, 1, &error);
    if (ecode != NETWORK_OK) {
	ERR(NOERR, "Could not read %d bytes of encrypted packet", bytes);
	FREE(p);
	return NULL;
    }
    p->mac = p->blob + total_bytes;
    s->in_sequence++;
    if (!verify_mac(s,p)) 
	return NULL;
    return p;
}

ssh_packet *read_plain_ssh_packet(session *s) {
    /* this should only get called during the initial KEX */
    char *error;
    tr_client *t = s->transport;
    int ecode, bytes = MAX_SSH_PACKET_SIZE, total_bytes = 0;
    ssh_packet *p = MALLOC(sizeof(*p));
    
    p->pos = 0;
	/*
    do {
        ecode = read_data(t, p->blob + total_bytes, &bytes, 0, &error);
        if (ecode != NETWORK_OK) {
            ERR(NOERR, "Could not read ssh packet size. %s", error);
            FREE(p);
            return NULL;
        }
        total_bytes += bytes;
		bytes = MAX_SSH_PACKET_SIZE - total_bytes;
    } while (total_bytes< sizeof(p->padding_length) + sizeof(p->packet_length));
	*/
	total_bytes = bytes = sizeof(p->padding_length) + sizeof(p->packet_length);
	ecode  = read_data(t, p->blob, &bytes, READ_ALL, &error);
	if (ecode != NETWORK_OK) {
		ERR(NOERR, "Could not read ssh packet size. %s", error);
		FREE(p);
		return NULL;
	}

    p->packet_length = make_uint32(p->blob);
    p->padding_length = *(unsigned char *)(p->blob + sizeof(p->packet_length));
	
	bytes = p->packet_length + sizeof(p->packet_length) - bytes;
	ecode = read_data(t, p->blob + total_bytes, &bytes, READ_ALL, &error);
	if (ecode != NETWORK_OK) {
		ERR(NOERR, "Could not read ssh packet. %s", error);
		FREE(p);
		return NULL;
	}

    p->payload = p->blob + sizeof(p->padding_length) + sizeof(p->packet_length);
    p->payload_length = p->packet_length - p->padding_length - 1;
    p->data = (char *)p->payload + sizeof(p->type);
    p->padding = (char *)p->payload + p->packet_length - p->padding_length - sizeof(p->packet_length);
    /* there is no mac negotiated yet */
    p->mac = NULL;
    p->type = ((char *)p->payload)[0];
    s->in_sequence++;
    return p;
}

byte *build_mac(session *s, plain_packet *p) {
    byte temp[MAX_SSH_PACKET_SIZE + sizeof(uint32)], *hmac;
    uint32 seq = long_swap(s->out_sequence);
    
    memcpy(temp, &seq, sizeof(uint32));
    memcpy(temp + sizeof(uint32), p->data, p->plain_packet_len);
    hmac = crypto_mac(s->s2c_mac_ctx, s->mac_s2c, temp, p->plain_packet_len + sizeof(uint32));
    return hmac;
}

int write_encrypted_ssh_packet(session *s, plain_packet *p) {
    tr_client *t = s->transport;
    byte outbuff[MAX_SSH_PACKET_SIZE], *mac;
    int i, total_bytes = 0, csize = crypto_cipher_block_size(s->e_s2c) / 8;
    char *error;

    for (i = 0; i < p->plain_packet_len; i += csize) 
        crypto_cbc_encrypt(s->enc_ctx, s->e_s2c, p->data + i, outbuff + i);

    s->out_sequence++;;
    mac = build_mac(s, p);
    memcpy(outbuff + p->plain_packet_len, mac, 20);
    FREE(mac);
    total_bytes = p->plain_packet_len + 20;

    if (write_data(t, outbuff, &total_bytes, &error) != NETWORK_OK) {
        ERR(NOERR, "Failed to write encrypted packet to client. %s", error);
        FREE(p->data);
        FREE(p);
        s->out_sequence--;
        return 0;
    }
    FREE(p->data);
    FREE(p);
    return 1;
}


ssh_packet *read_ssh_packet(session *s) {
    if (s->enc) 
        return read_encrypted_ssh_packet(s);
    else
        return read_plain_ssh_packet(s);
}

session *make_session() {
    session *s = MALLOC(sizeof(*s));
    memset(s, 0x0, sizeof(*s));
    s->cleanup_transport = cleanup_transport;
    s->server_ctx = sshd_server_ctx();
    return s;
}

void cleanup_session(session *s) {
    if (s->cleanup_channel)
        s->cleanup_channel(s);
    if (s->cleanup_auth)
        s->cleanup_auth(s);
    if (s->cleanup_kex)
        s->cleanup_kex(s);
    if (s->cleanup_transport)
        s->cleanup_transport(s);
    if (s->client_version)
        FREE(s->client_version);
    if (s->dec_ctx) 
        crypto_free_cipher_context(s->dec_ctx, s->e_c2s);
    if (s->enc_ctx)
        crypto_free_cipher_context(s->enc_ctx, s->e_s2c);
    if (s->c2s_mac_ctx)
        crypto_free_mac_context(s->c2s_mac_ctx, s->mac_c2s);
    if (s->s2c_mac_ctx)
        crypto_free_mac_context(s->s2c_mac_ctx, s->mac_s2c);
    if (s->session_id)
        FREE(s->session_id);
	if (s->secret_key) {
        FREE(s->secret_key);
	}
    {
        int i;

        for (i = 0; i < 6; i++) {
            if (s->keys[i])
                FREE(s->keys[i]);
        }
    }
    FREE(s);
}

int transport_ignore(session *s, ssh_packet *p) {
    return 1;
}

int transport_teardown_session(session *s, ssh_packet *p) {
    return -1;
}

int transport_service_request(session *s, ssh_packet *p) {
    plain_packet *packet;
    char *service = make_cstring(p->data);
    
    DEBUG("Client requested service \"%s\"", service);
    if (strcmp(AUTH_SERVICE, service)) {
        FREE(service);
        return 0;
    }
    FREE(service);
    plain_ssh_packet_begin(&packet, SSH_MSG_SERVICE_ACCEPT);
    plain_ssh_packet_add_string(packet, p->data);
    plain_ssh_packet_finalize(s, packet);
    return write_encrypted_ssh_packet(s, packet);
}

void loop(session *s) {
    while (1) {
        /*
          read packets in a loop and dispatch to the registered handler for
          that packet type
        */
        int err;
        ssh_packet *p = read_ssh_packet(s);
        if (!p){
            break;
        }
        DEBUG("incoming packet type=%d", p->type);
        if (!handler[p->type]) {
            ERR(NOERR, "Unknown packet - no handler registered");
            destroy_ssh_packet(p);
            break;
        }
        err = (*handler[p->type])(s, p);
        if (!err) {
            ERR(NOERR, "Handler raised error - terminating connection");
            destroy_ssh_packet(p);
            break;
        }
        destroy_ssh_packet(p);
        if (err == -1) 
            break;
    }
    cleanup_session(s);
}

void process_client(void *client, void **fns) {
    session *s = make_session();
    tr_client *t = MALLOC(sizeof(*t));
	
    s->transport = t;

    t->client = client;
    t->read = (iofunc)fns[0];
    t->write = (iofunc)fns[1];
    t->close = (clfunc)fns[2];
    t->_pos = 0;
    t->_cur = 0;
	
    if (!protocol_version_exchange(s)) {
		cleanup_session(s);
		return;
    }
    loop(s);
    return;
}

void transport_init() {
    handler[SSH_MSG_DISCONNECT] = transport_teardown_session;
    handler[SSH_MSG_IGNORE] = transport_ignore;
    handler[SSH_MSG_UNIMPLEMENTED] = transport_teardown_session;
    handler[SSH_MSG_DEBUG] = transport_ignore;
    handler[SSH_MSG_SERVICE_REQUEST] = transport_service_request;
}
