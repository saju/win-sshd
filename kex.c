/*
 * SSH2 key exchange
 */
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "ssh.h"
#include "transport.h"
#include "crypto.h"

typedef struct {
	byte header;
	byte *cookie;
	name_list *kex_algorithms;
	name_list *server_host_key_algorithms;
	name_list *enc_c2s;
	name_list *enc_s2c;
	name_list *mac_c2s;
	name_list *mac_s2c;
	name_list *compression_c2s;
	name_list *compression_s2c;
	name_list *languages_c2s;
	name_list *languages_s2c;
	boolean kex_follows;
	uint32  reserved;
	uint32 IC_len;
	char *IC;  /* the kexinit msg payload from the client */
	uint32 IS_len;
	char *IS; /* the kexinit msg payload from the server */
	byte *kex_hash;
} kexinit_packet;


void free_nl(name_list *nl) {
	uint32 i;
	for (i = 0; i < nl->count; i++)
		FREE(nl->names[i]);
	FREE(nl->names);
	FREE(nl);
}

name_list *parse_name_list(void **addr) {
	uint32 size = make_uint32(*addr);
	char *start, *temp;
	uint32 i;
	size_t len = 0;
	name_list *nlist;
	
	start = (char *)*addr + sizeof(uint32);
	*addr = start + size;
	if (size == 0) 
		return NULL;
	nlist = MALLOC(sizeof(*nlist));
	temp = MALLOC(size + 1);
	memcpy(temp, start, size);
	temp[size] = '\0';
	for (i = 0, nlist->count = 1; i < size; i++) {
		if (temp[i] == ',') {
			nlist->count++;
			temp[i] = '\0';
		}
	}
	nlist->names = MALLOC(sizeof(char *) * nlist->count);
	for (i = 0; i < nlist->count; i++) {
		nlist->names[i] = _strdup(temp + len);
		len += strlen(nlist->names[i]) + 1;
	}
	FREE(temp);
	return nlist;
}

void free_kexinit(kexinit_packet *kp) {
	free_nl(kp->kex_algorithms);
	free_nl(kp->server_host_key_algorithms);
	free_nl(kp->enc_c2s);
	free_nl(kp->enc_s2c);
	free_nl(kp->mac_c2s);
	free_nl(kp->mac_s2c);
	free_nl(kp->compression_c2s);
	free_nl(kp->compression_s2c);
	if (kp->languages_c2s)
		free_nl(kp->languages_c2s);
	if (kp->languages_s2c)
		free_nl(kp->languages_s2c);
	
	if (kp->IC)
		FREE(kp->IC);
	if (kp->IS)
		FREE(kp->IS);
	if (kp->kex_hash)
		FREE(kp->kex_hash);
	FREE(kp);
}

void kex_cleanup(session *s) {
	if (s->kex) 
		free_kexinit(s->kex);
	s->kex = NULL;
}

kexinit_packet *parse_kexinit(ssh_packet *p) {
	kexinit_packet *kp;
	char *next, *payload = p->payload;
	
	
	kp = MALLOC(sizeof(*kp));
	
	kp->header = (byte)payload[0];
	kp->cookie = payload + sizeof(kp->header);
	
	next = payload + 16 + sizeof(kp->header);
	
	kp->kex_algorithms = parse_name_list(&next);
	kp->server_host_key_algorithms = parse_name_list(&next);	
	kp->enc_c2s = parse_name_list(&next);
	kp->enc_s2c = parse_name_list(&next);
	kp->mac_c2s = parse_name_list(&next);
	kp->mac_s2c = parse_name_list(&next);
	
	kp->compression_c2s = parse_name_list(&next);
	kp->compression_s2c = parse_name_list(&next);
	kp->languages_c2s = parse_name_list(&next);
	kp->languages_s2c = parse_name_list(&next);
	kp->kex_follows = *(boolean *)next;
	kp->reserved = make_uint32(next + sizeof(kp->kex_follows));
	
	kp->IC_len = p->payload_length;
	kp->IC = MALLOC(kp->IC_len);
	memcpy(kp->IC, (void *)((char *)p->payload), kp->IC_len);
	
	return kp;
}

byte *_build_kp(session *s, kexinit_packet *client_kp){
	/*
	  We will always build using the MUST algorithms - because we don't support
	  optional/custom algos yet. Any RFC compliant SSH2 client should like our
	  KEXINIT packet and reply with a DH_INIT
	*/
	void *packet;
	uint32 i;
	int group1=0, group14=0, ssh_dss=0, ssh_rsa=0, aes256=0, aes192=0, aes128=0, des3=0, sha96=0, sha1=0;
	char *kex_algos, *host_keys, *enc, *mac, *compression, *languages;
	
	for (i = 0; i < client_kp->kex_algorithms->count; i++) {
		if (!strcmp(client_kp->kex_algorithms->names[i], "diffie-hellman-group14-sha1")) {
			group14 = 1; 
			break;
		}
		if (!strcmp(client_kp->kex_algorithms->names[i], "diffie-hellman-group1-sha1")) {
			group1 = 1; 
			break;
		}
	}
	
	if (group14) {
		kex_algos = "diffie-hellman-group14-sha1,diffie-hellman-group1-sha1";
		s->kex_algo = DH14;
	}
	else if(group1) {
		kex_algos = "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1";
		s->kex_algo = DH1;
	}
	else {
		ERR(NOERR, "Client only uses unsupported key exchange algorithms");
		return NULL;
	}
	
	for (i = 0; i < client_kp->server_host_key_algorithms->count; i++) {
		if (!strcmp(client_kp->server_host_key_algorithms->names[i], "ssh-dss")) {
			ssh_dss = 1; 
			break;
		}
		/*
		  if (!strcmp(client_kp->server_host_key_algorithms->names[i], "ssh-rsa")) {
		  ssh_rsa = 1; 
		  break;
		  }
		*/
	}
	
	if (ssh_dss) {
		host_keys = "ssh-dss";
		s->host_key = DSS;
	}
	/*	RSA not available right now
        else if (ssh_rsa) {
        host_keys = "ssh-rsa,ssh-dss";
        s->host_key = SSH_RSA;
        }
	*/
	else {
		ERR(NOERR, "Client doesn't use ssh-dss public key algorithm - this is a violation of spec");
		return NULL;
	}
	
	for (i = 0; i < client_kp->enc_c2s->count; i++) {
		if (!strcmp(client_kp->enc_c2s->names[i], "aes256-cbc")) {
			aes256 = 1; 
			break;
		}
		if (!strcmp(client_kp->enc_c2s->names[i], "aes192-cbc")) {
			aes192 = 1; 
			break;
		}
		if (!strcmp(client_kp->enc_c2s->names[i], "aes128-cbc")) {
			aes128 = 1; 
			break;
		}
		/*
		  if (!strcmp(client_kp->enc_c2s->names[i], "3des-cbc")) {
		  des3 = 1; 
		  break;
		  }
		*/
	}
	
	/* only AES is available */
	
	if (aes256) {
		enc = "aes256-cbc";
		s->e_c2s = s->e_s2c = AES256_CBC;
	}
	else if (aes192) {
		enc = "aes192-cbc";
		s->e_c2s = s->e_s2c = AES192_CBC;
	}
	else if (aes128) {
		enc = "aes128-cbc";
		s->e_c2s = s->e_s2c = AES128_CBC;
	}
	/*
	  else if (des3) {
	  enc = "3des-cbc";
	  s->e_c2s = s->e_s2c = TRIPLE_DES_CBC;
	  } 
	*/
	else {
		ERR(NOERR, "Client doesn't use any ciphers we know of");
		return NULL;
	}
	
	for (i = 0; i < client_kp->mac_c2s->count; i++) {
		/*
		  if (!strcmp(client_kp->mac_c2s->names[i], "hmac-sha1-96")) {
		  sha96 = 1; 
		  break;
		  }*/
    if (!strcmp(client_kp->mac_c2s->names[i], "hmac-sha1")) {
		sha1 = 1;
		break;
    }
	}
	
	if (sha1) {
		mac = "hmac-sha1";
		s->mac_s2c = s->mac_c2s = HMAC_SHA1;
	}
	else {
		ERR(NOERR, "Client doesnt use a hashing algorithm we know of");
		return NULL;
	}
	
	compression = "none"; /* no compression */
	languages = ""; 
	
	plain_ssh_packet_begin(&packet, SSH_MSG_KEXINIT);
	plain_ssh_packet_add_randomness(packet, 16);
	plain_ssh_packet_add_name_list(packet, kex_algos);
	plain_ssh_packet_add_name_list(packet, host_keys);
	plain_ssh_packet_add_name_list(packet, enc);
	plain_ssh_packet_add_name_list(packet, enc);
	plain_ssh_packet_add_name_list(packet, mac);
	plain_ssh_packet_add_name_list(packet, mac);
	plain_ssh_packet_add_name_list(packet, compression);
	plain_ssh_packet_add_name_list(packet, compression);
	plain_ssh_packet_add_name_list(packet, languages);
	plain_ssh_packet_add_name_list(packet, languages);
	plain_ssh_packet_add_byte(packet, 0);
	plain_ssh_packet_add_uint32(packet, 0);
	return packet;
}

int kex_exchange(session *s, ssh_packet *p) {
	void *server_kp;
	kexinit_packet *client_kp;
	char *IS;
	uint32 IS_len;
	
	
	s->cleanup_kex = kex_cleanup;
	
	client_kp = parse_kexinit(p);
	if (!client_kp) 
		return 0;
	s->kex = client_kp;
	
	server_kp = _build_kp(s, client_kp);
	if (!server_kp) {
		kex_cleanup(s);
		return 0;
	}
	plain_ssh_packet_peek(server_kp, &IS, &IS_len);
	client_kp->IS = MALLOC(IS_len);
	client_kp->IS_len = IS_len;
	memcpy(client_kp->IS, IS, IS_len);
	plain_ssh_packet_finalize(s, server_kp);
	if (!plain_ssh_packet_write(s, server_kp)) {
		kex_cleanup(s);
		return 0;
	}
	//DEBUG("wrote KEX_INIT REPLY");
	return 1;
}

int kex_dhinit(session *s, ssh_packet *p) {
	char buf[MAX_SSH_PAYLOAD_SIZE], *t;
	uint32 pos = 0, bytes;
	byte *sign, *KS;
	void *packet;
	kexinit_packet *cl = (kexinit_packet *)s->kex;
	mpint *pub_key;
	unsigned int want_keylen;
	char *err;
	
	want_keylen = (unsigned int)crypto_cipher_key_size(s->e_s2c);
	
	s->secret_key = crypto_kex(s->kex_algo, p->data, &pub_key, want_keylen, &err);
	if (!s->secret_key) {
		/** XXX: free secret_key & dh_pub_key on cleanup - register crypto_cleanup()  */
		kex_cleanup(s);
		DEBUG("KEX gen failed - %s (%d-%d-%d)", err, DH1, DH14, s->kex_algo);
		return 0;
	}
	/* compute H = HASH(V_C || V_S || I_C || I_S || K_S || e || f || K) */
	
	/* string VC */
	t = make_string(s->client_version, &bytes);
	memcpy(buf+pos, t, bytes);
	FREE(t);
	pos += bytes;
	
	/* string VS */
	t = make_string(SSH_IDENT, &bytes);
	memcpy(buf+pos, t, bytes);
	FREE(t);
	pos += bytes;
	
	/* string IC */
	t = make_string_b(cl->IC, cl->IC_len, &bytes);
	memcpy(buf+pos, t, bytes);
	FREE(t);
	pos += bytes;
	
	/* string IS */
	//show_hex(cl->IS, cl->IS_len);
	t = make_string_b(cl->IS, cl->IS_len, &bytes);
	memcpy(buf+pos, t, bytes);
	FREE(t);
	pos += bytes;
	
	/* string KS */
	t = KS = make_ssh_key(s->host_key, s->server_ctx->dsa_keys, &bytes);
	KS = make_string_b(KS, bytes, &bytes);
	FREE(t);
	memcpy(buf+pos, KS, bytes);
	pos += bytes;
	
	/* mpint e */
	bytes = long_swap(*(uint32 *)p->data) + sizeof(uint32);
	memcpy(buf+pos, p->data, bytes);
	pos += bytes;
	
	/* mpint f */
	bytes = long_swap(*(uint32 *)pub_key) + sizeof(uint32);
	memcpy(buf+pos, pub_key, bytes);
	pos += bytes;
	
	/* mpint K */
	bytes = long_swap(*(uint32 *)s->secret_key) + sizeof(uint32);
	memcpy(buf+pos, s->secret_key, bytes);
	pos += bytes;
	
	t = crypto_hash(SHA1, buf, &pos, &err);
	
	if (!s->enc) {
		s->session_id = MALLOC(20);
		memcpy(s->session_id, t, 20);
	}
	cl->kex_hash = t;
	/* sign the hash with our host private key */
	bytes = 20;
	sign = do_sign(s->host_key, t, &bytes, s, &err);
	t = sign;
	sign = make_string_b(sign, bytes, &bytes);
	FREE(t);
	plain_ssh_packet_begin(&packet, SSH_MSG_KEXDH_REPLY);
	plain_ssh_packet_add_string(packet, KS);
	plain_ssh_packet_add_mpint(packet, pub_key);
	plain_ssh_packet_add_string(packet, sign);
	plain_ssh_packet_finalize(s, packet);
	FREE(sign);
	FREE(KS);
	FREE(pub_key);
	if (!plain_ssh_packet_write(s, packet)) {
		kex_cleanup(s);
		DEBUG("failed to write KEXDH_REPLY");
		return 0;
	}
	return 1;
}

byte *keymaker(char c, int len_needed, session *s) {
	char buff[1024], *outb = MALLOC(len_needed), *km, *err;
	int total_bytes, bytes;
	kexinit_packet *cl = (kexinit_packet *)s->kex;
	
	bytes = long_swap(*(uint32 *)s->secret_key) + sizeof(uint32);
	memcpy(buff, s->secret_key, bytes);
	memcpy(buff+bytes, cl->kex_hash, 20);
	bytes += 20;
	memcpy(buff+bytes, &c, 1);
	bytes += 1;
	memcpy(buff+bytes, s->session_id, 20);
	bytes += 20;
	km = crypto_hash(SHA1, buff, &bytes, &err);
	total_bytes = bytes;
	memcpy(outb, km, total_bytes <= len_needed ? total_bytes : len_needed);
	FREE(km);
	
	while (total_bytes < len_needed) {
		int need = len_needed - total_bytes;
		
		bytes = long_swap(*(uint32 *)s->secret_key) + sizeof(uint32);
		memcpy(buff, s->secret_key, bytes);
		memcpy(buff+bytes, cl->kex_hash, 20);
		bytes += 20;
		memcpy(buff+bytes, outb, total_bytes);
		bytes += total_bytes;
		km = crypto_hash(SHA1, buff, &bytes, &err);
		if (need <= bytes) {
			memcpy(outb+total_bytes, km, need);
			total_bytes += need;
		} else {
			memcpy(outb+total_bytes, km, bytes);
			total_bytes += bytes;
		}
		FREE(km);
	}
	
	return outb;
}

int kex_newkeys(session *s, ssh_packet *p) {
	/* Client successfully generated keys. */
	unsigned int len_needed;
	kexinit_packet *cl = (kexinit_packet *)s->kex;
	void *packet;
	
	len_needed = crypto_cipher_block_size(s->e_c2s) / 8;
	/* Initial IV client to server */
	s->keys[0] = keymaker('A', len_needed, s);
	/* Initial IV server to client */
	len_needed = crypto_cipher_block_size(s->e_s2c) / 8;
	s->keys[1] = keymaker('B', len_needed, s);
	
	len_needed = (unsigned int) crypto_cipher_key_size(s->e_c2s) / 8;
	/* Encryption key client to server */
	s->keys[2] = keymaker('C', len_needed, s);
	
	len_needed = (unsigned int) crypto_cipher_key_size(s->e_s2c) / 8;
	/* Encryption key server to client */
	s->keys[3] = keymaker('D', len_needed, s);
	
	len_needed = 20;
	/* Integrity key client to server */
	s->keys[4] = keymaker('E', len_needed, s);
	/* Integrity key server to client */
	s->keys[5] = keymaker('F', len_needed, s);
	
	plain_ssh_packet_begin(&packet, SSH_MSG_NEWKEYS);
	plain_ssh_packet_finalize(s, packet);
	plain_ssh_packet_write(s, packet);
	kex_cleanup(s);
	/* encrypted packets from now on */
	s->enc = 1;
	s->dec_ctx = crypto_setup_cipher_context(s->e_c2s, s->keys[2], s->keys[0], CBC_DECRYPT);
	s->enc_ctx = crypto_setup_cipher_context(s->e_s2c, s->keys[3], s->keys[1], CBC_ENCRYPT);
	s->c2s_mac_ctx = crypto_setup_mac_context(s->mac_c2s, s->keys[4], 20);
	s->s2c_mac_ctx = crypto_setup_mac_context(s->mac_s2c, s->keys[5], 20);
	//DEBUG("Wrote NEWKEYS");
	return 1;
}

void kex_init() {
	handler[SSH_MSG_KEXINIT] = kex_exchange;
	handler[SSH_MSG_KEXDH_INIT] = kex_dhinit;
	handler[SSH_MSG_NEWKEYS] = kex_newkeys;
}
