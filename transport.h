/*
 * rfc 4253 - SSH transport layer
 */

#ifndef __TRANSPORT_H__
#define __TRANSPORT_H__

#define MAX_SSH_PAYLOAD_SIZE 32768
#define MAX_SSH_PACKET_SIZE 35000

typedef unsigned int (*iofunc)(void *, void *, int *, int, char **);
typedef void (*clfunc)(void *);

void process_client(void *client, void *fns);
void plain_ssh_packet_begin(void **p, byte type);
void plain_ssh_packet_add_name_list(void *p, char *names);
void plain_ssh_packet_add_mpint(void *p, mpint *s);
void plain_ssh_packet_add_string(void *p, string *s);
void plain_ssh_packet_peek(void *packet, char **data, int *len);
byte *read_ssh_payload(void *t, boolean encrypted);

#endif
