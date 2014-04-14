/**
   RFC-4254 - Channels.

   Only exec/pty sessions. No X11, port forwarding

   XXX: We are only supporting 1 thread per session. This means we can't handle OOB data and multiple channel
   execution on 1 session simultaneously. In other words, this architecture sucks !
**/

#include "ssh.h"
#include "log.h"
#include "win.h"

/* supported session types */
#define EXEC      1
#define SUBSYSTEM 2

/* supported subsystems */
#define SFTP      1

#define SSH_OPEN_UNKNOWN_CHANNEL_TYPE 3

struct _exec {
    char *command;
    void *proc;
};

struct _sftp {
    void *ctx;
    void (*cleanup)(void *);
    int (*incoming) (void *, void *);
};

struct _channel {
    uint32 rec_num;  /* channel number for the other side (sender num) */
    uint32 local_num; /* our number (recipient num) */
    int type;       
    int subsystem;
    int pty;
    int in_window_sz; 
    int out_window_sz;
    int pkt_sz;
    struct _channel *next;
    union {
	struct _exec exec;
	struct _sftp sftp;
    };
};

typedef struct _channel channel;

void free_channel(channel *c) {
    if (c->type == EXEC) {
	if (c->exec.command)
	    free(c->exec.command);
	if (c->exec.proc)
	    free(c->exec.proc);
    } else if (c->type == SUBSYSTEM) {
	if (c->subsystem == SFTP)
	    c->sftp.cleanup(c->sftp.ctx);
    }
    free(c);
}

void attach_channel(session *s, channel *c) {
    channel *i;

    i = s->channel;
    while (i->next)
        i = i->next;
    i->next = c;
}

channel *find_channel(session *s, uint32 num) {
    channel *i;

    i = ((channel *)s->channel)->next;
    while (i) {
        if (i->local_num == num) {
            return i;
        }
        i = i->next;
    }
    return i;
}

void detach_channel(session *s, uint32 num) {
    channel *j, *i;

    i = s->channel;
    j = i;
    while (i) {
        if (i->local_num == num) {
            j->next = i->next;                 
            free_channel(i);
            break;
        }
        j = i;
        i = i->next;
    }
}

void channel_send_close(session *s, channel *ch) {
    void *packet;

    plain_ssh_packet_begin(&packet, SSH_MSG_CHANNEL_CLOSE);
    plain_ssh_packet_add_uint32(packet, ch->rec_num);
    plain_ssh_packet_finalize(s, packet);
    write_encrypted_ssh_packet(s, packet);
}

void channel_request_status(session *s, channel *ch, byte status) {
    void *packet;

    plain_ssh_packet_begin(&packet, status);
    plain_ssh_packet_add_uint32(packet, ch->rec_num);
    plain_ssh_packet_finalize(s, packet);
    write_encrypted_ssh_packet(s, packet);
}

void channel_send_window_adjust(session *s, channel *ch, int mode) {
    void *packet;

    plain_ssh_packet_begin(&packet, SSH_MSG_CHANNEL_WINDOW_ADJUST);
    /* XXX: we cant do flow control on the outbound side, the other guy must do this
       - why the hell are we doing this ?
    */
    plain_ssh_packet_add_uint32(packet, mode == 0 ? ch->rec_num : ch->local_num); 
    plain_ssh_packet_add_uint32(packet, 65536L);
    plain_ssh_packet_finalize(s, packet);
    write_encrypted_ssh_packet(s, packet);
    if (mode == 0)
	ch->in_window_sz += 65536L;
    else 
	ch->out_window_sz += 65536L;
}

int channel_send_data(session *s, channel *ch, byte *b, uint32 len) {
    void *packet;
    char *temp;

    plain_ssh_packet_begin(&packet, SSH_MSG_CHANNEL_DATA);
    plain_ssh_packet_add_uint32(packet, ch->rec_num);
    temp = make_string_b(b, len, NULL);
    plain_ssh_packet_add_string(packet, temp);
    free(temp);
    plain_ssh_packet_finalize(s, packet);
    if (!write_encrypted_ssh_packet(s, packet))
	return 0;
    /* trust the client to adjust window */
    if (ch->out_window_sz <= 0)
	ch->out_window_sz += 65536L;
    return 1;
}

void _xfr_data(session *s, channel *ch) {
    byte *buff = malloc(MAX_SSH_PAYLOAD_SIZE);
    string *temp;
    void *packet;
    int bytes;

    while (1) {
	/* XXX:  ideally we should read upto pkt_size bytes and send the data 
	   over to client, but that would be deemed 'slow' or 'unresponsive'.
	   We really have to treat this session as if this were an interactive
	   session - remote must send a smaller window size not Zero
	   
	   The amount of data to be read is a f(pkt_size, window_sz, max_payload_sz);
	   The pkt_size and window_sz can be updated OOB by the client
	   
	   XXX: we will always dup stderr onto stdout (like in pty support) - this is wrong !
	*/
	unsigned int ecode;
	int want_bytes = (ch->out_window_sz > ch->pkt_sz) ? ch->pkt_sz : ch->out_window_sz;
	want_bytes = want_bytes < MAX_SSH_PAYLOAD_SIZE ? want_bytes : MAX_SSH_PAYLOAD_SIZE;

	bytes = win_read_proc_pipe(ch->exec.proc, buff, want_bytes, &ecode);
        if (!bytes) {
            /* process has terminated and there is nothing to read() 
	     send the exit status */
	    plain_ssh_packet_begin(&packet, SSH_MSG_CHANNEL_REQUEST);
	    plain_ssh_packet_add_uint32(packet, ch->rec_num);
	    temp = make_string("exit-status", NULL);
	    plain_ssh_packet_add_string(packet, temp);
	    free(temp);
	    plain_ssh_packet_add_byte(packet, 0);
	    plain_ssh_packet_add_uint32(packet, ecode);
	    plain_ssh_packet_finalize(s, packet);
	    write_encrypted_ssh_packet(s, packet);
            channel_send_close(s, ch);
            break;
        }
        
        if (!channel_send_data(s, ch, buff, bytes)) {
			if (ch->pty) {
				win_terminate_proc(ch->exec.proc);
			} else {
				win_wait_for_proc(ch->exec.proc);
			}
			channel_send_close(s, ch);
			break;
		}
    }
    free(buff);
}


int execute_command(session *s, channel *ch, int want_reply) {
    void *token;
    wchar_t *user, *password, *domain, *command, *root;
    char *temp;
    
    auth_get_user_creds(s, &user, &password, &domain, &token);
	temp = win_get_homedir(token);
	root = utf8_to_wchar(temp);
	free(temp);
	temp = malloc(strlen("/c ") + strlen(ch->exec.command) + 3);
	sprintf(temp, "/c \"%s\"", ch->exec.command);
    command = utf8_to_wchar(temp);
    free(temp);
    /* always use pty mode - this is broken */
    ch->exec.proc = win_execute_command(s->server_ctx->shell, command, user, password, domain, root, 1);
    free(command);
	free(root);
    if (!ch->exec.proc) {
        if (want_reply)
            channel_request_status(s, ch, SSH_MSG_CHANNEL_FAILURE);
        DEBUG("Executed (failed) %s\n", ch->exec.command);
        return 0;
    } else {
        if (want_reply) 
            channel_request_status(s, ch, SSH_MSG_CHANNEL_SUCCESS);
        DEBUG("Executed (OK) %s\n", ch->exec.command);
    }
    
    /** XXX: ideally _xfr_data should be executed in a different thread **/
    _xfr_data(s, ch);
    detach_channel(s, ch->local_num);
    return 1;
}


void channel_failure(session *s, uint32 rec_num) {
    void *packet;
    string *st = make_string("", NULL);

    plain_ssh_packet_begin(&packet, SSH_MSG_CHANNEL_OPEN_FAILURE);
    plain_ssh_packet_add_uint32(packet, rec_num);
    plain_ssh_packet_add_uint32(packet, SSH_OPEN_UNKNOWN_CHANNEL_TYPE);
    plain_ssh_packet_add_string(packet, st);
    plain_ssh_packet_add_string(packet, st);
    plain_ssh_packet_finalize(s, packet);
    write_encrypted_ssh_packet(s, packet);
    FREE(st);
}

channel *make_session_channel(session *s, ssh_packet *p, void **opacket) {
    void *packet;
    channel *ch = malloc(sizeof(*ch));
    uint32 rec_num = read_next_uint32(p);

    ch->in_window_sz = 4294967295;
    ch->out_window_sz = read_next_uint32(p);
    ch->pkt_sz = read_next_uint32(p);
    ch->rec_num = rec_num;
    ch->local_num = s->in_sequence;
    ch->type = 0;
    ch->subsystem = 0;
    ch->pty = 0;
    ch->next = NULL;
    
    plain_ssh_packet_begin(&packet, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    plain_ssh_packet_add_uint32(packet, rec_num);
    plain_ssh_packet_add_uint32(packet, ch->local_num);
    plain_ssh_packet_add_uint32(packet, ch->in_window_sz);
    plain_ssh_packet_add_uint32(packet, ch->pkt_sz);
    *opacket = packet;
    
    return ch;
}

void cleanup_channel(session *s) {
    channel *i, *j;

    i = s->channel;
    while (i) {
        j = i->next;
        free_channel(i);
        i = j;
    }
}

int channel_data(session *s, ssh_packet *p) {
    uint32 len, num = read_next_uint32(p);
    channel *ch = find_channel(s, num);

    if (!ch || ch->type != SUBSYSTEM || ch->subsystem != SFTP) {
	return 1;
    }
    /**
       Jump the "string" length bytes - this is really transport layer info
       SFTP shouldn't know that it is working over SSH and receiving data
       encoded as SSH strings
    */
    len = read_next_uint32(p);
    ch->in_window_sz -= len;
    if (!ch->sftp.incoming(p, ch->sftp.ctx)) {
	/* shutdown this sftp session */
	detach_channel(s, ch->local_num);
    }
    if (ch->in_window_sz <= 0)  
	channel_send_window_adjust(s, ch, 0);
    return 1;
}

int channel_window_adjust(session *s, ssh_packet *p) {
    /* useless for us */
    return 1;
}

int channel_request(session *s, ssh_packet *p) {
    channel *ch;
    uint32 num = read_next_uint32(p);
    char *rtype = read_next_string(p);
    byte want_reply = read_next_byte(p);
    
    ch = find_channel(s, num);
    if (ch) {
		if (!strcmp(rtype, "pty-req")) {
			ch->pty = 1;
			if (want_reply) 
				channel_request_status(s, ch, SSH_MSG_CHANNEL_SUCCESS);
		} else if (!strcmp(rtype, "exec")) {
			ch->type = EXEC;
			ch->exec.command = read_next_string(p);
			execute_command(s, ch, want_reply);
		} else if (!strcmp(rtype, "subsystem")) {
			char *subsys;
			ch->type = SUBSYSTEM;
			subsys = read_next_string(p);
			if (!strcmp(subsys, "sftp")) {
				wchar_t *user, *password, *domain;
				void *token;
				
				auth_get_user_creds(s, &user, &password, &domain, &token);
				ch->subsystem = SFTP;
				ch->sftp.ctx = sftp_boot(s, ch, user, domain, token, channel_send_data, &ch->sftp.incoming, &ch->sftp.cleanup);
				if (want_reply) 
					channel_request_status(s, ch, SSH_MSG_CHANNEL_SUCCESS);
			} else {
				if (want_reply) 
					channel_request_status(s, ch, SSH_MSG_CHANNEL_FAILURE);
			}
			FREE(subsys);
		} else {
			channel_request_status(s, ch, SSH_MSG_CHANNEL_FAILURE);
		}
    }
    FREE(rtype);
    return 1;
}

int channel_eof(session *s, ssh_packet *p) {
    /* we are only bothered with CLOSE msgs */
    return 1;
}

int channel_close(session *s, ssh_packet *p) {
    uint32 num = read_next_uint32(p), remote_num;
    channel *ch = find_channel(s, num);

    if (!ch) {
        return 1; /* bad channel */
    }
    remote_num = ch->rec_num;
    detach_channel(s, num);  /*
    plain_ssh_packet_begin(&packet, SSH_MSG_CHANNEL_CLOSE);
    plain_ssh_packet_add_uint32(packet, remote_num);
    plain_ssh_packet_finalize(s, packet);
	DEBUG("sending our close\n");
    write_encrypted_ssh_packet(s, packet);
	DEBUG("sent our close\n"); */
    return 1;
}

int channel_open(session *s, ssh_packet *p) {
    channel *ch;
    char *type;
    uint32 rec_num;
    void *packet;

    if (!s->authenticated) {
        ERR(NOERR, "Channel requested on unencrypted channel. Bye");
        return 0;
    }
    if (!s->cleanup_channel) { /* first time around */
        s->cleanup_channel = cleanup_channel;
        ch = MALLOC(sizeof(channel));
        ch->next = NULL;
        ch->local_num = ch->rec_num = 0;
        s->channel = ch;
    }

    type = read_next_string(p);
    if (!strcmp(type, "session"))
        ch = make_session_channel(s, p, &packet);
    else {
        /* we only support session channel for now */
        rec_num = read_next_uint32(p);
        channel_failure(s, rec_num);
        FREE(type);
        return 0;
    }
    FREE(type);

    if (!ch)
        return 0;

    attach_channel(s, ch);
    plain_ssh_packet_finalize(s, packet);
    write_encrypted_ssh_packet(s, packet);
    return 1;
}

void channel_init() {
    handler[SSH_MSG_CHANNEL_OPEN]          = channel_open;
    handler[SSH_MSG_CHANNEL_EOF]           = channel_eof;
    handler[SSH_MSG_CHANNEL_CLOSE]         = channel_close;
    handler[SSH_MSG_CHANNEL_REQUEST]       = channel_request;
    handler[SSH_MSG_CHANNEL_DATA]          = channel_data;
    handler[SSH_MSG_CHANNEL_WINDOW_ADJUST] = channel_window_adjust;
}
