#include <winsock2.h> /* fixme - move these into win.c */
#include <process.h>
#include "log.h"
#include "ssh.h"
#include "win.h"

#define MAX_REQUESTS 100

int thread_counter = 0;
int kill_counter = 0;

int winsock2_init() {
	int err;
	WSADATA wsadata;
	
	err = WSAStartup(MAKEWORD(2,2), &wsadata);
	if (err != 0) {
		FATAL(NOERR, "Could not init wsock2.2 networking. Quitting..");
		return 0;
	}
	if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wVersion) != 2) {
		FATAL(NOERR, "Networking subsystem too old(%u.%u), we want 2.2", LOBYTE(wsadata.wVersion), HIBYTE(wsadata.wVersion));
		return 0;
	}
	return 1;
}

void *network_init(unsigned int port) {
	SOCKET server;
	SOCKADDR_IN service;
	int err, b=1, blen=sizeof(int);

	if (!winsock2_init())
		return NULL;
	
	server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (server == INVALID_SOCKET) {
		FATAL(WSAGetLastError(), "Failed to create TCP socket");
		return NULL;
	}

	service.sin_family = AF_INET;
	service.sin_addr.s_addr = htonl(INADDR_ANY);
	service.sin_port = htons(port);

	err = bind(server, (SOCKADDR *)&service, sizeof(service));
	if (err == SOCKET_ERROR) {
		FATAL(WSAGetLastError(), "Failed to bind to port %d", port);
		closesocket(server);
		return NULL;
	}

	setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (char *)&b, blen);

	err = listen(server, SOMAXCONN);
	if (err == SOCKET_ERROR) {
		FATAL(WSAGetLastError(), "Failed to listen()");
		closesocket(server);
		return NULL;
	}

	return (void *)server;
}

unsigned int read_client(void *client, void *buffer, int *bufflen, int flags, char **emsg) {
    int len, fl = 0;
    
    if (flags & READ_ALL) 
		fl = MSG_WAITALL;

	len = *bufflen;
    *bufflen = recv((SOCKET)client, buffer, len, flags);
    
    if (*bufflen < 0) {
		*emsg = make_err_str("recv() failed:", WSAGetLastError());
		return NETWORK_ERROR;
    } else if (*bufflen == 0) {
		*emsg = "Client closed connection";
		return NETWORK_CLOSE;
    }
    else
		return NETWORK_OK;
}

unsigned int write_client(void *client, void *buffer, int *bufflen, int flags, char **emsg) {
    int len;
    len = send((SOCKET)client, buffer, *bufflen, flags);
    if (len == SOCKET_ERROR) {
		*bufflen = len;
		*emsg = make_err_str("send() failed:", WSAGetLastError());
		return NETWORK_ERROR;
    }
    *bufflen = len;
    return NETWORK_OK;
}

void close_client(void *client) {
	closesocket((SOCKET)client);
}

void *cb_f[3] = {read_client, write_client, close_client};

void set_socket_timeout(SOCKET s, DWORD timeout) {
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(DWORD));
}

void worker_main(void *data) {
    DWORD timeout = RECV_TIMEOUT;
    ssh_server *ctx = sshd_server_ctx();
    
    thread_lock_acquire(ctx->lock);
    thread_counter++;
    kill_counter++;
    thread_lock_release(ctx->lock);
    
    set_socket_timeout((SOCKET)data, timeout);
    process_client(data, cb_f);
    /* 
       Kill yourself after a certain number of requests. Our monitor program will relaunch us 
       This is a "bigger fscking hammers" solution to the memory & resource leak problem 
    */
    thread_lock_acquire(ctx->lock);
    thread_counter--;
    DEBUG("Kill Counter=%d, MAX_REQUESTS=%d, Thread Counter=%d\n", kill_counter, MAX_REQUESTS, thread_counter);
    if (kill_counter > MAX_REQUESTS && !thread_counter) {
        INFO(NOERR, "Max requests served. Restarting Server");
        ExitProcess(42);
    }
    //_CrtDumpMemoryLeaks();
    thread_lock_release(ctx->lock);
}

void start_server(void *srv, int (*quit)()) {
    SOCKET server = (SOCKET)srv;
	
    thread_counter = kill_counter = 0;
    while (1) {
        SOCKET client;
        if (quit && quit())
			break;
        client = accept(server, NULL, NULL); 
        if (client == INVALID_SOCKET) {
            ERR(WSAGetLastError(), "Failed to accept connection.");
            continue;
        }
        DEBUG("New client connection accepted at %d\n", client);
        _beginthread(worker_main, 0, (void *)client);
	}
    closesocket(server);
}


