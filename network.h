#ifndef __NETWORK_H__
#define __NETWORK_H__

#define READ_ALL 1

#define NETWORK_OK 0
#define NETWORK_CLOSE 1
#define NETWORK_ERROR 2

#include "ssh.h"
void *network_init(unsigned int port);

#endif
