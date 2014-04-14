#ifndef __SSH_MSG_H__
#define __SSH_MSG_H_

/* SSH known message ids */

#define SSH_MSG_DISCONNECT    1
#define SSH_MSG_IGNORE        2
#define SSH_MSG_UNIMPLEMENTED 3
#define SSH_MSG_DEBUG         4

#define SSH_MSG_SERVICE_REQUEST 5
#define SSH_MSG_SERVICE_ACCEPT  6

#define SSH_MSG_KEXINIT       20
#define SSH_MSG_NEWKEYS       21

#define SSH_MSG_KEXDH_INIT    30
#define SSH_MSG_KEXDH_REPLY   31

#define SSH_MSG_USERAUTH_REQUEST 50
#define SSH_MSG_USERAUTH_FAILURE 51
#define SSH_MSG_USERAUTH_SUCCESS 52

#define SSH_MSG_CHANNEL_OPEN               90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION  91
#define SSH_MSG_CHANNEL_OPEN_FAILURE       92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST      93
#define SSH_MSG_CHANNEL_DATA               94
#define SSH_MSG_CHANNEL_EOF                96
#define SSH_MSG_CHANNEL_CLOSE              97
#define SSH_MSG_CHANNEL_REQUEST            98
#define SSH_MSG_CHANNEL_SUCCESS            99
#define SSH_MSG_CHANNEL_FAILURE            100

/* SSH known service names */

#define AUTH_SERVICE        "ssh-userauth"
#define CONNECTION_SERVICE  "ssh-connection"

#endif
