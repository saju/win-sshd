#include <stdarg.h>
#include <errno.h>
#include <stdio.h>

#define MSG_CREATOR "EpsilonAgent"
#define DEFAULT_LOGFILE "sshd.log"

#define NOERR -424242

#define DEBUG_L  2
#define INFO_L   3
#define ERR_L    4
#define FATAL_L  5

#define DEBUG(b, ...) log(DEBUG_L, "DEBUG", __FILE__, __LINE__, __FUNCTION__, NOERR, b, __VA_ARGS__)
#define INFO(a, b, ...) log(INFO_L, "INFO", __FILE__, __LINE__, __FUNCTION__, a, b, __VA_ARGS__)
#define ERR(a, b, ...) log(ERR_L, "ERR", __FILE__, __LINE__, __FUNCTION__, a, b, __VA_ARGS__)
#define FATAL(a, b, ...) log(FATAL_L, "FATAL", __FILE__, __LINE__, __FUNCTION__, a, b, __VA_ARGS__)



int log_init(char *lfile);
void toggle_level(const char *level);
char *get_error_msg(int ecode);
char *make_err_str(char *msg, int ecode);
void log(int level, char *mlevel, const char *file, unsigned int line, const char *function, int ecode, const char *msg, ...);
