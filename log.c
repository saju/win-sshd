#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <windows.h>
#include "log.h"

FILE *logfd = NULL;
int debug = 0;
int glevel = INFO_L;

int log_init(char *lfile) {
	/* open a logfile in the EpsilonAgent/log dir */
	logfd = fopen(lfile, "a+");
	if (logfd == NULL) {
		fprintf(stderr, "Failed to open %s. Error is %s\n", lfile, strerror(errno));
		return 0;
	}
	return 1;
}

size_t __write(const char *msg) {
	size_t in = strlen(msg);
	size_t out;
	out = fwrite(msg, in, 1, logfd);
	fflush(logfd);
	return out;
}

char *get_error_msg(int ecode) {
	char *b = NULL;
	HLOCAL msgbuff;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				  NULL, ecode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&msgbuff, 0, NULL);
	if (msgbuff) {
		b = _strdup(msgbuff);
		LocalFree(msgbuff);
	}
	return b;
}

void log(int level, char *mlevel, const char *file, unsigned int line, const char *function, int ecode, const char *msg, ...) {
	char ebuff[1000], fbuff[1024], *estr;
	va_list ap;

	if (level < glevel)
		return;

	va_start(ap, msg);
	vsprintf(ebuff, msg, ap);
	va_end(ap);
	
	if (ecode == NOERR) {
		sprintf(fbuff, "[%s] [%d] [%s,%s,%d] %s\n", mlevel, GetCurrentThreadId(), file, function, line, ebuff);
	} else {
		estr = get_error_msg(ecode);
		sprintf(fbuff, "[%s] [%d] [%s,%s,%d] %s Error=%s\n", mlevel, GetCurrentThreadId(), file, function, line, ebuff, estr ? estr : "NA");
		if (estr) free(estr);
	}
	if (level == DEBUG_L) 
		fprintf(stderr, fbuff);
	__write(fbuff);
}

void toggle_level(const char *level) {
	if (!strcmp(level, "DEBUG"))
		glevel = DEBUG_L;
	else if (!strcmp(level, "INFO"))
		glevel = INFO_L;
	else if (!strcmp(level, "ERROR"))
		glevel = ERR_L;
	else if (!strcmp(level, "FATAL"))
		glevel = FATAL_L;
}

char *make_err_str(char *msg, int ecode) {
	char *s = malloc(1024);
	sprintf(s, "%s %s", msg, get_error_msg(ecode));
	return s;
}
