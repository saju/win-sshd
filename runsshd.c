#include <windows.h>
#include "log.h"

#define SSHD "sshd.exe"

int dirname(char *program, char *srvcmd) {
	int i; 

	for (i = strlen(program); i > 0; i--) {
		if (program[i] == '\\')
			break;
	}
	if (i == 0) 
		return 0;
	strncpy(srvcmd, program, i+1);
	srvcmd[i+1] = '\0';
	return i;
}

HANDLE launch_command(char *module, char *command, char *rundir) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	int ret;

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	ret = CreateProcess(module, command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, rundir, &si, &pi);
	if (!ret) {
		printf("Failed to run %s %s with cwd %s - %s\n", module, command ? command : "",
				rundir, get_error_msg(GetLastError()));
		return INVALID_HANDLE_VALUE;
	}
	printf("Process started with pid %d\n", pi.dwProcessId);
	CloseHandle(pi.hThread);
	return pi.hProcess;
}

int monitor_child(HANDLE child) {
	DWORD exitcode;

	if (WaitForSingleObject(child, INFINITE) != WAIT_OBJECT_0) {
		printf("Unable to monitor child process - %s\n", get_error_msg(GetLastError()));
		CloseHandle(child);
		return 0;
	}
	GetExitCodeProcess(child, &exitcode);
	if (exitcode == 42) 
		printf("Child Controlled Exit. Relaunching\n");
	else 

		printf("Child Unexpected Exit %d. Relaunching\n");
	CloseHandle(child);
	return 1;
}
	
int main(int argc, char **argv) {
	int i;
	HANDLE cproc;
	char program[MAX_PATH], srv_cmd[MAX_PATH], rundir[MAX_PATH], args[8192]; /* cmd.exe limit */
	
	if (!GetModuleFileName(NULL, program, sizeof(program))) {
		printf("Could not get module name - %s\n", get_error_msg(GetLastError()));
		return 0;
    }

	/* we need the dir part of the name & I can't find a dirname equivalent that is available 
	 on win server 2003 & 2008 */
	if (!dirname(program, rundir)) {
		printf("Could not extract dirname from module name (%s)\n", program);
		return 0;
	}
	strcpy(srv_cmd, rundir);
	strcat(srv_cmd, SSHD);
	if (argc > 1) {
		for (i = 1; i < argc; i++) {
			strcat(args, argv[i]);
			strcat(args, " ");
		}
	}
	printf("Launching %s %s\n", srv_cmd, argc > 1 ? args : "");

	while (1) {
		cproc = launch_command(srv_cmd, argc > 1 ? args : NULL, rundir);
		if (cproc ==  INVALID_HANDLE_VALUE) 
			return 0;
		if (!monitor_child(cproc)) 
			return 0;
	}
	return 1;
}
