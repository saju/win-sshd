#include <windows.h>
#include <string.h>
#include "log.h"

#define EPSILON_AGENT "EpsilonAgent"
#define EPSILON_AGENT_NICE "\"Epsilon Secure Shell Agent\""

void usage() {
    fprintf(stderr, "Please specify one of -install, -uninstall");
    exit(1);
}
int main(int argc, char **argv) {
    if (argc < 2) 
		usage();
    if (!strcmp(argv[1], "-install")) {
		printf("%s will now be installed as a service\n", EPSILON_AGENT_NICE);
		if (!install_service()) {
	    fprintf(stderr, "Service installation failed !\n");
	    exit(1);
		} else {
			printf("Service installed\n");
			exit(0);
		}
    } else if (!strcmp(argv[1], "-uninstall")) {
		printf("%s will now be uninstalled\n", EPSILON_AGENT_NICE);
		if (!uninstall_service()) {
			fprintf(stderr, "Service uninstall failed !\n");
			exit(1);
		} else {
			printf("Service uninstalled\n");
			exit(0);
		}
    } else
		usage();
}

int uninstall_service() {
    return 0;
}

int install_service() {
    char program[MAX_PATH], srv_cmd[MAX_PATH + 256];
    SC_HANDLE scmgr, service;
    
    if (!GetModuleFileName(NULL, program, sizeof(program))) {
		fprintf(stderr, "Could not get module name - %s\n", get_error_msg(GetLastError()));
		return 0;
    }
	
    scmgr = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scmgr) {
		fprintf(stderr, "Could not open service control manager - %s\n", get_error_msg(GetLastError()));
		return 0;
    }
	
    sprintf(srv_cmd, "\"%s\" -start", program);
    service = CreateService(scmgr, EPSILON_AGENT, EPSILON_AGENT_NICE, SERVICE_ALL_ACCESS, 
							SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
							srv_cmd, NULL, NULL, NULL, NULL, NULL);
    if (!service) {
		fprintf(stderr, "Could not register service for (%s) - %s\n", srv_cmd, get_error_msg(GetLastError()));
		return 0;
    }
    CloseServiceHandle(service);
    CloseServiceHandle(scmgr);
    return 1;
}
