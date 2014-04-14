#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "log.h"

int service_install(char *name, char *desc, char *args, char **emsg) {
	char this_file[MAX_PATH], cmd[MAX_PATH];
	SERVICE_DESCRIPTION sd;
	SC_HANDLE service_mgr, service;

	if (!GetModuleFileName(NULL, this_file, sizeof(this_file))) {
		*emsg = get_error_msg(GetLastError());
		return 0;
	}

	service_mgr = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!service_mgr) {
		*emsg = get_error_msg(GetLastError());
		return 0;
	}
	if (args)
		sprintf(cmd, "%s %s", this_file, args);
	else
		sprintf(cmd, "%s", this_file);

	service = CreateService(service_mgr, name, name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
							SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmd, NULL, NULL, "Tcpip\0Afd\0",
							NULL, NULL);
	if (!service) {
		*emsg = get_error_msg(GetLastError());
		CloseServiceHandle(service_mgr);
		return 0;
	}
	CloseServiceHandle(service);
	CloseServiceHandle(service_mgr);

	if (!desc)
		return 1;

	service_mgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!service_mgr) {
		*emsg = get_error_msg(GetLastError());
		return 0;
	}
	service = OpenService(service_mgr, name, SERVICE_CHANGE_CONFIG);
	if (!service) {
		*emsg = get_error_msg(GetLastError());
		CloseServiceHandle(service_mgr);
		return 0;
	}
	sd.lpDescription = desc;
	if (!ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &sd)) {
		CloseServiceHandle(service);
		CloseServiceHandle(service_mgr);
		*emsg = get_error_msg(GetLastError());
		return 0;
	}
	CloseServiceHandle(service);
	CloseServiceHandle(service_mgr);
	return 1;
}

int service_uninstall(char *name, char **emsg) {
	SC_HANDLE service_mgr, service;

	service_mgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
	if (!service_mgr) {
		*emsg = get_error_msg(GetLastError());
		return 0;
	}
	service = OpenService(service_mgr, name, DELETE);
	if (!service) {
		*emsg = get_error_msg(GetLastError());
		CloseServiceHandle(service_mgr);
		return 0;
	}
	if (!DeleteService(service)) {
		*emsg = get_error_msg(GetLastError());
		CloseServiceHandle(service);
		CloseServiceHandle(service_mgr);
		return 0;
	}
	CloseServiceHandle(service);
	CloseServiceHandle(service_mgr);
	return 1;
}

void *pdata = NULL;
void (*payload)() = NULL;
char *service_name = NULL;
SERVICE_STATUS svc_status;
SERVICE_STATUS_HANDLE hstatus;

int service_isstopped() {
	return svc_status.dwCurrentState == SERVICE_STOPPED;
}

VOID WINAPI service_ctrl(DWORD ctrl) {
	switch (ctrl) {
		case SERVICE_CONTROL_STOP:
		case SERVICE_CONTROL_SHUTDOWN:
			svc_status.dwWin32ExitCode = NO_ERROR;
			svc_status.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus(hstatus, &svc_status);
			return;
		default:
			return;
	}
}

VOID WINAPI service_main(int argc, char **argv) {
	hstatus = RegisterServiceCtrlHandler(service_name, service_ctrl);
	if (!hstatus) {
		return;
	}
	svc_status.dwServiceSpecificExitCode = 0;
	svc_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	svc_status.dwCurrentState = SERVICE_RUNNING;
	svc_status.dwWin32ExitCode = NO_ERROR;
	svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	SetServiceStatus(hstatus, &svc_status);
	payload(pdata, service_isstopped);
	return;
}

int service_start(void(*f)(void *, int(*g)()), void *data, char *name, char **emsg) {
	SERVICE_TABLE_ENTRY tbl[] = {
		{name, (LPSERVICE_MAIN_FUNCTION)service_main},
		{NULL, NULL}
	};
	service_name = name;
	payload = f;
	pdata = data;
	if (!StartServiceCtrlDispatcher(tbl)) {
		*emsg = get_error_msg(GetLastError());
		return 0;
	}
	return 1;
}
