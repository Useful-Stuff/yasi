// KernelPortect.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include "KernelProtect.h"
#include <stdlib.h>
// {D91E1EB2-97C0-4459-B30A-731543F407C6}
TCHAR NAME[] = _T("{D91E1EB2-97C0-4459-B30A-731543F407C6}");


int _tmain(int argc, _TCHAR* argv[])
{
	DWORD dwReturn;
	HANDLE hFile = LoadDriver();



	CMD_RECORD cmd = {0};
	cmd.op = CMD_GET_PROCESS_COUNT;
	DWORD processCount = 0;
	DeviceIoControl(hFile, IOCTL_CMD_READ, &cmd, sizeof(CMD_RECORD), &processCount, 4, &dwReturn, NULL);


	for( int index = 0 ; index < processCount; index++ ){
		PROCESS_RECORD proc = {0};

		ULONG total_len = sizeof(cmd.op) + sizeof(cmd.total_len) + sizeof(ULONG);
		CMD_RECORD* record = (CMD_RECORD*)malloc(total_len);
		memset(record, 0, total_len);
		record->op = CMD_GET_PROCESS_BY_INDEX;
		record->total_len = total_len;
		*((ULONG*)(&(record->param[0]))) = index;
		DeviceIoControl(hFile, IOCTL_CMD_READ, record, total_len, &proc, sizeof(PROCESS_RECORD), &dwReturn, NULL);

		printf("[%d] %s \r\n", proc.processID, proc.imageName);
		
		free(record);
	}



	UnloadDriver(hFile);
	return 0;
}


HANDLE LoadDriver()
{
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	SERVICE_STATUS ss;
	DWORD error;
	BOOL loaded = FALSE;

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);


	if(hSCManager)
	{

		TCHAR szFileName[MAX_PATH] = {0};
		::GetModuleFileName(NULL, szFileName, MAX_PATH);
		TCHAR* tmp = wcsstr(szFileName, _T("\\"));
		while( tmp ){
			*tmp = _T('\0');
			TCHAR* old = tmp;
			tmp = wcsstr(tmp+1, _T("\\"));
			if( tmp ){
				*old = _T('\\');
			}
		}

		wcscat(szFileName, _T("\\ring0.sys"));
		hService = CreateService(hSCManager, NAME, NAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, szFileName, NULL, NULL, NULL, NULL, NULL);
		error = GetLastError();
		if(!hService)
		{
			hService = OpenService(hSCManager, NAME, SERVICE_ALL_ACCESS);
			error = GetLastError();
		}

		if(hService)
		{
			BOOL result = StartService(hService, 0, NULL);
			if( !result )
				error = GetLastError();
			else
				loaded = TRUE;

			

			CloseServiceHandle(hService);

		}

		CloseServiceHandle(hSCManager);
	}


	if( loaded ){
		HANDLE hFile;

		hFile = CreateFile(L"\\\\.\\KernelProtect", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

		if(hFile){
			return hFile;
		}else{
			return NULL;
		}
	}else{
		return NULL;
	}

}

void UnloadDriver(HANDLE file)
{
	SC_HANDLE hSCManager;
	SC_HANDLE hService;
	SERVICE_STATUS ss;
	DWORD error;
	BOOL result;

	if( file ){
		CloseHandle(file);
	}

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);


	if(hSCManager)
	{

		hService = OpenService(hSCManager, NAME, SERVICE_ALL_ACCESS);

		if(hService)
		{
			QueryServiceStatus(hService, &ss);
			if( ss.dwCurrentState == SERVICE_RUNNING )
				result = ControlService(hService, SERVICE_CONTROL_STOP, &ss);
			if( !result )
				error = GetLastError();

			result = DeleteService(hService);
			if( !result )
				error = GetLastError();

			result = CloseServiceHandle(hService);
			if( !result )
				error = GetLastError();


		}

		CloseServiceHandle(hSCManager);
	}
}
