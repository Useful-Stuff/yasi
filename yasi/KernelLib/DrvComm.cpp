#include "stdafx.h"
#include "DrvComm.h"
TCHAR NAME[] = _T("{D91E1EB2-97C0-4459-B30A-731543F407C6}");
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
