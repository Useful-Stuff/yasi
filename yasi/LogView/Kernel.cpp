#include "stdafx.h"
#include "LogView.h"
TCHAR NAME[] = _T("{A625A9B3-78A3-4fbe-927B-0B86B117CD39}");
OVERLAPPED readOverlap;
void AdjustPrivilege()
{
    DWORD dwError, dwLength;
    HANDLE hdCurrent, hdCurrentToken;
    unsigned char ucBuffer[512] = {0};
    TOKEN_PRIVILEGES* stToken = NULL;
    stToken = (TOKEN_PRIVILEGES*)ucBuffer;
    hdCurrent = GetCurrentProcess();
    dwError = OpenProcessToken(hdCurrent, TOKEN_ALL_ACCESS, &hdCurrentToken);
    dwError = GetTokenInformation(hdCurrentToken, TokenPrivileges, (TOKEN_PRIVILEGES*)ucBuffer, 512, &dwLength);
    for( dwError = 0 ; dwError < stToken->PrivilegeCount; dwError++){
        LUID uid = stToken->Privileges[dwError].Luid;
        stToken->Privileges[dwError].Attributes = SE_PRIVILEGE_ENABLED;
    }
    dwError = AdjustTokenPrivileges(hdCurrentToken, false, stToken, /*sizeof(DWORD)+stToken->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES)*/dwLength, NULL, NULL);
    //dwError = GetTokenInformation(hdCurrentToken, TokenPrivileges, (TOKEN_PRIVILEGES*)ucBuffer, 512, &dwLength);
    CloseHandle(hdCurrentToken);
}

void UnloadDriver(HANDLE file);
HANDLE LoadDriver()
{
    UnloadDriver(0);
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

        wcscat(szFileName, _T("\\dbgdrv.sys"));
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
            if( !result ){
                loaded = TRUE;
                error = GetLastError();
            }else
                loaded = TRUE;



            CloseServiceHandle(hService);

        }

        CloseServiceHandle(hSCManager);
    }


    if( loaded ){
        HANDLE hFile;

        hFile = CreateFile(L"\\\\.\\yaDbgView", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

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
    BOOL result = FALSE;

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



DWORD WINAPI KernelCaptureThread(void* context)
{

    HANDLE driver = OpenDriverHandle();
    if( driver == INVALID_HANDLE_VALUE )
        return 0;

    char buf[4096] = {0};
    unsigned dwRead = 0;
    while( KernelRead(driver, buf, 4096, &dwRead) )
    {
        if( dwRead == 0 || dwRead == -1 ){
            Sleep(500);
            continue;
        }
        char msg[4096] = {0};
        FixStringToDbgViewStyle(buf, msg, FALSE);
        PDbgInfo info = (PDbgInfo)malloc(sizeof( DbgInfo ));
        info->length = strlen(msg)+1;
        info->buffer = (char*)malloc(info->length);
        memcpy(info->buffer, msg, info->length);
        PostThreadMessage(g_main_thread, WM_STRING_READ, NULL, (LPARAM)info);
    }


    CloseDriverHandle(driver);
}

HANDLE OpenDriverHandle()
{
    memset( &readOverlap , 0, sizeof(OVERLAPPED) );
    readOverlap.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    AdjustPrivilege();
    return LoadDriver();

}
void CloseDriverHandle(HANDLE h)
{
    UnloadDriver(h);
    SetEvent(readOverlap.hEvent);
    CloseHandle(readOverlap.hEvent);
    readOverlap.hEvent = NULL;

}



BOOL KernelRead(HANDLE h, void* buffer, unsigned len, unsigned* dwRead)
{
    DWORD dwBytesRead = 0L;
    ResetEvent(readOverlap.hEvent);
    BOOL bRc = DeviceIoControl ( h,
        (DWORD) IOCTL_CMD_READ,
        NULL,
        0,
        buffer,
        len,
        &dwBytesRead,
        &readOverlap
        );
    if( bRc ){
        if( dwBytesRead == 0 ){
            dwBytesRead = -1;
        }
        //good data
    }else{
        DWORD error = GetLastError();
        if ( error == ERROR_IO_PENDING)
        { 		
            bRc = GetOverlappedResult(readOverlap.hEvent,
                &readOverlap,
                &dwBytesRead,
                TRUE);
            if( dwBytesRead == 0 ){
                dwBytesRead = -1;
            }else if( bRc ){
                //good data
            }else{

                if( ERROR_IO_INCOMPLETE == GetLastError() ){
                    DWORD res = WaitForSingleObject(readOverlap.hEvent, 1000);
                    if( WAIT_TIMEOUT == res ){
                        dwBytesRead = -1;
                    }else if(WAIT_OBJECT_0 == res ){
                        //good
                    }else{
                        dwBytesRead = -1;
                    }
                }else{
                    dwBytesRead = -1;
                }
            }

        } else {
            dwBytesRead = -1;
        }

    }
    if( dwRead )
        *dwRead = dwBytesRead;

    return TRUE;
}