// LogView.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "signal.h"
#include "LogView.h"



typedef void (*signalhandler)(int);
HANDLE file = NULL;
UINT g_main_thread = 0;
void signal_handler( int sig )
{
    if( file )
        CloseHandle(file);
}

int _tmain(int argc, _TCHAR* argv[])
{
    OPENFILENAME ofn;
    TCHAR szFile[MAX_PATH];
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.lpstrFile[0] = _T('\0');
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = _T("All\0*.*\0LOG\0*.log\0");
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_SHOWHELP | OFN_OVERWRITEPROMPT;
    if( !GetSaveFileName(&ofn) )
        return 0;

    g_main_thread = GetCurrentThreadId();
    signalhandler oldhandler;
    oldhandler = signal(SIGINT, signal_handler);

    DWORD id;
    HANDLE h = ::CreateThread(NULL,	
        0,	
        UserCaptureThread,	
        NULL,	
        CREATE_SUSPENDED,	
        &id);	

    if ( INVALID_HANDLE_VALUE != h)
    {
        ResumeThread( h );
    }

    h = ::CreateThread(NULL,	
        0,	
        KernelCaptureThread,	
        NULL,	
        CREATE_SUSPENDED,	
        &id);	

    if ( INVALID_HANDLE_VALUE != h)
    {
        ResumeThread( h );
    }



    file = CreateFile(szFile, GENERIC_WRITE, FILE_SHARE_WRITE|FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);


    MSG _msg;
    UINT count = 0;
    while(GetMessage(&_msg, 0, NULL,NULL))
    {
        switch(_msg.message)
        {
        case WM_STRING_READ:
            {
                DbgInfo* info = (PDbgInfo)_msg.lParam;
                printf(info->buffer);
                DWORD len = info->length;
                WriteFile(file, info->buffer, info->length-1, &len, NULL);
                free(info->buffer);
                free(info);
            }
            break;
        default:
            break;
        }
    }
    CloseHandle(file);

	return 0;
}

void FixStringToDbgViewStyle(char* src, char* des, BOOL userMode, ULONG pid)
{
    if( !src || !des || !*src )
        return;

    char* buffer = src;
    UINT logLen = strlen(buffer);
    for( int index = 0 ; index < logLen ; index++)
    {
        if( buffer[index] == '\r' || buffer[index] == '\n' )
            buffer[index] = ' ';
    }
    if( logLen < 4095 ){
        buffer[logLen] = '\r';
        buffer[logLen+1] = '\n';
        buffer[logLen+2] = '\0';
    }
    char* msgBuf = buffer;
    static UINT count = 0;
    static UINT start = ::GetTickCount();
    if( pid == -1 )
        pid = GetCurrentProcessId();
    if( !userMode )
    {
        sprintf(des,"%.8d\t%f\t%s" ,count++, (float)(::GetTickCount() - start) / 1000.0,  msgBuf);
    }
    else
    {
        sprintf(des,"%.8d\t%f\t[%d] %s" ,count++, (float)(::GetTickCount() - start) / 1000.0, pid, msgBuf);
    }
    
}

