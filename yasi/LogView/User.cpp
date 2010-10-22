#include "stdafx.h"
#include "LogView.h"
DWORD WINAPI UserCaptureThread(void* context)
{
    DWORD m_dwResult;
    HANDLE hMapping = NULL;
    HANDLE hAckEvent = NULL;
    HANDLE m_hReadyEvent = NULL;
    PDEBUGBUFFER pdbBuffer = NULL;
    UINT count = 0;
    DWORD start = GetTickCount();
    char buffer[4096];
    try
    { 
        m_dwResult = ERROR_INVALID_HANDLE;
        hAckEvent = CreateEvent(NULL, FALSE, FALSE, TEXT("DBWIN_BUFFER_READY"));
        m_hReadyEvent = CreateEvent(NULL, FALSE, FALSE, TEXT("DBWIN_DATA_READY"));
        hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, MAX_DebugBuffer, TEXT("DBWIN_BUFFER"));
        pdbBuffer = (PDEBUGBUFFER) MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        for (m_dwResult = ERROR_SIGNAL_PENDING; (m_dwResult == ERROR_SIGNAL_PENDING); )
        { 
            SetEvent(hAckEvent);
            if (WaitForSingleObject(m_hReadyEvent, INFINITE) == WAIT_OBJECT_0)
            { 
                if (m_dwResult == ERROR_SIGNAL_PENDING)
                { 
                    strcpy(buffer, pdbBuffer->data);
                    char msg[4096] = {0};
                    FixStringToDbgViewStyle(buffer, msg, TRUE, pdbBuffer->dwProcessId);
                    //printf("\rworking [%.8d] logs", count);
                    //DWORD len = strlen(msg)+1;
                    //WriteFile(file, msg, strlen(msg), &len, NULL);
                    PDbgInfo info = (PDbgInfo)malloc(sizeof( DbgInfo ));
                    info->length = strlen(msg)+1;
                    info->buffer = (char*)malloc(info->length);
                    memcpy(info->buffer, msg, info->length);
                    PostThreadMessage(g_main_thread, WM_STRING_READ, NULL, (LPARAM)info);

                }
            }
            else
            { 
                m_dwResult = WAIT_ABANDONED;
            }
        }
    }
    catch(...)
    { 
        if (pdbBuffer)
        { 
            UnmapViewOfFile(pdbBuffer);
        }
        CloseHandle(hMapping);
        CloseHandle(m_hReadyEvent);
        CloseHandle(hAckEvent);		
        return m_dwResult;
    }
}