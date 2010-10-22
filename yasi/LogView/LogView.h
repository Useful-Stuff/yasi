#pragma once
#include "windows.h"
#define WM_STRING_READ  (WM_USER+1)
#define MAX_DebugBuffer 4096
typedef struct _DbgInfo
{
    char* buffer;
    unsigned length;
}DbgInfo, *PDbgInfo;

typedef struct dbwin_buffer {
    DWORD   dwProcessId;
    char    data[4096-sizeof(DWORD)];
}DEBUGBUFFER,*PDEBUGBUFFER;

#define RING_IOCTL_INDEX             0x0C01    
#define IOCTL_CMD_READ                CTL_CODE(FILE_DEVICE_UNKNOWN,     \
    RING_IOCTL_INDEX, \
    METHOD_BUFFERED,         \
    FILE_ANY_ACCESS)


void FixStringToDbgViewStyle(char* src, char* des, BOOL userMode, ULONG pid = -1);
DWORD WINAPI UserCaptureThread(void* context);
DWORD WINAPI KernelCaptureThread(void* context);
HANDLE OpenDriverHandle();
void CloseDriverHandle(HANDLE h);
BOOL KernelRead(HANDLE h, void* buffer, unsigned len, unsigned* dwRead);

extern UINT g_main_thread;