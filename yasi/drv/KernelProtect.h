



#ifndef __EXAMPLE_H__
#define __EXAMPLE_H__
#define XP_SP3

typedef unsigned int UINT;
typedef char * PCHAR;
typedef unsigned long ULONG;
typedef char UCHAR;
typedef unsigned int BOOL;
typedef void * PVOID;
typedef unsigned short WORD;
#define TRUE (1==1)
#define FALSE (1==0)

#include "../internal.h"

#define RING_IOCTL_INDEX             0x0C00                                                 
#define IOCTL_CMD_READ                CTL_CODE(FILE_DEVICE_UNKNOWN,     \
                                                     RING_IOCTL_INDEX, \
                                                     METHOD_BUFFERED,         \
                                                     FILE_ANY_ACCESS)



struct CMD_RECORD
{
	ULONG op;
	ULONG total_len;
	char  param[0];

};

enum
{
	CMD_GET_PROCESS_COUNT,
	CMD_GET_PROCESS_BY_INDEX,
	CMD_GET_PROCESS_DETAIL,
	CMD_KILL_PROCESS,
	CMD_GET_PROCESS_STRING,
	CMD_READ_PROCESS_MEMORY,
	CMD_WRITE_PROCESS_MEMORY,
	CMD_GET_THREAD_DETAIL,
	CMD_KILL_THREAD,
	CMD_GET_HANDLE_COUNT,
	CMD_GET_HANDLEINFO_BY_INDEX,
	CMD_GET_LOADED_DRIVER_LIST

};

enum
{
	STRING_CSDVersion,
	STRING_DllPath,
	STRING_ImagePathName,
	STRING_CommandLine,
	STRING_WindowTitle,
	STRING_DesktopInfo,
	STRING_ShellInfo,
	STRING_RuntimeData,
	STRING_CurrentDirectore
};

struct PROCESS_RECORD
{

	ULONG processID;
	UCHAR imageName[16];
};

struct EPROCESS_WAPPER
{
#ifdef XP_SP3
	EPROCESS_XP_SP3 process;
#else
#endif
};

struct ETHREAD_WAPPER
{
#ifdef XP_SP3
	ETHREAD_XP_SP3 thread;
#else
#endif
};

typedef struct _HANDLE_INFO
{
#ifdef XP_SP3
	ULONG canFound;
	ULONG handle;
	ULONG objAddress;
	ULONG refrenced;
	ULONG handles;
	wchar_t typeName[1024];
	wchar_t objName[1024];
#else
#endif
} HANDLE_INFO;

struct PROCESS_DETAIL
{
	WCHAR fullName[128];
#ifdef XP_SP3
	EPROCESS_XP_SP3 process;
#else
#endif
};

struct THREAD_DETAIL
{
#ifdef XP_SP3
	ETHREAD_XP_SP3 thread;
#else
#endif
};

NTSTATUS KernelProtect_Create(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS KernelProtect_Close(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS KernelProtect_IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS KernelProtect_Read(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS KernelProtect_WriteBufferedIO(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS KernelProtect_WriteDirectIO(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS KernelProtect_WriteNeither(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS KernelProtect_UnSupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp);

void EnumProcessList(ULONG index, struct PROCESS_RECORD* processes);
ULONG GetProcessCount();
void GetProcessDetail(ULONG id, struct PROCESS_DETAIL* detail);
void KillProcess(ULONG id);
void GetProcessString(ULONG id,  ULONG* str);
BOOL YasiReadProcessMemory(ULONG id, PVOID lpBaseAddress, PVOID lpBuffer, ULONG size, ULONG* bytesRead);
BOOL YasiWriteProcessMemory(ULONG id, PVOID lpBaseAddress,PVOID lpBuffer, ULONG nSize, ULONG * lpNumberOfBytesWritten);
BOOL GetThreadDetail(ULONG pid, ULONG thread_idx, struct THREAD_DETAIL* detail);
void KillThread(ULONG pid, ULONG tid);

ULONG GetHandleCount(ULONG pid);
void GetHandleInfo(ULONG pid, ULONG index, HANDLE_INFO* info);

enum
{

	EPROCESS_SIZE = 0,
	PEB_OFFSET,
	FILE_NAME_OFFSET,
	PROCESS_LINK_OFFSET,
	PROCESS_ID_OFFSET,
	EXIT_TIME_OFFSET,
	ProcessParameters_OFFSET,
	CSDVersion_OFFSET,
	DllPath_OFFSET,
	ImagePathName_OFFSET,
	CommandLine_OFFSET,
	WindowTitle_OFFSET,
	DesktopInfo_OFFSET,
	ShellInfo_OFFSET,
	RuntimeData_OFFSET,
	CurrentDirectore_OFFSET,
	PorcessThreadListEntry_OFFSET,
	ThreadExitStatus_OFFSET
	
};

#ifdef __USE_DIRECT__
#define IO_TYPE DO_DIRECT_IO
#define USE_WRITE_FUNCTION  KernelProtect_WriteDirectIO
#endif
 
#ifdef __USE_BUFFERED__
#define IO_TYPE DO_BUFFERED_IO
#define USE_WRITE_FUNCTION  KernelProtect_WriteBufferedIO
#endif

#ifndef IO_TYPE
#define IO_TYPE 0
#define USE_WRITE_FUNCTION  KernelProtect_WriteNeither
#endif

#endif






