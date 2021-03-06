#pragma once
#include <WinIoCtl.h>
#include "internal.h"
#define XP_SP3

#ifdef __cplusplus
extern "C"
{

#endif

#define DllExport   __declspec( dllexport )
typedef void* YASI_HANDLE;

#define RING_IOCTL_INDEX             0x0C00  
#define IOCTL_CMD_READ               CTL_CODE(FILE_DEVICE_UNKNOWN,		\
										RING_IOCTL_INDEX,				\
										METHOD_BUFFERED,				\
										FILE_ANY_ACCESS)
#define MAX_ACCEPT_STRING_LEN 128

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

struct PROCESS_DETAIL
{
	WCHAR fullName[MAX_ACCEPT_STRING_LEN];
#ifdef XP_SP3
	EPROCESS_XP_SP3 process;
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

struct THREAD_DETAIL
{
#ifdef XP_SP3
	ETHREAD_XP_SP3 thread;
#else
#endif
};

DllExport YASI_HANDLE yasi_create();

DllExport void yasi_destroy(YASI_HANDLE h);

DllExport ULONG yasi_get_process_count(YASI_HANDLE h);

DllExport void yasi_get_process(YASI_HANDLE h, ULONG index, struct PROCESS_RECORD * record);

DllExport void yasi_get_process_detail(YASI_HANDLE h, ULONG processID, PROCESS_DETAIL* detail);

DllExport void yasi_kill_process(YASI_HANDLE h, ULONG processID);

DllExport ULONG yasi_get_peb_address(YASI_HANDLE h, ULONG processID);

DllExport ULONG yasi_get_loaded_module_list(YASI_HANDLE h);

DllExport ULONG yasi_get_base_address(YASI_HANDLE h, ULONG processID);

DllExport void yasi_get_process_info(YASI_HANDLE h, ULONG processID, UINT which, wchar_t* str);

DllExport void yasi_get_process_string(YASI_HANDLE h, ULONG processID, PVOID addr, wchar_t* str, ULONG bufferLen);

DllExport ULONG yasi_get_module_count(YASI_HANDLE h, ULONG processID);

DllExport void yasi_get_module_info(YASI_HANDLE h, ULONG processID, ULONG index, LDR_DATA_TABLE_ENTRY_XP_SP3* info);

DllExport FARPROC yasi_get_proc_address(YASI_HANDLE h, ULONG processID, char* dllName, char* funcName);

DllExport FARPROC yasi_get_export_address(YASI_HANDLE h, ULONG processID, wchar_t* dllName, char* funcName);

DllExport void yasi_set_proc_address(YASI_HANDLE h, ULONG processID, char* dllName, char* funcName, PVOID newAddr);

DllExport void yasi_load_dll(YASI_HANDLE h, ULONG processID, wchar_t* fullPath);

DllExport BOOL yasi_read_process_memory(YASI_HANDLE h, ULONG processID, PVOID lpBaseAddress, PVOID lpBuffer, ULONG size, ULONG* bytesRead);

DllExport BOOL yasi_write_process_memory(YASI_HANDLE h, ULONG processID, PVOID lpBaseAddress, PVOID lpBuffer, ULONG size, ULONG* bytesWrite);

//inline hook的方法就是：
//1。 找出目标函数的地址DestFuncAddress
//2。 BYTE JmpAddress[5]={0xE9,0,0,0,0};       跳转指令
//3。 *(ULONG *)(JmpAddress+1)=(ULONG)MyFuncAddress-((ULONG)DestFuncAddress+5);
//4.  yasi_write_process_memory(core, pid, (BYTE *)DestFuncAddress,JmpAddress,5);
//但是我不提供现成的方法

DllExport ULONG yasi_get_thread_count(YASI_HANDLE h, ULONG processID);
DllExport void yasi_get_thread_detail(YASI_HANDLE h, ULONG processID, ULONG threadIndex, THREAD_DETAIL* detail);
DllExport void yasi_export_all_func(YASI_HANDLE h , ULONG processID, char* fileName);
DllExport void yasi_kill_thread(YASI_HANDLE h, ULONG processID, ULONG threadID);


DllExport ULONG yasi_get_handle_count(YASI_HANDLE h, ULONG processID);
DllExport void yasi_get_handle_info(YASI_HANDLE h , ULONG processID, ULONG index, HANDLE_INFO* info );
#ifdef __cplusplus
};

#endif