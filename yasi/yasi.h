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
	CMD_GET_PROCESS_STRING

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

DllExport YASI_HANDLE yasi_create();

DllExport void yasi_destroy(YASI_HANDLE h);

DllExport ULONG yasi_get_process_count(YASI_HANDLE h);

DllExport void yasi_get_process(YASI_HANDLE h, ULONG index, struct PROCESS_RECORD * record);

DllExport void yasi_get_process_detail(YASI_HANDLE h, ULONG processID, PROCESS_DETAIL* detail);

DllExport void yasi_kill_process(YASI_HANDLE h, ULONG processID);

DllExport ULONG yasi_get_peb_address(YASI_HANDLE h, ULONG processID);

DllExport ULONG yasi_get_base_address(YASI_HANDLE h, ULONG processID);

DllExport void yasi_get_process_info(YASI_HANDLE h, ULONG processID, UINT which, wchar_t* str);

DllExport void yasi_get_process_string(YASI_HANDLE h, ULONG processID, PVOID addr, wchar_t* str, ULONG bufferLen);

DllExport ULONG yasi_get_module_count(YASI_HANDLE h, ULONG processID);

DllExport void yasi_get_module_info(YASI_HANDLE h, ULONG processID, ULONG index, LDR_DATA_TABLE_ENTRY_XP_SP3* info);

DllExport FARPROC yasi_get_proc_address(YASI_HANDLE h, ULONG processID, char* dllName, char* funcName);

DllExport FARPROC yasi_get_export_address(YASI_HANDLE h, ULONG processID, wchar_t* dllName, char* funcName);

DllExport void yasi_set_proc_address(YASI_HANDLE h, ULONG processID, char* dllName, char* funcName, PVOID newAddr);

DllExport void yasi_load_dll(YASI_HANDLE h, ULONG processID, wchar_t* fullPath);

#ifdef __cplusplus
};

#endif