#pragma once
#include <WinIoCtl.h>
#include "internal.h"
#define XP_SP3


#define DllExport   __declspec( dllexport )
typedef void* YASI_HANDLE;

#define RING_IOCTL_INDEX             0x0C00  
#define IOCTL_CMD_READ               CTL_CODE(FILE_DEVICE_UNKNOWN,		\
										RING_IOCTL_INDEX,				\
										METHOD_BUFFERED,				\
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
	CMD_GET_PROCESS_BY_INDEX,	CMD_GET_PROCESS_DETAIL,	CMD_KILL_PROCESS
};

struct PROCESS_RECORD
{
	ULONG processID;
	UCHAR imageName[16];
};

struct PROCESS_DETAIL
{
	WCHAR fullName[128];
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