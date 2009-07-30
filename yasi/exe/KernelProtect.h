#pragma once

#include <WinIoCtl.h>
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
	CMD_GET_PROCESS_BY_INDEX
};

struct PROCESS_RECORD
{
	ULONG processID;
	UCHAR imageName[16];
};
#define MAX_PROCESS_RECORD_NUM 50

HANDLE LoadDriver();
void UnloadDriver(HANDLE handle);
