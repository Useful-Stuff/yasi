



#ifndef __EXAMPLE_H__
#define __EXAMPLE_H__

#define RING_IOCTL_INDEX             0x0C00                                                 
#define IOCTL_CMD_READ                CTL_CODE(FILE_DEVICE_UNKNOWN,     \
                                                     RING_IOCTL_INDEX, \
                                                     METHOD_BUFFERED,         \
                                                     FILE_ANY_ACCESS)

typedef unsigned int UINT;
typedef char * PCHAR;
typedef unsigned long ULONG;
typedef char UCHAR;
typedef unsigned int BOOL;
#define TRUE (1==1)
#define FALSE (1==0)

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

enum
{
	EPROCESS_SIZE = 0,
	PEB_OFFSET,
	FILE_NAME_OFFSET,
	PROCESS_LINK_OFFSET,
	PROCESS_ID_OFFSET,
	EXIT_TIME_OFFSET
	
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






