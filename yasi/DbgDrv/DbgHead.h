#ifndef _DBGHEAD_H
#define _DBGHEAD_H

typedef unsigned int UINT;
typedef char * PCHAR;
typedef unsigned long ULONG;
typedef char UCHAR;
typedef unsigned int BOOL;
typedef void * PVOID;
typedef unsigned short WORD;

//typedef void (*PDEBUG_PRINT_CALLBACK_FUNCTION) (IN PANSI_STRING String, IN ULONG ComponentId, IN ULONG Level); 
//typedef (*fpDbgSetDebugPrintCallback)(IN PDEBUG_PRINT_CALLBACK_FUNCTION f, IN BOOLEAN mode);
//static fpDbgSetDebugPrintCallback  DbgSetDebugPrintCallback;

VOID LogCapture_Unload(PDRIVER_OBJECT  DriverObject);    
NTSTATUS LogCapture_Create(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS LogCapture_Close(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS LogCapture_IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS LogCapture_UnSupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void DebugPrintCallback(IN PANSI_STRING String, IN ULONG ComponentId, IN ULONG Level);

#define RING_IOCTL_INDEX             0x0C01    
#define IOCTL_CMD_READ                CTL_CODE(FILE_DEVICE_UNKNOWN,     \
    RING_IOCTL_INDEX, \
    METHOD_BUFFERED,         \
    FILE_ANY_ACCESS)

typedef struct _DbgInfo
{
    PANSI_STRING str;
    LIST_ENTRY node;
}DbgInfo;


typedef struct _DeviceExtensionEx
{
    ULONG list_depth;
    KSPIN_LOCK ReadLock;
    PIRP        ReadIrp;
    LIST_ENTRY	EventList;
}DeviceExtensionEx;

#endif