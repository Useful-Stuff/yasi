/**********************************************************************
 * 
 *  Toby Opferman
 *
 *  Driver Example
 *
 *  This example is for educational purposes only.  I license this source
 *  out for use in learning how to write a device driver.
 *
 *     Driver Entry Point
 **********************************************************************/
#define _X86_

#include <wdm.h>
#include "DbgHead.h"

#pragma alloc_text(PAGE, LogCapture_Create) 
#pragma alloc_text(PAGE, LogCapture_Close) 
#pragma alloc_text(PAGE, LogCapture_IoControl) 
#pragma alloc_text(NONPAGE, DebugPrintCallback) 
#define  MAX_BUFFER_DEPTH 100
DeviceExtensionEx * g_ex = NULL;
    
NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath); 

/* 
 * These compiler directives tell the Operating System how to load the
 * driver into memory. The "INIT" section is discardable as you only
 * need the driver entry upon initialization, then it can be discarded.
 *
 */
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, LogCapture_Unload)

/**********************************************************************
 * 
 *  DriverEntry
 *
 *    This is the default entry point for drivers.  The parameters
 *    are a driver object and the registry path.
 *
 **********************************************************************/



NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath)
{
	//RTL_OSVERSIONINFOW versionInfo;
    NTSTATUS NtStatus = STATUS_SUCCESS;
    UINT uiIndex = 0;
    PDEVICE_OBJECT pDeviceObject = NULL;
    UNICODE_STRING usDriverName, usDosDeviceName;
    DeviceExtensionEx* ex = NULL;

    

    RtlInitUnicodeString(&usDriverName, L"\\Device\\yaDbgView");
    RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\yaDbgView"); 

    NtStatus = IoCreateDevice(pDriverObject, 0, &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);

    if(NtStatus == STATUS_SUCCESS)
    {

        /*
         * The "MajorFunction" is a list of function pointers for entry points into the driver.
         * You can set them all to point to 1 function, then have a switch statement for all
         * IRP_MJ_*** functions or you can set specific function pointers for each entry
         * into the driver.
         *
         */
        for(uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
             pDriverObject->MajorFunction[uiIndex] = LogCapture_UnSupportedFunction;
    
        pDriverObject->MajorFunction[IRP_MJ_CLOSE]             = LogCapture_Close;
        pDriverObject->MajorFunction[IRP_MJ_CREATE]            = LogCapture_Create;
        pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]    = LogCapture_IoControl;
        ex = ExAllocatePool(NonPagedPool, sizeof(DeviceExtensionEx));
        pDeviceObject->DeviceExtension = ex;
        KeInitializeSpinLock(&ex->ReadLock);
        ex->ReadIrp = NULL;
        InitializeListHead(&ex->EventList);
        ex->list_depth = 0;
    
        g_ex = ex;
        /* 
         * Required to unload the driver dynamically.  If this function is missing
         * the driver cannot be dynamically unloaded.
         */
        pDriverObject->DriverUnload =  LogCapture_Unload; 
         
        pDeviceObject->Flags |= DO_DIRECT_IO;
    
        pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
    
        IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
    }


    return NtStatus;
}


/**********************************************************************
 * 
 *  LogCapture_Unload
 *
 *    This is an optional unload function which is called when the
 *    driver is unloaded.
 *
 **********************************************************************/
VOID LogCapture_Unload(PDRIVER_OBJECT  DriverObject)
{    
    
    UNICODE_STRING usDosDeviceName;
    
    DbgPrint("LogCapture_Unload Called \r\n");
    
    RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\KernelProtect");
    IoDeleteSymbolicLink(&usDosDeviceName);

    IoDeleteDevice(DriverObject->DeviceObject);
}

void DebugPrintCallback(IN PANSI_STRING String, IN ULONG ComponentId, IN ULONG Level)
{
    PIRP irp = NULL;
    DbgInfo* info = NULL;
    if( !g_ex )
        return;
    if( !String || !String->Buffer )
        return;
    {

        info = ExAllocatePool(NonPagedPool, sizeof(*info));
        info->node.Blink = info->node.Flink = NULL;
        info->str = ExAllocatePool(NonPagedPool, sizeof(*String));
        info->str->Buffer = ExAllocatePool(NonPagedPool, String->Length);
        info->str->Length = String->Length;
        info->str->MaximumLength = String->MaximumLength;
        RtlCopyMemory(info->str->Buffer, String->Buffer, String->Length);
        KeAcquireSpinLockAtDpcLevel(&g_ex->ReadLock);
        if( g_ex->list_depth >= MAX_BUFFER_DEPTH )
        {
            LIST_ENTRY * node = RemoveHeadList(&g_ex->EventList);
            DbgInfo* tmpinfo = CONTAINING_RECORD(node, DbgInfo, node);
            if( tmpinfo ){
                ExFreePool(tmpinfo->str->Buffer);
                ExFreePool(tmpinfo->str);
                ExFreePool(tmpinfo);
                g_ex->list_depth--;
            }
        }
        InsertTailList(&g_ex->EventList, &info->node);
        g_ex->list_depth++;
        KeReleaseSpinLockFromDpcLevel(&g_ex->ReadLock);
    }
}


/**********************************************************************
* 
*  LogCapture_Create
*
*    This is called when an instance of this driver is created (CreateFile)
*
**********************************************************************/
NTSTATUS LogCapture_Create(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    DbgPrint("[ring0] LogCapture_Create Called \r\n");
    DbgSetDebugPrintCallback(DebugPrintCallback, TRUE);

    return NtStatus;
}

/**********************************************************************
* 
*  LogCapture_Close
*
*    This is called when an instance of this driver is closed (CloseHandle)
*
**********************************************************************/
NTSTATUS LogCapture_Close(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    KIRQL irql;
    NTSTATUS NtStatus = STATUS_SUCCESS;
    DeviceExtensionEx *ex = DeviceObject->DeviceExtension;
    PIRP readIrp = NULL;
    DbgInfo* info = NULL;
    DbgPrint("[ring0] LogCapture_Close Called \r\n");
    DbgSetDebugPrintCallback(DebugPrintCallback, FALSE);
    KeAcquireSpinLock(&ex->ReadLock, &irql);
    while( IsListEmpty(&ex->EventList) )
    {
        LIST_ENTRY * node = RemoveHeadList(&ex->EventList);
        info = CONTAINING_RECORD(node, DbgInfo, node);
        ExFreePool(info->str->Buffer);
        ExFreePool(info->str);
        ExFreePool(info);
    }
    KeReleaseSpinLock(&ex->ReadLock, irql);

    ExFreePool(ex);
    ex = NULL;
    g_ex = NULL;
    return NtStatus;
}

NTSTATUS LogCapture_UnSupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS NtStatus = STATUS_NOT_SUPPORTED;
    DbgPrint("LogCapture_UnSupportedFunction Called \r\n");

    return NtStatus;
}



NTSTATUS LogCapture_IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS			Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION	irpStack;
    ULONG				inBufLength, outBufLength;
    ULONG				i = 0;
    ULONG				ioControlCode;
    UCHAR				*InputBuffer, *OutputBuffer;
    DeviceExtensionEx   *ex = NULL;
    KIRQL irql;

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    inBufLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outBufLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    ex = DeviceObject->DeviceExtension;
    if (ioControlCode == IOCTL_CMD_READ)
    {
        //DbgPrint("[ring0] IOCTL_CMD_READ : 0x%X", ioControlCode);
        //InputBuffer = (UCHAR *)Irp->AssociatedIrp.SystemBuffer;
        {
            PIRP old = NULL;
            KeAcquireSpinLock(&ex->ReadLock, &irql);
            if( IsListEmpty(&ex->EventList) )
            {
                KeReleaseSpinLock(&ex->ReadLock, irql );
                Irp->IoStatus.Information = 0;
            }
            else
            {
                PLIST_ENTRY entry = NULL;
                DbgInfo* info = NULL;
                entry = RemoveHeadList(&ex->EventList);
                g_ex->list_depth--;
                KeReleaseSpinLock(&ex->ReadLock, irql );
                if( !entry )
                {
                    Irp->IoStatus.Information = 0;
                }
                else
                {
                    info = CONTAINING_RECORD(entry, DbgInfo, node);
                    if( outBufLength < info->str->Length )
                    {
                        Irp->IoStatus.Information = 0;
                    }
                    else
                    {
                        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, info->str->Buffer, info->str->Length);
                        Irp->IoStatus.Information = info->str->Length;
                        Status = STATUS_SUCCESS;
                    }
                    ExFreePool(info->str->Buffer);
                    ExFreePool(info->str);
                    ExFreePool(info);
                }

            }
            
        }

    } 
    else
    {
        Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;

    }    
    // Íê³ÉIRP
    Irp->IoStatus.Status = Status;
    IoSetCancelRoutine(Irp,NULL);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;


}