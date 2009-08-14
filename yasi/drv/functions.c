/**********************************************************************
 * 
 *  Toby Opferman
 *
 *  Driver Example
 *
 *  This example is for educational purposes only.  I license this source
 *  out for use in learning how to write a device driver.
 *
 *     Driver Functionality
 **********************************************************************/

#define _X86_ 

//#include <wdm.h>
#include <ntddk.h>
#include "KernelProtect.h"


/**********************************************************************
 * Internal Functions
 **********************************************************************/
BOOLEAN KernelProtect_IsStringTerminated(PCHAR pString, UINT uiLength);


#pragma alloc_text(PAGE, KernelProtect_Create) 
#pragma alloc_text(PAGE, KernelProtect_Close) 
#pragma alloc_text(PAGE, KernelProtect_IoControl) 
#pragma alloc_text(PAGE, KernelProtect_Read)
#pragma alloc_text(PAGE, KernelProtect_WriteDirectIO)
#pragma alloc_text(PAGE, KernelProtect_WriteBufferedIO)
#pragma alloc_text(PAGE, KernelProtect_WriteNeither)
#pragma alloc_text(PAGE, KernelProtect_UnSupportedFunction)
#pragma alloc_text(PAGE, KernelProtect_IsStringTerminated)



typedef struct _SRVTABLE {
	PVOID    *ServiceTable;
	ULONG          LowCall;        
	ULONG          HiCall;
	PVOID    *ArgTable;
} SRVTABLE, *PSRVTABLE;

extern PSRVTABLE KeServiceDescriptorTable;


#define SYSCALL(_function) ServiceTable->ServiceTable[*(PULONG)((PUCHAR)_function+1)]

PSRVTABLE              ServiceTable;

NTSTATUS
(*RealZwSetInformationFile)(IN HANDLE FileHandle,
							OUT PIO_STATUS_BLOCK IoStatusBlock,
							IN PVOID FileInformation,
							IN ULONG Length,
							IN FILE_INFORMATION_CLASS FileInformationClass); 

NTSTATUS HookZwSetInformationFile(IN HANDLE FileHandle,
								  OUT PIO_STATUS_BLOCK IoStatusBlock,
								  IN PVOID FileInformation,
								  IN ULONG Length,
								  IN FILE_INFORMATION_CLASS FileInformationClass); 

VOID HookAPI();
VOID UnHook();
VOID UnhookSystemCall();



/**********************************************************************
 * 
 *  KernelProtect_Create
 *
 *    This is called when an instance of this driver is created (CreateFile)
 *
 **********************************************************************/
NTSTATUS KernelProtect_Create(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    DbgPrint("[ring0] KernelProtect_Create Called \r\n");

    return NtStatus;
}

/**********************************************************************
 * 
 *  KernelProtect_Close
 *
 *    This is called when an instance of this driver is closed (CloseHandle)
 *
 **********************************************************************/
NTSTATUS KernelProtect_Close(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    DbgPrint("[ring0] KernelProtect_Close Called \r\n");

    return NtStatus;
}



/**********************************************************************
 * 
 *  KernelProtect_IoControl
 *
 *    This is called when an IOCTL is issued on the device handle (DeviceIoControl)
 *
 **********************************************************************/
NTSTATUS KernelProtect_IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS			Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION	irpStack;
    ULONG				inBufLength, outBufLength;
    ULONG				i = 0;
    ULONG				ioControlCode;
    UCHAR				*InputBuffer, *OutputBuffer;
	ULONG				index = 0;
	ULONG				processID = 0;
	struct CMD_RECORD	*cmd;
	ULONG				*tmp;
	ULONG				strID;
	PVOID				baseAddress;
	PVOID				destAddress;
	ULONG				size;
	ULONG				bytesProcessed;
    irpStack = IoGetCurrentIrpStackLocation(Irp);
    inBufLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outBufLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    if (ioControlCode == IOCTL_CMD_READ)
    {
        //DbgPrint("[ring0] IOCTL_CMD_READ : 0x%X", ioControlCode);
        InputBuffer = (UCHAR *)Irp->AssociatedIrp.SystemBuffer;
		cmd = (struct CMD_RECORD*)InputBuffer;
		switch( cmd->op ){
			case CMD_GET_PROCESS_COUNT:
				OutputBuffer = (UCHAR *)Irp->AssociatedIrp.SystemBuffer;
		        memset(OutputBuffer, 0, outBufLength);
		        Irp->IoStatus.Information = outBufLength;
				//DbgPrint("[ring0] output length %d", outBufLength);
				*OutputBuffer = GetProcessCount();
				break;
			case CMD_GET_PROCESS_BY_INDEX:
				index = *((ULONG*)&cmd->param[0]);
				OutputBuffer = (UCHAR *)Irp->AssociatedIrp.SystemBuffer;
		        memset(OutputBuffer, 0, outBufLength);
		        Irp->IoStatus.Information = outBufLength;
				//DbgPrint("[ring0] output length %d", outBufLength);
				EnumProcessList(index, (struct PROCESS_RECORD *) OutputBuffer);
				break;
			case CMD_GET_PROCESS_DETAIL:
				processID = *((ULONG*)&cmd->param[0]); 
				OutputBuffer = (UCHAR *)Irp->AssociatedIrp.SystemBuffer;
		        memset(OutputBuffer, 0, outBufLength);
		        Irp->IoStatus.Information = outBufLength;
				//DbgPrint("[ring0] output length %d", outBufLength);
				GetProcessDetail(processID, (struct PROCESS_DETAIL *) OutputBuffer);
				break;
			case CMD_KILL_PROCESS:
				processID = *((ULONG*)&cmd->param[0]); 
		        Irp->IoStatus.Information = 1;
				KillProcess(processID);
				break;
				
			case CMD_GET_PROCESS_STRING:
				tmp = (ULONG*)&cmd->param[0];
				processID = *tmp;
				OutputBuffer = (UCHAR *)Irp->AssociatedIrp.SystemBuffer;
		        memset(OutputBuffer, 0, outBufLength);
				Irp->IoStatus.Information = outBufLength;
				//DbgPrint("[ring0] output length %d", outBufLength);
				//DbgPrint("[ring0] processID %d", processID);
				GetProcessString(processID, OutputBuffer);
				break;
			case CMD_READ_PROCESS_MEMORY:
				tmp = (ULONG*)&cmd->param[0];
				processID = *tmp;
				baseAddress = *(++tmp);
				destAddress = *(++tmp);
				size = *(++tmp);
				OutputBuffer = (UCHAR *)Irp->AssociatedIrp.SystemBuffer;
				Irp->IoStatus.Information = outBufLength;
				YasiReadProcessMemory(processID, baseAddress, destAddress, size, &bytesProcessed);
				if( outBufLength != 0 )
					*((ULONG*)OutputBuffer) = bytesProcessed;
				break;
			case CMD_WRITE_PROCESS_MEMORY:
				tmp = (ULONG*)&cmd->param[0];
				processID = *tmp;
				baseAddress = *(++tmp);
				destAddress = *(++tmp);
				size = *(++tmp);
				OutputBuffer = (UCHAR *)Irp->AssociatedIrp.SystemBuffer;
				Irp->IoStatus.Information = outBufLength;
				YasiWriteProcessMemory(processID, baseAddress, destAddress, size, &bytesProcessed);
				if( outBufLength != 0 )
					*((ULONG*)OutputBuffer) = bytesProcessed;
				break;
			default:
				Status = STATUS_ACCESS_DENIED;
				break;
		}

		/*
		 if( strcmp(InputBuffer, CMD_GETPROCESSES) == 0 ){

		 	OutputBuffer = (UCHAR *)Irp->AssociatedIrp.SystemBuffer;
	        memset(OutputBuffer, 0, outBufLength);
	        Irp->IoStatus.Information = outBufLength;
			DbgPrint("[ring0] output length %d", outBufLength);
			EnumProcessList((struct PROCESS_RECORD *) OutputBuffer);
		 }
		 */

    } 
    else
    {
        Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;

    }    
    // Íê³ÉIRP
    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;


}



/**********************************************************************
 * 
 *  KernelProtect_Read
 *
 *    This is called when a read is issued on the device handle (ReadFile/ReadFileEx)
 *
 **********************************************************************/
NTSTATUS KernelProtect_Read(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    
 
    NTSTATUS NtStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION pIoStackIrp = NULL;
    PCHAR pOutputBuffer;
	PCHAR pInputBuffer;
    int tmp = 0;

    DbgPrint("KernelProtect_Read Called address = %x \r\n", &tmp);
	DbgPrint("KeServiceDescriptorTable is %d", KeServiceDescriptorTable);

    /*
     * Each time the IRP is passed down the driver stack a new stack location is added
     * specifying certain parameters for the IRP to the driver.
     */
    pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
    
    if(!pIoStackIrp)
		return 0;


	__try {
		//ProbeForRead(Irp->UserBuffer, pIoStackIrp->Parameters.Write.Length, TYPE_ALIGNMENT(char));
		//
		//pInputBuffer = Irp->UserBuffer;     
		//ProbeForWrite(Irp->IoctlType3InputBuffer, pIoStackIrp->Parameters.Read.Length, TYPE_ALIGNMENT(char));
		//pOutputBuffer = Irp->IoctlType3InputBuffer;
		//if(!pInputBuffer){
		//	DbgPrint("[ring0] pInputBuffer is zero");
		//	return 0;
		//}
		//if( !pOutputBuffer ){
		//	DbgPrint("[ring0] pOutputBuffer is zero");
		//	return 0;
		//}

		//DbgPrint("[ring0]input buffer is" );
		
		//if( strcmp(pInputBuffer, CMD_GETPROCESSES) == 0 ){
		//	DbgPrint("[ring0] get process");
		//	//HookAPI();

		//}


	} __except( EXCEPTION_EXECUTE_HANDLER ) {
		NtStatus = GetExceptionCode();     
	}

    return NtStatus;
}



/**********************************************************************
 * 
 *  KernelProtect_WriteDirectIO
 *
 *    This is called when a write is issued on the device handle (WriteFile/WriteFileEx)
 *
 *    This version uses Direct I/O
 *
 **********************************************************************/
NTSTATUS KernelProtect_WriteDirectIO(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION pIoStackIrp = NULL;
    PCHAR pWriteDataBuffer;

    DbgPrint("KernelProtect_WriteDirectIO Called \r\n");
    
    /*
     * Each time the IRP is passed down the driver stack a new stack location is added
     * specifying certain parameters for the IRP to the driver.
     */
    pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
    
    if(pIoStackIrp)
    {
        pWriteDataBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    
        if(pWriteDataBuffer)
        {                             
            /*
             * We need to verify that the string is NULL terminated. Bad things can happen
             * if we access memory not valid while in the Kernel.
             */
           if(KernelProtect_IsStringTerminated(pWriteDataBuffer, pIoStackIrp->Parameters.Write.Length))
           {
                DbgPrint(pWriteDataBuffer);
           }
        }
    }

    return NtStatus;
}

/**********************************************************************
 * 
 *  KernelProtect_WriteBufferedIO
 *
 *    This is called when a write is issued on the device handle (WriteFile/WriteFileEx)
 *
 *    This version uses Buffered I/O
 *
 **********************************************************************/
NTSTATUS KernelProtect_WriteBufferedIO(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION pIoStackIrp = NULL;
    PCHAR pWriteDataBuffer;

    DbgPrint("KernelProtect_WriteBufferedIO Called \r\n");
    
    /*
     * Each time the IRP is passed down the driver stack a new stack location is added
     * specifying certain parameters for the IRP to the driver.
     */
    pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
    
    if(pIoStackIrp)
    {
        pWriteDataBuffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
    
        if(pWriteDataBuffer)
        {                             
            /*
             * We need to verify that the string is NULL terminated. Bad things can happen
             * if we access memory not valid while in the Kernel.
             */
           if(KernelProtect_IsStringTerminated(pWriteDataBuffer, pIoStackIrp->Parameters.Write.Length))
           {
                DbgPrint(pWriteDataBuffer);
           }
        }
    }

    return NtStatus;
}

/**********************************************************************
 * 
 *  KernelProtect_WriteNeither
 *
 *    This is called when a write is issued on the device handle (WriteFile/WriteFileEx)
 *
 *    This version uses Neither buffered or direct I/O.  User mode memory is
 *    read directly.
 *
 **********************************************************************/
NTSTATUS KernelProtect_WriteNeither(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS NtStatus = STATUS_SUCCESS;
    PIO_STACK_LOCATION pIoStackIrp = NULL;
    PCHAR pWriteDataBuffer;
    int tmp = 0;

    DbgPrint("KernelProtect_WriteNeither Called address = %x \r\n", &tmp);
	DbgPrint("KeServiceDescriptorTable is %d", KeServiceDescriptorTable);

    /*
     * Each time the IRP is passed down the driver stack a new stack location is added
     * specifying certain parameters for the IRP to the driver.
     */
    pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
    
    if(!pIoStackIrp)
		return 0;


	__try {
		ProbeForRead(Irp->UserBuffer, pIoStackIrp->Parameters.Write.Length, TYPE_ALIGNMENT(char));
		pWriteDataBuffer = Irp->UserBuffer;      
		if(!pWriteDataBuffer)
			return 0;
		DbgPrint("[ring0] %s", pWriteDataBuffer);



	} __except( EXCEPTION_EXECUTE_HANDLER ) {
		NtStatus = GetExceptionCode();     
	}

    return NtStatus;
}
                       

/**********************************************************************
 * 
 *  KernelProtect_UnSupportedFunction
 *
 *    This is called when a major function is issued that isn't supported.
 *
 **********************************************************************/
NTSTATUS KernelProtect_UnSupportedFunction(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS NtStatus = STATUS_NOT_SUPPORTED;
    DbgPrint("KernelProtect_UnSupportedFunction Called \r\n");

    return NtStatus;
}


/**********************************************************************
 * 
 *  KernelProtect_IsStringTerminated
 *
 *    Simple function to determine a string is NULL terminated.
 *
 **** We could validate also the characters in the string are printable! ***
 *
 **********************************************************************/
BOOLEAN KernelProtect_IsStringTerminated(PCHAR pString, UINT uiLength)
{
    BOOLEAN bStringIsTerminated = FALSE;
    UINT uiIndex = 0;

    while(uiIndex < uiLength && bStringIsTerminated == FALSE)
    {
        if(pString[uiIndex] == '\0')
        {
            bStringIsTerminated = TRUE;
        }
        else
        {
           uiIndex++;
        }
    }

    return bStringIsTerminated;
}



VOID HookAPI()
{
	RealZwSetInformationFile = SYSCALL(ZwSetInformationFile);
	__asm
	{
		cli
			mov eax,cr0
			and eax,not 10000h
			mov cr0,eax
	}
	SYSCALL(ZwSetInformationFile) = (PVOID)HookZwSetInformationFile;
	__asm
	{
		mov eax,cr0
			or eax,10000h
			mov cr0,eax
			sti
	}
	return;
}


NTSTATUS HookZwSetInformationFile(IN HANDLE FileHandle,
								  OUT PIO_STATUS_BLOCK IoStatusBlock,
								  IN PVOID FileInformation,
								  IN ULONG Length,
								  IN FILE_INFORMATION_CLASS FileInformationClass)
{
	PFILE_OBJECT pFileObject;
	UNICODE_STRING uDosName;

	NTSTATUS nRet= ObReferenceObjectByHandle(FileHandle, GENERIC_READ, 
		*IoFileObjectType, KernelMode, (PVOID*)&pFileObject, 0);
	DbgPrint("[hook] ObReferenceObjectByHandle ret is %d", nRet);
 
	if(NT_SUCCESS(nRet))
	{
		nRet = RtlVolumeDeviceToDosName(pFileObject->DeviceObject, &uDosName);
		DbgPrint("[hook] RtlVolumeDeviceToDosName ret is %d", nRet);
		if (NT_SUCCESS(nRet))
		{
			if (!_wcsicmp(pFileObject->FileName.Buffer, L"\\test.txt") &&
				!_wcsicmp(uDosName.Buffer, L"D:"))
			{
				ExFreePool(uDosName.Buffer);
				return STATUS_ACCESS_DENIED;
			}
			ExFreePool(uDosName.Buffer);
		}
	}
	return RealZwSetInformationFile(FileHandle, IoStatusBlock, FileInformation, 
		Length, FileInformationClass);
}



VOID UnHook()
{
	__asm
	{
		cli
			mov eax,cr0
			and eax,not 10000h
			mov cr0,eax
	}
	UnhookSystemCall();
	__asm
	{
		mov eax,cr0
			or eax,10000h
			mov cr0,eax
			sti
	}
}

VOID UnhookSystemCall()
{
	SYSCALL(ZwSetInformationFile) = (PVOID)RealZwSetInformationFile;

	return;
}
