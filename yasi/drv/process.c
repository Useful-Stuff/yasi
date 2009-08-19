#define _X86_ 
#include <Ntifs.h>
#include <ntddk.h>

#include "KernelProtect.h"


ULONG
GetPlantformDependentInfo(
    ULONG dwFlag
)  
{   
#ifdef XP_SP3
	ULONG current_build = 2600;   
#else
	ULONG current_build = 0;  
#endif
    ULONG ans = 0;   
   
    //PsGetVersion(NULL, NULL, &current_build, NULL);   
   
    switch ( dwFlag )  
    {   
    case EPROCESS_SIZE:   
        if (current_build == 2195) ans = 0 ;        // 2000����ǰ��֧��2000����ͬ  
        if (current_build == 2600) ans = 0x25C;     // xp  
        if (current_build == 3790) ans = 0x270;     // 2003  
        break;   
    case PEB_OFFSET:   
        if (current_build == 2195)  ans = 0;   
        if (current_build == 2600)  ans = 0x1b0;   
        if (current_build == 3790)  ans = 0x1a0;  
        break;   
    case FILE_NAME_OFFSET:   
        if (current_build == 2195)  ans = 0;   
        if (current_build == 2600)  ans = 0x174;   
        if (current_build == 3790)  ans = 0x164;  
        break;   
    case PROCESS_LINK_OFFSET:   
        if (current_build == 2195)  ans = 0;   
        if (current_build == 2600)  ans = 0x088;   
        if (current_build == 3790)  ans = 0x098;  
        break;   
    case PROCESS_ID_OFFSET:   
        if (current_build == 2195)  ans = 0;   
        if (current_build == 2600)  ans = 0x084;   
        if (current_build == 3790)  ans = 0x094;  
        break;   
    case EXIT_TIME_OFFSET:   
        if (current_build == 2195)  ans = 0;   
        if (current_build == 2600)  ans = 0x078;   
        if (current_build == 3790)  ans = 0x088;  
        break;   
	case ProcessParameters_OFFSET:
		if (current_build == 2600)  ans = 0x10; 
		break;
	case CSDVersion_OFFSET:
		if (current_build == 2600)  ans = 0x1f0;  
		break;
	case DllPath_OFFSET:
		if (current_build == 2600)  ans = 0x30;  
		break;
	case ImagePathName_OFFSET:
		if (current_build == 2600)  ans = 0x38;  
		break;
	case CommandLine_OFFSET:
		if (current_build == 2600)  ans = 0x40;  
		break;
	case WindowTitle_OFFSET:
		if (current_build == 2600)  ans = 0x70;  
		break;
	case DesktopInfo_OFFSET:
		if (current_build == 2600)  ans = 0x78;  
		break;
	case ShellInfo_OFFSET:
		if (current_build == 2600)  ans = 0x80;  
		break;
	case RuntimeData_OFFSET:
		if (current_build == 2600)  ans = 0x88;  
		break;
	case CurrentDirectore_OFFSET:
		if (current_build == 2600)  ans = 0x90;  
		break;
	case PorcessThreadListEntry_OFFSET:
		if( current_build == 2600) ans = 0x1b0;
		break;
	case ThreadExitStatus_OFFSET:
		if( current_build == 2600 ) ans = 0x1d0;
		break;
    }   
    return ans;   
}

ULONG GetProcessCount()
{

	struct PROCESS_RECORD	*ProcessInfo;
    ULONG            EProcess;
    ULONG            FirstProcess;
    ULONG            dwCount = 0;
    LIST_ENTRY*        ActiveProcessLinks;

    ULONG    dwPIdOffset = GetPlantformDependentInfo(PROCESS_ID_OFFSET);
    ULONG    dwPNameOffset = GetPlantformDependentInfo(FILE_NAME_OFFSET);
    ULONG    dwPLinkOffset = GetPlantformDependentInfo(PROCESS_LINK_OFFSET);
   
    // ��ȡ��ǰ���̵ĵ�ַ
    FirstProcess = EProcess = (ULONG)PsGetCurrentProcess();
    do
    {
        dwCount++;
        //DbgPrint("[ring0] [Pid=%6d] %s\n", *((ULONG *)(EProcess + dwPIdOffset)), (PUCHAR)(EProcess + dwPNameOffset));
        ActiveProcessLinks = (LIST_ENTRY *)(EProcess + dwPLinkOffset);
        EProcess = (ULONG)ActiveProcessLinks->Flink - dwPLinkOffset;
        if (EProcess == FirstProcess)
        {
            break;
        }
    }while (EProcess != 0);

    return dwCount;

}


void EnumProcessList(ULONG index, struct PROCESS_RECORD* processes)
{
    ULONG            EProcess;
    ULONG            FirstProcess;
    ULONG            dwCount = 0;
    LIST_ENTRY*        ActiveProcessLinks;

    ULONG    dwPIdOffset = GetPlantformDependentInfo(PROCESS_ID_OFFSET);
    ULONG    dwPNameOffset = GetPlantformDependentInfo(FILE_NAME_OFFSET);
    ULONG    dwPLinkOffset = GetPlantformDependentInfo(PROCESS_LINK_OFFSET);
	ULONG	ProcessCount = 0;
	BOOL	found = TRUE;

	memset(processes, 0, sizeof(struct PROCESS_RECORD));

	
   
    // ��ȡ��ǰ���̵ĵ�ַ
    FirstProcess = EProcess = (ULONG)PsGetCurrentProcess();

	while( dwCount < index ){
		dwCount++;
        ActiveProcessLinks = (LIST_ENTRY *)(EProcess + dwPLinkOffset);
        EProcess = (ULONG)ActiveProcessLinks->Flink - dwPLinkOffset;
        if (EProcess == FirstProcess)
        {
        	found = FALSE;
            break;
        }
	}

	if( found ){
		processes->processID = *((ULONG *)(EProcess + dwPIdOffset));
        memcpy(processes->imageName, (PUCHAR)(EProcess + dwPNameOffset), 16);
	}
}

BOOL FindProcessByID(ULONG id, ULONG* pProcess)
{
	ULONG			tmpID;
    ULONG            EProcess;
    ULONG            FirstProcess;
    ULONG            dwCount = 0;
    LIST_ENTRY*        ActiveProcessLinks;

    ULONG    dwPIdOffset = GetPlantformDependentInfo(PROCESS_ID_OFFSET);
    ULONG    dwPNameOffset = GetPlantformDependentInfo(FILE_NAME_OFFSET);
    ULONG    dwPLinkOffset = GetPlantformDependentInfo(PROCESS_LINK_OFFSET);
   
    FirstProcess = EProcess = (ULONG)PsGetCurrentProcess();
    do
    {
    	tmpID = *((ULONG *)(EProcess + dwPIdOffset));
		if( id == tmpID ){
			*pProcess = EProcess;
			return TRUE;
		}
        dwCount++;
        ActiveProcessLinks = (LIST_ENTRY *)(EProcess + dwPLinkOffset);
        EProcess = (ULONG)ActiveProcessLinks->Flink - dwPLinkOffset;
        if (EProcess == FirstProcess)
        {
            break;
        }
    }while (EProcess != 0);

    return FALSE;
}





void GetProcessDetail(ULONG id, struct PROCESS_DETAIL* detail)
{
	BOOL 			found;
	ULONG           EProcess;
	PEPROCESS_XP_SP3	EProcess_sp3;
	UNICODE_STRING*		fullName;
	UINT			nameLen;
	if( !detail ) return;
	EProcess = 0;
	found = FALSE;
	found = FindProcessByID(id, &EProcess);
	if( found ){
		//DbgPrint("[ring0] found process");
		EProcess_sp3 = (PEPROCESS_XP_SP3)EProcess;
		memcpy(&(detail->process), EProcess_sp3, sizeof(EPROCESS_XP_SP3));
		fullName = (struct UNICODE_STRING*)EProcess_sp3->SeAuditProcessCreationInfo;
		if( fullName->Length > 127 )
			nameLen = 127;
		else
			nameLen = fullName->Length;
		memcpy(&(detail->fullName[0]), fullName->Buffer, nameLen);
	}
	


}


BOOLEAN _stdcall
KeInsertQueueApc (PKAPC	Apc,
				  PVOID	SystemArgument1,
				  PVOID	SystemArgument2,
				  KPRIORITY PriorityBoost);

VOID _stdcall
KeInitializeApc(
				IN PKAPC  Apc,
				IN PKTHREAD  Thread,
				IN char  TargetEnvironment,
				IN PKKERNEL_ROUTINE  KernelRoutine,
				IN PKRUNDOWN_ROUTINE  RundownRoutine OPTIONAL,
				IN PKNORMAL_ROUTINE  NormalRoutine,
				IN KPROCESSOR_MODE  Mode,
				IN PVOID  Context);

ULONG _stdcall
KeForceResumeThread(PKTHREAD Thread);


NTSTATUS PspTerminateThreadByPointer(PETHREAD Thread, NTSTATUS status);
typedef VOID (*MyPspExitThread)(NTSTATUS status);


ULONG GetPspTerminateThreadByPointer()
{
	char * PsTerminateSystemThreadAddr;
	int iLen;
	ULONG dwAddr;
	ULONG NtTerminateThreadAddr;
	char * pAddr;

			PsTerminateSystemThreadAddr= (char *)PsTerminateSystemThread;
			__asm
			{
					__emit 0x90;
					__emit 0x90;
			}
			for (iLen=0;iLen<50;iLen++)
			{
					if (*PsTerminateSystemThreadAddr == (char)0xff
						&& *(PsTerminateSystemThreadAddr+1) == (char)0x75
						&& *(PsTerminateSystemThreadAddr+2) == (char)0x08
						)
					{
							__asm
							{
									__emit 0x90;
									__emit 0x90;
							}
							PsTerminateSystemThreadAddr += 5;
							dwAddr = *(ULONG *)PsTerminateSystemThreadAddr + (ULONG)PsTerminateSystemThreadAddr +4;

							//DbgPrint("[ring0] PspTerminateThreadByPointer:: 0x%x ",dwAddr);
							return dwAddr;
							//break;
					}
					PsTerminateSystemThreadAddr++;
			}
	return FALSE;
}


PVOID GetPspExitThread()

{
#ifdef XP_SP3
	char* sPtr;
	ULONG end = (ULONG)GetPspTerminateThreadByPointer() + 0x60;
	sPtr = (char*)GetPspTerminateThreadByPointer();
	while ( (ULONG)sPtr <  end) //0x60 = ������ PspTerminateThreadByPointer ���̶ֳ�
	{
		//DbgPrint("[ring0] addr: 0x%x, val: 0x%x", sPtr, *(WORD*)sPtr);
		if ( *(WORD*)sPtr == 3189 )
		{
			return (PVOID)(*(ULONG*)(sPtr + 3) + sPtr + 7);        
		}
		sPtr ++;
	}
	return NULL;
#else
	return NULL;
#endif

}


VOID _stdcall
PiTerminateThreadRundownRoutine(PKAPC Apc)
{
	ExFreePool(Apc);
}

VOID _stdcall
PiTerminateThreadKernelRoutine(PKAPC Apc,
							   PKNORMAL_ROUTINE* NormalRoutine,
							   PVOID* NormalContext,
							   PVOID* SystemArgument1,
							   PVOID* SystemArguemnt2)
{
#ifdef XP_SP3
	PETHREAD_XP_SP3 current;
	MyPspExitThread myExitThread = (MyPspExitThread)GetPspExitThread();
	ExFreePool(Apc);
	//DbgPrint("[ring0] myExitThread is 0x%x", myExitThread);
	current = (PETHREAD_XP_SP3)PsGetCurrentThread();
	//��ɱ360
	if( myExitThread )
		myExitThread(STATUS_SUCCESS);
#else
#endif
}

VOID _stdcall
PiTerminateThreadNormalRoutine(PVOID NormalContext,
							   PVOID SystemArgument1,
							   PVOID SystemArgument2)
{
	//ExFreePool(Apc);
}

void TerminateThreadByPointer(PKTHREAD tcb)
{
	PKAPC			Apc;
	Apc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 1001);
	KeInitializeApc(Apc, (PKTHREAD)tcb,
		0, 
		PiTerminateThreadKernelRoutine,
		NULL,
		NULL,
		KernelMode, NULL
		);
	//�˴�������,������current��ò���
	KeInsertQueueApc(Apc, NULL, NULL, IO_NO_INCREMENT);
}


void KillProcessByAPC(ULONG id)
{
	KSPIN_LOCK		PiThreadListLock;
	PKAPC			Apc;
	BOOL 			found;
	ULONG           EProcess;
	KIRQL			oldLvl;
	PLIST_ENTRY		current_entry;
	
#ifdef XP_SP3
	PETHREAD_XP_SP3		current;
	PEPROCESS_XP_SP3 Process;
#else
	PEPROCESS		Process;
#endif
	EProcess = 0;
	found = FALSE;
	found = FindProcessByID(id, &EProcess);
	if( found ){
#ifdef XP_SP3
		Process = (PEPROCESS_XP_SP3 )EProcess;
		KeInitializeSpinLock(&PiThreadListLock);
		Process->ExitStatus = STATUS_SUCCESS;
		KeAcquireSpinLock(&PiThreadListLock, &oldLvl);
		current_entry = Process->ThreadListHead.Flink;
		while( current_entry != &Process->ThreadListHead ){
			current = CONTAINING_RECORD(current_entry, ETHREAD_XP_SP3, ThreadListEntry);
			//current = (PETHREAD_XP_SP3)((ULONG)current_entry - GetPlantformDependentInfo(PorcessThreadListEntry_OFFSET));
			if( current != PsGetCurrentThread() ){
				KeReleaseSpinLock(&PiThreadListLock, oldLvl);
				current->u2.ExitStatus = STATUS_SUCCESS;
				//*((ULONG*)((ULONG)current+GetPlantformDependentInfo(ThreadExitStatus_OFFSET))) = STATUS_SUCCESS;
				TerminateThreadByPointer((PKTHREAD)&current->Tcb);
				KeAcquireSpinLock(&PiThreadListLock, &oldLvl);
				//KeForceResumeThread((PKTHREAD)&current->Tcb);
				current_entry =  current_entry->Flink;
			}else{
				current_entry = current_entry->Flink;
			}
		}
		KeReleaseSpinLock(&PiThreadListLock, oldLvl);
#else
#endif
	}
}

void KillThread(ULONG pid, ULONG tid)
{
	KSPIN_LOCK		PiThreadListLock;
	PKAPC			Apc;
	BOOL 			found;
	ULONG           EProcess;
	KIRQL			oldLvl;
	PLIST_ENTRY		current_entry;

#ifdef XP_SP3
	PETHREAD_XP_SP3		current;
	PEPROCESS_XP_SP3	Process;
#else
	PEPROCESS		Process;
#endif
	EProcess = 0;
	found = FALSE;
	found = FindProcessByID(pid, &EProcess);
	if( found ){
#ifdef XP_SP3
		Process = (PEPROCESS_XP_SP3 )EProcess;
		KeInitializeSpinLock(&PiThreadListLock);
		KeAcquireSpinLock(&PiThreadListLock, &oldLvl);
		current_entry = Process->ThreadListHead.Flink;
		while( current_entry != &Process->ThreadListHead ){
			current = CONTAINING_RECORD(current_entry, ETHREAD_XP_SP3, ThreadListEntry);
			//current = (PETHREAD_XP_SP3)((ULONG)current_entry - GetPlantformDependentInfo(PorcessThreadListEntry_OFFSET));
			if( current != PsGetCurrentThread() && (ULONG)current->Cid.UniqueThread == tid){
				KeReleaseSpinLock(&PiThreadListLock, oldLvl);
				current->u2.ExitStatus = STATUS_SUCCESS;
				TerminateThreadByPointer((PKTHREAD)&current->Tcb);
				break;
			}else{
				current_entry = current_entry->Flink;
			}
		}
		KeReleaseSpinLock(&PiThreadListLock, oldLvl);
#else
#endif
	}
}

void KillProcess(ULONG id)
{

	BOOL 			found;
	ULONG           EProcess;
	PVOID                ProcessHandle;

	return KillProcessByAPC(id);

	EProcess = 0;
	found = FALSE;
	found = FindProcessByID(id, &EProcess);
	if( found ){

		if ( ObOpenObjectByPointer( (PVOID)EProcess, 0, NULL, 0, NULL, KernelMode, &ProcessHandle) != STATUS_SUCCESS)
			return;
		ZwTerminateProcess( (HANDLE)ProcessHandle, STATUS_SUCCESS);
		ZwClose( (HANDLE)ProcessHandle );
	}
}


void GetProcessString(ULONG id,  ULONG* pebAddress)
{
	BOOL 			found;
	ULONG           EProcess;
	EProcess = 0;
	found = FALSE;
	found = FindProcessByID(id, &EProcess);
	if( found ){
		//DbgPrint("[ring0] process %d found! EPROCESS is 0x%x", id, EProcess);
		*pebAddress = *((ULONG*)(EProcess+GetPlantformDependentInfo(PEB_OFFSET)));
		
	}else{
		//DbgPrint("[ring0] do not found %d", id);
		*pebAddress = 0;
	}

	//DbgPrint("[ring0] pebAddress %d", *pebAddress);
}

//��������뿴 http://www.cnblogs.com/gussing/archive/2009/07/01/1514925.html
BOOL YasiReadProcessMemory(ULONG id, PVOID BaseAddress, PVOID Buffer, ULONG size, ULONG* bytesRead)
{
	ULONG           EProcess;
	BOOL			found;
	PMDL			mdl;
	PVOID			SystemAddress;
	found = FindProcessByID(id, &EProcess);
	if( !found ) return FALSE;
	if( BaseAddress == NULL || size == 0 ) return FALSE;
	mdl = MmCreateMdl(NULL, Buffer, size);
	MmProbeAndLockPages(mdl, UserMode, IoWriteAccess);
	KeAttachProcess((PEPROCESS)EProcess);
	SystemAddress = MmGetSystemAddressForMdl(mdl);
	if( MmIsAddressValid(BaseAddress) && MmIsAddressValid((char*)BaseAddress+size-1) ) 
		memcpy(SystemAddress, BaseAddress, size);
	KeDetachProcess((PEPROCESS)EProcess);

	if( mdl->MappedSystemVa != NULL ){
		MmUnmapLockedPages(mdl->MappedSystemVa, mdl);
	}
	MmUnlockPages(mdl);
	ExFreePool(mdl);
	*bytesRead = size;
	return TRUE;
}
BOOL YasiWriteProcessMemory(ULONG id, PVOID BaseAddress,PVOID Buffer, ULONG size, ULONG * bytesRead)
{
	ULONG           EProcess;
	BOOL			found;
	PMDL			mdl;
	PVOID			SystemAddress;
	ULONG			CR0VALUE;
	KIRQL			Irql;

	found = FindProcessByID(id, &EProcess);
	if( !found ) return FALSE;
	if( BaseAddress == NULL || size == 0 ) return FALSE;

	mdl = MmCreateMdl(NULL, Buffer, size);
	MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
	KeAttachProcess((PEPROCESS)EProcess);
	SystemAddress = MmGetSystemAddressForMdl(mdl);
	if( MmIsAddressValid(BaseAddress) && MmIsAddressValid((char*)BaseAddress+size-1) ) {
		//�ر��ڴ�д����
		_asm
		{
			push eax
			mov eax, cr0
			mov CR0VALUE, eax
			and eax, 0fffeffffh
			mov cr0, eax
			pop eax
		}
		Irql=KeRaiseIrqlToDpcLevel();
		//DbgPrint("[ring0] BaseAddress 0x%x, SystemAddress 0x%x",BaseAddress,SystemAddress);
		memcpy(BaseAddress, SystemAddress, size);
		//�ָ�Irql
		KeLowerIrql(Irql);
		//�����ڴ�д����
		__asm
		{      
			push eax
			mov eax, CR0VALUE
			mov cr0, eax
			pop eax
		}

	}
	KeDetachProcess((PEPROCESS)EProcess);

	if( mdl->MappedSystemVa != NULL ){
		MmUnmapLockedPages(mdl->MappedSystemVa, mdl);
	}
	MmUnlockPages(mdl);
	ExFreePool(mdl);
	*bytesRead = size;
	return TRUE;
}

BOOL GetThreadDetail(ULONG id, ULONG thread_idx, struct THREAD_DETAIL* detail)
{
	BOOL 			found;
	ULONG           EProcess;
	struct EPROCESS_WAPPER* pEprocess;
	LIST_ENTRY		threadHeader;
	LIST_ENTRY*		currentThread;
	ULONG			count = 0;
	struct ETHREAD_WAPPER*	pEThread;
	EProcess = 0;
	found = FALSE;
	//DbgPrint("[ring0] id is %d, index is %d", id, thread_idx);
	found = FindProcessByID(id, &EProcess);
	if( found ){
		//DbgPrint("[ring0] found process, EProcess is 0x%x!", EProcess);
		pEprocess = (struct ETHREAD_WAPPER*)EProcess;
		threadHeader = pEprocess->process.ThreadListHead;
		currentThread = threadHeader.Flink;
		if( currentThread == &threadHeader )
			return FALSE;
		while( count < thread_idx )
		{
			currentThread = currentThread->Flink;
			count++;
			if( currentThread == &threadHeader )
				return FALSE;
		}

		//DbgPrint("[ring0] found thread, current thread address 0x%x!", currentThread);
		pEThread = (struct ETHREAD_WAPPER*)CONTAINING_RECORD(currentThread, ETHREAD_XP_SP3, ThreadListEntry);
		memcpy(&detail->thread, &pEThread->thread, sizeof(struct ETHREAD_WAPPER));
	}
	return TRUE;
}