// KernelPortect.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include "KernelProtect.h"
#include <stdlib.h>

#include "../yasi.h"
// {D91E1EB2-97C0-4459-B30A-731543F407C6}
TCHAR NAME[] = _T("{D91E1EB2-97C0-4459-B30A-731543F407C6}");
#define INDEXOF(type, field) ( (UINT)(&(((type*)0)->field)) )
#define PRINT_INFO(type, field) {printf("%s->%s : 0x%x\r\n", #type, #field, INDEXOF(type, field));}
HANDLE LoadDriver();
void UnloadDriver(HANDLE file);
int _tmain(int argc, _TCHAR* argv[])
{

	/*
	PRINT_INFO(EPROCESS_XP_SP3,  Pcb);
	PRINT_INFO(EPROCESS_XP_SP3,  ProcessLock);
	PRINT_INFO(EPROCESS_XP_SP3,  CreateTime);
	PRINT_INFO(EPROCESS_XP_SP3,  ExitTime);
	PRINT_INFO(EPROCESS_XP_SP3,  RundownProtect);
	PRINT_INFO(EPROCESS_XP_SP3,  UniqueProcessId);
	PRINT_INFO(EPROCESS_XP_SP3,  ActiveProcessLinks);
	PRINT_INFO(EPROCESS_XP_SP3,  QuotaUsage);
	PRINT_INFO(EPROCESS_XP_SP3,  QuotaPeak);
	PRINT_INFO(EPROCESS_XP_SP3,  CommitCharge);
	PRINT_INFO(EPROCESS_XP_SP3,  PeakVirtualSize);
	PRINT_INFO(EPROCESS_XP_SP3,  VirtualSize);
	PRINT_INFO(EPROCESS_XP_SP3,  SessionProcessLinks);
	PRINT_INFO(EPROCESS_XP_SP3,  DebugPort);
	PRINT_INFO(EPROCESS_XP_SP3,  ExceptionPort);
	PRINT_INFO(EPROCESS_XP_SP3,  ObjectTable);
	PRINT_INFO(EPROCESS_XP_SP3,  Token);
	PRINT_INFO(EPROCESS_XP_SP3,  WorkingSetLock);
	PRINT_INFO(EPROCESS_XP_SP3,  WorkingSetPage);
	PRINT_INFO(EPROCESS_XP_SP3,  AddressCreationLock);
	PRINT_INFO(EPROCESS_XP_SP3,  HyperSpaceLock);
	PRINT_INFO(EPROCESS_XP_SP3,  ForkInProgress);
	PRINT_INFO(EPROCESS_XP_SP3,  HardwareTrigger);
	PRINT_INFO(EPROCESS_XP_SP3,  VadRoot);
	PRINT_INFO(EPROCESS_XP_SP3,  VadHint);
	PRINT_INFO(EPROCESS_XP_SP3,  CloneRoot);
	PRINT_INFO(EPROCESS_XP_SP3,  NumberOfPrivatePages);
	PRINT_INFO(EPROCESS_XP_SP3,  NumberOfLockedPages);
	PRINT_INFO(EPROCESS_XP_SP3,  Win32Process);
	PRINT_INFO(EPROCESS_XP_SP3,  Job);
	PRINT_INFO(EPROCESS_XP_SP3,  SectionObject);
	PRINT_INFO(EPROCESS_XP_SP3,  SectionBaseAddress);
	PRINT_INFO(EPROCESS_XP_SP3,  QuotaBlock);
	PRINT_INFO(EPROCESS_XP_SP3,  WorkingSetWatch);
	PRINT_INFO(EPROCESS_XP_SP3,  Win32WindowStation);
	PRINT_INFO(EPROCESS_XP_SP3, InheritedFromUniqueProcessId);
	PRINT_INFO(EPROCESS_XP_SP3,  LdtInformation);
	PRINT_INFO(EPROCESS_XP_SP3,  VadFreeHint);
	PRINT_INFO(EPROCESS_XP_SP3,  VdmObjects);
	PRINT_INFO(EPROCESS_XP_SP3,  DeviceMap);
	PRINT_INFO(EPROCESS_XP_SP3,  PhysicalVadList);
	PRINT_INFO(EPROCESS_XP_SP3,  PageDirectoryPte);
	PRINT_INFO(EPROCESS_XP_SP3,  Session);
	PRINT_INFO(EPROCESS_XP_SP3,  ImageFileName);
	PRINT_INFO(EPROCESS_XP_SP3,  JobLinks);
	PRINT_INFO(EPROCESS_XP_SP3,  LockedPagesList);
	PRINT_INFO(EPROCESS_XP_SP3,  ThreadListHead);
	PRINT_INFO(EPROCESS_XP_SP3,  SecurityPort);
	PRINT_INFO(EPROCESS_XP_SP3,  PaeTop);
	PRINT_INFO(EPROCESS_XP_SP3,  ActiveThreads);
	PRINT_INFO(EPROCESS_XP_SP3,  GrantedAccess);
	PRINT_INFO(EPROCESS_XP_SP3,  DefaultHardErrorProcessing);
	PRINT_INFO(EPROCESS_XP_SP3,  LastThreadExitStatus);
	PRINT_INFO(EPROCESS_XP_SP3,  Peb);
	PRINT_INFO(EPROCESS_XP_SP3,  PrefetchTrace);
	PRINT_INFO(EPROCESS_XP_SP3,  ReadOperationCount);
	PRINT_INFO(EPROCESS_XP_SP3,  WriteOperationCount);
	PRINT_INFO(EPROCESS_XP_SP3,  OtherOperationCount);
	PRINT_INFO(EPROCESS_XP_SP3,  ReadTransferCount);
	PRINT_INFO(EPROCESS_XP_SP3,  WriteTransferCount);
	PRINT_INFO(EPROCESS_XP_SP3,  OtherTransferCount);
	PRINT_INFO(EPROCESS_XP_SP3,  CommitChargeLimit);
	PRINT_INFO(EPROCESS_XP_SP3,  CommitChargePeak);
	PRINT_INFO(EPROCESS_XP_SP3,  AweInfo);
	PRINT_INFO(EPROCESS_XP_SP3,  SeAuditProcessCreationInfo);
	PRINT_INFO(EPROCESS_XP_SP3,  Vm);
	PRINT_INFO(EPROCESS_XP_SP3,  LastFaultCount);
	PRINT_INFO(EPROCESS_XP_SP3,  ModifiedPageCount);
	PRINT_INFO(EPROCESS_XP_SP3,  NumberOfVads);
	PRINT_INFO(EPROCESS_XP_SP3,  JobStatus);
	PRINT_INFO(EPROCESS_XP_SP3,  Flags);
	PRINT_INFO(EPROCESS_XP_SP3,  ExitStatus);
	PRINT_INFO(EPROCESS_XP_SP3,  NextPageColor);
	PRINT_INFO(EPROCESS_XP_SP3,  SubSystemVersion);
	PRINT_INFO(EPROCESS_XP_SP3,  PriorityClass);
	PRINT_INFO(EPROCESS_XP_SP3,  WorkingSetAcquiredUnsafe);
	PRINT_INFO(EPROCESS_XP_SP3,  Cookie);

	printf("----------------\r\n");

	PRINT_INFO(DISPATCHER_HEADER_XP_SP3, Type);
	PRINT_INFO(DISPATCHER_HEADER_XP_SP3, Absolute);
	PRINT_INFO(DISPATCHER_HEADER_XP_SP3, Size);
	PRINT_INFO(DISPATCHER_HEADER_XP_SP3, Inserted);
	PRINT_INFO(DISPATCHER_HEADER_XP_SP3, SignalState);
	PRINT_INFO(DISPATCHER_HEADER_XP_SP3, WaitListHead);

	printf("-----------------\r\n");

	PRINT_INFO(KPROCESS_XP_SP3, Header);
	PRINT_INFO(KPROCESS_XP_SP3, ProfileListHead);
	PRINT_INFO(KPROCESS_XP_SP3, DirectoryTableBase);
	PRINT_INFO(KPROCESS_XP_SP3, LdtDescriptor);
	PRINT_INFO(KPROCESS_XP_SP3, Int21Descriptor);
	PRINT_INFO(KPROCESS_XP_SP3, unknow);
	PRINT_INFO(KPROCESS_XP_SP3, ActiveProcessors); 
	PRINT_INFO(KPROCESS_XP_SP3, KernelTime); 
	PRINT_INFO(KPROCESS_XP_SP3, UserTime); 
	PRINT_INFO(KPROCESS_XP_SP3, ReadyListHead);
	PRINT_INFO(KPROCESS_XP_SP3, SwapListEntry );
	PRINT_INFO(KPROCESS_XP_SP3, VdmTrapcHandler);
	PRINT_INFO(KPROCESS_XP_SP3, ThreadListHead);
	PRINT_INFO(KPROCESS_XP_SP3, ProcessLock );
	PRINT_INFO(KPROCESS_XP_SP3, Affinity );
	PRINT_INFO(KPROCESS_XP_SP3, StackCount);
	PRINT_INFO(KPROCESS_XP_SP3, BasePriority);
	PRINT_INFO(KPROCESS_XP_SP3, ThreadQuantum );
	PRINT_INFO(KPROCESS_XP_SP3, AutoAlignment );
	PRINT_INFO(KPROCESS_XP_SP3, State);
	PRINT_INFO(KPROCESS_XP_SP3, ThreadSeed);
	PRINT_INFO(KPROCESS_XP_SP3, DisableBoost);
	PRINT_INFO(KPROCESS_XP_SP3, PowerState);
	PRINT_INFO(KPROCESS_XP_SP3, DisableQuantum);
	PRINT_INFO(KPROCESS_XP_SP3, IdealNode);
	PRINT_INFO(KPROCESS_XP_SP3, Flags);


	printf("-------------------\r\n");
	PRINT_INFO(MMSUPPORT_XP_SP3, LastTrimTime);
	PRINT_INFO(MMSUPPORT_XP_SP3, Flags);
	PRINT_INFO(MMSUPPORT_XP_SP3, PageFaultCount);
	PRINT_INFO(MMSUPPORT_XP_SP3, PeakWorkingSetSize);
	PRINT_INFO(MMSUPPORT_XP_SP3, WorkingSetSize);
	PRINT_INFO(MMSUPPORT_XP_SP3, MinimumWorkingSetSize);
	PRINT_INFO(MMSUPPORT_XP_SP3, MaximumWorkingSetSize);
	PRINT_INFO(MMSUPPORT_XP_SP3, VmWorkingSetList);
	PRINT_INFO(MMSUPPORT_XP_SP3, WorkingSetExpansionLinks);
	PRINT_INFO(MMSUPPORT_XP_SP3, Claim);
	PRINT_INFO(MMSUPPORT_XP_SP3, NextEstimationSlot);
	PRINT_INFO(MMSUPPORT_XP_SP3, NextAgingSlot);
	PRINT_INFO(MMSUPPORT_XP_SP3, EstimatedAvailable);
	PRINT_INFO(MMSUPPORT_XP_SP3, GrowthSinceLastEstimate);

	*/

/*
PRINT_INFO(KTHREAD_XP_SP3, Header);
PRINT_INFO(KTHREAD_XP_SP3,	Header);//0x000
PRINT_INFO(KTHREAD_XP_SP3,	MutantListHead);////+0x010
PRINT_INFO(KTHREAD_XP_SP3,	InitialStack);//0x018
PRINT_INFO(KTHREAD_XP_SP3,	StackLimit);//0x01c
PRINT_INFO(KTHREAD_XP_SP3,	Teb);//0x020
PRINT_INFO(KTHREAD_XP_SP3,	TlsArray);//0x024
PRINT_INFO(KTHREAD_XP_SP3,	KernelStack);//0x028
PRINT_INFO(KTHREAD_XP_SP3,	DebugActive);//0x02c
PRINT_INFO(KTHREAD_XP_SP3,	State);//0x02d
PRINT_INFO(KTHREAD_XP_SP3,	Alerted);//0x02e
PRINT_INFO(KTHREAD_XP_SP3,	Iopl);//0x030
PRINT_INFO(KTHREAD_XP_SP3,	NpxState);//0x031
PRINT_INFO(KTHREAD_XP_SP3,	Saturation);//0x032
PRINT_INFO(KTHREAD_XP_SP3,	Priority);//0x033
PRINT_INFO(KTHREAD_XP_SP3,	ApcState);//0x034
PRINT_INFO(KTHREAD_XP_SP3,	ContextSwitches);////+0x04c
PRINT_INFO(KTHREAD_XP_SP3,	IdleSwapBlock);//0x050
PRINT_INFO(KTHREAD_XP_SP3,	Spare0);//0x051
PRINT_INFO(KTHREAD_XP_SP3,	WaitStatus);//0x054
PRINT_INFO(KTHREAD_XP_SP3,	WaitIrql);//0x058
PRINT_INFO(KTHREAD_XP_SP3,	WaitMode);//0x059
PRINT_INFO(KTHREAD_XP_SP3,	WaitNext);//0x05a
PRINT_INFO(KTHREAD_XP_SP3,	WaitReason);//0x05b
PRINT_INFO(KTHREAD_XP_SP3,	WaitBlockList);////+0x05c

	PRINT_INFO(KTHREAD_XP_SP3,	u1.WaitListEntry);////+0x060
	PRINT_INFO(KTHREAD_XP_SP3,	u1.SwapListEntry);//0x060

PRINT_INFO(KTHREAD_XP_SP3,	WaitTime);//0x068
PRINT_INFO(KTHREAD_XP_SP3,	BasePriority);//0x06c
PRINT_INFO(KTHREAD_XP_SP3,	DecrementCount);////+0x06d
PRINT_INFO(KTHREAD_XP_SP3,	PriorityDecrement);//0x06e
PRINT_INFO(KTHREAD_XP_SP3,	Quantum);//0x06f
PRINT_INFO(KTHREAD_XP_SP3,	WaitBlock);//0x070
PRINT_INFO(KTHREAD_XP_SP3,	LegoData);//0x0d0
PRINT_INFO(KTHREAD_XP_SP3,	KernelApcDisable);//0x0d4
PRINT_INFO(KTHREAD_XP_SP3,	UserAffinity);//0x0d8
PRINT_INFO(KTHREAD_XP_SP3,	SystemAffinityActive);//0x0dc
PRINT_INFO(KTHREAD_XP_SP3,	PowerState);//0x0dd
PRINT_INFO(KTHREAD_XP_SP3,	NpxIrql);//0x0de
PRINT_INFO(KTHREAD_XP_SP3,	InitialNode);//0x0df
PRINT_INFO(KTHREAD_XP_SP3,	ServiceTable);//0x0e0
PRINT_INFO(KTHREAD_XP_SP3,	Queue);//0x0e4
PRINT_INFO(KTHREAD_XP_SP3,	ApcQueueLock);//0x0e8
PRINT_INFO(KTHREAD_XP_SP3,	Timer);//0x0f0
PRINT_INFO(KTHREAD_XP_SP3,	QueueListEntry);//0x118
PRINT_INFO(KTHREAD_XP_SP3,	SoftAffinity);//0x120
PRINT_INFO(KTHREAD_XP_SP3,	Affinity);//0x124
PRINT_INFO(KTHREAD_XP_SP3,	Preempted);//0x128
PRINT_INFO(KTHREAD_XP_SP3,	ProcessReadyQueue);//0x129
PRINT_INFO(KTHREAD_XP_SP3,	KernelStackResident);//0x12a
PRINT_INFO(KTHREAD_XP_SP3,	NextProcessor);//0x12b
PRINT_INFO(KTHREAD_XP_SP3,	CallbackStack);//0x12c
PRINT_INFO(KTHREAD_XP_SP3,	Win32Thread);////+0x130
PRINT_INFO(KTHREAD_XP_SP3,	TrapFrame);//0x134
PRINT_INFO(KTHREAD_XP_SP3,	ApcStatePointer);////+0x138
PRINT_INFO(KTHREAD_XP_SP3,	PreviousMode);//0x140
PRINT_INFO(KTHREAD_XP_SP3,	EnableStackSwap);//0x141
PRINT_INFO(KTHREAD_XP_SP3,	LargeStack);//0x142
PRINT_INFO(KTHREAD_XP_SP3,	ResourceIndex);//0x143
PRINT_INFO(KTHREAD_XP_SP3,	KernelTime);//0x144
PRINT_INFO(KTHREAD_XP_SP3,	UserTime);//0x148
PRINT_INFO(KTHREAD_XP_SP3,	SavedApcState);//0x14c
PRINT_INFO(KTHREAD_XP_SP3,	Alertable);//0x164
PRINT_INFO(KTHREAD_XP_SP3,	ApcStateIndex);//0x165
PRINT_INFO(KTHREAD_XP_SP3,	ApcQueueable);//0x166
PRINT_INFO(KTHREAD_XP_SP3,	AutoAlignment);////+0x167
PRINT_INFO(KTHREAD_XP_SP3,	StackBase);//0x168
PRINT_INFO(KTHREAD_XP_SP3,	SuspendApc);//0x16c
PRINT_INFO(KTHREAD_XP_SP3,	SuspendSemaphore);////+0x19c
PRINT_INFO(KTHREAD_XP_SP3,	ThreadListEntry);//0x1b0
PRINT_INFO(KTHREAD_XP_SP3,	FreezeCount);//0x1b8
PRINT_INFO(KTHREAD_XP_SP3,	SuspendCount);//0x1b9
PRINT_INFO(KTHREAD_XP_SP3,	IdealProcessor);//0x1ba
PRINT_INFO(KTHREAD_XP_SP3,	DisableBoost);//0x1bb


PRINT_INFO(ETHREAD_XP_SP3,	Tcb);
PRINT_INFO(ETHREAD_XP_SP3,	CreateTime);//0x1c0
	PRINT_INFO(ETHREAD_XP_SP3,	u1.ExitTime);//0x1c8
	PRINT_INFO(ETHREAD_XP_SP3,	u1.LpcReplyChain);//0x1c8
	PRINT_INFO(ETHREAD_XP_SP3,	u1.KeyedWaitChain);//0x1c8

	PRINT_INFO(ETHREAD_XP_SP3,	u2.ExitStatus);//0x1d0
	PRINT_INFO(ETHREAD_XP_SP3,	u2.OfsChain);//0x1d0

PRINT_INFO(ETHREAD_XP_SP3,	PostBlockList);//0x1d4

	PRINT_INFO(ETHREAD_XP_SP3,	u3.TerminationPort);//0x1dc
	PRINT_INFO(ETHREAD_XP_SP3,	u3.ReaperLink);//0x1dc
	PRINT_INFO(ETHREAD_XP_SP3,	u3.KeyedWaitValue);//0x1dc

PRINT_INFO(ETHREAD_XP_SP3	,ActiveTimerListLock);//0x1e0
PRINT_INFO(ETHREAD_XP_SP3,	ActiveTimerListHead);//0x1e4
PRINT_INFO(ETHREAD_XP_SP3,	Cid);//0x1ec

	PRINT_INFO(ETHREAD_XP_SP3,	u4.LpcReplySemaphore);////+0x1f4
	PRINT_INFO(ETHREAD_XP_SP3,	u4.KeyedWaitSemaphore);//0x1f4


	PRINT_INFO(ETHREAD_XP_SP3,	u5.LpcReplyMessage);////+0x208
	PRINT_INFO(ETHREAD_XP_SP3,	u5.LpcWaitingOnPort);//0x208

PRINT_INFO(ETHREAD_XP_SP3,	ImpersonationInfo);//0x20c
PRINT_INFO(ETHREAD_XP_SP3,	IrpList);//0x210
PRINT_INFO(ETHREAD_XP_SP3,	TopLevelIrp);//0x218
PRINT_INFO(ETHREAD_XP_SP3,	DeviceToVerify);//0x21c
PRINT_INFO(ETHREAD_XP_SP3,	ThreadsProcess);//0x220
PRINT_INFO(ETHREAD_XP_SP3,	StartAddress);////+0x224

	PRINT_INFO(ETHREAD_XP_SP3	,u6.Win32StartAddress);//0x228
	PRINT_INFO(ETHREAD_XP_SP3	,u6.LpcReceivedMessageId);//0x228

PRINT_INFO(ETHREAD_XP_SP3,	ThreadListEntry);////+0x22c
PRINT_INFO(ETHREAD_XP_SP3,	RundownProtect);//0x234
PRINT_INFO(ETHREAD_XP_SP3,	ThreadLock);//0x238
PRINT_INFO(ETHREAD_XP_SP3,	LpcReplyMessageId);//0x23c
PRINT_INFO(ETHREAD_XP_SP3,	ReadClusterSize);////+0x240
PRINT_INFO(ETHREAD_XP_SP3,	GrantedAccess);//0x244
PRINT_INFO(ETHREAD_XP_SP3,	CrossThreadFlags);//0x248
PRINT_INFO(ETHREAD_XP_SP3,	SameThreadPassiveFlags);//0x24c
PRINT_INFO(ETHREAD_XP_SP3,	SameThreadApcFlags);//0x250
PRINT_INFO(ETHREAD_XP_SP3,	ForwardClusterOnly);//0x254
PRINT_INFO(ETHREAD_XP_SP3,	DisablePageFaultClustering);//0x255
*/
	//return 0;
	//DWORD dwReturn;
	HANDLE hFile = yasi_create();
	THREAD_DETAIL info = {0};
	yasi_get_thread_detail(hFile, 364, 0, &info);

	//yasi_kill_process(hFile, 1156);

	//PROCESS_DETAIL detail = {0};
	//yasi_get_process_detail(hFile, 1576, &detail);


	//wchar_t dllPath[4096] = {0};
	//yasi_get_process_info(hFile, 2524, STRING_DllPath, dllPath);
	//printf("%S\r\n", dllPath);
	//memset(dllPath, 0, sizeof(dllPath));
	//yasi_get_process_info(hFile, 2524, STRING_ImagePathName, dllPath);
	//printf("%S\r\n", dllPath);
	//memset(dllPath, 0, sizeof(dllPath));
	//yasi_get_process_info(hFile, 2524, STRING_CommandLine, dllPath);
	//printf("%S\r\n", dllPath);
	//memset(dllPath, 0, sizeof(dllPath));
	//yasi_get_process_info(hFile, 2524, STRING_WindowTitle, dllPath);
	//printf("%S\r\n", dllPath);
	//memset(dllPath, 0, sizeof(dllPath));
	//yasi_get_process_info(hFile, 2524, STRING_DesktopInfo, dllPath);
	//printf("%S\r\n", dllPath);
	//memset(dllPath, 0, sizeof(dllPath));
	//yasi_get_process_info(hFile, 2524, STRING_ShellInfo, dllPath);
	//printf("%S\r\n", dllPath);
	//memset(dllPath, 0, sizeof(dllPath));
	//yasi_get_process_info(hFile, 2524, STRING_RuntimeData, dllPath);
	//printf("%S\r\n", dllPath);
	//memset(dllPath, 0, sizeof(dllPath));
	//yasi_get_process_info(hFile, 2524, STRING_CurrentDirectore, dllPath);
	//printf("%S\r\n", dllPath);
	//memset(dllPath, 0, sizeof(dllPath));
	//DWORD processCount = yasi_get_process_count(hFile);


	//for( int index = 0 ; index < processCount; index++ ){
	//	PROCESS_RECORD proc = {0};
	//	yasi_get_process(hFile, index, &proc);
	//	printf("[%x] %s \r\n", proc.processID, proc.imageName);

	//}


	//ULONG count = yasi_get_module_count(hFile, 3584);
	//for( ULONG index = 0 ; index < count; index ++ )
	//{
	//	LDR_DATA_TABLE_ENTRY_XP_SP3 info = {0};
	//	yasi_get_module_info(hFile, 3584, index, &info);
	//	yasi_get_process_string(hFile, 3584, info.BaseDllName.Buffer, dllPath, info.FullDllName.Length+2);
	//	printf("[%S]--->", dllPath);
	//	yasi_get_process_string(hFile, 3584, info.FullDllName.Buffer, dllPath, info.FullDllName.Length+2);
	//	printf("%S\r\n", dllPath);
	//}

	//FARPROC addr = yasi_get_proc_address(hFile, 484, "Kernel32.dll", "LoadLibraryW");

	//yasi_load_dll(hFile, 484, _T("D:\\project\\yasi\\yasi\\i386\\KernelLib.dll"));

	yasi_destroy(hFile);
	return 0;
}
