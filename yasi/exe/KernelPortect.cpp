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
	//return 0;
	DWORD dwReturn;
	HANDLE hFile = yasi_create();

	//yasi_kill_process(hFile, 1156);

	//PROCESS_DETAIL detail = {0};
	//yasi_get_process_detail(hFile, 1576, &detail);


	wchar_t dllPath[4096] = {0};
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

	FARPROC addr = yasi_get_proc_address(hFile, 484, "Kernel32.dll", "LoadLibraryW");

	yasi_load_dll(hFile, 484, _T("D:\\project\\yasi\\yasi\\i386\\KernelLib.dll"));

	yasi_destroy(hFile);
	return 0;
}
