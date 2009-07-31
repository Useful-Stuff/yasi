#pragma once;

/*
	output from WinDbg
*/
/* xp sp3
lkd> dt _EPROCESS
ntdll!_EPROCESS
+0x000 Pcb              : _KPROCESS
+0x06c ProcessLock      : _EX_PUSH_LOCK
+0x070 CreateTime       : _LARGE_INTEGER
+0x078 ExitTime         : _LARGE_INTEGER
+0x080 RundownProtect   : _EX_RUNDOWN_REF
+0x084 UniqueProcessId  : Ptr32 Void
+0x088 ActiveProcessLinks : _LIST_ENTRY
+0x090 QuotaUsage       : [3] Uint4B
+0x09c QuotaPeak        : [3] Uint4B
+0x0a8 CommitCharge     : Uint4B
+0x0ac PeakVirtualSize  : Uint4B
+0x0b0 VirtualSize      : Uint4B
+0x0b4 SessionProcessLinks : _LIST_ENTRY
+0x0bc DebugPort        : Ptr32 Void
+0x0c0 ExceptionPort    : Ptr32 Void
+0x0c4 ObjectTable      : Ptr32 _HANDLE_TABLE
+0x0c8 Token            : _EX_FAST_REF
+0x0cc WorkingSetLock   : _FAST_MUTEX
+0x0ec WorkingSetPage   : Uint4B
+0x0f0 AddressCreationLock : _FAST_MUTEX
+0x110 HyperSpaceLock   : Uint4B
+0x114 ForkInProgress   : Ptr32 _ETHREAD
+0x118 HardwareTrigger  : Uint4B
+0x11c VadRoot          : Ptr32 Void
+0x120 VadHint          : Ptr32 Void
+0x124 CloneRoot        : Ptr32 Void
+0x128 NumberOfPrivatePages : Uint4B
+0x12c NumberOfLockedPages : Uint4B
+0x130 Win32Process     : Ptr32 Void
+0x134 Job              : Ptr32 _EJOB
+0x138 SectionObject    : Ptr32 Void
+0x13c SectionBaseAddress : Ptr32 Void
+0x140 QuotaBlock       : Ptr32 _EPROCESS_QUOTA_BLOCK
+0x144 WorkingSetWatch  : Ptr32 _PAGEFAULT_HISTORY
+0x148 Win32WindowStation : Ptr32 Void
+0x14c InheritedFromUniqueProcessId : Ptr32 Void
+0x150 LdtInformation   : Ptr32 Void
+0x154 VadFreeHint      : Ptr32 Void
+0x158 VdmObjects       : Ptr32 Void
+0x15c DeviceMap        : Ptr32 Void
+0x160 PhysicalVadList  : _LIST_ENTRY
+0x168 PageDirectoryPte : _HARDWARE_PTE_X86
+0x168 Filler           : Uint8B
+0x170 Session          : Ptr32 Void
+0x174 ImageFileName    : [16] UChar
+0x184 JobLinks         : _LIST_ENTRY
+0x18c LockedPagesList  : Ptr32 Void
+0x190 ThreadListHead   : _LIST_ENTRY
+0x198 SecurityPort     : Ptr32 Void
+0x19c PaeTop           : Ptr32 Void
+0x1a0 ActiveThreads    : Uint4B
+0x1a4 GrantedAccess    : Uint4B
+0x1a8 DefaultHardErrorProcessing : Uint4B
+0x1ac LastThreadExitStatus : Int4B
+0x1b0 Peb              : Ptr32 _PEB
+0x1b4 PrefetchTrace    : _EX_FAST_REF
+0x1b8 ReadOperationCount : _LARGE_INTEGER
+0x1c0 WriteOperationCount : _LARGE_INTEGER
+0x1c8 OtherOperationCount : _LARGE_INTEGER
+0x1d0 ReadTransferCount : _LARGE_INTEGER
+0x1d8 WriteTransferCount : _LARGE_INTEGER
+0x1e0 OtherTransferCount : _LARGE_INTEGER
+0x1e8 CommitChargeLimit : Uint4B
+0x1ec CommitChargePeak : Uint4B
+0x1f0 AweInfo          : Ptr32 Void
+0x1f4 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
+0x1f8 Vm               : _MMSUPPORT
+0x238 LastFaultCount   : Uint4B
+0x23c ModifiedPageCount : Uint4B
+0x240 NumberOfVads     : Uint4B
+0x244 JobStatus        : Uint4B
+0x248 Flags            : Uint4B
+0x248 CreateReported   : Pos 0, 1 Bit
+0x248 NoDebugInherit   : Pos 1, 1 Bit
+0x248 ProcessExiting   : Pos 2, 1 Bit
+0x248 ProcessDelete    : Pos 3, 1 Bit
+0x248 Wow64SplitPages  : Pos 4, 1 Bit
+0x248 VmDeleted        : Pos 5, 1 Bit
+0x248 OutswapEnabled   : Pos 6, 1 Bit
+0x248 Outswapped       : Pos 7, 1 Bit
+0x248 ForkFailed       : Pos 8, 1 Bit
+0x248 HasPhysicalVad   : Pos 9, 1 Bit
+0x248 AddressSpaceInitialized : Pos 10, 2 Bits
+0x248 SetTimerResolution : Pos 12, 1 Bit
+0x248 BreakOnTermination : Pos 13, 1 Bit
+0x248 SessionCreationUnderway : Pos 14, 1 Bit
+0x248 WriteWatch       : Pos 15, 1 Bit
+0x248 ProcessInSession : Pos 16, 1 Bit
+0x248 OverrideAddressSpace : Pos 17, 1 Bit
+0x248 HasAddressSpace  : Pos 18, 1 Bit
+0x248 LaunchPrefetched : Pos 19, 1 Bit
+0x248 InjectInpageErrors : Pos 20, 1 Bit
+0x248 VmTopDown        : Pos 21, 1 Bit
+0x248 Unused3          : Pos 22, 1 Bit
+0x248 Unused4          : Pos 23, 1 Bit
+0x248 VdmAllowed       : Pos 24, 1 Bit
+0x248 Unused           : Pos 25, 5 Bits
+0x248 Unused1          : Pos 30, 1 Bit
+0x248 Unused2          : Pos 31, 1 Bit
+0x24c ExitStatus       : Int4B
+0x250 NextPageColor    : Uint2B
+0x252 SubSystemMinorVersion : UChar
+0x253 SubSystemMajorVersion : UChar
+0x252 SubSystemVersion : Uint2B
+0x254 PriorityClass    : UChar
+0x255 WorkingSetAcquiredUnsafe : UChar
+0x258 Cookie           : Uint4B
*/

typedef struct _EPROCESS_XP_SP3
{
	char Pcb[108];
	char ProcessLock[4];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER ExitTime;
	char RundownProtect[4];
	PVOID UniqueProcessId;
	LIST_ENTRY ActiveProcessLinks;
	UINT QuotaUsage[3];
	UINT QuotaPeak[3];
	UINT CommitCharge;
	UINT PeakVirtualSize;
	UINT VirtualSize;
	LIST_ENTRY SessionProcessLinks;
	PVOID DebugPort;
	PVOID ExceptionPort;
	PVOID ObjectTable;
	char Token[4];
	char WorkingSetLock[32];
	UINT WorkingSetPage;
	char AddressCreationLock[32];
	UINT HyperSpaceLock;
	PVOID ForkInProgress;
	UINT HardwareTrigger;
	PVOID VadRoot;
	PVOID VadHint;
	PVOID CloneRoot;
	UINT NumberOfPrivatePages;
	UINT NumberOfLockedPages;
	PVOID Win32Process;
	PVOID Job;
	PVOID SectionObject;
	PVOID SectionBaseAddress;
	PVOID QuotaBlock;
	PVOID WorkingSetWatch;
	PVOID Win32WindowStation;
	PVOID InheritedFromUniqueProcessId;
	PVOID LdtInformation;
	PVOID VadFreeHint;
	PVOID VdmObjects;
	PVOID DeviceMap;
	LIST_ENTRY PhysicalVadList;
	ULONGLONG PageDirectoryPte;
	PVOID Session;
	char ImageFileName[16];
	LIST_ENTRY JobLinks;
	PVOID LockedPagesList;
	LIST_ENTRY ThreadListHead;
	PVOID SecurityPort;
	PVOID PaeTop;
	UINT ActiveThreads;
	UINT GrantedAccess;
	UINT DefaultHardErrorProcessing;
	int LastThreadExitStatus;
	PVOID Peb;
	char PrefetchTrace[4];
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	UINT CommitChargeLimit;
	UINT CommitChargePeak;
	PVOID AweInfo;
	PVOID SeAuditProcessCreationInfo;
	char Vm[64];
	UINT LastFaultCount;
	UINT ModifiedPageCount;
	UINT NumberOfVads;
	UINT JobStatus;
	UINT Flags;
	int ExitStatus;
	WORD NextPageColor;
	WORD SubSystemVersion;
	UCHAR PriorityClass;
	UCHAR WorkingSetAcquiredUnsafe[3];
	UINT Cookie;
} EPROCESS_XP_SP3, *PEPROCESS_XP_SP3;

