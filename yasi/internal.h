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


/*
ntdll!_MMSUPPORT
+0x000 LastTrimTime     : _LARGE_INTEGER
+0x008 Flags            : _MMSUPPORT_FLAGS
+0x00c PageFaultCount   : Uint4B
+0x010 PeakWorkingSetSize : Uint4B
+0x014 WorkingSetSize   : Uint4B
+0x018 MinimumWorkingSetSize : Uint4B
+0x01c MaximumWorkingSetSize : Uint4B
+0x020 VmWorkingSetList : Ptr32 _MMWSL
+0x024 WorkingSetExpansionLinks : _LIST_ENTRY
+0x02c Claim            : Uint4B
+0x030 NextEstimationSlot : Uint4B
+0x034 NextAgingSlot    : Uint4B
+0x038 EstimatedAvailable : Uint4B
+0x03c GrowthSinceLastEstimate : Uint4B
*/

/*

lkd> dt _DISPATCHER_HEADER
ntdll!_DISPATCHER_HEADER
+0x000 Type             : UChar
+0x001 Absolute         : UChar
+0x002 Size             : UChar
+0x003 Inserted         : UChar
+0x004 SignalState      : Int4B
+0x008 WaitListHead     : _LIST_ENTRY


lkd> dt _KPROCESS
ntdll!_KPROCESS
+0x000 Header           : _DISPATCHER_HEADER
+0x010 ProfileListHead  : _LIST_ENTRY
+0x018 DirectoryTableBase : [2] Uint4B
+0x020 LdtDescriptor    : _KGDTENTRY
+0x028 Int21Descriptor  : _KIDTENTRY
+0x030 IopmOffset       : Uint2B
+0x032 Iopl             : UChar
+0x033 Unused           : UChar
+0x034 ActiveProcessors : Uint4B
+0x038 KernelTime       : Uint4B
+0x03c UserTime         : Uint4B
+0x040 ReadyListHead    : _LIST_ENTRY
+0x048 SwapListEntry    : _SINGLE_LIST_ENTRY
+0x04c VdmTrapcHandler  : Ptr32 Void
+0x050 ThreadListHead   : _LIST_ENTRY
+0x058 ProcessLock      : Uint4B
+0x05c Affinity         : Uint4B
+0x060 StackCount       : Uint2B
+0x062 BasePriority     : Char
+0x063 ThreadQuantum    : Char
+0x064 AutoAlignment    : UChar
+0x065 State            : UChar
+0x066 ThreadSeed       : UChar
+0x067 DisableBoost     : UChar
+0x068 PowerState       : UChar
+0x069 DisableQuantum   : UChar
+0x06a IdealNode        : UChar
+0x06b Flags            : _KEXECUTE_OPTIONS
+0x06b ExecuteOptions   : UChar
*/
#pragma  pack (1)

#ifndef BYTE
#define BYTE char
#endif
typedef struct _UNICODE_STRING_XP_SP3 {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING_XP_SP3, *PUNICODE_STRING_XP_SP3;



typedef struct _DISPATCHER_HEADER_XP_SP3
{
	char Type;
	char Absolute;
	char Size;
	char Inserted;
	int SignalState;
	LIST_ENTRY WaitListHead;
}DISPATCHER_HEADER_XP_SP3, *PDISPATCHER_HEADER_XP_SP3;


typedef struct _KPROCESS_XP_SP3
{
	DISPATCHER_HEADER_XP_SP3 Header; //16
	LIST_ENTRY ProfileListHead; //8
	UINT DirectoryTableBase[2];  //8
	ULONGLONG LdtDescriptor; //8
	ULONGLONG Int21Descriptor; //8
	char unknow[4]; 
	UINT ActiveProcessors; 
	UINT KernelTime; 
	UINT UserTime; 
	LIST_ENTRY ReadyListHead;
	SINGLE_LIST_ENTRY SwapListEntry ;
	PVOID VdmTrapcHandler;
	LIST_ENTRY ThreadListHead;
	UINT ProcessLock ;
	UINT Affinity ;
	USHORT StackCount;
	char BasePriority;
	char ThreadQuantum ;
	char AutoAlignment ;
	char State;
	char ThreadSeed;
	char DisableBoost;
	char PowerState;
	char DisableQuantum;
	char IdealNode;
	char Flags;
}KPROCESS_XP_SP3, *PKPROCESS_XP_SP3;

typedef struct _MMSUPPORT_XP_SP3
{
	LARGE_INTEGER LastTrimTime;
	ULONG Flags;
	UINT PageFaultCount;
	UINT PeakWorkingSetSize;
	UINT WorkingSetSize;
	UINT MinimumWorkingSetSize;
	UINT MaximumWorkingSetSize;
	PVOID VmWorkingSetList;
	LIST_ENTRY WorkingSetExpansionLinks;
	UINT Claim;
	UINT NextEstimationSlot;
	UINT NextAgingSlot;
	UINT EstimatedAvailable;
	UINT GrowthSinceLastEstimate;
} MMSUPPORT_XP_SP3 , *PMMSUPPORT_XP_SP3;

typedef struct _EPROCESS_XP_SP3
{
	KPROCESS_XP_SP3 Pcb;
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
	MMSUPPORT_XP_SP3 Vm;
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


/*
lkd> dt _PEB
ntdll!_PEB
+0x000 InheritedAddressSpace : UChar
+0x001 ReadImageFileExecOptions : UChar
+0x002 BeingDebugged    : UChar
+0x003 SpareBool        : UChar
+0x004 Mutant           : Ptr32 Void
+0x008 ImageBaseAddress : Ptr32 Void
+0x00c Ldr              : Ptr32 _PEB_LDR_DATA
+0x010 ProcessParameters : Ptr32 _RTL_USER_PROCESS_PARAMETERS
+0x014 SubSystemData    : Ptr32 Void
+0x018 ProcessHeap      : Ptr32 Void
+0x01c FastPebLock      : Ptr32 _RTL_CRITICAL_SECTION
+0x020 FastPebLockRoutine : Ptr32 Void
+0x024 FastPebUnlockRoutine : Ptr32 Void
+0x028 EnvironmentUpdateCount : Uint4B
+0x02c KernelCallbackTable : Ptr32 Void
+0x030 SystemReserved   : [1] Uint4B
+0x034 AtlThunkSListPtr32 : Uint4B
+0x038 FreeList         : Ptr32 _PEB_FREE_BLOCK
+0x03c TlsExpansionCounter : Uint4B
+0x040 TlsBitmap        : Ptr32 Void
+0x044 TlsBitmapBits    : [2] Uint4B
+0x04c ReadOnlySharedMemoryBase : Ptr32 Void
+0x050 ReadOnlySharedMemoryHeap : Ptr32 Void
+0x054 ReadOnlyStaticServerData : Ptr32 Ptr32 Void
+0x058 AnsiCodePageData : Ptr32 Void
+0x05c OemCodePageData  : Ptr32 Void
+0x060 UnicodeCaseTableData : Ptr32 Void
+0x064 NumberOfProcessors : Uint4B
+0x068 NtGlobalFlag     : Uint4B
+0x070 CriticalSectionTimeout : _LARGE_INTEGER
+0x078 HeapSegmentReserve : Uint4B
+0x07c HeapSegmentCommit : Uint4B
+0x080 HeapDeCommitTotalFreeThreshold : Uint4B
+0x084 HeapDeCommitFreeBlockThreshold : Uint4B
+0x088 NumberOfHeaps    : Uint4B
+0x08c MaximumNumberOfHeaps : Uint4B
+0x090 ProcessHeaps     : Ptr32 Ptr32 Void
+0x094 GdiSharedHandleTable : Ptr32 Void
+0x098 ProcessStarterHelper : Ptr32 Void
+0x09c GdiDCAttributeList : Uint4B
+0x0a0 LoaderLock       : Ptr32 Void
+0x0a4 OSMajorVersion   : Uint4B
+0x0a8 OSMinorVersion   : Uint4B
+0x0ac OSBuildNumber    : Uint2B
+0x0ae OSCSDVersion     : Uint2B
+0x0b0 OSPlatformId     : Uint4B
+0x0b4 ImageSubsystem   : Uint4B
+0x0b8 ImageSubsystemMajorVersion : Uint4B
+0x0bc ImageSubsystemMinorVersion : Uint4B
+0x0c0 ImageProcessAffinityMask : Uint4B
+0x0c4 GdiHandleBuffer  : [34] Uint4B
+0x14c PostProcessInitRoutine : Ptr32     void 
+0x150 TlsExpansionBitmap : Ptr32 Void
+0x154 TlsExpansionBitmapBits : [32] Uint4B
+0x1d4 SessionId        : Uint4B
+0x1d8 AppCompatFlags   : _ULARGE_INTEGER
+0x1e0 AppCompatFlagsUser : _ULARGE_INTEGER
+0x1e8 pShimData        : Ptr32 Void
+0x1ec AppCompatInfo    : Ptr32 Void
+0x1f0 CSDVersion       : _UNICODE_STRING
+0x1f8 ActivationContextData : Ptr32 Void
+0x1fc ProcessAssemblyStorageMap : Ptr32 Void
+0x200 SystemDefaultActivationContextData : Ptr32 Void
+0x204 SystemAssemblyStorageMap : Ptr32 Void
+0x208 MinimumStackCommit : Uint4B
*/

/*
lkd> dt _RTL_USER_PROCESS_PARAMETERS
ntdll!_RTL_USER_PROCESS_PARAMETERS
+0x000 MaximumLength    : Uint4B
+0x004 Length           : Uint4B
+0x008 Flags            : Uint4B
+0x00c DebugFlags       : Uint4B
+0x010 ConsoleHandle    : Ptr32 Void
+0x014 ConsoleFlags     : Uint4B
+0x018 StandardInput    : Ptr32 Void
+0x01c StandardOutput   : Ptr32 Void
+0x020 StandardError    : Ptr32 Void
+0x024 CurrentDirectory : _CURDIR
+0x030 DllPath          : _UNICODE_STRING
+0x038 ImagePathName    : _UNICODE_STRING
+0x040 CommandLine      : _UNICODE_STRING
+0x048 Environment      : Ptr32 Void
+0x04c StartingX        : Uint4B
+0x050 StartingY        : Uint4B
+0x054 CountX           : Uint4B
+0x058 CountY           : Uint4B
+0x05c CountCharsX      : Uint4B
+0x060 CountCharsY      : Uint4B
+0x064 FillAttribute    : Uint4B
+0x068 WindowFlags      : Uint4B
+0x06c ShowWindowFlags  : Uint4B
+0x070 WindowTitle      : _UNICODE_STRING
+0x078 DesktopInfo      : _UNICODE_STRING
+0x080 ShellInfo        : _UNICODE_STRING
+0x088 RuntimeData      : _UNICODE_STRING
+0x090 CurrentDirectores : [32] _RTL_DRIVE_LETTER_CURDIR
*/

/*
ntdll!_RTL_DRIVE_LETTER_CURDIR
+0x000 Flags            : Uint2B
+0x002 Length           : Uint2B
+0x004 TimeStamp        : Uint4B
+0x008 DosPath          : _STRING
*/

//comes from http://bbs.pediy.com/archive/index.php?t-71204.html
typedef struct _PEB_LDR_DATA {
	ULONG Length;
	ULONG Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;


typedef struct _LDR_DATA_TABLE_ENTRY_XP_SP3 {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING_XP_SP3 FullDllName;
	UNICODE_STRING_XP_SP3 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
	struct _ACTIVATION_CONTEXT * EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY_XP_SP3, *PLDR_DATA_TABLE_ENTRY_XP_SP3;

typedef struct _KAPC_STATE_XP_SP3
{
	LIST_ENTRY ApcListHead[2];//+0x000
	PVOID	Process;//+0x010
	char	KernelApcInProgress;//+0x014
	char	KernelApcPending;//+0x015
	char	UserApcPending;//+0x016
	char	useless;
}KAPC_STATE_XP_SP3, *PKAPC_STATE_XP_SP3;

typedef struct _KAPC_XP_SP3
{
	unsigned short	Type;//+0x000
	unsigned short	Size;//+0x002
	ULONG	Spare0;//+0x004
	PVOID	Thread;//+0x008
	LIST_ENTRY	ApcListEntry;//+0x00c
	PVOID	KernelRoutine;//+0x014
	PVOID	RundownRoutine;//+0x018
	PVOID	NormalRoutine;//+0x01c
	PVOID	NormalContext;//+0x020
	PVOID	SystemArgument1;//+0x024
	PVOID	SystemArgument2;//+0x028
	char	ApcStateIndex;//+0x02c
	char	ApcMode;//+0x02d
	char	Inserted;//+0x02e
	char	useless;
}KAPC_XP_SP3, *PKAPC_XP_SP3;

typedef struct _KWAIT_BLOCK_XP_SP3
{
	LIST_ENTRY	WaitListEntry;//+0x000
	PVOID	Thread;//+0x008
	PVOID	Object;//+0x00c
	PVOID	NextWaitBlock;//+0x010
	unsigned short	WaitKey;//+0x014
	unsigned short	WaitType;//+0x016
}KWAIT_BLOCK_XP_SP3, *PKWAIT_BLOCK_XP_SP3;

typedef struct _KTIMER_XP_SP3
{
	DISPATCHER_HEADER_XP_SP3	Header;//+0x000
	ULARGE_INTEGER	DueTime;//+0x010
	LIST_ENTRY	TimerListEntry;//+0x018
	PVOID	Dpc;//+0x020
	int	Period;//+0x024

}KTIMER_XP_SP3, *PKTIMER_XP_SP3;

typedef struct _KSEMAPHORE_XP_SP3
{
	DISPATCHER_HEADER_XP_SP3	Header;//+0x000
	int	Limit;//+0x010

}KSEMAPHORE_XP_SP3, *PKSEMAPHORE_XP_SP3;

typedef struct _KTHREAD_XP_SP3
{
	DISPATCHER_HEADER_XP_SP3	Header;//+0x000
	LIST_ENTRY	MutantListHead;//+0x010
	PVOID	InitialStack;//+0x018
	PVOID	StackLimit;//+0x01c
	PVOID	Teb;//+0x020
	PVOID	TlsArray;//+0x024
	PVOID	KernelStack;//+0x028
	char	DebugActive;//+0x02c
	char	State;//+0x02d
	char	Alerted[2];//+0x02e
	char	Iopl;//+0x030
	char	NpxState;//+0x031
	char	Saturation;//+0x032
	char	Priority;//+0x033
	KAPC_STATE_XP_SP3	ApcState;//+0x034
	ULONG	ContextSwitches;//+0x04c
	char	IdleSwapBlock;//+0x050
	char	Spare0[3];//+0x051
	int	WaitStatus;//+0x054
	char	WaitIrql;//+0x058
	char	WaitMode;//+0x059
	char	WaitNext;//+0x05a
	char	WaitReason;//+0x05b
	PVOID	WaitBlockList;//+0x05c
	union{
		LIST_ENTRY	WaitListEntry;//+0x060
		SINGLE_LIST_ENTRY	SwapListEntry;//+0x060
	}u1;
	ULONG	WaitTime;//+0x068
	char	BasePriority;//+0x06c
	char	DecrementCount;//+0x06d
	char	PriorityDecrement;//+0x06e
	char	Quantum;//+0x06f
	KWAIT_BLOCK_XP_SP3	WaitBlock[4];//+0x070
	PVOID	LegoData;//+0x0d0
	ULONG	KernelApcDisable;//+0x0d4
	ULONG	UserAffinity;//+0x0d8
	char	SystemAffinityActive;//+0x0dc
	char	PowerState;//+0x0dd
	char	NpxIrql;//+0x0de
	char	InitialNode;//+0x0df
	PVOID	ServiceTable;//+0x0e0
	PVOID	Queue;//+0x0e4
	ULONG	ApcQueueLock[2];//+0x0e8
	KTIMER_XP_SP3	Timer;//+0x0f0
	LIST_ENTRY	QueueListEntry;//+0x118
	ULONG	SoftAffinity;//+0x120
	ULONG	Affinity;//+0x124
	char	Preempted;//+0x128
	char	ProcessReadyQueue;//+0x129
	char	KernelStackResident;//+0x12a
	char	NextProcessor;//+0x12b
	PVOID	CallbackStack;//+0x12c
	PVOID	Win32Thread;//+0x130
	PVOID	TrapFrame;//+0x134
	PVOID	ApcStatePointer[2];//+0x138
	char	PreviousMode;//+0x140
	char	EnableStackSwap;//+0x141
	char	LargeStack;//+0x142
	char	ResourceIndex;//+0x143
	ULONG	KernelTime;//+0x144
	ULONG	UserTime;//+0x148
	KAPC_STATE_XP_SP3	SavedApcState;//+0x14c
	char	Alertable;//+0x164
	char	ApcStateIndex;//+0x165
	char	ApcQueueable;//+0x166
	char	AutoAlignment;//+0x167
	PVOID	StackBase;//+0x168
	KAPC_XP_SP3	SuspendApc;//+0x16c
	KSEMAPHORE_XP_SP3	SuspendSemaphore;//+0x19c
	LIST_ENTRY	ThreadListEntry;//+0x1b0
	char	FreezeCount;//+0x1b8
	char	SuspendCount;//+0x1b9
	char	IdealProcessor;//+0x1ba
	char	DisableBoost;//+0x1bb
	UINT	useless;
}KTHREAD_XP_SP3, *PKTHREAD_XP_SP3;

typedef struct _CLIENT_ID_XP_SP3
{
	PVOID	UniqueProcess;//+0x000
	PVOID	UniqueThread;//+0x004
}CLIENT_ID_XP_SP3, *PCLIENT_ID_XP_SP3;

typedef struct _EX_RUNDOWN_REF_XP_SP3
{
	union{
		ULONG	Count;//+0x000
		PVOID	Ptr;//+0x000
	}u;
}EX_RUNDOWN_REF_XP_SP3, *PEX_RUNDOWN_REF_XP_SP3;

typedef struct _ETHREAD_XP_SP3
{
	KTHREAD_XP_SP3	Tcb;//+0x000
	LARGE_INTEGER	CreateTime;//+0x1c0
	union{
		LARGE_INTEGER	ExitTime;//+0x1c8
		LIST_ENTRY	LpcReplyChain;//+0x1c8
		LIST_ENTRY	KeyedWaitChain;//+0x1c8
	}u1;
	union{
		int	ExitStatus;//+0x1d0
		PVOID	OfsChain;//+0x1d0
	}u2;
	LIST_ENTRY	PostBlockList;//+0x1d4
	union{
		PVOID	TerminationPort;//+0x1dc
		PVOID	ReaperLink;//+0x1dc
		PVOID	KeyedWaitValue;//+0x1dc
	}u3;
	ULONG	ActiveTimerListLock;//+0x1e0
	LIST_ENTRY	ActiveTimerListHead;//+0x1e4
	CLIENT_ID_XP_SP3	Cid;//+0x1ec
	union{
		KSEMAPHORE_XP_SP3	LpcReplySemaphore;//+0x1f4
		KSEMAPHORE_XP_SP3	KeyedWaitSemaphore;//+0x1f4
	}u4;
	union{
		PVOID	LpcReplyMessage;//+0x208
		PVOID	LpcWaitingOnPort;//+0x208
	}u5;
	PVOID	ImpersonationInfo;//+0x20c
	LIST_ENTRY	IrpList;//+0x210
	ULONG	TopLevelIrp;//+0x218
	PVOID	DeviceToVerify;//+0x21c
	PVOID	ThreadsProcess;//+0x220
	PVOID	StartAddress;//+0x224
	union{
		PVOID	Win32StartAddress;//+0x228
		ULONG	LpcReceivedMessageId;//+0x228
	}u6;
	LIST_ENTRY	ThreadListEntry;//+0x22c
	EX_RUNDOWN_REF_XP_SP3	RundownProtect;//+0x234
	PVOID	ThreadLock;//+0x238
	ULONG	LpcReplyMessageId;//+0x23c
	ULONG	ReadClusterSize;//+0x240
	ULONG	GrantedAccess;//+0x244
	ULONG	CrossThreadFlags;//+0x248
	ULONG	SameThreadPassiveFlags;//+0x24c
	ULONG	SameThreadApcFlags;//+0x250
	char	ForwardClusterOnly;//+0x254
	char	DisablePageFaultClustering;//+0x255;
} ETHREAD_XP_SP3, *PETHREAD_XP_SP3;

typedef struct _HANDLE_TABLE_XP_SP3 // 0x44
{
	ULONG TableCode; // +0x0(0x4)
	PEPROCESS_XP_SP3 QuotaProcess; // +0x4(0x4)
	void* UniqueProcessId; // +0x8(0x4)
	ULONG HandleTableLock[0x4]; // +0xc(0x10)
	LIST_ENTRY HandleTableList; // +0x1c(0x8)
	ULONG HandleContentionEvent; // +0x24(0x4)
	PVOID DebugInfo; // +0x28(0x4)
	long ExtraInfoPages; // +0x2c(0x4)
	ULONG FirstFree; // +0x30(0x4)
	ULONG LastFree; // +0x34(0x4)
	ULONG NextHandleNeedingPool; // +0x38(0x4)
	long HandleCount; // +0x3c(0x4)
	union{
		ULONG Flags; // +0x40(0x4)
		BYTE StrictFIFO; // +0x40(0x1)
	}u1;
}HANDLE_TABLE_XP_SP3, *PHANDLE_TABLE_XP_SP3;

typedef struct _HANDLE_TABLE_ENTRY_XP_SP3
{
	union{
		PVOID Object;
		ULONG ObAttributes;
		PVOID InfoTable;
		ULONG Value;
	}u1;
	union{
		struct _s1
		{
			union{
				ULONG GrantedAccess;
				struct _s2{
					unsigned short GrantedAccessIndex;
					unsigned short GreatorBackTraceIndex;
				}s2;
			}u2;
		}s1;
		int NextFreeTableEntry;
	}u3;
}HANDLE_TABLE_ENTRY_XP_SP3,*PHANDLE_TABLE_ENTRY_XP_SP3;


typedef struct _OBJECT_HEADER_NAME_INFO_XP_SP3 // 0x10
{
	PVOID Directory; // +0x0(0x4)
	UNICODE_STRING_XP_SP3 Name; // +0x4(0x8)
	ULONG QueryReferences; // +0xc(0x4)
}OBJECT_HEADER_NAME_INFO_XP_SP3, *POBJECT_HEADER_NAME_INFO_XP_SP3;

typedef struct _OBJECT_NAME_INFORMATION_XP_SP3 // 0x8
{
	UNICODE_STRING_XP_SP3 Name; // +0x0(0x8)
}OBJECT_NAME_INFORMATION_XP_SP3, *POBJECT_NAME_INFORMATION_XP_SP3;

typedef struct _OBJECT_TYPE_INITIALIZER_XP_SP3 // 0x4c
{
	WORD Length; // +0x0(0x2)
	BYTE UseDefaultObject; // +0x2(0x1)
	BYTE CaseInsensitive; // +0x3(0x1)
	ULONG InvalidAttributes; // +0x4(0x4)
	GENERIC_MAPPING GenericMapping; // +0x8(0x10)
	ULONG ValidAccessMask; // +0x18(0x4)
	BYTE SecurityRequired; // +0x1c(0x1)
	BYTE MaintainHandleCount; // +0x1d(0x1)
	BYTE MaintainTypeList; // +0x1e(0x1)
	BYTE useless;
	ULONG PoolType; // +0x20(0x4)
	ULONG DefaultPagedPoolCharge; // +0x24(0x4)
	ULONG DefaultNonPagedPoolCharge; // +0x28(0x4)
	void (__stdcall * DumpProcedure)(void*, PVOID); // +0x2c(0x4)
	long (__stdcall * OpenProcedure)(ULONG , PEPROCESS_XP_SP3, void*, ULONG, ULONG); // +0x30(0x4)
	void (__stdcall * CloseProcedure)(PEPROCESS_XP_SP3, void*, ULONG, ULONG, ULONG); // +0x34(0x4)
	void (__stdcall * DeleteProcedure)(void*); // +0x38(0x4)
	long (__stdcall * ParseProcedure)(void*, void*, struct _ACCESS_STATE*, char, ULONG, UNICODE_STRING_XP_SP3*, UNICODE_STRING_XP_SP3*, void*, PVOID, void**); // +0x3c(0x4)
	long (__stdcall * SecurityProcedure)(void*, enum _SECURITY_OPERATION_CODE, ULONG*, void*, ULONG*, void**, ULONG, PVOID, char); // +0x40(0x4)
	long (__stdcall * QueryNameProcedure)(void*, BYTE, POBJECT_NAME_INFORMATION_XP_SP3 , ULONG, ULONG*); // +0x44(0x4)
	BYTE (__stdcall * OkayToCloseProcedure)(PEPROCESS_XP_SP3, void*, void*, char); // +0x48(0x4)
}OBJECT_TYPE_INITIALIZER_XP_SP3, *POBJECT_TYPE_INITIALIZER_XP_SP3;


typedef struct _OBJECT_TYPE_XP_SP3 // 0x190
{
	ULONG Mutex[14]; // +0x0(0x38)
	LIST_ENTRY TypeList; // +0x38(0x8)
	UNICODE_STRING_XP_SP3 Name; // +0x40(0x8)
	void* DefaultObject; // +0x48(0x4)
	ULONG Index; // +0x4c(0x4)
	ULONG TotalNumberOfObjects; // +0x50(0x4)
	ULONG TotalNumberOfHandles; // +0x54(0x4)
	ULONG HighWaterNumberOfObjects; // +0x58(0x4)
	ULONG HighWaterNumberOfHandles; // +0x5c(0x4)
	OBJECT_TYPE_INITIALIZER_XP_SP3 TypeInfo; // +0x60(0x4c)
	ULONG Key; // +0xac(0x4)
	ULONG ObjectLocks[14][4]; // +0xb0(0xe0)

}OBJECT_TYPE_XP_SP3,*POBJECT_TYPE_XP_SP3;

typedef struct _OBJECT_CREATE_INFORMATION_XP_SP3 // 0x30
{
	ULONG Attributes; // +0x0(0x4)
	void* RootDirectory; // +0x4(0x4)
	void* ParseContext; // +0x8(0x4)
	char ProbeMode; // +0xc(0x1)
	char useless[3];
	ULONG PagedPoolCharge; // +0x10(0x4)
	ULONG NonPagedPoolCharge; // +0x14(0x4)
	ULONG SecurityDescriptorCharge; // +0x18(0x4)
	void* SecurityDescriptor; // +0x1c(0x4)
	struct _SECURITY_QUALITY_OF_SERVICE* SecurityQos; // +0x20(0x4)
	struct _SECURITY_QUALITY_OF_SERVICE SecurityQualityOfService; // +0x24(0xc)
}OBJECT_CREATE_INFORMATION_XP_SP3, *POBJECT_CREATE_INFORMATION_XP_SP3;

typedef struct _OBJECT_HEADER_XP_SP3 // 0x20
{
	long PointerCount; // +0x0(0x4)
	long HandleCount; // +0x4(0x4)
	POBJECT_TYPE_XP_SP3 Type; // +0x8(0x4)
	BYTE NameInfoOffset; // +0xc(0x1)
	BYTE HandleInfoOffset; // +0xd(0x1)
	BYTE QuotaInfoOffset; // +0xe(0x1)
	BYTE Flags; // +0xf(0x1)
	union
	{
		POBJECT_CREATE_INFORMATION_XP_SP3 ObjectCreateInfo; // +0x10(0x4)
		void* QuotaBlockCharged; // +0x10(0x4)
	}u1;
	void* SecurityDescriptor; // +0x14(0x4)
	char Body; // +0x18(0x8)
}OBJECT_HEADER_XP_SP3,*POBJECT_HEADER_XP_SP3;

typedef struct _KEVENT_XP_SP3 // 0x10
{
	DISPATCHER_HEADER_XP_SP3 Header; // +0x0(0x10)
}KEVENT_XP_SP3, *PKEVENT_XP_SP3;

typedef struct _FILE_OBJECT_XP_SP3 // 0x70
{
	short Type; // +0x0(0x2)
	short Size; // +0x2(0x2)
	PVOID DeviceObject; // +0x4(0x4)
	PVOID Vpb; // +0x8(0x4)
	void* FsContext; // +0xc(0x4)
	void* FsContext2; // +0x10(0x4)
	PVOID SectionObjectPointer; // +0x14(0x4)
	void* PrivateCacheMap; // +0x18(0x4)
	long FinalStatus; // +0x1c(0x4)
	PVOID RelatedFileObject; // +0x20(0x4)
	BYTE LockOperation; // +0x24(0x1)
	BYTE DeletePending; // +0x25(0x1)
	BYTE ReadAccess; // +0x26(0x1)
	BYTE WriteAccess; // +0x27(0x1)
	BYTE DeleteAccess; // +0x28(0x1)
	BYTE SharedRead; // +0x29(0x1)
	BYTE SharedWrite; // +0x2a(0x1)
	BYTE SharedDelete; // +0x2b(0x1)
	ULONG Flags; // +0x2c(0x4)
	UNICODE_STRING_XP_SP3 FileName; // +0x30(0x8)
	LARGE_INTEGER CurrentByteOffset; // +0x38(0x8)
	ULONG Waiters; // +0x40(0x4)
	ULONG Busy; // +0x44(0x4)
	PVOID LastLock; // +0x48(0x4)
	KEVENT_XP_SP3 Lock; // +0x4c(0x10)
	KEVENT_XP_SP3 Event; // +0x5c(0x10)
	PVOID CompletionContext; // +0x6c(0x4)
}FILE_OBJECT_XP_SP3, *PFILE_OBJECT_XP_SP3;

typedef struct _CM_KEY_HASH_XP_SP3 // 0x10
{
	ULONG ConvKey; // +0x0(0x4)
	PVOID NextHash; // +0x4(0x4)
	PVOID KeyHive; // +0x8(0x4)
	ULONG KeyCell; // +0xc(0x4)
}CM_KEY_HASH_XP_SP3, *PCM_KEY_HASH_XP_SP3;

typedef struct _CM_NAME_HASH_XP_SP3 // 0xc
{
	ULONG ConvKey; // +0x0(0x4)
	PVOID NextHash; // +0x4(0x4)
	WORD NameLength; // +0x8(0x2)
	WORD Name[0x1]; // +0xa(0x2)
}CM_NAME_HASH_XP_SP3,*PCM_NAME_HASH_XP_SP3;

typedef struct _CACHED_CHILD_LIST_XP_SP3 // 0x8
{
	ULONG Count; // +0x0(0x4)
	union{
		ULONG ValueList; // +0x4(0x4)
		PVOID RealKcb; // +0x4(0x4)
	}u1;
}CACHED_CHILD_LIST_XP_SP3, *PCACHED_CHILD_LIST_XP_SP3;

typedef struct _CM_NAME_CONTROL_BLOCK_XP_SP3 // 0x10
{
	BYTE Compressed; // +0x0(0x1)
	BYTE useless;
	WORD RefCount; // +0x2(0x2)
	union {
		PCM_NAME_HASH_XP_SP3 NameHash; // +0x4(0xc)
		ULONG ConvKey; // +0x4(0x4)
	}u1;
	PVOID NextHash; // +0x8(0x4)
	WORD NameLength; // +0xc(0x2)
	WORD Name[0x1]; // +0xe(0x2)
}CM_NAME_CONTROL_BLOCK_XP_SP3, *PCM_NAME_CONTROL_BLOCK_XP_SP3;

typedef struct _CM_KEY_CONTROL_BLOCK_XP_SP3// 0x50
{
	ULONG RefCount; // +0x0(0x4)
	union{
		ULONG ExtFlags; // +0x4(0x4)
		ULONG PrivateAlloc; // +0x4(0x4)
		ULONG Delete; // +0x4(0x4)
		ULONG DelayedCloseIndex; // +0x4(0x4)
		ULONG TotalLevels; // +0x4(0x4)
	}u1;
	union{
		PCM_KEY_HASH_XP_SP3 KeyHash; // +0x8(0x10)
		ULONG ConvKey; // +0x8(0x4)
	}u2;
	PVOID NextHash; // +0xc(0x4)
	PVOID KeyHive; // +0x10(0x4)
	ULONG KeyCell; // +0x14(0x4)
	PVOID ParentKcb; // +0x18(0x4)
	PCM_NAME_CONTROL_BLOCK_XP_SP3 NameBlock; // +0x1c(0x4)
	PVOID CachedSecurity; // +0x20(0x4)
	CACHED_CHILD_LIST_XP_SP3 ValueCache; // +0x24(0x8)
	union{
		PVOID IndexHint; // +0x2c(0x4)
		ULONG HashKey; // +0x2c(0x4)
		ULONG SubKeyCount; // +0x2c(0x4)
	}u3;
	union{
		LIST_ENTRY KeyBodyListHead; // +0x30(0x8)
		LIST_ENTRY FreeListEntry; // +0x30(0x8)
	}u4;
	LARGE_INTEGER KcbLastWriteTime; // +0x38(0x8)
	WORD KcbMaxNameLen; // +0x40(0x2)
	WORD KcbMaxValueNameLen; // +0x42(0x2)
	ULONG KcbMaxValueDataLen; // +0x44(0x4)
	union{
		ULONG KcbUserFlags; // +0x48(0x4)
		ULONG KcbVirtControlFlags; // +0x48(0x4)
		ULONG KcbDebug; // +0x48(0x4)
		ULONG Flags; // +0x48(0x4)
	}u5;
}CM_KEY_CONTROL_BLOCK_XP_SP3, *PCM_KEY_CONTROL_BLOCK_XP_SP3;

typedef struct _CM_KEY_BODY_XP_SP3 // 0x44
{
	ULONG Type; // +0x0(0x4)
	PCM_KEY_CONTROL_BLOCK_XP_SP3 KeyControlBlock; // +0x4(0x4)
	PVOID NotifyBlock; // +0x8(0x4)
	void* ProcessID; // +0xc(0x4)
	ULONG Callers; // +0x10(0x4)
	void* CallerAddress[0xa]; // +0x14(0x28)
	LIST_ENTRY KeyBodyList; // +0x3c(0x8)
}CM_KEY_BODY_XP_SP3,*PCM_KEY_BODY_XP_SP3;


#pragma  pack ()