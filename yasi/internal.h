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

#pragma  pack ()