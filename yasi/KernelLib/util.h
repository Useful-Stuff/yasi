#pragma once

enum
{
	EPROCESS_SIZE = 0,
	PEB_OFFSET,
	FILE_NAME_OFFSET,
	PROCESS_LINK_OFFSET,
	PROCESS_ID_OFFSET,
	EXIT_TIME_OFFSET,
	ProcessParameters_OFFSET,
	CSDVersion_OFFSET,
	DllPath_OFFSET,
	ImagePathName_OFFSET,
	CommandLine_OFFSET,
	WindowTitle_OFFSET,
	DesktopInfo_OFFSET,
	ShellInfo_OFFSET,
	RuntimeData_OFFSET,
	CurrentDirectore_OFFSET,
	Ldr_OFFSET,
	ImageBaseAddress_OFFSET

};
PVOID GetStringPoint(void* h, ULONG processID, ULONG pebAddress, ULONG strID);
ULONG GetPlantformDependentInfo( ULONG dwFlag ) ;
BOOL ReadUnicodeString(void* h, ULONG processID, ULONG unicodeAddress, wchar_t* str);
void mtoupper(char* s);
void AdjustPrivilege();
