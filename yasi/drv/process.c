#define _X86_ 
#include <Ntifs.h>
#include <ntddk.h>

#include "KernelProtect.h"


ULONG
GetPlantformDependentInfo(
    ULONG dwFlag
)  
{   
    ULONG current_build;   
    ULONG ans = 0;   
   
    PsGetVersion(NULL, NULL, &current_build, NULL);   
   
    switch ( dwFlag )  
    {   
    case EPROCESS_SIZE:   
        if (current_build == 2195) ans = 0 ;        // 2000，当前不支持2000，下同  
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
   
    // 获取当前进程的地址
    FirstProcess = EProcess = (ULONG)PsGetCurrentProcess();
    do
    {
        dwCount++;
        DbgPrint("[ring0] [Pid=%6d] %s\n", *((ULONG *)(EProcess + dwPIdOffset)), (PUCHAR)(EProcess + dwPNameOffset));
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

	
   
    // 获取当前进程的地址
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
		DbgPrint("[ring0] found process");
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

void KillProcess(ULONG id)
{
	BOOL 			found;
	ULONG           EProcess;
	PVOID                ProcessHandle;
	
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
/*
PVOID GetStringPoint(ULONG EProcess, ULONG strID)
{
	ULONG pebAddress;
	ULONG processParametersAddress;
	ULONG tmpAddress;
	pebAddress = *((ULONG*)(EProcess+GetPlantformDependentInfo(PEB_OFFSET)));
	processParametersAddress = *((ULONG*)(pebAddress + GetPlantformDependentInfo(ProcessParameters_OFFSET)));
	switch( strID ){
		case	STRING_CSDVersion:
			tmpAddress = pebAddress + GetPlantformDependentInfo(CSDVersion_OFFSET);
			break;
		case	STRING_DllPath:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(STRING_DllPath);
			break;
		case	STRING_ImagePathName:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(STRING_ImagePathName);
			break;
		case	STRING_CommandLine:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(STRING_CommandLine);
			break;
		case	STRING_WindowTitle:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(STRING_WindowTitle);
			break;
		case	STRING_DesktopInfo:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(STRING_DesktopInfo);
			break;
		case	STRING_ShellInfo:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(STRING_ShellInfo);
			break;
		case	STRING_RuntimeData:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(STRING_RuntimeData);
			break;
		default:
			return NULL;
	}
	return (PVOID)tmpAddress;
}

*/

void GetProcessString(ULONG id,  ULONG* pebAddress)
{
	BOOL 			found;
	ULONG           EProcess;
	EProcess = 0;
	found = FALSE;
	found = FindProcessByID(id, &EProcess);
	if( found ){
		DbgPrint("[ring0] process %d found! EPROCESS is 0x%x", id, EProcess);
		*pebAddress = *((ULONG*)(EProcess+GetPlantformDependentInfo(PEB_OFFSET)));
		
	}else{
		DbgPrint("[ring0] do not found %d", id);
		*pebAddress = 0;
	}

	DbgPrint("[ring0] pebAddress %d", *pebAddress);
}

