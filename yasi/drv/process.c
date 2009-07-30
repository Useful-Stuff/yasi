#define _X86_ 

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

/*
    do
    {

        processes->processID = *((ULONG *)(EProcess + dwPIdOffset));
        memcpy(processes->imageName, (PUCHAR)(EProcess + dwPNameOffset), 16);
        dwCount++;

		

        ActiveProcessLinks = (LIST_ENTRY *)(EProcess + dwPLinkOffset);
        EProcess = (ULONG)ActiveProcessLinks->Flink - dwPLinkOffset;

		ProcessCount++;

        if (EProcess == FirstProcess)
        {
            break;
        }
    }while (EProcess != 0 && dwCount <= index);
*/
}
