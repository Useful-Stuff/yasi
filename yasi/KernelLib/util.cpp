#include "stdafx.h"
#include "util.h"
#include <windows.h>
#include "../internal.h"


enum
{
	STRING_CSDVersion,
	STRING_DllPath,
	STRING_ImagePathName,
	STRING_CommandLine,
	STRING_WindowTitle,
	STRING_DesktopInfo,
	STRING_ShellInfo,
	STRING_RuntimeData,
	STRING_CurrentDirectore
};

ULONG
GetPlantformDependentInfo(
						  ULONG dwFlag
						  )  
{   
	OSVERSIONINFO info = {0};
	info.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
	ULONG ans = 0;   

	GetVersionEx(&info);

	UINT current_build = info.dwBuildNumber;

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
		if (current_build == 2600)  ans = 0x24;  
		break;
	case Ldr_OFFSET:
		if( current_build == 2600 ) ans = 0x0c;
		break;
	case ImageBaseAddress_OFFSET:
		if( current_build == 2600 ) ans = 0x08;
		break;
	}   
	return ans;   
}

PVOID GetStringPoint(HANDLE process, ULONG pebAddress, ULONG strID)
{
	ULONG tmpAddress = 0;
	ULONG dwRead = 0;
	PVOID addr = (PVOID*)(pebAddress + GetPlantformDependentInfo(ProcessParameters_OFFSET));
	ULONG processParametersAddress;
	ReadProcessMemory(process, addr, &processParametersAddress, sizeof(ULONG), &dwRead);
	switch( strID ){
		case	STRING_CSDVersion:
			tmpAddress = (ULONG)pebAddress + GetPlantformDependentInfo(CSDVersion_OFFSET);
			break;
		case	STRING_DllPath:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(DllPath_OFFSET);
			break;
		case	STRING_ImagePathName:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(ImagePathName_OFFSET);
			break;
		case	STRING_CommandLine:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(CommandLine_OFFSET);
			break;
		case	STRING_WindowTitle:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(WindowTitle_OFFSET);
			break;
		case	STRING_DesktopInfo:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(DesktopInfo_OFFSET);
			break;
		case	STRING_ShellInfo:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(ShellInfo_OFFSET);
			break;
		case	STRING_RuntimeData:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(RuntimeData_OFFSET);
			break;
		case STRING_CurrentDirectore:
			tmpAddress = processParametersAddress + GetPlantformDependentInfo(CurrentDirectore_OFFSET);
			break;
		default:
			return NULL;
	}

	return (PVOID)tmpAddress;
}

BOOL ReadUnicodeString(HANDLE process, ULONG unicodeAddress, wchar_t* str)
{
	ULONG dwRead = 0;
	PVOID strAddr;
	//strAddr = (PVOID)unicodeAddress;
	UNICODE_STRING_XP_SP3 uniStr = {0};
	ReadProcessMemory(process, (LPCVOID)unicodeAddress, &uniStr, sizeof(UNICODE_STRING_XP_SP3), &dwRead);
	strAddr = uniStr.Buffer;
	ULONG size = 0;
	if( uniStr.Length > 4096 )
		size = 4094;
	else
		size = uniStr.Length;
	return ReadProcessMemory(process, strAddr, str, size, &dwRead);
}



void mtoupper(char* s)
{
	if(s == NULL ) 
		return;

	char* des = s;

	for( int index = 0 ; index < strlen(s); index++ )
	{
		*des = toupper((int)*des);
		des++;
	}
}

void AdjustPrivilege()
{
	DWORD dwError, dwLength;
	HANDLE hdCurrent, hdCurrentToken;
	unsigned char ucBuffer[512] = {0};
	TOKEN_PRIVILEGES* stToken = NULL;
	stToken = (TOKEN_PRIVILEGES*)ucBuffer;
	hdCurrent = GetCurrentProcess();
	dwError = OpenProcessToken(hdCurrent, TOKEN_ALL_ACCESS, &hdCurrentToken);
	dwError = GetTokenInformation(hdCurrentToken, TokenPrivileges, (TOKEN_PRIVILEGES*)ucBuffer, 512, &dwLength);
	for( dwError = 0 ; dwError < stToken->PrivilegeCount; dwError++){
		LUID uid = stToken->Privileges[dwError].Luid;
		stToken->Privileges[dwError].Attributes = SE_PRIVILEGE_ENABLED;
	}
	dwError = AdjustTokenPrivileges(hdCurrentToken, false, stToken, /*sizeof(DWORD)+stToken->PrivilegeCount * sizeof(LUID_AND_ATTRIBUTES)*/dwLength, NULL, NULL);
	//dwError = GetTokenInformation(hdCurrentToken, TokenPrivileges, (TOKEN_PRIVILEGES*)ucBuffer, 512, &dwLength);
	CloseHandle(hdCurrentToken);
}