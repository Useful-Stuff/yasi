#include "stdafx.h"
#include "../yasi.h"
#include "DrvComm.h"
#include "util.h"


YASI_HANDLE yasi_create()
{

	AdjustPrivilege();
	//first of all we need load driver privilege
	return LoadDriver();
}

void yasi_destroy(YASI_HANDLE h)
{
	UnloadDriver(h);
}

ULONG yasi_get_process_count(YASI_HANDLE h)
{
	DWORD dwReturn;

	CMD_RECORD cmd = {0};
	cmd.op = CMD_GET_PROCESS_COUNT;
	DWORD processCount = 0;
	DeviceIoControl(h, IOCTL_CMD_READ, &cmd, sizeof(CMD_RECORD), &processCount, 4, &dwReturn, NULL);
	return processCount;

	return 0;
}

void yasi_get_process(YASI_HANDLE h, ULONG index, struct PROCESS_RECORD * record)
{
	if( !record )
		return;
	DWORD dwReturn;
	ULONG total_len = sizeof(ULONG) + sizeof(ULONG) + sizeof(ULONG);
	CMD_RECORD* cmd = (CMD_RECORD*)malloc(total_len);
	memset(cmd, 0, total_len);
	cmd->op = CMD_GET_PROCESS_BY_INDEX;
	cmd->total_len = total_len;
	*((ULONG*)(&(cmd->param[0]))) = index;
	DeviceIoControl(h, IOCTL_CMD_READ, cmd, total_len, record, sizeof(PROCESS_RECORD), &dwReturn, NULL);

	free(cmd);
}

void yasi_get_process_detail(YASI_HANDLE h, ULONG processID, PROCESS_DETAIL* detail)
{
	if( !detail )
		return;
	DWORD dwReturn;
	ULONG total_len = sizeof(ULONG) + sizeof(ULONG) + sizeof(ULONG);
	CMD_RECORD* cmd = (CMD_RECORD*)malloc(total_len);
	memset(cmd, 0, total_len);
	cmd->op = CMD_GET_PROCESS_DETAIL;
	cmd->total_len = total_len;
	*((ULONG*)(&(cmd->param[0]))) = processID;
	DeviceIoControl(h, IOCTL_CMD_READ, cmd, total_len, detail, sizeof(PROCESS_DETAIL), &dwReturn, NULL);

	free(cmd);
}

ULONG yasi_get_peb_address(YASI_HANDLE h, ULONG processID)
{
	DWORD dwReturn;
	ULONG total_len = sizeof(ULONG) + sizeof(ULONG) + sizeof(ULONG);
	CMD_RECORD* cmd = (CMD_RECORD*)malloc(total_len);
	memset(cmd, 0, total_len);
	cmd->op = CMD_GET_PROCESS_STRING;
	cmd->total_len = total_len;
	ULONG* param = ((ULONG*)(&(cmd->param[0])));
	*param = processID;
	ULONG pebAddress = 0;
	DeviceIoControl(h, IOCTL_CMD_READ, cmd, total_len, &pebAddress, sizeof(ULONG), &dwReturn, NULL);
	free(cmd);

	return pebAddress;
}

ULONG yasi_get_base_address(YASI_HANDLE h, ULONG processID)
{
	ULONG pebAddress = yasi_get_peb_address(h, processID);
	ULONG ibaAddress = pebAddress+GetPlantformDependentInfo(ImageBaseAddress_OFFSET);
	ULONG baseAddress = 0;
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	ReadProcessMemory(process, (PVOID)ibaAddress, &baseAddress, sizeof(ULONG), NULL);
	CloseHandle(process);
	return baseAddress;
}

DllExport void yasi_get_process_string(YASI_HANDLE h, ULONG processID, PVOID addr, wchar_t* str, ULONG bufferLen)
{
	if( !str )
		return;
	ULONG dwReturn;
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	ReadProcessMemory(process, addr, (PVOID)str, bufferLen, &dwReturn);
	CloseHandle(process);
}

void yasi_get_process_info(YASI_HANDLE h, ULONG processID, UINT which, wchar_t* str)
{
	if( !str )
		return;

	ULONG pebAddress = yasi_get_peb_address(h, processID);
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	PVOID strPtr = GetStringPoint(process, pebAddress, which);
	ReadUnicodeString(process, (ULONG)strPtr, str);
	CloseHandle(process);

}

void yasi_kill_process(YASI_HANDLE h, ULONG processID)
{

	DWORD dwReturn;
	ULONG total_len = sizeof(ULONG) + sizeof(ULONG) + sizeof(ULONG);
	CMD_RECORD* cmd = (CMD_RECORD*)malloc(total_len);
	memset(cmd, 0, total_len);
	cmd->op = CMD_KILL_PROCESS;
	cmd->total_len = total_len;
	*((ULONG*)(&(cmd->param[0]))) = processID;
	DeviceIoControl(h, IOCTL_CMD_READ, cmd, total_len, NULL, 0, &dwReturn, NULL);

	free(cmd);
}


ULONG yasi_get_module_count(YASI_HANDLE h, ULONG processID)
{
	DWORD dwReturn;
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	ULONG pebAddress = yasi_get_peb_address(h, processID);
	ULONG ldrAddress = pebAddress + GetPlantformDependentInfo(Ldr_OFFSET);
	ULONG ldrDataAddress = 0;
	ReadProcessMemory(process, (PVOID)ldrAddress, &ldrDataAddress, sizeof(ULONG), &dwReturn);
	_PEB_LDR_DATA ldrData = {0};
	ReadProcessMemory(process, (PVOID)ldrDataAddress, &ldrData, sizeof(ldrData), &dwReturn);
	ULONG count = 0;
	LIST_ENTRY* first = ldrData.InLoadOrderModuleList.Flink;
	if( first == NULL ) return 0;

	LIST_ENTRY first_entry = {0};
	ReadProcessMemory(process, (PVOID)first, &first_entry, sizeof(LIST_ENTRY), &dwReturn);
	LIST_ENTRY* next = first_entry.Flink;
	do 
	{
		count++;
		if( next == first || next == first ) break;
		LIST_ENTRY tmp = {0};
		ReadProcessMemory(process, (PVOID)next, &tmp, sizeof(LIST_ENTRY), &dwReturn);
		next = tmp.Flink;
	} while (true);

	return count;
}

void yasi_get_module_info(YASI_HANDLE h, ULONG processID, ULONG index, LDR_DATA_TABLE_ENTRY_XP_SP3* info)
{
	DWORD dwReturn;
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	ULONG pebAddress = yasi_get_peb_address(h, processID);
	ULONG ldrAddress = pebAddress + GetPlantformDependentInfo(Ldr_OFFSET);
	ULONG ldrDataAddress = 0;
	ReadProcessMemory(process, (PVOID)ldrAddress, &ldrDataAddress, sizeof(ULONG), &dwReturn);
	_PEB_LDR_DATA ldrData = {0};
	ReadProcessMemory(process, (PVOID)ldrDataAddress, &ldrData, sizeof(ldrData), &dwReturn);
	ULONG count = 0;
	LIST_ENTRY* first = ldrData.InLoadOrderModuleList.Flink;
	if( first == NULL ) return;

	LIST_ENTRY first_entry = {0};
	ReadProcessMemory(process, (PVOID)first, &first_entry, sizeof(LIST_ENTRY), &dwReturn);
	LIST_ENTRY* next = first_entry.Flink;
	do 
	{
		if( count == index )
		{
			ReadProcessMemory(process, (PVOID)next, (PVOID)info, sizeof(LDR_DATA_TABLE_ENTRY_XP_SP3), &dwReturn);
			return;
		}
		count++;
		if( next == first || next == first ) break;
		LIST_ENTRY tmp = {0};
		ReadProcessMemory(process, (PVOID)next, &tmp, sizeof(LIST_ENTRY), &dwReturn);
		next = tmp.Flink;
	} while (true);
}

void yasi_load_dll(YASI_HANDLE h, ULONG processID, wchar_t* fullPath)
{
	FARPROC farLoadLibrary = yasi_get_proc_address(h, processID, ("Kernel32.dll"), ("LoadLibraryW"));

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if( process == NULL )
		return;
	LPVOID lpDllAddr = VirtualAllocEx(process, NULL, (wcslen(fullPath)+1)*sizeof(fullPath), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if( lpDllAddr == NULL )
	{
		CloseHandle(process);
		return;
	}
	if( !WriteProcessMemory(process, lpDllAddr, fullPath, (wcslen(fullPath)+1)*2, NULL))
	{
		CloseHandle(process);
		return;
	}
	HANDLE ht = CreateRemoteThread( process, 
		NULL, 
		0, 
		(LPTHREAD_START_ROUTINE)farLoadLibrary, 
		lpDllAddr, 0, NULL );

	CloseHandle(process);
}

FARPROC yasi_get_proc_address(YASI_HANDLE h, ULONG processID, char* _destDllName, char* _desFuncName)
{
	char* destDllName = new char[strlen(_destDllName)+1];
	memset(destDllName, 0, strlen(_destDllName)+1);
	strcpy(destDllName, _destDllName);
	char* desFuncName = new char[strlen(_desFuncName)+1];
	memset(desFuncName, 0, strlen(_desFuncName)+1);
	strcpy(desFuncName, _desFuncName);
	mtoupper(destDllName);
	mtoupper(desFuncName);
	ULONG dllBase = yasi_get_base_address(h, processID);

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if( process == NULL )
		return NULL ;
	IMAGE_DOS_HEADER dosHeader = {0};
	ReadProcessMemory(process, (PVOID)dllBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
	IMAGE_NT_HEADERS ntHeader = {0};
	ReadProcessMemory(process, (PVOID)(dllBase+dosHeader.e_lfanew), &ntHeader, sizeof(IMAGE_NT_HEADERS), NULL);
	IMAGE_IMPORT_DESCRIPTOR importDes = {0};
	ReadProcessMemory(process, (PVOID)(dllBase+ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress), &importDes, sizeof(importDes), NULL);
	ULONG imCount = 0;
	while (importDes.Name != 0)
	{

		PCHAR modeName = (PCHAR)(dllBase + (ULONG)importDes.Name);
		char _name[16] = {0};
		ReadProcessMemory(process, modeName, _name, 16, NULL);
		mtoupper(_name);
		if( strnicmp(_name, destDllName, 16)==0 )
		{
			IMAGE_THUNK_DATA orgTHunkData = {0};
			IMAGE_THUNK_DATA imgThunkData = {0};
			ReadProcessMemory(process, (PVOID)(dllBase+importDes.OriginalFirstThunk), &orgTHunkData, sizeof(orgTHunkData), NULL);
			ReadProcessMemory(process, (PVOID)(dllBase+importDes.FirstThunk), &imgThunkData, sizeof(imgThunkData), NULL);

			ULONG funCount = 0;
			while( imgThunkData.u1.Function )
			{
				IMAGE_IMPORT_BY_NAME* impName = (IMAGE_IMPORT_BY_NAME*)malloc(sizeof(IMAGE_IMPORT_BY_NAME)+32);
				ReadProcessMemory(process, (PVOID)(dllBase+orgTHunkData.u1.AddressOfData), impName, sizeof(IMAGE_IMPORT_BY_NAME)+32, NULL);

				char funcName[32] = {0};
				strcpy(funcName, (char*)(impName->Name));
				mtoupper(funcName);
				if( strnicmp(funcName, desFuncName, 32) == 0 )
				{
					free(impName);
					return (FARPROC)imgThunkData.u1.Function;
				}

				funCount++;
				ReadProcessMemory(process, (PVOID)(dllBase+importDes.OriginalFirstThunk + funCount*sizeof(IMAGE_THUNK_DATA)), &orgTHunkData, sizeof(orgTHunkData), NULL);
				ReadProcessMemory(process, (PVOID)(dllBase+importDes.FirstThunk + funCount*sizeof(IMAGE_THUNK_DATA)), &imgThunkData, sizeof(imgThunkData), NULL);
				free(impName);
			}
		}

		imCount++;
		ReadProcessMemory(process, (PVOID)(dllBase+ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + imCount*sizeof(importDes)), &importDes, sizeof(importDes), NULL);

	}
	return NULL;
}

void yasi_set_proc_address(YASI_HANDLE h, ULONG processID, char* _destDllName, char* _desFuncName, PVOID newAddr)
{
	char* destDllName = new char[strlen(_destDllName)+1];
	memset(destDllName, 0, strlen(_destDllName)+1);
	strcpy(destDllName, _destDllName);
	char* desFuncName = new char[strlen(_desFuncName)+1];
	memset(desFuncName, 0, strlen(_desFuncName)+1);
	strcpy(desFuncName, _desFuncName);
	mtoupper(destDllName);
	mtoupper(desFuncName);
	ULONG dllBase = yasi_get_base_address(h, processID);

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if( process == NULL )
		return ;
	IMAGE_DOS_HEADER dosHeader = {0};
	ReadProcessMemory(process, (PVOID)dllBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
	IMAGE_NT_HEADERS ntHeader = {0};
	ReadProcessMemory(process, (PVOID)(dllBase+dosHeader.e_lfanew), &ntHeader, sizeof(IMAGE_NT_HEADERS), NULL);
	IMAGE_IMPORT_DESCRIPTOR importDes = {0};
	ReadProcessMemory(process, (PVOID)(dllBase+ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress), &importDes, sizeof(importDes), NULL);
	ULONG imCount = 0;
	while (importDes.Name != 0)
	{

		PCHAR modeName = (PCHAR)(dllBase + (ULONG)importDes.Name);
		char _name[16] = {0};
		ReadProcessMemory(process, modeName, _name, 16, NULL);
		mtoupper(_name);
		if( strnicmp(_name, destDllName, 16)==0 )
		{
			IMAGE_THUNK_DATA orgTHunkData = {0};
			IMAGE_THUNK_DATA imgThunkData = {0};
			ReadProcessMemory(process, (PVOID)(dllBase+importDes.OriginalFirstThunk), &orgTHunkData, sizeof(orgTHunkData), NULL);
			ReadProcessMemory(process, (PVOID)(dllBase+importDes.FirstThunk), &imgThunkData, sizeof(imgThunkData), NULL);

			ULONG funCount = 0;
			while( imgThunkData.u1.Function )
			{
				IMAGE_IMPORT_BY_NAME* impName = (IMAGE_IMPORT_BY_NAME*)malloc(sizeof(IMAGE_IMPORT_BY_NAME)+32);
				ReadProcessMemory(process, (PVOID)(dllBase+orgTHunkData.u1.AddressOfData), impName, sizeof(IMAGE_IMPORT_BY_NAME)+32, NULL);

				char funcName[32] = {0};
				strcpy(funcName, (char*)(impName->Name));
				mtoupper(funcName);
				if( strnicmp(funcName, desFuncName, 32) == 0 )
				{
					free(impName);
					ULONG funcAddress = (dllBase+importDes.FirstThunk + funCount*sizeof(IMAGE_THUNK_DATA));
					WriteProcessMemory(process, (LPVOID)funcAddress, &newAddr, 4, NULL);
					return;
				}

				funCount++;
				ReadProcessMemory(process, (PVOID)(dllBase+importDes.OriginalFirstThunk + funCount*sizeof(IMAGE_THUNK_DATA)), &orgTHunkData, sizeof(orgTHunkData), NULL);
				ReadProcessMemory(process, (PVOID)(dllBase+importDes.FirstThunk + funCount*sizeof(IMAGE_THUNK_DATA)), &imgThunkData, sizeof(imgThunkData), NULL);
				free(impName);
			}
		}

		imCount++;
		ReadProcessMemory(process, (PVOID)(dllBase+ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + imCount*sizeof(importDes)), &importDes, sizeof(importDes), NULL);

	}
	return ;
}