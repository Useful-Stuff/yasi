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
	//HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	yasi_read_process_memory(h, processID, (PVOID)ibaAddress, &baseAddress, sizeof(ULONG), NULL);
	//CloseHandle(process);
	return baseAddress;
}

DllExport void yasi_get_process_string(YASI_HANDLE h, ULONG processID, PVOID addr, wchar_t* str, ULONG bufferLen)
{
	if( !str )
		return;
	ULONG dwReturn;
	//HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	yasi_read_process_memory(h, processID, addr, (PVOID)str, bufferLen, &dwReturn);
	//CloseHandle(process);
}

void yasi_get_process_info(YASI_HANDLE h, ULONG processID, UINT which, wchar_t* str)
{
	if( !str )
		return;

	ULONG pebAddress = yasi_get_peb_address(h, processID);
	//HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	PVOID strPtr = GetStringPoint(h, processID, pebAddress, which);
	ReadUnicodeString(h, processID, (ULONG)strPtr, str);
	//CloseHandle(process);

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
	//HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	ULONG pebAddress = yasi_get_peb_address(h, processID);
	ULONG ldrAddress = pebAddress + GetPlantformDependentInfo(Ldr_OFFSET);
	ULONG ldrDataAddress = 0;
	yasi_read_process_memory(h, processID, (PVOID)ldrAddress, &ldrDataAddress, sizeof(ULONG), &dwReturn);
	_PEB_LDR_DATA ldrData = {0};
	yasi_read_process_memory(h, processID, (PVOID)ldrDataAddress, &ldrData, sizeof(ldrData), &dwReturn);
	ULONG count = 0;
	LIST_ENTRY* first = ldrData.InLoadOrderModuleList.Flink;
	if( first == NULL ) return 0;

	LIST_ENTRY first_entry = {0};
	yasi_read_process_memory(h, processID, (PVOID)first, &first_entry, sizeof(LIST_ENTRY), &dwReturn);
	LIST_ENTRY* next = first_entry.Flink;
	do 
	{
		count++;
		if( next == first || next == first ) break;
		LIST_ENTRY tmp = {0};
		yasi_read_process_memory(h, processID, (PVOID)next, &tmp, sizeof(LIST_ENTRY), &dwReturn);
		next = tmp.Flink;
	} while (true);

	return count;
}

void yasi_get_module_info(YASI_HANDLE h, ULONG processID, ULONG index, LDR_DATA_TABLE_ENTRY_XP_SP3* info)
{
	DWORD dwReturn;
	//HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	ULONG pebAddress = yasi_get_peb_address(h, processID);
	ULONG ldrAddress = pebAddress + GetPlantformDependentInfo(Ldr_OFFSET);
	ULONG ldrDataAddress = 0;
	yasi_read_process_memory(h, processID, (PVOID)ldrAddress, &ldrDataAddress, sizeof(ULONG), &dwReturn);
	_PEB_LDR_DATA ldrData = {0};
	yasi_read_process_memory(h, processID, (PVOID)ldrDataAddress, &ldrData, sizeof(ldrData), &dwReturn);
	ULONG count = 0;
	LIST_ENTRY* first = ldrData.InLoadOrderModuleList.Flink;
	if( first == NULL ) return;

	LIST_ENTRY first_entry = {0};
	yasi_read_process_memory(h, processID, (PVOID)first, &first_entry, sizeof(LIST_ENTRY), &dwReturn);
	LIST_ENTRY* next = first_entry.Flink;
	do 
	{
		if( count == index )
		{
			yasi_read_process_memory(h, processID, (PVOID)next, (PVOID)info, sizeof(LDR_DATA_TABLE_ENTRY_XP_SP3), &dwReturn);
			return;
		}
		count++;
		if( next == first || next == first ) break;
		LIST_ENTRY tmp = {0};
		yasi_read_process_memory(h, processID, (PVOID)next, &tmp, sizeof(LIST_ENTRY), &dwReturn);
		next = tmp.Flink;
	} while (true);
}

void yasi_load_dll(YASI_HANDLE h, ULONG processID, wchar_t* fullPath)
{
	FARPROC farLoadLibrary = yasi_get_proc_address(h, processID, ("Kernel32.dll"), ("LoadLibraryW"));

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if( process == NULL || farLoadLibrary == NULL)
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

	//HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	//if( process == NULL )
	//	return NULL ;
	IMAGE_DOS_HEADER dosHeader = {0};
	yasi_read_process_memory(h, processID, (PVOID)dllBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
	IMAGE_NT_HEADERS ntHeader = {0};
	yasi_read_process_memory(h, processID, (PVOID)(dllBase+dosHeader.e_lfanew), &ntHeader, sizeof(IMAGE_NT_HEADERS), NULL);
	IMAGE_IMPORT_DESCRIPTOR importDes = {0};
	yasi_read_process_memory(h, processID, (PVOID)(dllBase+ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress), &importDes, sizeof(importDes), NULL);
	ULONG imCount = 0;
	while (importDes.Name != 0)
	{

		PCHAR modeName = (PCHAR)(dllBase + (ULONG)importDes.Name);
		char _name[16] = {0};
		yasi_read_process_memory(h, processID, modeName, _name, 16, NULL);
		mtoupper(_name);
		if( strnicmp(_name, destDllName, 16)==0 )
		{
			IMAGE_THUNK_DATA orgTHunkData = {0};
			IMAGE_THUNK_DATA imgThunkData = {0};
			yasi_read_process_memory(h, processID, (PVOID)(dllBase+importDes.OriginalFirstThunk), &orgTHunkData, sizeof(orgTHunkData), NULL);
			yasi_read_process_memory(h, processID, (PVOID)(dllBase+importDes.FirstThunk), &imgThunkData, sizeof(imgThunkData), NULL);

			ULONG funCount = 0;
			while( imgThunkData.u1.Function )
			{
				IMAGE_IMPORT_BY_NAME* impName = (IMAGE_IMPORT_BY_NAME*)malloc(sizeof(IMAGE_IMPORT_BY_NAME)+64);
				memset(impName, 0, sizeof(IMAGE_IMPORT_BY_NAME)+64);
				if( !yasi_read_process_memory(h, processID, (PVOID)(dllBase+orgTHunkData.u1.AddressOfData), impName, sizeof(IMAGE_IMPORT_BY_NAME)+64, NULL))
					break;
				if( impName->Name == NULL )
					break;
				char funcName[64] = {0};
				strcpy(funcName, (char*)(impName->Name));
				mtoupper(funcName);
				if( strnicmp(funcName, desFuncName, 64) == 0 )
				{
					free(impName);
					return (FARPROC)imgThunkData.u1.Function;
				}

				funCount++;
				yasi_read_process_memory(h, processID, (PVOID)(dllBase+importDes.OriginalFirstThunk + funCount*sizeof(IMAGE_THUNK_DATA)), &orgTHunkData, sizeof(orgTHunkData), NULL);
				yasi_read_process_memory(h, processID, (PVOID)(dllBase+importDes.FirstThunk + funCount*sizeof(IMAGE_THUNK_DATA)), &imgThunkData, sizeof(imgThunkData), NULL);
				free(impName);
			}
		}

		imCount++;
		yasi_read_process_memory(h, processID, (PVOID)(dllBase+ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + imCount*sizeof(importDes)), &importDes, sizeof(importDes), NULL);

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

	//HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	//if( process == NULL )
	//	return ;
	IMAGE_DOS_HEADER dosHeader = {0};
	yasi_read_process_memory(h, processID, (PVOID)dllBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
	IMAGE_NT_HEADERS ntHeader = {0};
	yasi_read_process_memory(h, processID, (PVOID)(dllBase+dosHeader.e_lfanew), &ntHeader, sizeof(IMAGE_NT_HEADERS), NULL);
	IMAGE_IMPORT_DESCRIPTOR importDes = {0};
	yasi_read_process_memory(h, processID, (PVOID)(dllBase+ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress), &importDes, sizeof(importDes), NULL);
	ULONG imCount = 0;
	while (importDes.Name != 0)
	{

		PCHAR modeName = (PCHAR)(dllBase + (ULONG)importDes.Name);
		char _name[16] = {0};
		yasi_read_process_memory(h, processID, modeName, _name, 16, NULL);
		mtoupper(_name);
		if( strnicmp(_name, destDllName, 16)==0 )
		{
			IMAGE_THUNK_DATA orgTHunkData = {0};
			IMAGE_THUNK_DATA imgThunkData = {0};
			yasi_read_process_memory(h, processID, (PVOID)(dllBase+importDes.OriginalFirstThunk), &orgTHunkData, sizeof(orgTHunkData), NULL);
			yasi_read_process_memory(h, processID, (PVOID)(dllBase+importDes.FirstThunk), &imgThunkData, sizeof(imgThunkData), NULL);

			ULONG funCount = 0;
			while( imgThunkData.u1.Function )
			{
				IMAGE_IMPORT_BY_NAME* impName = (IMAGE_IMPORT_BY_NAME*)malloc(sizeof(IMAGE_IMPORT_BY_NAME)+64);
				yasi_read_process_memory(h, processID, (PVOID)(dllBase+orgTHunkData.u1.AddressOfData), impName, sizeof(IMAGE_IMPORT_BY_NAME)+64, NULL);

				char funcName[64] = {0};
				strcpy(funcName, (char*)(impName->Name));
				mtoupper(funcName);
				if( strnicmp(funcName, desFuncName, 64) == 0 )
				{
					free(impName);
					ULONG funcAddress = (dllBase+importDes.FirstThunk + funCount*sizeof(IMAGE_THUNK_DATA));
					DWORD dwRet = 0;
					DWORD error = 0;
					BOOL ret = yasi_write_process_memory(h, processID, (PVOID)funcAddress, &newAddr, 4, &dwRet);
					if( !ret )
					{
						error = GetLastError();
					}
					return;
				}

				funCount++;
				yasi_read_process_memory(h, processID, (PVOID)(dllBase+importDes.OriginalFirstThunk + funCount*sizeof(IMAGE_THUNK_DATA)), &orgTHunkData, sizeof(orgTHunkData), NULL);
				yasi_read_process_memory(h, processID, (PVOID)(dllBase+importDes.FirstThunk + funCount*sizeof(IMAGE_THUNK_DATA)), &imgThunkData, sizeof(imgThunkData), NULL);
				free(impName);
			}
		}

		imCount++;
		yasi_read_process_memory(h, processID, (PVOID)(dllBase+ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + imCount*sizeof(importDes)), &importDes, sizeof(importDes), NULL);

	}
	return ;
}


FARPROC yasi_get_export_address(YASI_HANDLE h, ULONG processID, wchar_t* _destDllName, char* _desFuncName)
{
	wchar_t* destDllName = new wchar_t[(wcslen(_destDllName)+1)];
	memset(destDllName, 0, sizeof(wchar_t)*(wcslen(_destDllName)+1));
	wcscpy(destDllName, _destDllName);
	char* desFuncName = new char[strlen(_desFuncName)+1];
	memset(desFuncName, 0, strlen(_desFuncName)+1);
	strcpy(desFuncName, _desFuncName);
	mtoupper(desFuncName);
	//ULONG dllBase = yasi_get_base_address(h, processID);
	ULONG dllBase = NULL;
	BOOL found = FALSE;
	UINT count = yasi_get_module_count(h, processID);
	for( int index = 0 ; index < count; index++ )
	{
		LDR_DATA_TABLE_ENTRY_XP_SP3 info = {0};
		yasi_get_module_info(h, processID, index, &info);
		wchar_t tmpStr[256] = {0};
		yasi_get_process_string(h, processID, info.BaseDllName.Buffer, tmpStr, info.BaseDllName.Length);
		if( wcscmp(tmpStr, _destDllName) == 0 )
		{
			found = TRUE;
			dllBase = (ULONG)info.DllBase;
			break;
		}
	}
	if( !found )
		return NULL;

	//HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	//if( process == NULL )
	//	return NULL;
	IMAGE_DOS_HEADER dosHeader = {0};
	yasi_read_process_memory(h, processID, (PVOID)dllBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
	IMAGE_NT_HEADERS ntHeader = {0};
	yasi_read_process_memory(h, processID, (PVOID)(dllBase+dosHeader.e_lfanew), &ntHeader, sizeof(IMAGE_NT_HEADERS), NULL);
	IMAGE_OPTIONAL_HEADER optionalHeader = ntHeader.OptionalHeader;
	IMAGE_DATA_DIRECTORY dataDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	//yasi_read_process_memory(h, processID, (PVOID)(optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), &dataDirectory,
	//	sizeof( IMAGE_DATA_DIRECTORY), NULL);
	IMAGE_EXPORT_DIRECTORY ExportDirectory = {0};
	yasi_read_process_memory(h, processID, (PVOID)(dllBase + dataDirectory.VirtualAddress), &ExportDirectory, sizeof(ExportDirectory), NULL);
	//some code comes from http://bbs.pediy.com/showthread.php?t=58199
	PULONG NameTableBase = (PULONG)((PCHAR)dllBase + (ULONG)ExportDirectory.AddressOfNames);
	PUSHORT  NameOrdinalTableBase = (PUSHORT )((PCHAR)dllBase + (ULONG)ExportDirectory.AddressOfNameOrdinals);

	ULONG Middle = 0;
	ULONG High = ExportDirectory.NumberOfNames - 1;
	ULONG Low = 0;
	while (High >= Low) {
		Middle = (Low + High) >> 1;
		ULONG nameTableIndex = 0;
		yasi_read_process_memory(h, processID, (PVOID)(NameTableBase+Low), &nameTableIndex, sizeof(ULONG), NULL);
		PCHAR nameBase = (PCHAR)((ULONG)dllBase + (ULONG)nameTableIndex);
		char tmpName[64] = {0};
		yasi_read_process_memory(h, processID, (PVOID)(nameBase), tmpName, 64, NULL);
		mtoupper(tmpName);


		int Result = strcmp (tmpName, desFuncName);

		if( Result != 0 ){
			Low++;
		}else {
			break;
		}
	}

	if (High < Low) {
		return NULL;
	}


	USHORT OrdinalNumber = 0;
	yasi_read_process_memory(h, processID, (PVOID)(NameOrdinalTableBase+Low), &OrdinalNumber, sizeof(USHORT), NULL);


	if ((ULONG)OrdinalNumber >= ExportDirectory.NumberOfFunctions) {
		return NULL;
	}

	PULONG Addr = (PULONG)((PCHAR)dllBase + (ULONG)ExportDirectory.AddressOfFunctions);

	PULONG FunctionAddress  = 0;
	ULONG addrOffset = 0;
	yasi_read_process_memory(h, processID, Addr+OrdinalNumber, &addrOffset, sizeof(ULONG), NULL);
	FunctionAddress = (PULONG)(dllBase + addrOffset);
	return (FARPROC)FunctionAddress;

}

BOOL yasi_read_process_memory(YASI_HANDLE h, ULONG processID, PVOID lpBaseAddress, PVOID lpBuffer, ULONG size, ULONG* bytesRead)
{
	DWORD dwReturn;
	ULONG total_len = sizeof(ULONG) + sizeof(ULONG) + sizeof(ULONG)*4;
	CMD_RECORD* cmd = (CMD_RECORD*)malloc(total_len);
	memset(cmd, 0, total_len);
	cmd->op = CMD_READ_PROCESS_MEMORY;
	cmd->total_len = total_len;
	ULONG* tmp = (ULONG*)(&(cmd->param[0]));
	*tmp = (ULONG)processID;
	tmp++;
	*tmp = (ULONG)lpBaseAddress;
	tmp++;
	*tmp = (ULONG)lpBuffer;
	tmp++;
	*tmp = size;

	ULONG outSize = (bytesRead == NULL ? 0: sizeof(ULONG));
	BOOL ret = DeviceIoControl(h, IOCTL_CMD_READ, cmd, total_len, bytesRead, outSize, &dwReturn, NULL);

	free(cmd);

	return ret;
}

BOOL yasi_write_process_memory(YASI_HANDLE h, ULONG processID, PVOID lpBaseAddress, PVOID lpBuffer, ULONG size, ULONG* bytesWrite)
{
	DWORD dwReturn;
	ULONG total_len = sizeof(ULONG) + sizeof(ULONG) + sizeof(ULONG)*4;
	CMD_RECORD* cmd = (CMD_RECORD*)malloc(total_len);
	memset(cmd, 0, total_len);
	cmd->op = CMD_WRITE_PROCESS_MEMORY;
	cmd->total_len = total_len;
	ULONG* tmp = (ULONG*)(&(cmd->param[0]));
	*tmp = (ULONG)processID;
	tmp++;
	*tmp = (ULONG)lpBaseAddress;
	tmp++;
	*tmp = (ULONG)lpBuffer;
	tmp++;
	*tmp = size;

	ULONG outSize = (bytesWrite == NULL ? 0: sizeof(ULONG));
	BOOL ret = DeviceIoControl(h, IOCTL_CMD_READ, cmd, total_len, bytesWrite, outSize, &dwReturn, NULL);

	free(cmd);

	return ret;
}

ULONG yasi_get_thread_count(YASI_HANDLE h, ULONG processID)
{
	PROCESS_DETAIL detail = {0};
	yasi_get_process_detail(h, processID, &detail);
	return detail.process.ActiveThreads;
}

void yasi_get_thread_detail(YASI_HANDLE h, ULONG processID, ULONG threadIndex, THREAD_DETAIL* detail)
{
	DWORD dwReturn;
	ULONG total_len = sizeof(ULONG) + sizeof(ULONG) + sizeof(ULONG)*2;
	CMD_RECORD* cmd = (CMD_RECORD*)malloc(total_len);
	memset(cmd, 0, total_len);
	cmd->op = CMD_GET_THREAD_DETAIL;
	cmd->total_len = total_len;
	ULONG* tmp = (ULONG*)(&(cmd->param[0]));
	*tmp = (ULONG)processID;
	tmp++;
	*tmp = (ULONG)threadIndex;

	BOOL ret = DeviceIoControl(h, IOCTL_CMD_READ, cmd, total_len, detail, sizeof(THREAD_DETAIL), &dwReturn, NULL);

	free(cmd);

	return;
}


void yasi_export_all_func(YASI_HANDLE h , ULONG processID, char* fileName)
{
	ULONG distance = 0xffffffff;
	FILE* file = fopen(fileName, "wb");
	if( file == NULL )
		return;

	ULONG dllBase = NULL;
	BOOL found = FALSE;
	UINT count = yasi_get_module_count(h, processID);
	for( int index = 0 ; index < count; index++ )
	{
		LDR_DATA_TABLE_ENTRY_XP_SP3 info = {0};
		yasi_get_module_info(h, processID, index, &info);
		wchar_t dllname[256] = {0};
		yasi_get_process_string(h, processID, info.BaseDllName.Buffer, dllname, info.BaseDllName.Length);
		dllBase = (ULONG)info.DllBase;
		





		IMAGE_DOS_HEADER dosHeader = {0};
		yasi_read_process_memory(h, processID, (PVOID)dllBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL);
		IMAGE_NT_HEADERS ntHeader = {0};
		yasi_read_process_memory(h, processID, (PVOID)(dllBase+dosHeader.e_lfanew), &ntHeader, sizeof(IMAGE_NT_HEADERS), NULL);
		IMAGE_OPTIONAL_HEADER optionalHeader = ntHeader.OptionalHeader;
		IMAGE_DATA_DIRECTORY dataDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		//yasi_read_process_memory(h, processID, (PVOID)(optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), &dataDirectory,
		//	sizeof( IMAGE_DATA_DIRECTORY), NULL);
		IMAGE_EXPORT_DIRECTORY ExportDirectory = {0};
		yasi_read_process_memory(h, processID, (PVOID)(dllBase + dataDirectory.VirtualAddress), &ExportDirectory, sizeof(ExportDirectory), NULL);
		//some code comes from http://bbs.pediy.com/showthread.php?t=58199
		PULONG NameTableBase = (PULONG)((PCHAR)dllBase + (ULONG)ExportDirectory.AddressOfNames);
		PUSHORT  NameOrdinalTableBase = (PUSHORT )((PCHAR)dllBase + (ULONG)ExportDirectory.AddressOfNameOrdinals);

		ULONG Middle = 0;
		ULONG High = ExportDirectory.NumberOfNames - 1;
		ULONG Low = 0;
		while (High >= Low) {
			Middle = (Low + High) >> 1;
			ULONG nameTableIndex = 0;
			yasi_read_process_memory(h, processID, (PVOID)(NameTableBase+Low), &nameTableIndex, sizeof(ULONG), NULL);
			PCHAR nameBase = (PCHAR)((ULONG)dllBase + (ULONG)nameTableIndex);
			char tmpName[64] = {0};
			yasi_read_process_memory(h, processID, (PVOID)(nameBase), tmpName, 64, NULL);
			

			USHORT OrdinalNumber = 0;
			yasi_read_process_memory(h, processID, (PVOID)(NameOrdinalTableBase+Low), &OrdinalNumber, sizeof(USHORT), NULL);


			if ((ULONG)OrdinalNumber >= ExportDirectory.NumberOfFunctions) {
				return;
			}

			PULONG Addr = (PULONG)((PCHAR)dllBase + (ULONG)ExportDirectory.AddressOfFunctions);

			PULONG FunctionAddress  = 0;
			ULONG addrOffset = 0;
			yasi_read_process_memory(h, processID, Addr+OrdinalNumber, &addrOffset, sizeof(ULONG), NULL);
			FunctionAddress = (PULONG)(dllBase + addrOffset);

			char cDllName[256] = {0};
			wchar_t* itor = dllname;
			char* cItor = cDllName;
			while( itor != NULL && *itor != _T('\0')){
				*cItor = (char)(*itor);
				cItor++;
				itor++;
			}
			*cItor = '\0';
			fwrite(cDllName, (strlen(cDllName)+0), 1, file);
			fwrite("||", 2, 1, file);
			fwrite(tmpName, strlen(tmpName), 1, file);
			fwrite("||", 2, 1, file);
			char numTpm[32] = {0};
			sprintf_s(numTpm, 32, "%d", FunctionAddress);
			fwrite(numTpm, strlen(numTpm)+0, 1, file);
			fwrite("\r\n", 2, 1, file);
			Low++;
		}
	}
	fflush(file);
	fclose(file);

}


void yasi_kill_thread(YASI_HANDLE h, ULONG processID, ULONG threadID)
{
	DWORD dwReturn;
	ULONG total_len = sizeof(ULONG) + sizeof(ULONG) + sizeof(ULONG)*2;
	CMD_RECORD* cmd = (CMD_RECORD*)malloc(total_len);
	memset(cmd, 0, total_len);
	cmd->op = CMD_KILL_THREAD;
	cmd->total_len = total_len;
	ULONG* tmp = (ULONG*)(&(cmd->param[0]));
	*tmp = (ULONG)processID;
	tmp++;
	*tmp = (ULONG)threadID;

	BOOL ret = DeviceIoControl(h, IOCTL_CMD_READ, cmd, total_len, NULL, 0, &dwReturn, NULL);

	free(cmd);

	return;
}