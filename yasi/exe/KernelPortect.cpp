// KernelPortect.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include "KernelProtect.h"
#include <stdlib.h>

#include "../yasi.h"
// {D91E1EB2-97C0-4459-B30A-731543F407C6}
TCHAR NAME[] = _T("{D91E1EB2-97C0-4459-B30A-731543F407C6}");

HANDLE LoadDriver();
void UnloadDriver(HANDLE file);
int _tmain(int argc, _TCHAR* argv[])
{

	DWORD dwReturn;
	HANDLE hFile = yasi_create();


	PROCESS_DETAIL detail = {0};
	yasi_get_process_detail(hFile, 536, &detail);

	//DWORD processCount = yasi_get_process_count(hFile);


	//for( int index = 0 ; index < processCount; index++ ){
	//	PROCESS_RECORD proc = {0};
	//	yasi_get_process(hFile, index, &proc);
	//	printf("[%d] %s \r\n", proc.processID, proc.imageName);

	//}

	yasi_destroy(hFile);
	return 0;
}
