#include "stdafx.h"
#include "../yasi.h"
#include "DrvComm.h"


YASI_HANDLE yasi_create()
{
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