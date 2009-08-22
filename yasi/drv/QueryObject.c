#define _X86_ 
#include <Ntifs.h>
#include <ntddk.h>
#include "KernelProtect.h"
#include "QueryObject.h"

#ifdef XP_SP3
void QueryFileName(HANDLE h, PVOID object, wchar_t* name)
{
	PFILE_OBJECT_XP_SP3 fileObject = (PFILE_OBJECT_XP_SP3)object;
	ULONG strLen = fileObject->FileName.Length;

	if( strLen > 1022 )
		strLen = 1022;

	if( MmIsAddressValid( fileObject->FileName.Buffer) )
		memcpy(name, fileObject->FileName.Buffer, strLen);
}
void QueryEventName(HANDLE h, PVOID object, wchar_t* name)
{

}

void QueryKeyNameByAPI(HANDLE h, ULONG EProcess, PVOID object, wchar_t* name)
{
	PKEY_NAME_INFORMATION nameInfo;
	ULONG dwRet;
	ULONG strLen;
	NTSTATUS status;
	PVOID			SystemAddress;
	PMDL			mdl;
	KAPC_STATE apc;
	nameInfo = (PKEY_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, 2048, 1001);
	memset(nameInfo, 0, 2048);
	mdl = MmCreateMdl(NULL, nameInfo, 2048);
	MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
	KeStackAttachProcess ((PEPROCESS)EProcess, &apc);
	SystemAddress = MmGetSystemAddressForMdl(mdl);
	status = ZwQueryKey(h,  KeyNameInformation, SystemAddress, 2048, &dwRet);
	KeDetachProcess( &apc);
	if( status == STATUS_SUCCESS )
	{
		strLen = nameInfo->NameLength;
		if( strLen > 1022 )
			strLen = 1022;

		if( MmIsAddressValid( nameInfo->Name ) )
			memcpy(name, nameInfo->Name, strLen*sizeof(wchar_t));
	}

	if( mdl->MappedSystemVa != NULL ){
		MmUnmapLockedPages(mdl->MappedSystemVa, mdl);
	}
	MmUnlockPages(mdl);
	ExFreePool(mdl);
	ExFreePool(nameInfo);

}

void QueryKeyNameByOurselves(PVOID object, wchar_t* name)
{
	PCM_KEY_BODY_XP_SP3 keyBody = (PCM_KEY_BODY_XP_SP3)object;
	PCM_KEY_CONTROL_BLOCK_XP_SP3 Kcb = (PCM_KEY_CONTROL_BLOCK_XP_SP3)keyBody->KeyControlBlock;
	PCM_KEY_CONTROL_BLOCK_XP_SP3 tmpKcb = Kcb;
	ULONG bufferLength = 0;
	PVOID Buffer = NULL ;
	ULONG base = 1;
	wchar_t* current;
	wchar_t* cur_inStr;
	ULONG index;
	ULONG strLen;

	//Kcb->NameBlock->NameLength是Buffer大小，不是字符长短

	while( tmpKcb ){
		if( tmpKcb->NameBlock->Compressed ){ //ascii
			base = sizeof(wchar_t);
		}else{ //unicode
			base = 1;
		}
		bufferLength += (tmpKcb->NameBlock->NameLength)*base; //+1是因为有分隔符
		bufferLength += sizeof(wchar_t);
		tmpKcb = (PCM_KEY_CONTROL_BLOCK_XP_SP3)tmpKcb->ParentKcb;
	}
	bufferLength += 2;//末两位为0
	Buffer = ExAllocatePoolWithTag(PagedPool, bufferLength, 1001);
	memset(Buffer, 0, bufferLength);

	current = (char*)Buffer + bufferLength - 2;//-2是因为current是wchar_t类型的
	tmpKcb = Kcb;
	while( tmpKcb ){

		if( tmpKcb->NameBlock->Compressed ){ //ascii
			current -= (tmpKcb->NameBlock->NameLength+1);
			cur_inStr = current;
			*cur_inStr = (wchar_t)'\\';
			cur_inStr++;
			for(index = 0 ; index < tmpKcb->NameBlock->NameLength; index++ ){
				*cur_inStr = (wchar_t)(((char*)&tmpKcb->NameBlock->Name[0])[index]);
				cur_inStr++;
			}
		}else{
			current -= tmpKcb->NameBlock->NameLength;
			cur_inStr = current;
			*cur_inStr = (wchar_t)'\\';
			for(index = 0 ; index < tmpKcb->NameBlock->NameLength; index++ ){
				*cur_inStr = (wchar_t)(((wchar_t*)&tmpKcb->NameBlock->Name[0])[index]);
				cur_inStr++;
			}
		}
		tmpKcb = (PCM_KEY_CONTROL_BLOCK_XP_SP3)tmpKcb->ParentKcb;
	}
	strLen = bufferLength;
	if( strLen > 1022*sizeof(wchar_t) )
		strLen = 1022*sizeof(wchar_t);
	memcpy(name, Buffer, strLen);

	ExFreePool(Buffer);
}

void QueryKeyName(HANDLE h, ULONG EProcess, PVOID object, wchar_t* name)
{
	//QueryKeyNameByAPI(h, EProcess, object, name);
	QueryKeyNameByOurselves(object, name);
}
void QueryMutantName(HANDLE h, PVOID object, wchar_t* name)
{

}
void QuerySectionName(HANDLE h, PVOID object, wchar_t* name)
{

}
void QuerySymbolicLinkName(HANDLE h, PVOID object, wchar_t* name)
{

}
#else
#endif
