#define _X86_ 
#include <Ntifs.h>
#include <ntddk.h>
#include "KernelProtect.h"
#include "QueryObject.h"

#define   MAX_ENTRY_COUNT (0x1000/8)
#define   MAX_ADDR_COUNT   (0x1000/4) 

extern BOOL FindProcessByID(ULONG id, ULONG* pProcess);

ULONG GetHandleCount(ULONG pid)
{
#ifdef XP_SP3
	BOOL found;
	EPROCESS_XP_SP3* EProcess;
	PHANDLE_TABLE_XP_SP3 HandleTable;
	ULONG MaxHandle;

	found = FindProcessByID(pid, &((ULONG)EProcess));
	if( !found )
		return 0;
	//DbgPrint("[ring0] eprocess 0x%x", EProcess);
	HandleTable = (PHANDLE_TABLE_XP_SP3)EProcess->ObjectTable;
	if( HandleTable == NULL )
		return 0;
	//DbgPrint("[ring0] HandleTable 0x%x", HandleTable);
	MaxHandle=HandleTable->HandleCount;
	return MaxHandle;

#else
	return 0;
#endif
}

PHANDLE_TABLE_ENTRY_XP_SP3 GetTableEntry(PHANDLE_TABLE_ENTRY_XP_SP3 first, int index)
{
	int i = 0;
	PHANDLE_TABLE_ENTRY_XP_SP3 ret = first;
	PHANDLE_TABLE_ENTRY_XP_SP3 current;
	ULONG count = 0;
	/*while(1)
	{
		current = ret;
		if( current->u1.Object && MmIsAddressValid(current->u1.Object) ){
			count++;
			if( count > index )
				return current; 
		}
		ret++;
		i++;
		if( i > 2048 )
			return NULL;
	}
	return NULL;*/
	return &(first[index]);
}

BOOL FindObjectByIndex(ULONG pid, ULONG index, ULONG* obj, ULONG* handle)
{
#ifdef XP_SP3
	BOOL found;
	EPROCESS_XP_SP3* EProcess;
	PHANDLE_TABLE_XP_SP3 HandleTable;
	ULONG i,j,k,count;
	ULONG_PTR CapturedTable;
	ULONG TableLevel;
	PHANDLE_TABLE_ENTRY_XP_SP3 TableLevel1,*TableLevel2,**TableLevel3;
	BOOLEAN CallBackRetned=FALSE;
	BOOLEAN ResultValue=FALSE;
	ULONG MaxHandle;
	PVOID foundHandle;
	BOOL handleCanFound = FALSE;
	PHANDLE_TABLE_ENTRY_XP_SP3 current;



	count = 0;
	found = FindProcessByID(pid, &((ULONG)EProcess));

	if( !found )
		return ;
	HandleTable = (PHANDLE_TABLE_XP_SP3)EProcess->ObjectTable;
	if( HandleTable == NULL )
		return ;

	//DbgPrint("[ring0] TableCode 0x%x", HandleTable->TableCode);
	CapturedTable=(HandleTable->TableCode)&~3;
	TableLevel=(HandleTable->TableCode)&3;
	MaxHandle=HandleTable->NextHandleNeedingPool;

	if( index >= MaxHandle )
		return FALSE;

	//DbgPrint("[ring0] TableLevel 0x%x", TableLevel);
	//DbgPrint("[ring0] CapturedTable 0x%x", CapturedTable);
	switch(TableLevel)
	{
	case 0:
		{
			//一级表
			TableLevel1=(PHANDLE_TABLE_ENTRY_XP_SP3)CapturedTable;
			//current = GetTableEntry(TableLevel1, index);
			current = &(TableLevel1[index]);

			//DbgPrint("[ring0] current 0x%x", current);
			//DbgPrint("[ring0] current.Object 0x%x", current.u1.Object);

			if( current->u1.Object && MmIsAddressValid((ULONG)current->u1.Object & 0xFFFFFFF8) ){
				handleCanFound = TRUE;
				foundHandle = current->u1.Object;
				*handle=(index*4);

				break;
			}
		}
		break;
	case 1:
		{
			//二级表
			count = 0;
			TableLevel2=(PHANDLE_TABLE_ENTRY_XP_SP3*)CapturedTable;
			for (j=0;j<MaxHandle/(MAX_ENTRY_COUNT*4);j++)
			{
				//TableLevel1= GetTableEntry(TableLevel2,j);
				TableLevel1 = TableLevel2[j];
				//DbgPrint("[ring0]---TableLevel1 0x%x", TableLevel1);
				if (!TableLevel1)
					break; //为零则跳出
				for (i=0;i<MAX_ENTRY_COUNT;i++)
				{
					//current = GetTableEntry(TableLevel1, i);
					current = &(TableLevel1[i]);
					//DbgPrint("[ring0]------current 0x%x", current);
					if( current->u1.Object && MmIsAddressValid((ULONG)current->u1.Object & 0xFFFFFFF8) ){
						if( count == index ){
							handleCanFound = TRUE;
							foundHandle = current->u1.Object;
							*handle=(j*MAX_ENTRY_COUNT*4+i*4);
							break;
						}else{
							count++;
						}
					}
				}//end of for i
			}//end of for j
		}
		break;
	case 2:
		{
			//三级表
			count = 0;
			TableLevel3=(PHANDLE_TABLE_ENTRY_XP_SP3**)CapturedTable;
			for (k=0;k<MaxHandle/(MAX_ENTRY_COUNT*4*MAX_ADDR_COUNT);k++)
			{
				//TableLevel2=GetTableEntry(TableLevel3,k);
				TableLevel2 = TableLevel3[k];
				if (!TableLevel2)
					break; //为零则跳出
				for (j=0;j<MaxHandle/(MAX_ENTRY_COUNT*4);j++)
				{
					//TableLevel1=GetTableEntry(TableLevel2,j);
					TableLevel1 = TableLevel2[j];
					if (!TableLevel1)
						break; //为零则跳出
					for (i=0;i<MAX_ENTRY_COUNT;i++)
					{
						//current = GetTableEntry(TableLevel1, i);
						current = &(TableLevel1[i]);
						//DbgPrint("[ring0] current 0x%x", current);
						if( current->u1.Object && MmIsAddressValid((ULONG)current->u1.Object & 0xFFFFFFF8) )
						{
							if( count == index ){
								handleCanFound = TRUE;
								foundHandle = current->u1.Object;
								*handle=(i*MAX_ENTRY_COUNT*MAX_ADDR_COUNT+j*MAX_ENTRY_COUNT+i*4);
								break;
							}else{
								count++;
							}
						}
					}//end of for i
				}//end of for j
			}//end of for k
		}
		break;
	default:
		{
			return FALSE;
		}
		break;
	}

	if( handleCanFound ){
		//foundHandle; 
		*obj = (ULONG)foundHandle;
		(*obj) = (*obj) & 0xFFFFFFF8; //末3位为0,见windows internal p139
	}

	//DbgPrint("[ring0] obj header 0x%x", (*obj));

	return handleCanFound;

#else
#endif
}

BOOL FindObjectByHandle(ULONG pid, ULONG handle, ULONG* obj)
{
#ifdef XP_SP3
	BOOL found;
	EPROCESS_XP_SP3* EProcess;
	PHANDLE_TABLE_XP_SP3 HandleTable;
	ULONG i,j,k,count;
	ULONG_PTR CapturedTable;
	ULONG TableLevel;
	PHANDLE_TABLE_ENTRY_XP_SP3 TableLevel1,*TableLevel2,**TableLevel3;
	BOOLEAN CallBackRetned=FALSE;
	BOOLEAN ResultValue=FALSE;
	ULONG MaxHandle;
	PVOID foundHandle;
	BOOL handleCanFound = FALSE;
	PHANDLE_TABLE_ENTRY_XP_SP3 current;
	ULONG tableIndex1, tableIndex2, tableIndex3;
	ULONG tmp;
	

	//MaxHandle=HandleTable->NextHandleNeedingPool;


	found = FindProcessByID(pid, &((ULONG)EProcess));

	if( !found )
		return ;
	HandleTable = (PHANDLE_TABLE_XP_SP3)EProcess->ObjectTable;
	if( HandleTable == NULL )
		return ;

	CapturedTable=(HandleTable->TableCode)&~3;
	TableLevel=(HandleTable->TableCode)&3;
	//DbgPrint("[ring0] index 0x%x", handle / 4);
	//DbgPrint("[ring0] TableLevel 0x%x", TableLevel);
	//DbgPrint("[ring0] CapturedTable 0x%x", CapturedTable);


	switch( TableLevel ){
		case 0:
			TableLevel1=(PHANDLE_TABLE_ENTRY_XP_SP3)CapturedTable;
			//current = GetTableEntry(TableLevel1, index);
			current = &(TableLevel1[handle / 4]);

			//DbgPrint("[ring0] current.Object 0x%x", current.u1.Object);

			if( current->u1.Object && MmIsAddressValid((ULONG)current->u1.Object & 0xFFFFFFF8) ){
				handleCanFound = TRUE;
				foundHandle = current->u1.Object;
				break;
			}
			break;
		case 1:
			TableLevel2=(PHANDLE_TABLE_ENTRY_XP_SP3*)CapturedTable;
			tableIndex2 = (handle / 4 ) / MAX_ENTRY_COUNT;
			tableIndex1 = (handle / 4 ) % MAX_ENTRY_COUNT;

			//DbgPrint("[ring0] tableIndex1 0x%x", tableIndex1);
			//DbgPrint("[ring0] tableIndex2 0x%x", tableIndex2);
			TableLevel1 = TableLevel2[tableIndex2];
			if (!TableLevel1)
				break; //为零则跳出

			current = &(TableLevel1[tableIndex1]);
			//DbgPrint("[ring0]------current 0x%x", current);
			if( current->u1.Object && MmIsAddressValid((ULONG)current->u1.Object & 0xFFFFFFF8) ){
				handleCanFound = TRUE;
				foundHandle = current->u1.Object;
			}

			break;
		case 2:
			TableLevel3=(PHANDLE_TABLE_ENTRY_XP_SP3**)CapturedTable;
			tableIndex3 = (handle / 4 ) / (MAX_ENTRY_COUNT*MAX_ADDR_COUNT);
			tmp = (handle / 4 ) - tableIndex3*(MAX_ENTRY_COUNT*MAX_ADDR_COUNT);
			tableIndex2 = tmp / MAX_ENTRY_COUNT;
			tableIndex1 = tmp % MAX_ENTRY_COUNT;

			//DbgPrint("[ring0] tableIndex1 0x%x", tableIndex1);
			//DbgPrint("[ring0] tableIndex2 0x%x", tableIndex2);
			//DbgPrint("[ring0] tableIndex3 0x%x", tableIndex3);

			TableLevel2 = TableLevel3[tableIndex3];
			if( !TableLevel2  )
				break;

			TableLevel1 = TableLevel2[tableIndex2];
			if (!TableLevel1)
				break; //为零则跳出

			current = &(TableLevel1[tableIndex1]);
			
			if( current->u1.Object && MmIsAddressValid((ULONG)current->u1.Object & 0xFFFFFFF8) ){
				handleCanFound = TRUE;
				foundHandle = current->u1.Object;
			}
			break;
	}


	if( handleCanFound ){
		//foundHandle; 
		*obj = (ULONG)foundHandle;
		(*obj) = (*obj) & 0xFFFFFFF8; //末3位为0,见windows internal p139
	}

	//DbgPrint("[ring0] obj header 0x%x", (*obj));

	return handleCanFound;

#else
	return FALSE;
#endif
}

void GetHandleInfo(ULONG pid, ULONG index, HANDLE_INFO* info)
{
#ifdef XP_SP3

	POBJECT_HEADER_XP_SP3 objHeader;
	POBJECT_NAME_INFORMATION_XP_SP3 ObjNameInfo;
	POBJECT_HEADER_NAME_INFO_XP_SP3 NameInfo;
	ULONG dwReturn;
	BOOL handleCanFound;
	PVOID foundHandle;
	ULONG strLen = 0;
	ULONG handleValue = 0;
	BYTE secondParam = 0;
	BOOL isFetched;
	char tmpTypeName[56];
	ULONG i;



	ULONG EProcess;
	//handleCanFound = FindObjectByIndex(pid, index, &((ULONG)foundHandle), &handleValue);
	handleCanFound = FindObjectByHandle(pid, index*4, &((ULONG)foundHandle));
	handleValue = index*4;
	info->canFound = handleCanFound;

	//DbgPrint("[ring0] handleCanFound 0x%x", handleCanFound);
	__try{
		if( handleCanFound ){
			
			objHeader = (POBJECT_HEADER_XP_SP3)foundHandle;
			info->handle = handleValue;
			info->handles = objHeader->HandleCount;
			info->refrenced = objHeader->PointerCount;
			info->objAddress = (ULONG)(&(objHeader->Body));
			if( objHeader->Type->Name.Length > 1024 )
				strLen = 1022;
			else
				strLen = objHeader->Type->Name.Length;
			//memset(info->typeName, 0, 1024*sizeof(wchar_t));
			if( MmIsAddressValid(objHeader->Type->Name.Buffer) )
				memcpy(info->typeName, objHeader->Type->Name.Buffer, strLen);
			//info->typeName = objHeader->Type->Name;
			if( objHeader->NameInfoOffset == 0 )
			{
				NameInfo = NULL;
			}
			else
			{
				NameInfo = (POBJECT_HEADER_NAME_INFO_XP_SP3)((ULONG)objHeader-objHeader->NameInfoOffset);
			}

			memset(tmpTypeName, 0, 56);
			i = 0;
			while( info->typeName[i] != 0 ){
				tmpTypeName[i] = (char)info->typeName[i];
				i++;
			}

			isFetched = FALSE;
			if( strcmp(tmpTypeName, "File") == 0 )
			{
				QueryFileName(index*4, (PVOID)&objHeader->Body, info->objName);
				isFetched = TRUE;
			}
			else if( strcmp(tmpTypeName, "Key") == 0 )
			{
				FindProcessByID(pid, &EProcess);
				DbgPrint("[ring0] EProcess 0x%x",EProcess);
				QueryKeyName(index*4,EProcess,(PVOID)&objHeader->Body, info->objName);
				isFetched = TRUE;
			}
			//else if( strcmp(tmpTypeName, "Event") && objHeader->Type->TypeInfo.QueryNameProcedure != NULL )
			//{
			//	//ObjNameInfo.Name.Buffer = info->objName;
			//	//ObjNameInfo.Name.MaximumLength = 1024;
			//	ObjNameInfo = (POBJECT_NAME_INFORMATION_XP_SP3)ExAllocatePoolWithTag(PagedPool, 2048, 1001);
			//	if( NameInfo == NULL ){
			//		secondParam = FALSE;
			//	}else if( NameInfo->Name.Length == 0 ){
			//		secondParam = FALSE;
			//	}else{
			//		secondParam = TRUE;
			//	}
			//	__try{
			//		(*objHeader->Type->TypeInfo.QueryNameProcedure)(
			//			(PVOID)&objHeader->Body,
			//			secondParam,
			//			ObjNameInfo,
			//			2048,
			//			&dwReturn
			//			);
			//	}__except(EXCEPTION_EXECUTE_HANDLER){
			//		memset(info->objName, 0, 1024*sizeof(wchar_t));
			//	}
			//	if( ObjNameInfo->Name.Length > 1024 )
			//		strLen = 1022;
			//	else
			//		strLen = ObjNameInfo->Name.Length;
			//	//memset(info->objName, 0, 1024*sizeof(wchar_t));
			//	if( MmIsAddressValid(ObjNameInfo->Name.Buffer) )
			//		memcpy(info->objName, ObjNameInfo->Name.Buffer, strLen );
			//	ExFreePool(ObjNameInfo);



			//}

			if( isFetched )
			{

			}
			else
			{
				if( NameInfo == NULL )
				{
					//memset(info->objName, 0, 1024*sizeof(wchar_t));
				}
				else
				{
					if( NameInfo->Name.Length > 1024 )
						strLen = 1022;
					else
						strLen = NameInfo->Name.Length;
					//memset(info->objName, 0, 1024*sizeof(wchar_t));
					if( MmIsAddressValid(NameInfo->Name.Buffer) )
						memcpy(info->objName, NameInfo->Name.Buffer, strLen );
				}
			}
			
		}
	}__except(EXCEPTION_EXECUTE_HANDLER){
		return;
	}

	return ;

#else
#endif
}