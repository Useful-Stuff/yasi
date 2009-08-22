#ifndef __QUERY_OBJECT__
#define __QUERY_OBJECT__
#define XP_SP3

void QueryFileName(HANDLE h, PVOID object, wchar_t* name);
void QueryEventName(HANDLE h, PVOID object, wchar_t* name);
void QueryKeyName(HANDLE h, ULONG EProcess, PVOID object, wchar_t* name);
void QueryMutantName(HANDLE h, PVOID object, wchar_t* name);
void QuerySectionName(HANDLE h, PVOID object, wchar_t* name);
void QuerySymbolicLinkName(HANDLE h, PVOID object, wchar_t* name);

#endif
