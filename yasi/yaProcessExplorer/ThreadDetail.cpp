// ThreadDetail.cpp : implementation file
//

#include "stdafx.h"
#include "yaProcessExplorer.h"
#include "ThreadDetail.h"


// CThreadDetail dialog

IMPLEMENT_DYNAMIC(CThreadDetail, CDialog)

CThreadDetail::CThreadDetail(CWnd* pParent /*=NULL*/, YASI_HANDLE _core, ULONG _pid )
	: CDialog(CThreadDetail::IDD, pParent)
{
	core = _core;
	pid = _pid;
}

CThreadDetail::~CThreadDetail()
{
}

void CThreadDetail::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_THREAD, m_ThreadList);
	DDX_Control(pDX, IDC_EDIT1, m_ThreadID);
	DDX_Control(pDX, IDC_EDIT31, m_StartTime);
	DDX_Control(pDX, IDC_EDIT30, m_State);
	DDX_Control(pDX, IDC_EDIT32, m_KernelTime);
	DDX_Control(pDX, IDC_EDIT33, m_UserTime);
	DDX_Control(pDX, IDC_EDIT34, m_ContextSwitches);
	DDX_Control(pDX, IDC_EDIT35, m_BasePriority);
	DDX_Control(pDX, IDC_EDIT36, m_DynamicPriority);
}


BEGIN_MESSAGE_MAP(CThreadDetail, CDialog)
	ON_NOTIFY(NM_CLICK, IDC_LIST_THREAD, &CThreadDetail::OnNMClickListThread)
	ON_BN_CLICKED(IDC_BUTTON_KILL, &CThreadDetail::OnBnClickedButtonKill)
	ON_WM_TIMER()
END_MESSAGE_MAP()


// CThreadDetail message handlers

void CThreadDetail::OnTimer(UINT_PTR nIDEvent)
{
	KillTimer(1);
	m_ThreadList.DeleteAllItems();
	UndateThread();
}

BOOL CThreadDetail::OnInitDialog()
{
	CDialog::OnInitDialog();
	UndateThread();

	return TRUE;
}

void CThreadDetail::UndateThread()
{
	//module base address
	baseAddressCollection.RemoveAll();
	baseAddressToModuleName.clear();
	ULONG moduleCount = yasi_get_module_count(core, pid);
	for( int index = 0 ; index < moduleCount; index++ ){
		LDR_DATA_TABLE_ENTRY_XP_SP3 moduleInfo = {0};
		yasi_get_module_info(core, pid, index, &moduleInfo);
		if( moduleInfo.DllBase == NULL )
			continue;
		baseAddressCollection.Add(moduleInfo.DllBase);
		wchar_t tmp[256] = {0};
		yasi_get_process_string(core, pid, moduleInfo.BaseDllName.Buffer, tmp, moduleInfo.BaseDllName.Length);
		baseAddressToModuleName[moduleInfo.DllBase] = CString(tmp);
	}

	int collectCount = baseAddressCollection.GetSize();
	for( int i = 0 ; i < collectCount; i++ ){
		for( int j = collectCount-1; j > i ; j-- ){
			ULONG at_j = (ULONG)baseAddressCollection.GetAt(j);
			ULONG at_jm1 = (ULONG)baseAddressCollection.GetAt(j-1);
			if( at_j < at_jm1){
				baseAddressCollection.SetAt(j, (PVOID)at_jm1);
				baseAddressCollection.SetAt(j-1, (PVOID)at_j);
			}
		}
	}

	/*
	for( int index = 0 ; index < collectCount; index++)
	{
		ULONG a = (ULONG)baseAddressCollection.GetAt(index);
		CString msg;
		msg.Format(_T("[0x%x] --> [%s]\r\n"), a, baseAddressToModuleName[(PVOID)a]);
		OutputDebugString(msg);
	}
	*/

	//thread info collection
	threadInfos.clear();
	ULONG threadCount = yasi_get_thread_count(core, pid);
	for( int index = 0 ; index < threadCount; index++ ){
		THREAD_DETAIL detail = {0};
		yasi_get_thread_detail(core, pid, index, &detail);
		SimpleThreadDetail simpleDetail = {0};
		simpleDetail.basePriority = detail.thread.Tcb.BasePriority;
		simpleDetail.contextSwitches = detail.thread.Tcb.ContextSwitches;
		simpleDetail.dynamicPriority = detail.thread.Tcb.BasePriority - detail.thread.Tcb.PriorityDecrement;
		simpleDetail.kernelTime = detail.thread.Tcb.KernelTime;
		simpleDetail.userTime = detail.thread.Tcb.UserTime;
		simpleDetail.startAddress = (ULONG)detail.thread.u6.Win32StartAddress;
		if( simpleDetail.startAddress == 0 )
			simpleDetail.startAddress = (ULONG)detail.thread.StartAddress;
		simpleDetail.startTime = detail.thread.CreateTime;
		simpleDetail.state = detail.thread.Tcb.State;
		simpleDetail.tid = (ULONG)detail.thread.Cid.UniqueThread;
		threadInfos[index] = simpleDetail;
	}

	//thread list ctrl
	DWORD oldStyle = LVS_REPORT;
	m_ThreadList.ModifyStyle(LVS_TYPEMASK,oldStyle);
	m_ThreadList.SetExtendedStyle(LVS_EX_FULLROWSELECT);
	LV_COLUMN lvColumn;
	TCHAR szColumn[32] = { 0 };
	RECT rect = {0};
	m_ThreadList.GetWindowRect(&rect);
	DWORD columnSize = (rect.right-rect.left)/2;

	TCHAR   szString[2][20] = {
		_TEXT("CID"),
		_TEXT("Start Address")
	};  //empty the list

	lvColumn.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvColumn.fmt = LVCFMT_LEFT;


	for(int i = 0; i < 2; i++)    
	{    
		lvColumn.pszText = szString[i];  
		if( i == 0 )
			lvColumn.cx = 50;
		else if( i == 1 )
			lvColumn.cx = 2*columnSize-50;
		else
			lvColumn.cx = columnSize;
		ListView_InsertColumn(m_ThreadList.m_hWnd, i, &lvColumn);    
	} 





	for( hash_map<ULONG, SimpleThreadDetail>::iterator itor = threadInfos.begin(); itor != threadInfos.end(); itor++  ){
		CString tid;
		tid.Format(_T("%d"), itor->second.tid);
		int i = m_ThreadList.InsertItem(m_ThreadList.GetItemCount(), tid);

		ULONG tmpAddr = itor->second.startAddress;

		CString funcName;
		ULONG baseAddr = 0;
		for( int index = 0 ; index < baseAddressCollection.GetCount(); index++ ){
			if( tmpAddr < (ULONG)baseAddressCollection.GetAt(index)){
				if( index == 0 )
					baseAddr = 0;
				else
					baseAddr = (ULONG)baseAddressCollection.GetAt(index-1);
				break;
			}
		}
		if( baseAddressToModuleName.find((PVOID)baseAddr) == baseAddressToModuleName.end() )
			funcName = _T("[NULL]");
		else
			funcName = baseAddressToModuleName[(PVOID)baseAddr];
		CString addition;
		addition.Format(_T(" + 0x%x"), tmpAddr-baseAddr);
		funcName+=addition;
		m_ThreadList.SetItemText(i, 1, funcName);

	}

	//yasi_export_all_func(core, pid, "d:\\a.txt");
	
}

void CThreadDetail::UpdateThreadDetail(UINT index)
{
	SimpleThreadDetail simpleDetail = threadInfos[index];
	CString tmp;
	tmp.Format(_T("%d"), simpleDetail.tid);
	m_ThreadID.SetWindowText(tmp);
	tmp = "";

	tmp.Format(_T("%d"),simpleDetail.contextSwitches);
	m_ContextSwitches.SetWindowText(tmp);
	tmp = "";

	tmp.Format(_T("%d"),simpleDetail.dynamicPriority);
	m_DynamicPriority.SetWindowText(tmp);
	tmp = "";

	tmp.Format(_T("%d"),simpleDetail.kernelTime);
	m_KernelTime.SetWindowText(tmp);

	tmp.Format(_T("%lld"),simpleDetail.startTime);
	m_StartTime.SetWindowText(tmp);
	tmp = "";

	tmp.Format(_T("%d"),simpleDetail.state);
	m_State.SetWindowText(tmp);
	tmp = "";

	tmp.Format(_T("%d"),simpleDetail.userTime);
	m_UserTime.SetWindowText(tmp);
	tmp = "";

	tmp.Format(_T("%d"),simpleDetail.basePriority);
	m_BasePriority.SetWindowText(tmp);
	tmp = "";
}
void CThreadDetail::OnNMClickListThread(NMHDR *pNMHDR, LRESULT *pResult)
{
	POSITION pos = m_ThreadList.GetFirstSelectedItemPosition();
	UINT index = m_ThreadList.GetNextSelectedItem(pos);
	if( threadInfos.find(index) == threadInfos.end() )
		return;

	UpdateThreadDetail(index);
	*pResult = 0;
}

void CThreadDetail::OnBnClickedButtonKill()
{
	CString szTid;
	m_ThreadID.GetWindowText(szTid);
	if( szTid.GetLength() == 0 )
		return;
	ULONG tid;
	swscanf(szTid.GetBuffer(), _T("%d"), &tid);
	yasi_kill_thread(core, pid, tid);

	this->SetTimer(1, 3000, NULL);

}
