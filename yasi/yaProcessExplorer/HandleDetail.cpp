// HandleDetail.cpp : implementation file
//

#include "stdafx.h"
#include "yaProcessExplorer.h"
#include "HandleDetail.h"


// CHandleDetail dialog

IMPLEMENT_DYNAMIC(CHandleDetail, CDialog)

CHandleDetail::CHandleDetail(CWnd* pParent, YASI_HANDLE _core , ULONG _pid)
	: CDialog(CHandleDetail::IDD, pParent)
{
	core = _core;
	pid = _pid;
}

CHandleDetail::~CHandleDetail()
{
}

void CHandleDetail::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_HANDLES, m_HandleList);
}


BEGIN_MESSAGE_MAP(CHandleDetail, CDialog)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_HANDLES, &CHandleDetail::OnNMDblclkListHandles)
	ON_WM_TIMER()
END_MESSAGE_MAP()


// CHandleDetail message handlers

void CHandleDetail::OnNMDblclkListHandles(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: Add your control notification handler code here
	*pResult = 0;
}


void CHandleDetail::OnTimer(UINT_PTR nIDEvent)
{
	if( nIDEvent == 1)
	{
		RefreshList();
	}
}

BOOL CHandleDetail::OnInitDialog()
{
	CDialog::OnInitDialog();
	//thread list ctrl
	DWORD oldStyle = LVS_REPORT;
	m_HandleList.ModifyStyle(LVS_TYPEMASK,oldStyle);
	m_HandleList.SetExtendedStyle(LVS_EX_FULLROWSELECT);
	LV_COLUMN lvColumn;
	TCHAR szColumn[32] = { 0 };
	RECT rect = {0};
	m_HandleList.GetWindowRect(&rect);
	DWORD columnSize = (rect.right-rect.left)/6;

	TCHAR   szString[6][20] = {
		_TEXT("HANDLE"),
		_TEXT("Type"),
		_TEXT("Name"),
		_TEXT("Object Address"),
		_TEXT("Refrenced"),
		_TEXT("With Handles")
	};  //empty the list

	lvColumn.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvColumn.fmt = LVCFMT_LEFT;


	for(int i = 0; i < 6; i++)    
	{    
		lvColumn.pszText = szString[i];  
		if( i == 0  || i == 1 || i == 3 || i ==  4 || i == 5)
			lvColumn.cx = 80;
		else if( i == 2 )
			lvColumn.cx = 6*columnSize-5*80;
		else
			lvColumn.cx = columnSize;
		ListView_InsertColumn(m_HandleList.m_hWnd, i, &lvColumn);    
	} 
	current_index = 0;
	realCount = 0;
	RefreshList();
	this->SetTimer(1, 1000, NULL);
	return TRUE;
}

void CHandleDetail::RefreshList()
{
	m_HandleList.SetRedraw(FALSE);
	UINT topIndex = m_HandleList.GetTopIndex()+m_HandleList.GetCountPerPage()-1;
	POSITION pos = m_HandleList.GetFirstSelectedItemPosition();
	UINT selected = m_HandleList.GetNextSelectedItem(pos);
	//m_HandleList.DeleteAllItems();

	ULONG count = yasi_get_handle_count(core, pid);

	for( int index = current_index ; index < current_index+1024; index++ ){
		HANDLE_INFO info = {0};
		yasi_get_handle_info(core, pid, index, &info);
		if( !info.canFound )
			continue;
		CString sz_Index;
		sz_Index.Format(_T("0x%08x"), info.handle);
		int i = m_HandleList.InsertItem(m_HandleList.GetItemCount(), sz_Index);
		m_HandleList.SetItemText(i, 1, info.typeName);
		m_HandleList.SetItemText(i, 2, info.objName);
		sz_Index.Format(_T("0x%08x"), info.objAddress);
		m_HandleList.SetItemText(i, 3, sz_Index);
		sz_Index.Format(_T("%d"), info.refrenced);
		m_HandleList.SetItemText(i, 4, sz_Index);
		sz_Index.Format(_T("%d"), info.handles);
		m_HandleList.SetItemText(i, 5, sz_Index);
		realCount++;
		if(realCount >= count ){
			KillTimer(1);
			break;
		}
	}
	current_index+=1024;

	m_HandleList.EnsureVisible(topIndex, FALSE);
	m_HandleList.SetItemState(selected, LVIS_SELECTED, LVIS_SELECTED);
	m_HandleList.SetRedraw(TRUE);
}