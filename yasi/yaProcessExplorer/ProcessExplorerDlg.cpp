// ProcessExplorerDlg.cpp : implementation file
//

#include "stdafx.h"
#include "yaProcessExplorer.h"
#include "ProcessExplorerDlg.h"
#include "ProcessDetail.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CProcessExplorerDlg dialog




CProcessExplorerDlg::CProcessExplorerDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CProcessExplorerDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CProcessExplorerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_PROCESS, m_ProcessView);
}

BEGIN_MESSAGE_MAP(CProcessExplorerDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_TIMER()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BUTTON_Close, &CProcessExplorerDlg::OnBnClickedButtonClose)
	ON_WM_CLOSE()
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST_PROCESS, &CProcessExplorerDlg::OnLvnItemchangedListProcess)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_PROCESS, &CProcessExplorerDlg::OnNMDblclkListProcess)
END_MESSAGE_MAP()


// CProcessExplorerDlg message handlers

BOOL CProcessExplorerDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	core = yasi_create();
	DWORD oldStyle = LVS_REPORT;
	m_ProcessView.ModifyStyle(LVS_TYPEMASK,oldStyle);
	m_ProcessView.SetExtendedStyle(LVS_EX_FULLROWSELECT);
	LV_COLUMN lvColumn;
	TCHAR szColumn[32] = { 0 };
	RECT rect = {0};
	m_ProcessView.GetWindowRect(&rect);
	DWORD columnSize = (rect.right-rect.left)/4;

	TCHAR   szString[5][20] = {
		_TEXT("Name"),
		_TEXT("PID"),
		_TEXT("path"),
		_TEXT("VM")
	};  //empty the list

	lvColumn.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvColumn.fmt = LVCFMT_LEFT;


	for(int i = 0; i < 4; i++)    
	{    
		lvColumn.pszText = szString[i];  
		if( i == 1 )
			lvColumn.cx = 50;
		else if( i == 2 )
			lvColumn.cx = 2*columnSize-50;
		else
			lvColumn.cx = columnSize;
		ListView_InsertColumn(m_ProcessView.m_hWnd, i, &lvColumn);    
	} 
	RefreshProcess();
	SetTimer(1, 3000, NULL);
	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CProcessExplorerDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CProcessExplorerDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CProcessExplorerDlg::OnBnClickedButtonClose()
{
	//if( core ){
		yasi_destroy(core);
		core = NULL;
	//}
	OnOK();
}


void CProcessExplorerDlg::OnTimer(UINT_PTR nIDEvent)
{
	if( nIDEvent == 1 )
	{
		RefreshProcess();
	}
}

void CProcessExplorerDlg::RefreshProcess()
{
	m_ProcessView.SetRedraw(FALSE);
	UINT topIndex = m_ProcessView.GetTopIndex()+m_ProcessView.GetCountPerPage()-1;
	POSITION pos = m_ProcessView.GetFirstSelectedItemPosition();
	UINT selected = m_ProcessView.GetNextSelectedItem(pos);
	m_ProcessView.DeleteAllItems();
	UINT processCount = yasi_get_process_count(core);
	for( int index = 0 ; index < processCount; index++ )
	{
		PROCESS_RECORD record = {0};
		yasi_get_process(core, index, &record);
		if( record.processID > (unsigned short)-1 )
			continue;
		PROCESS_DETAIL detail = {0};
		yasi_get_process_detail(core, record.processID, &detail);

		CString name(record.imageName);
		int i = m_ProcessView.InsertItem(m_ProcessView.GetItemCount(), name);
		CString pid;
		pid.Format(_T("%d"), record.processID);
		m_ProcessView.SetItemText(i, 1, pid);
		if( detail.process.ExitTime.QuadPart != 0 ) //already exit
		{
			m_ProcessView.SetItemText(i, 2, _T("****[already dead]****"));
		}
		else
		{
			wchar_t path[256] = {0};
			yasi_get_process_info(core, record.processID, STRING_ImagePathName, path);
			m_ProcessView.SetItemText(i, 2, path);
		}

		CString vm;

		UINT vsize = detail.process.VirtualSize;
		if( vsize / (1024*1024) > 0 )
			vm.Format(_T("[%d]MB"), vsize / (1024*1024));
		else if( vsize / (1024) > 0 )
			vm.Format(_T("[%d]KB"), vsize / (1024));
		else
			vm.Format(_T("[%d]B"), vsize );

		m_ProcessView.SetItemText(i, 3, vm);

	}
	m_ProcessView.EnsureVisible(topIndex, FALSE);
	m_ProcessView.SetItemState(selected, LVIS_SELECTED, LVIS_SELECTED);
	m_ProcessView.SetRedraw(TRUE);
}
void CProcessExplorerDlg::OnClose()
{
	// TODO: Add your message handler code here and/or call default

	//if( core ){
		yasi_destroy(core);
		core = NULL;
	//}
	CDialog::OnClose();
}

void CProcessExplorerDlg::OnLvnItemchangedListProcess(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	//nothing to do
	*pResult = 0;
}

void CProcessExplorerDlg::OnNMDblclkListProcess(NMHDR *pNMHDR, LRESULT *pResult)
{
	POSITION pos = m_ProcessView.GetFirstSelectedItemPosition();
	UINT selected = m_ProcessView.GetNextSelectedItem(pos);
	wchar_t sz_pid[32] = {0};
	m_ProcessView.GetItemText(selected, 1, sz_pid, 32);
	int pid;
	swscanf(sz_pid, _T("%d"), &pid);

	KillTimer(1);
	CProcessDetail dialog(this, core, pid);
	dialog.DoModal();
	SetTimer(1, 3000, NULL);

	*pResult = 0;
}
