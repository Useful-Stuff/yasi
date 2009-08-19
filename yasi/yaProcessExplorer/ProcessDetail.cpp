// ProcessDetail.cpp : implementation file
//

#include "stdafx.h"
#include "yaProcessExplorer.h"
#include "ProcessDetail.h"
#include "ThreadDetail.h"


// CProcessDetail dialog

IMPLEMENT_DYNAMIC(CProcessDetail, CDialog)

CProcessDetail::CProcessDetail(CWnd* pParent /*=NULL*/, YASI_HANDLE _core, UINT _pid)
	: CDialog(CProcessDetail::IDD, pParent),
	core(_core),
	pid(_pid)
	, m_CommitCharge(0)
	, m_VirtualSize(0)
	, m_PrivatePages(0)
	, m_ActiveThreads(0)
	, m_CommitChargeLimit(0)
	, m_CommitChargePeak(0)
	, m_NumberOfVads(0)
	, m_PeakWorkingSetSize(0)
	, m_MinWorkingSetSize(0)
	, m_MaxWorkingSetSize(0)
	, m_PeakVirtualSize(0)
	, m_WorkingSetPage(0)
	, m_LockedPages(0)
	, m_LastThreadExitStatus(0)
	, m_LastFaultCount(0)
	, m_ModifiedPageCount(0)
	, m_JobStatus(0)
	, m_PageFaultCount(0)
	, m_WorkingSetSize(0)
{

}

CProcessDetail::~CProcessDetail()
{
}

void CProcessDetail::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_DLLS, m_LoadedDlls);
	DDX_Control(pDX, IDC_EDIT_DLLPATH, e_DllPath);
	DDX_Control(pDX, IDC_EDIT_IMAGE_PATH, e_ImagePath);
	DDX_Control(pDX, IDC_EDIT_CMD_LINE, e_CommandLine);
	DDX_Control(pDX, IDC_EDIT_WINDOW_TITLE, e_WindowTitle);
	DDX_Control(pDX, IDC_EDIT_CUR_DIR, e_CurrentDirectory);
	DDX_Control(pDX, IDC_EDIT2, e_CreateTime);
	DDX_Control(pDX, IDC_EDIT3, e_CommitCharge);
	DDX_Control(pDX, IDC_EDIT4, e_VirtualSize);
	DDX_Control(pDX, IDC_EDIT5, e_PrivatePages);
	DDX_Control(pDX, IDC_EDIT6, e_ActiveThreads);
	DDX_Control(pDX, IDC_EDIT7, e_ReadOperation);
	DDX_Control(pDX, IDC_EDIT8, e_OtherOperation);
	DDX_Control(pDX, IDC_EDIT9, e_ReadTransfer);
	DDX_Control(pDX, IDC_EDIT10, e_OtherTransfer);
	DDX_Control(pDX, IDC_EDIT11, e_CommitChargeLimit);
	DDX_Control(pDX, IDC_EDIT12, e_CommitChargePeak);
	DDX_Control(pDX, IDC_EDIT13, e_NumberOfVads);
	DDX_Control(pDX, IDC_EDIT14, e_LastTrimTime);
	DDX_Control(pDX, IDC_EDIT15, e_PeakWorkingSetSize);
	DDX_Control(pDX, IDC_EDIT16, e_MinimumWorkingSetSize);
	DDX_Control(pDX, IDC_EDIT17, e_MaximumWorkingSetSize);
	DDX_Control(pDX, IDC_EDIT18, e_ExitTime);
	DDX_Control(pDX, IDC_EDIT19, e_PeakVirtualSize);
	DDX_Control(pDX, IDC_EDIT20, e_WorkingSetPage);
	DDX_Control(pDX, IDC_EDIT21, e_LockedPages);
	DDX_Control(pDX, IDC_EDIT22, e_LastThreadExitStatus);
	DDX_Control(pDX, IDC_EDIT23, e_WriteOperation);
	DDX_Control(pDX, IDC_EDIT24, e_WriteTransfer);
	DDX_Control(pDX, IDC_EDIT25, e_LastFaultCount);
	DDX_Control(pDX, IDC_EDIT26, e_ModifiedPageCount);
	DDX_Control(pDX, IDC_EDIT27, e_JobStatus);
	DDX_Control(pDX, IDC_EDIT28, e_PageFaultCount);
	DDX_Control(pDX, IDC_EDIT29, e_WorkingSetSize);

	DDX_Control(pDX, IDC_EDIT_DLL, m_DllName);
	DDX_Control(pDX, IDC_EDIT_ADDRESS, m_Address);
	DDX_Control(pDX, IDC_EDIT_FUNC, m_Func);
	DDX_Control(pDX, IDC_COMBO_IORE, m_IorE);
	DDX_Control(pDX, IDC_BUTTON_WRITE, m_BtnWrite);
}

BOOL CProcessDetail::OnInitDialog()
{
	CDialog::OnInitDialog();

	m_IorE.AddString(_T("import table"));
	m_IorE.AddString(_T("export table"));
	m_IorE.SetCurSel(0);
	m_BtnWrite.EnableWindow(FALSE);

	DWORD oldStyle = LVS_REPORT;
	m_LoadedDlls.ModifyStyle(LVS_TYPEMASK,oldStyle);
	m_LoadedDlls.SetExtendedStyle(LVS_EX_FULLROWSELECT);
	LV_COLUMN lvColumn;
	TCHAR szColumn[32] = { 0 };
	RECT rect = {0};
	m_LoadedDlls.GetWindowRect(&rect);
	DWORD columnSize = (rect.right-rect.left)/4;

	TCHAR   szString[4][20] = {
		_TEXT("index"),
		_TEXT("name"),
		_TEXT("path"),
	};  //empty the list

	lvColumn.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
	lvColumn.fmt = LVCFMT_LEFT;


	for(int i = 0; i < 3; i++)    
	{    
		lvColumn.pszText = szString[i];  
		if( i == 1 )
			lvColumn.cx = 50;
		else if( i == 2 )
			lvColumn.cx = 2*columnSize-50;
		else
			lvColumn.cx = columnSize;
		ListView_InsertColumn(m_LoadedDlls.m_hWnd, i, &lvColumn);    
	} 

	wchar_t title[256] = {0};
	yasi_get_process_info(core, pid, STRING_ImagePathName, title);
	this->SetWindowText(title);
	UpdateDetail();
	SetTimer(1, 3000, NULL);
	return TRUE;
}


BEGIN_MESSAGE_MAP(CProcessDetail, CDialog)
	ON_WM_TIMER()
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_DLLS, &CProcessDetail::OnNMDblclkListDlls)
	ON_BN_CLICKED(IDC_BUTTON_READ, &CProcessDetail::OnBnClickedButtonRead)
	ON_BN_CLICKED(IDC_BUTTON_WRITE, &CProcessDetail::OnBnClickedButtonWrite)
	ON_NOTIFY(NM_CLICK, IDC_LIST_DLLS, &CProcessDetail::OnNMClickListDlls)
	ON_BN_CLICKED(IDC_BUTTON_LOAD, &CProcessDetail::OnBnClickedButtonLoad)
	ON_CBN_SELCHANGE(IDC_COMBO_IORE, &CProcessDetail::OnCbnSelchangeComboIore)
	ON_BN_CLICKED(IDC_BUTTON_VIEW_THREAD, &CProcessDetail::OnBnClickedButtonViewThread)
END_MESSAGE_MAP()


// CProcessDetail message handlers
void CProcessDetail::OnTimer(UINT_PTR nIDEvent)
{
	if( nIDEvent == 1 )
		UpdateDetail();
}

void CProcessDetail::UpdateDetail()
{
	PROCESS_DETAIL detail = {0};
	wchar_t tmpStr[4096] = {0};
	CString tmpCStr;
	yasi_get_process_detail(core, pid, &detail);
	m_CreateTime = detail.process.CreateTime;
	m_CommitCharge = (int)detail.process.CommitCharge;
	m_VirtualSize = (int)detail.process.VirtualSize;
	m_PrivatePages = (int)detail.process.NumberOfPrivatePages;
	m_ActiveThreads = (int)detail.process.ActiveThreads;
	 m_ReadOperation = detail.process.ReadOperationCount;
	 m_OtherOperation = detail.process.OtherOperationCount;
	 m_ReadTransfer = detail.process.ReadTransferCount;
	 m_OtherTransfer = detail.process.OtherTransferCount;
	 m_CommitChargeLimit = (int)detail.process.CommitChargeLimit;
	 m_CommitChargePeak = (int)detail.process.CommitChargePeak;
	 m_NumberOfVads = (int)detail.process.NumberOfVads;
	 m_LastTrimTime = detail.process.Vm.LastTrimTime;
	 m_PeakWorkingSetSize = (int)detail.process.Vm.PeakWorkingSetSize;
	 m_MinWorkingSetSize = (int)detail.process.Vm.MinimumWorkingSetSize;
	 m_MaxWorkingSetSize = (int)detail.process.Vm.MaximumWorkingSetSize;
	 m_ExitTime = detail.process.ExitTime;
	 m_PeakVirtualSize = (int)detail.process.PeakVirtualSize;
	 m_WorkingSetPage = (int)detail.process.WorkingSetPage;
	 m_LockedPages = (int)detail.process.NumberOfLockedPages;
	 m_LastThreadExitStatus = (int)detail.process.LastThreadExitStatus;
	 m_WriteOperation = detail.process.WriteOperationCount;
	 m_WriteTransfer = detail.process.WriteTransferCount;
	 m_LastFaultCount = (int)detail.process.LastFaultCount;
	 m_ModifiedPageCount = (int)detail.process.ModifiedPageCount;
	 m_JobStatus = (int)detail.process.JobStatus;
	 m_PageFaultCount = (int)detail.process.Vm.PageFaultCount;
	 m_WorkingSetSize = (int)detail.process.Vm.WorkingSetSize;

	 yasi_get_process_info(core, pid, STRING_DllPath, tmpStr);
	 e_DllPath.SetWindowText(tmpStr);
	 memset(tmpStr, 0, 4096);

	 yasi_get_process_info(core, pid, STRING_ImagePathName, tmpStr);
	 e_ImagePath.SetWindowText(tmpStr);
	 memset(tmpStr, 0, 4096);

	 yasi_get_process_info(core, pid, STRING_CommandLine, tmpStr);
	 e_CommandLine.SetWindowText(tmpStr);
	 memset(tmpStr, 0, 4096);

	 yasi_get_process_info(core, pid, STRING_WindowTitle, tmpStr);
	 e_WindowTitle.SetWindowText(tmpStr);
	 memset(tmpStr, 0, 4096);

	 yasi_get_process_info(core, pid, STRING_CurrentDirectore, tmpStr);
	 e_CurrentDirectory.SetWindowText(tmpStr);
	 memset(tmpStr, 0, 4096);

	 tmpCStr.Format(_T("(kernel) %d / (user)%d "), 
		 detail.process.Pcb.KernelTime  ,
		 detail.process.Pcb.UserTime );
	 this->SetWindowText(tmpCStr);

	 tmpCStr.Format(_T("%lld"), m_CreateTime.QuadPart);
	 e_CreateTime.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%lld"), m_ReadOperation.QuadPart);
	 e_ReadOperation.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%lld"), m_OtherOperation.QuadPart);
	 e_OtherOperation.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%lld"), m_ReadTransfer.QuadPart);
	 e_ReadTransfer.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%lld"), m_OtherTransfer.QuadPart);
	 e_OtherTransfer.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%lld"), m_LastTrimTime.QuadPart);
	 e_LastTrimTime.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%lld"), m_ExitTime.QuadPart);
	 e_ExitTime.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%lld"), m_WriteOperation.QuadPart);
	 e_WriteOperation.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%lld"), m_WriteTransfer.QuadPart);
	 e_WriteTransfer.SetWindowText(tmpCStr);


	 tmpCStr.Format(_T("%d"), m_CommitCharge);
	 e_CommitCharge.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_VirtualSize);
	 e_VirtualSize.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_PrivatePages);
	 e_PrivatePages.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_ActiveThreads);
	 e_ActiveThreads.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_CommitChargeLimit);
	 e_CommitChargeLimit.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_CommitChargePeak);
	 e_CommitChargePeak.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_NumberOfVads);
	 e_NumberOfVads.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_PeakWorkingSetSize);
	 e_PeakWorkingSetSize.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_MinWorkingSetSize);
	 e_MinimumWorkingSetSize.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_MaxWorkingSetSize);
	 e_MaximumWorkingSetSize.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_PeakVirtualSize);
	 e_PeakVirtualSize.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_WorkingSetPage);
	 e_WorkingSetPage.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_LockedPages);
	 e_LockedPages.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_LastThreadExitStatus);
	 e_LastThreadExitStatus.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_LastFaultCount);
	e_LastFaultCount.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_ModifiedPageCount);
	 e_ModifiedPageCount.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_JobStatus);
	 e_JobStatus.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_PageFaultCount);
	 e_PageFaultCount.SetWindowText(tmpCStr);
	 tmpCStr.Format(_T("%d"), m_WorkingSetSize);
	 e_WorkingSetSize.SetWindowText(tmpCStr);

	 //loaded dll
	 m_LoadedDlls.SetRedraw(FALSE);
	 UINT topIndex = m_LoadedDlls.GetTopIndex()+m_LoadedDlls.GetCountPerPage()-1;
	 POSITION pos = m_LoadedDlls.GetFirstSelectedItemPosition();
	 UINT selected = m_LoadedDlls.GetNextSelectedItem(pos);
	 m_LoadedDlls.DeleteAllItems();
	 UINT count = yasi_get_module_count(core, pid);
	 for( int index = 0 ; index < count; index++ )
	 {
		 LDR_DATA_TABLE_ENTRY_XP_SP3 module = {0};
		 yasi_get_module_info(core, pid, index, &module);
		 if(module.DllBase == NULL )
			 continue;
		 CString sz_Index;
		 sz_Index.Format(_T("%d"), index);
		 int i = m_LoadedDlls.InsertItem(m_LoadedDlls.GetItemCount(), sz_Index);
		 yasi_get_process_string(core, pid, module.BaseDllName.Buffer, tmpStr, module.BaseDllName.Length);
		 m_LoadedDlls.SetItemText(i, 1, tmpStr);
		 memset(tmpStr, 0, 4096);
		 yasi_get_process_string(core, pid, module.FullDllName.Buffer, tmpStr, module.FullDllName.Length);
		 m_LoadedDlls.SetItemText(i, 2,tmpStr);
		 memset(tmpStr, 0, 4096);
	 }
	 m_LoadedDlls.EnsureVisible(topIndex, FALSE);
	 m_LoadedDlls.SetItemState(selected, LVIS_SELECTED, LVIS_SELECTED);
	 m_LoadedDlls.SetRedraw(TRUE);
	 UpdateData(TRUE);
}
void CProcessDetail::OnNMDblclkListDlls(NMHDR *pNMHDR, LRESULT *pResult)
{
	KillTimer(1);

	SetTimer(1, 3000, NULL);
	*pResult = 0;
}

void CProcessDetail::OnBnClickedButtonRead()
{
	UINT iore;
	CString ioreS;
	m_IorE.GetWindowText(ioreS);
	if( ioreS == "import table" )
		iore = IMAGE_DIRECTORY_ENTRY_IMPORT;
	else
		iore = IMAGE_DIRECTORY_ENTRY_EXPORT;

	CString dllname;
	m_DllName.GetWindowText(dllname);
	if( dllname.GetLength() == 0 )
		return;

	CString funcName;
	m_Func.GetWindowText(funcName);
	if( funcName.GetLength() == 0 )
		return;

	if( iore == IMAGE_DIRECTORY_ENTRY_IMPORT )
	{


		char dll[256] = {0};
		char fun[256] = {0};

		if( !CStrCopyToCharStr(dllname, dll) )
			return;
		if( !CStrCopyToCharStr(funcName, fun) )
			return;



		DWORD address = (DWORD)yasi_get_proc_address(core, pid, dll, fun);

		CString addr;
		addr.Format(_T("0x%x"), address);
		m_Address.SetWindowText(addr);
	}
	else
	{
		char fun[256] = {0};

		if( !CStrCopyToCharStr(funcName, fun) )
			return;
		DWORD address = (DWORD)yasi_get_export_address(core, pid, dllname.GetBuffer(), fun);

		CString addr;
		addr.Format(_T("0x%x"), address);
		m_Address.SetWindowText(addr);
	}

}

void CProcessDetail::OnBnClickedButtonWrite()
{
	CString dllname;
	m_DllName.GetWindowText(dllname);
	if( dllname.GetLength() == 0 )
		return;

	CString funcName;
	m_Func.GetWindowText(funcName);
	if( funcName.GetLength() == 0 )
		return;

	char dll[256] = {0};
	char fun[256] = {0};

	if( !CStrCopyToCharStr(dllname, dll) )
		return;
	if( !CStrCopyToCharStr(funcName, fun) )
		return;

	CString szAddr;
	m_Address.GetWindowText(szAddr);
	UINT addr = 0;
	swscanf(szAddr.GetBuffer(), _T("%x"), &addr);
	yasi_set_proc_address(core, pid, dll, fun, (PVOID)addr);



}

void CProcessDetail::OnNMClickListDlls(NMHDR *pNMHDR, LRESULT *pResult)
{
	POSITION pos = m_LoadedDlls.GetFirstSelectedItemPosition();
	UINT selected = m_LoadedDlls.GetNextSelectedItem(pos);
	wchar_t sz_dllName[32] = {0};
	m_LoadedDlls.GetItemText(selected, 1, sz_dllName, 32);
	m_DllName.SetWindowText(sz_dllName);
	*pResult = 0;
}

BOOL CProcessDetail::CStrCopyToCharStr(CString& _src, char* _des)
{
	if( !_des ) return FALSE;

	wchar_t* src = _src.GetBuffer();
	while( src && *src != _T('\0') ){
		if( (*src)>>8 != 0 )
			return FALSE;
		*_des = (char)(*src);
		src++;
		_des++;
	}
	*_des = '\0';
}
void CProcessDetail::OnBnClickedButtonLoad()
{
	CFileDialog dialog(TRUE);
	dialog.DoModal();
	CString path = dialog.GetPathName();
	if( path.GetLength() == 0 )
		return;
	if( path.Right(4) != ".dll")
		return;

	yasi_load_dll(core, pid, path.GetBuffer());
}

void CProcessDetail::OnCbnSelchangeComboIore()
{
	CString ioreS;
	m_IorE.GetWindowText(ioreS);
	if( ioreS == "import table" )
		m_BtnWrite.EnableWindow(TRUE);
	else
		m_BtnWrite.EnableWindow(FALSE);
}

void CProcessDetail::OnBnClickedButtonViewThread()
{
	KillTimer(1);
	CThreadDetail detail(this, core, pid);
	detail.DoModal();
	SetTimer(1, 3000, NULL);
}
