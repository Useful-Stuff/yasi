#pragma once

#include "../yasi.h"
#include "../internal.h"
#include "afxwin.h"

// CProcessDetail dialog

class CProcessDetail : public CDialog
{
	DECLARE_DYNAMIC(CProcessDetail)

public:
	CProcessDetail(CWnd* pParent = NULL, YASI_HANDLE core = NULL, UINT pid = 0);   // standard constructor
	virtual ~CProcessDetail();

// Dialog Data
	enum { IDD = IDD_DIALOG_DETAIL };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	virtual BOOL OnInitDialog();
	DECLARE_MESSAGE_MAP()


private:
	void UpdateDetail();
	YASI_HANDLE core;
	UINT pid;
	CListCtrl m_LoadedDlls;
private:
	LARGE_INTEGER m_CreateTime;
	int m_CommitCharge;
	int m_VirtualSize;
	int m_PrivatePages;
	int m_ActiveThreads;
	LARGE_INTEGER m_ReadOperation;
	LARGE_INTEGER m_OtherOperation;
	LARGE_INTEGER m_ReadTransfer;
	LARGE_INTEGER m_OtherTransfer;
	int m_CommitChargeLimit;
	int m_CommitChargePeak;
	int m_NumberOfVads;
	LARGE_INTEGER m_LastTrimTime;
	int m_PeakWorkingSetSize;
	int m_MinWorkingSetSize;
	int m_MaxWorkingSetSize;
	LARGE_INTEGER m_ExitTime;
	int m_PeakVirtualSize;
	int m_WorkingSetPage;
	int m_LockedPages;
	int m_LastThreadExitStatus;
	LARGE_INTEGER m_WriteOperation;
	LARGE_INTEGER m_WriteTransfer;
	int m_LastFaultCount;
	int m_ModifiedPageCount;
	int m_JobStatus;
	int m_PageFaultCount;
	int m_WorkingSetSize;
	CEdit e_DllPath;
	CEdit e_ImagePath;
	CEdit e_CommandLine;
	CEdit e_WindowTitle;
	CEdit e_CurrentDirectory;
	CEdit e_CreateTime;
	CEdit e_CommitCharge;
	CEdit e_VirtualSize;
	CEdit e_PrivatePages;
	CEdit e_ActiveThreads;
	CEdit e_ReadOperation;
	CEdit e_OtherOperation;
	CEdit e_ReadTransfer;
	CEdit e_OtherTransfer;
	CEdit e_CommitChargeLimit;
	CEdit e_CommitChargePeak;
	CEdit e_NumberOfVads;
	CEdit e_LastTrimTime;
	CEdit e_PeakWorkingSetSize;
	CEdit e_MinimumWorkingSetSize;
	CEdit e_MaximumWorkingSetSize;
	CEdit e_ExitTime;
	CEdit e_PeakVirtualSize;
	CEdit e_WorkingSetPage;
	CEdit e_LockedPages;
	CEdit e_LastThreadExitStatus;
	CEdit e_WriteOperation;
	CEdit e_WriteTransfer;
	CEdit e_LastFaultCount;
	CEdit e_ModifiedPageCount;
	CEdit e_JobStatus;
	CEdit e_PageFaultCount;
	CEdit e_WorkingSetSize;
	CEdit e_KernelTime;
	CEdit e_UserTime;
	afx_msg void OnNMDblclkListDlls(NMHDR *pNMHDR, LRESULT *pResult);
	CEdit m_DllName;
	CEdit m_Address;
	CEdit m_Func;
	afx_msg void OnBnClickedButtonRead();
	afx_msg void OnBnClickedButtonWrite();
	afx_msg void OnNMClickListDlls(NMHDR *pNMHDR, LRESULT *pResult);
	BOOL CStrCopyToCharStr(CString& src, char* des);
	afx_msg void OnBnClickedButtonLoad();
	CComboBox m_IorE;
	afx_msg void OnCbnSelchangeComboIore();
	CButton m_BtnWrite;
	afx_msg void OnBnClickedButtonViewThread();
	afx_msg void OnBnClickedButtonHandles();
};
