// ProcessExplorerDlg.h : header file
//

#pragma once
#include "../yasi.h"
#include "../internal.h"
#include "afxcmn.h"

// CProcessExplorerDlg dialog
class CProcessExplorerDlg : public CDialog
{
// Construction
public:
	CProcessExplorerDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_YAPROCESSEXPLORER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonClose();



private:
	YASI_HANDLE core;
	CListCtrl m_ProcessView;
	void RefreshProcess();
	afx_msg void OnClose();
	afx_msg void OnLvnItemchangedListProcess(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnNMDblclkListProcess(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedButtonKill();
};
