#pragma once
#include "afxcmn.h"
#include "../yasi.h"
#include "../internal.h"

// CHandleDetail dialog

class CHandleDetail : public CDialog
{
	DECLARE_DYNAMIC(CHandleDetail)

public:
	CHandleDetail(CWnd* pParent = NULL, YASI_HANDLE _core = NULL, ULONG _pid = 0);   // standard constructor
	virtual ~CHandleDetail();

// Dialog Data
	enum { IDD = IDD_DIALOG_HANDLES };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual BOOL OnInitDialog();
	afx_msg void OnTimer(UINT_PTR nIDEvent);

	void RefreshList();

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_HandleList;
public:
	afx_msg void OnNMDblclkListHandles(NMHDR *pNMHDR, LRESULT *pResult);

private:
	YASI_HANDLE core;
	ULONG pid;
	ULONG current_index;
	ULONG realCount;
};
