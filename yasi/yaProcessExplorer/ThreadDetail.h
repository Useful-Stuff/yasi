#pragma once
#include <hash_map>
using namespace stdext;
#include "afxcmn.h"
#include "afxwin.h"
#include "../yasi.h"
#include "../internal.h"

// CThreadDetail dialog
struct SimpleThreadDetail
{
	ULONG tid;
	ULONG startAddress;
	LARGE_INTEGER startTime;
	UINT state;
	ULONG kernelTime;
	ULONG userTime;
	UINT contextSwitches;
	UINT basePriority;
	UINT dynamicPriority;
};

class CThreadDetail : public CDialog
{
	DECLARE_DYNAMIC(CThreadDetail)

public:
	CThreadDetail(CWnd* pParent = NULL, YASI_HANDLE _core = NULL, ULONG pid = 0);   // standard constructor
	virtual ~CThreadDetail();

// Dialog Data
	enum { IDD = IDD_DIALOG_THREAD };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	virtual BOOL OnInitDialog();
	afx_msg void OnTimer(UINT_PTR nIDEvent);

	DECLARE_MESSAGE_MAP()
private:
	void UndateThread();
	void UpdateThreadDetail(UINT index);
	CListCtrl m_ThreadList;
	CEdit m_ThreadID;
	CEdit m_StartTime;
	CEdit m_State;
	CEdit m_KernelTime;
	CEdit m_UserTime;
	CEdit m_ContextSwitches;
	CEdit m_BasePriority;
	CEdit m_DynamicPriority;
	YASI_HANDLE core;
	ULONG pid;
	hash_map<ULONG, SimpleThreadDetail> threadInfos;
	CArray<PVOID> baseAddressCollection;
	hash_map<PVOID, CString> baseAddressToModuleName;
	afx_msg void OnNMClickListThread(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnBnClickedButtonKill();
};
