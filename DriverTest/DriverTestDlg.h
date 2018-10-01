
// DriverTestDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"


// CDriverTestDlg �Ի���
class CDriverTestDlg : public CDialogEx
{
// ����
public:
	CDriverTestDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_DRIVERTEST_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
    afx_msg void OnBnClickedButtonLoadDr();
    afx_msg void OnBnClickedButtonUnloadDr();
    afx_msg void OnBnClickedButtonGetModule();
    afx_msg void OnBnClickedButtonReadDword();
    afx_msg void OnBnClickedButtonReadLong();
    afx_msg void OnBnClickedButtonReadByte();
    afx_msg void OnBnClickedButtonReadText();
    afx_msg void OnBnClickedButtonReadFloat();
    afx_msg void OnBnClickedButtonReadDouble();
    afx_msg void OnBnClickedButtonWriteDowrd();
    afx_msg void OnBnClickedButtonWriteLong();
    afx_msg void OnBnClickedButtonWriteByte();
    afx_msg void OnBnClickedButtonWriteText();
    afx_msg void OnBnClickedButtonWriteFloat();
    afx_msg void OnBnClickedButtonWriteDouble();
    CEdit mPidEdit;
    CEdit mModuleNameEdit;
    CEdit mTestAddrEdit;
    CEdit mReadValueEdit;
    CEdit mWriteValueEdit;
};
