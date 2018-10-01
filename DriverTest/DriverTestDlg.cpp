
// DriverTestDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "DriverTest.h"
#include "DriverTestDlg.h"
#include "afxdialogex.h"
#include "ZiyuHead.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CDriverTestDlg �Ի���



CDriverTestDlg::CDriverTestDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CDriverTestDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CDriverTestDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_EDIT_PID, mPidEdit);
    DDX_Control(pDX, IDC_EDIT_IMAGENAME, mModuleNameEdit);
    DDX_Control(pDX, IDC_EDIT_ADDR, mTestAddrEdit);
    DDX_Control(pDX, IDC_EDIT_READ_VALUE, mReadValueEdit);
    DDX_Control(pDX, IDC_EDIT_WRITE_VALUE, mWriteValueEdit);
}

BEGIN_MESSAGE_MAP(CDriverTestDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
    ON_BN_CLICKED(IDC_BUTTON_LOAD_DR, &CDriverTestDlg::OnBnClickedButtonLoadDr)
    ON_BN_CLICKED(IDC_BUTTON_UNLOAD_DR, &CDriverTestDlg::OnBnClickedButtonUnloadDr)
    ON_BN_CLICKED(IDC_BUTTON_GET_MODULE, &CDriverTestDlg::OnBnClickedButtonGetModule)
    ON_BN_CLICKED(IDC_BUTTON_READ_DWORD, &CDriverTestDlg::OnBnClickedButtonReadDword)
    ON_BN_CLICKED(IDC_BUTTON_READ_LONG, &CDriverTestDlg::OnBnClickedButtonReadLong)
    ON_BN_CLICKED(IDC_BUTTON_READ_BYTE, &CDriverTestDlg::OnBnClickedButtonReadByte)
    ON_BN_CLICKED(IDC_BUTTON_READ_TEXT, &CDriverTestDlg::OnBnClickedButtonReadText)
    ON_BN_CLICKED(IDC_BUTTON_READ_FLOAT, &CDriverTestDlg::OnBnClickedButtonReadFloat)
    ON_BN_CLICKED(IDC_BUTTON_READ_DOUBLE, &CDriverTestDlg::OnBnClickedButtonReadDouble)
    ON_BN_CLICKED(IDC_BUTTON_WRITE_DOWRD, &CDriverTestDlg::OnBnClickedButtonWriteDowrd)
    ON_BN_CLICKED(IDC_BUTTON_WRITE_LONG, &CDriverTestDlg::OnBnClickedButtonWriteLong)
    ON_BN_CLICKED(IDC_BUTTON_WRITE_BYTE, &CDriverTestDlg::OnBnClickedButtonWriteByte)
    ON_BN_CLICKED(IDC_BUTTON_WRITE_TEXT, &CDriverTestDlg::OnBnClickedButtonWriteText)
    ON_BN_CLICKED(IDC_BUTTON_WRITE_FLOAT, &CDriverTestDlg::OnBnClickedButtonWriteFloat)
    ON_BN_CLICKED(IDC_BUTTON_WRITE_DOUBLE, &CDriverTestDlg::OnBnClickedButtonWriteDouble)
END_MESSAGE_MAP()


// CDriverTestDlg ��Ϣ�������

BOOL CDriverTestDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	ShowWindow(SW_MINIMIZE);

	// TODO:  �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CDriverTestDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CDriverTestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CDriverTestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


//��������
void CDriverTestDlg::OnBnClickedButtonLoadDr()
{
    BOOL bRet = LoadNTDriver(DRIVER_NAME, DRIVER_PATH);
    if (!bRet)
    {
        MessageBox("��������ʧ��!");
    }
    else
    {
        MessageBox("�������سɹ�!");
    }
}

//ж������
void CDriverTestDlg::OnBnClickedButtonUnloadDr()
{
    BOOL bRet = UnloadNTDriver(DRIVER_NAME);
    if (!bRet)
    {
        MessageBox("ж������ʧ��!");
    }
    else
    {
        MessageBox("ж�������ɹ�!");
    }
}

//��ȡģ����
void CDriverTestDlg::OnBnClickedButtonGetModule()
{
    CString inputStr;
    //������������  
    HANDLE hDevice = CreateFile(ZIYU_DEVICE_FILE,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (hDevice != INVALID_HANDLE_VALUE)
    {
    }
    else
    {
        MessageBox("��ȡ�����豸����");
        goto Error;
    }

    
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid<=0)
    {
        MessageBox("��������ȷ��pid");
        goto Error;
    }
    char outName[16] = { 0 };
    DWORD dwOutput = 0;
    BOOL bRet;
    bRet = DeviceIoControl(hDevice, IOCTL_GETIMAGE, &pid, 4, outName, 16, &dwOutput, NULL);
    if (bRet)
    {
        mModuleNameEdit.SetWindowText(outName);
    }
    else
    {
        MessageBox("��ȡģ�����");
    }

Error:
    CloseHandle(hDevice);
}

//��dword
void CDriverTestDlg::OnBnClickedButtonReadDword()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("��������ȷ��pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("��������ȷ�Ĳ����ڴ��ַ");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("�����ڴ��ַ0x%x", addr);
    //    MessageBox(testStr);
    //}
    DWORD result = 0;
    BOOL bRet = ZiyuReadDWORD(pid, addr, &result);
    if (!bRet)
    {
        MessageBox("��ȡDWORD����");
        return;
    }
    CString show;
    show.Format("%u", result);
    mReadValueEdit.SetWindowText(show);
}

//��long
void CDriverTestDlg::OnBnClickedButtonReadLong()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("��������ȷ��pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("��������ȷ�Ĳ����ڴ��ַ");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("�����ڴ��ַ0x%x", addr);
    //    MessageBox(testStr);
    //}
    QWORD result = 0;
    BOOL bRet = ZiyuReadQWORD(pid, addr, &result);
    if (!bRet)
    {
        MessageBox("��ȡLONG����");
        return;
    }
    CString show;
    show.Format("%lu", result);
    mReadValueEdit.SetWindowText(show);
}

//���ֽ�
void CDriverTestDlg::OnBnClickedButtonReadByte()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("��������ȷ��pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("��������ȷ�Ĳ����ڴ��ַ");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("�����ڴ��ַ0x%x", addr);
    //    MessageBox(testStr);
    //}
    BYTE result = 0;
    BOOL bRet = ZiyuReadBYTE(pid, addr, &result);
    if (!bRet)
    {
        MessageBox("��ȡBYTE����");
        return;
    }
    CString show;
    show.Format("%u", result);
    mReadValueEdit.SetWindowText(show);
}

//���ַ���
void CDriverTestDlg::OnBnClickedButtonReadText()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("��������ȷ��pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("��������ȷ�Ĳ����ڴ��ַ");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("�����ڴ��ַ0x%x", addr);
    //    MessageBox(testStr);
    //}
    char result[64] = {0};
    BOOL bRet = ZiyuReadSTR(pid, addr, result, 60);
    if (!bRet)
    {
        MessageBox("��ȡSTR����");
        return;
    }

    mReadValueEdit.SetWindowText(result);
}

//��float
void CDriverTestDlg::OnBnClickedButtonReadFloat()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("��������ȷ��pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("��������ȷ�Ĳ����ڴ��ַ");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("�����ڴ��ַ0x%x", addr);
    //    MessageBox(testStr);
    //}
    float result = 0;
    BOOL bRet = ZiyuReadFloat(pid, addr, &result);
    if (!bRet)
    {
        MessageBox("��ȡfloat����");
        return;
    }
    CString show;
    show.Format("%f", result);
    mReadValueEdit.SetWindowText(show);
}

//��double
void CDriverTestDlg::OnBnClickedButtonReadDouble()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("��������ȷ��pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("��������ȷ�Ĳ����ڴ��ַ");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("�����ڴ��ַ0x%x", addr);
    //    MessageBox(testStr);
    //}
    double result = 0;
    BOOL bRet = ZiyuReadDOUBLE(pid, addr, &result);
    if (!bRet)
    {
        MessageBox("��ȡdouble����");
        return;
    }
    CString show;
    show.Format("%f", result);
    mReadValueEdit.SetWindowText(show);
}

//дdword
void CDriverTestDlg::OnBnClickedButtonWriteDowrd()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("��������ȷ��pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("��������ȷ�Ĳ����ڴ��ַ");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("�����ڴ��ַ0x%x", addr);
    //    MessageBox(testStr);
    //}
    mWriteValueEdit.GetWindowTextA(inputStr);
    DWORD value = 0;
    sscanf_s(inputStr.GetString(), "%u", &value);
    //CString testStr;
    //testStr.Format("����д����%u", value);
    //MessageBox(testStr);

    BOOL bRet = ZiyuWriteDWORD(pid, addr, value);
    if (!bRet)
    {
        MessageBox("д��DWORD����");
    }
}

//дlong
void CDriverTestDlg::OnBnClickedButtonWriteLong()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("��������ȷ��pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("��������ȷ�Ĳ����ڴ��ַ");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("�����ڴ��ַ0x%x", addr);
    //    MessageBox(testStr);
    //}
    mWriteValueEdit.GetWindowTextA(inputStr);
    QWORD value = 0;
    sscanf_s(inputStr.GetString(), "%llu", &value);
    //CString testStr;
    //testStr.Format("����д����%llu", value);
    //MessageBox(testStr);
    BOOL bRet = ZiyuWriteQWORD(pid, addr, value);
    if (!bRet)
    {
        MessageBox("д��QWORD����");
    }
}

//дbyte
void CDriverTestDlg::OnBnClickedButtonWriteByte()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("��������ȷ��pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("��������ȷ�Ĳ����ڴ��ַ");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("�����ڴ��ַ0x%x", addr);
    //    MessageBox(testStr);
    //}
    mWriteValueEdit.GetWindowTextA(inputStr);
    BYTE value = 0;
    sscanf_s(inputStr.GetString(), "%u", &value);

    BOOL bRet = ZiyuWriteBYTE(pid, addr, value);
    if (!bRet)
    {
        MessageBox("д��BYTE����");
    }
}

//дtext
void CDriverTestDlg::OnBnClickedButtonWriteText()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("��������ȷ��pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("��������ȷ�Ĳ����ڴ��ַ");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("�����ڴ��ַ0x%x", addr);
    //    MessageBox(testStr);
    //}
    mWriteValueEdit.GetWindowTextA(inputStr);
    
    //sscanf_s(inputStr.GetString(), "%u", &value);

    //MessageBox(inputStr.GetBuffer());
    BOOL bRet = ZiyuWriteSTR(pid, addr, inputStr.GetBuffer());
    if (!bRet)
    {
        MessageBox("д��str����");
    }
}

//дfloat
void CDriverTestDlg::OnBnClickedButtonWriteFloat()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("��������ȷ��pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("��������ȷ�Ĳ����ڴ��ַ");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("�����ڴ��ַ0x%x", addr);
    //    MessageBox(testStr);
    //}
    mWriteValueEdit.GetWindowTextA(inputStr);
    float value = 0;
    sscanf_s(inputStr.GetString(), "%f", &value);


    //CString testStr;
    //testStr.Format("����д����%f", value);
    //MessageBox(testStr);

    BOOL bRet = ZiyuWriteFloat(pid, addr, value);
    if (!bRet)
    {
        MessageBox("д��float����");
    }
}

//дdouble
void CDriverTestDlg::OnBnClickedButtonWriteDouble()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("��������ȷ��pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("��������ȷ�Ĳ����ڴ��ַ");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("�����ڴ��ַ0x%x", addr);
    //    MessageBox(testStr);
    //}
    mWriteValueEdit.GetWindowTextA(inputStr);
    double value = 0;
    sscanf_s(inputStr.GetString(), "%lf", &value);


    //CString testStr;
    //testStr.Format("����д����%lf", value);
    //MessageBox(testStr);

    BOOL bRet = ZiyuWriteDOUBLE(pid, addr, value);
    if (!bRet)
    {
        MessageBox("д��double����");
    }
}
