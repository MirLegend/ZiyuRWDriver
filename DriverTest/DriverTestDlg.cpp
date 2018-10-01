
// DriverTestDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "DriverTest.h"
#include "DriverTestDlg.h"
#include "afxdialogex.h"
#include "ZiyuHead.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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


// CDriverTestDlg 对话框



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


// CDriverTestDlg 消息处理程序

BOOL CDriverTestDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	ShowWindow(SW_MINIMIZE);

	// TODO:  在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CDriverTestDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CDriverTestDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


//加载驱动
void CDriverTestDlg::OnBnClickedButtonLoadDr()
{
    BOOL bRet = LoadNTDriver(DRIVER_NAME, DRIVER_PATH);
    if (!bRet)
    {
        MessageBox("驱动加载失败!");
    }
    else
    {
        MessageBox("驱动加载成功!");
    }
}

//卸载驱动
void CDriverTestDlg::OnBnClickedButtonUnloadDr()
{
    BOOL bRet = UnloadNTDriver(DRIVER_NAME);
    if (!bRet)
    {
        MessageBox("卸载驱动失败!");
    }
    else
    {
        MessageBox("卸载驱动成功!");
    }
}

//获取模块名
void CDriverTestDlg::OnBnClickedButtonGetModule()
{
    CString inputStr;
    //测试驱动程序  
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
        MessageBox("获取驱动设备出错");
        goto Error;
    }

    
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid<=0)
    {
        MessageBox("请输入正确的pid");
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
        MessageBox("获取模块出错");
    }

Error:
    CloseHandle(hDevice);
}

//读dword
void CDriverTestDlg::OnBnClickedButtonReadDword()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("请输入正确的pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("请输入正确的测试内存地址");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("测试内存地址0x%x", addr);
    //    MessageBox(testStr);
    //}
    DWORD result = 0;
    BOOL bRet = ZiyuReadDWORD(pid, addr, &result);
    if (!bRet)
    {
        MessageBox("读取DWORD错误！");
        return;
    }
    CString show;
    show.Format("%u", result);
    mReadValueEdit.SetWindowText(show);
}

//读long
void CDriverTestDlg::OnBnClickedButtonReadLong()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("请输入正确的pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("请输入正确的测试内存地址");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("测试内存地址0x%x", addr);
    //    MessageBox(testStr);
    //}
    QWORD result = 0;
    BOOL bRet = ZiyuReadQWORD(pid, addr, &result);
    if (!bRet)
    {
        MessageBox("读取LONG错误！");
        return;
    }
    CString show;
    show.Format("%lu", result);
    mReadValueEdit.SetWindowText(show);
}

//读字节
void CDriverTestDlg::OnBnClickedButtonReadByte()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("请输入正确的pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("请输入正确的测试内存地址");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("测试内存地址0x%x", addr);
    //    MessageBox(testStr);
    //}
    BYTE result = 0;
    BOOL bRet = ZiyuReadBYTE(pid, addr, &result);
    if (!bRet)
    {
        MessageBox("读取BYTE错误！");
        return;
    }
    CString show;
    show.Format("%u", result);
    mReadValueEdit.SetWindowText(show);
}

//读字符串
void CDriverTestDlg::OnBnClickedButtonReadText()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("请输入正确的pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("请输入正确的测试内存地址");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("测试内存地址0x%x", addr);
    //    MessageBox(testStr);
    //}
    char result[64] = {0};
    BOOL bRet = ZiyuReadSTR(pid, addr, result, 60);
    if (!bRet)
    {
        MessageBox("读取STR错误！");
        return;
    }

    mReadValueEdit.SetWindowText(result);
}

//读float
void CDriverTestDlg::OnBnClickedButtonReadFloat()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("请输入正确的pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("请输入正确的测试内存地址");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("测试内存地址0x%x", addr);
    //    MessageBox(testStr);
    //}
    float result = 0;
    BOOL bRet = ZiyuReadFloat(pid, addr, &result);
    if (!bRet)
    {
        MessageBox("读取float错误！");
        return;
    }
    CString show;
    show.Format("%f", result);
    mReadValueEdit.SetWindowText(show);
}

//读double
void CDriverTestDlg::OnBnClickedButtonReadDouble()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("请输入正确的pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("请输入正确的测试内存地址");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("测试内存地址0x%x", addr);
    //    MessageBox(testStr);
    //}
    double result = 0;
    BOOL bRet = ZiyuReadDOUBLE(pid, addr, &result);
    if (!bRet)
    {
        MessageBox("读取double错误！");
        return;
    }
    CString show;
    show.Format("%f", result);
    mReadValueEdit.SetWindowText(show);
}

//写dword
void CDriverTestDlg::OnBnClickedButtonWriteDowrd()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("请输入正确的pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("请输入正确的测试内存地址");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("测试内存地址0x%x", addr);
    //    MessageBox(testStr);
    //}
    mWriteValueEdit.GetWindowTextA(inputStr);
    DWORD value = 0;
    sscanf_s(inputStr.GetString(), "%u", &value);
    //CString testStr;
    //testStr.Format("测试写内容%u", value);
    //MessageBox(testStr);

    BOOL bRet = ZiyuWriteDWORD(pid, addr, value);
    if (!bRet)
    {
        MessageBox("写入DWORD错误！");
    }
}

//写long
void CDriverTestDlg::OnBnClickedButtonWriteLong()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("请输入正确的pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("请输入正确的测试内存地址");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("测试内存地址0x%x", addr);
    //    MessageBox(testStr);
    //}
    mWriteValueEdit.GetWindowTextA(inputStr);
    QWORD value = 0;
    sscanf_s(inputStr.GetString(), "%llu", &value);
    //CString testStr;
    //testStr.Format("测试写内容%llu", value);
    //MessageBox(testStr);
    BOOL bRet = ZiyuWriteQWORD(pid, addr, value);
    if (!bRet)
    {
        MessageBox("写入QWORD错误！");
    }
}

//写byte
void CDriverTestDlg::OnBnClickedButtonWriteByte()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("请输入正确的pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("请输入正确的测试内存地址");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("测试内存地址0x%x", addr);
    //    MessageBox(testStr);
    //}
    mWriteValueEdit.GetWindowTextA(inputStr);
    BYTE value = 0;
    sscanf_s(inputStr.GetString(), "%u", &value);

    BOOL bRet = ZiyuWriteBYTE(pid, addr, value);
    if (!bRet)
    {
        MessageBox("写入BYTE错误！");
    }
}

//写text
void CDriverTestDlg::OnBnClickedButtonWriteText()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("请输入正确的pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("请输入正确的测试内存地址");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("测试内存地址0x%x", addr);
    //    MessageBox(testStr);
    //}
    mWriteValueEdit.GetWindowTextA(inputStr);
    
    //sscanf_s(inputStr.GetString(), "%u", &value);

    //MessageBox(inputStr.GetBuffer());
    BOOL bRet = ZiyuWriteSTR(pid, addr, inputStr.GetBuffer());
    if (!bRet)
    {
        MessageBox("写入str错误！");
    }
}

//写float
void CDriverTestDlg::OnBnClickedButtonWriteFloat()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("请输入正确的pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("请输入正确的测试内存地址");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("测试内存地址0x%x", addr);
    //    MessageBox(testStr);
    //}
    mWriteValueEdit.GetWindowTextA(inputStr);
    float value = 0;
    sscanf_s(inputStr.GetString(), "%f", &value);


    //CString testStr;
    //testStr.Format("测试写内容%f", value);
    //MessageBox(testStr);

    BOOL bRet = ZiyuWriteFloat(pid, addr, value);
    if (!bRet)
    {
        MessageBox("写入float错误！");
    }
}

//写double
void CDriverTestDlg::OnBnClickedButtonWriteDouble()
{
    CString inputStr;
    mPidEdit.GetWindowTextA(inputStr);
    DWORD pid = _ttoi(inputStr);
    if (pid <= 0)
    {
        MessageBox("请输入正确的pid");
        return;
    }
    mTestAddrEdit.GetWindowTextA(inputStr);
    DWORD addr = 0;
    sscanf_s(inputStr.GetString(), "%x", &addr);
    if (!addr)
    {
        MessageBox("请输入正确的测试内存地址");
        return;
    }
    //else
    //{
    //    CString testStr;
    //    testStr.Format("测试内存地址0x%x", addr);
    //    MessageBox(testStr);
    //}
    mWriteValueEdit.GetWindowTextA(inputStr);
    double value = 0;
    sscanf_s(inputStr.GetString(), "%lf", &value);


    //CString testStr;
    //testStr.Format("测试写内容%lf", value);
    //MessageBox(testStr);

    BOOL bRet = ZiyuWriteDOUBLE(pid, addr, value);
    if (!bRet)
    {
        MessageBox("写入double错误！");
    }
}
