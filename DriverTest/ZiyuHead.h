#ifndef ZIYU_H
#define ZIYU_H

#include <windows.h>  
#include <winsvc.h>  
#include <conio.h>  
#include <stdio.h>

#include <winioctl.h>

#define  IN
#define  OUT

#define DRIVER_NAME "ZiyuDDK"
#define DRIVER_PATH "ZIYUDIVER.sys"
#define ZIYU_DEVICE_FILE           "\\\\.\\ZiyuDDK"

#define DP0(fmt) {TCHAR sOut[256];_stprintf_s(sOut,_T(fmt));OutputDebugString(sOut);}    
#define DP1(fmt,var) {TCHAR sOut[256];_stprintf_s(sOut,_T(fmt),var);OutputDebugString(sOut);}    
#define DP2(fmt,var1,var2) {TCHAR sOut[256];_stprintf_s(sOut,_T(fmt),var1,var2);OutputDebugString(sOut);}    
#define DP3(fmt,var1,var2,var3) {TCHAR sOut[256];_stprintf_s(sOut,_T(fmt),var1,var2,var3);OutputDebugString(sOut);}  

#define IOCTL_READ CTL_CODE(\
			FILE_DEVICE_UNKNOWN, \
			0x800, \
			METHOD_BUFFERED, \
			FILE_ANY_ACCESS)

#define IOCTL_WRITE CTL_CODE(\
			FILE_DEVICE_UNKNOWN, \
			0x801, \
            METHOD_BUFFERED, \
			FILE_ANY_ACCESS)

#define IOCTL_GETIMAGE CTL_CODE(\
			FILE_DEVICE_UNKNOWN, \
			0x802, \
            METHOD_BUFFERED, \
			FILE_ANY_ACCESS)



//装载NT驱动程序
BOOL LoadNTDriver(char* lpszDriverName, char* lpszDriverPath)
{
    char szDriverImagePath[256];
    //得到完整的驱动路径
    GetFullPathName(lpszDriverPath, 256, szDriverImagePath, NULL);

    BOOL bRet = FALSE;

    SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄
    SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄

    //打开服务控制管理器
    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (hServiceMgr == NULL)
    {
        //OpenSCManager失败
        //printf("OpenSCManager() Faild %d ! \n", GetLastError());
        bRet = FALSE;
        goto BeforeLeave;
    }
    else
    {
        ////OpenSCManager成功
        //printf("OpenSCManager() ok ! \n");
    }

    //创建驱动所对应的服务
    hServiceDDK = CreateService(hServiceMgr,
        lpszDriverName, //驱动程序的在注册表中的名字  
        lpszDriverName, // 注册表驱动程序的 DisplayName 值  
        SERVICE_ALL_ACCESS, // 加载驱动程序的访问权限  
        SERVICE_KERNEL_DRIVER,// 表示加载的服务是驱动程序  
        SERVICE_DEMAND_START, // 注册表驱动程序的 Start 值  
        SERVICE_ERROR_IGNORE, // 注册表驱动程序的 ErrorControl 值  
        szDriverImagePath, // 注册表驱动程序的 ImagePath 值  
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    DWORD dwRtn;
    //判断服务是否失败
    if (hServiceDDK == NULL)
    {
        dwRtn = GetLastError();
        if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
        {
            //由于其他原因创建服务失败
            //printf("CrateService() Faild %d ! \n", dwRtn);
            bRet = FALSE;
            goto BeforeLeave;
        }
        else
        {
            //服务创建失败，是由于服务已经创立过
            //printf("CrateService() Faild Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n");
        }

        // 驱动程序已经加载，只需要打开  
        hServiceDDK = OpenService(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
        if (hServiceDDK == NULL)
        {
            //如果打开服务也失败，则意味错误
            dwRtn = GetLastError();
            //printf("OpenService() Faild %d ! \n", dwRtn);
            bRet = FALSE;
            goto BeforeLeave;
        }
        else
        {
            //printf("OpenService() ok ! \n");
        }
    }
    else
    {
        //printf("CrateService() ok ! \n");
    }

    //开启此项服务
    bRet = StartService(hServiceDDK, NULL, NULL);
    if (!bRet)
    {
        DWORD dwRtn = GetLastError();
        if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
        {
            //printf("StartService() Faild %d ! \n", dwRtn);
            bRet = FALSE;
            goto BeforeLeave;
        }
        else
        {
            if (dwRtn == ERROR_IO_PENDING)
            {
                //设备被挂住
                //printf("StartService() Faild ERROR_IO_PENDING ! \n");
                bRet = FALSE;
                goto BeforeLeave;
            }
            else
            {
                //服务已经开启
                //printf("StartService() Faild ERROR_SERVICE_ALREADY_RUNNING ! \n");
                bRet = TRUE;
                goto BeforeLeave;
            }
        }
    }
    bRet = TRUE;
    //离开前关闭句柄
BeforeLeave:
    if (hServiceDDK)
    {
        CloseServiceHandle(hServiceDDK);
    }
    if (hServiceMgr)
    {
        CloseServiceHandle(hServiceMgr);
    }
    return bRet;
}

//卸载驱动程序  
BOOL UnloadNTDriver(char * szSvrName)
{
    BOOL bRet = FALSE;
    SC_HANDLE hServiceMgr = NULL;//SCM管理器的句柄
    SC_HANDLE hServiceDDK = NULL;//NT驱动程序的服务句柄
    SERVICE_STATUS SvrSta;
    //打开SCM管理器
    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hServiceMgr == NULL)
    {
        //带开SCM管理器失败
        //printf("OpenSCManager() Faild %d ! \n", GetLastError());
        bRet = FALSE;
        goto BeforeLeave;
    }
    else
    {
        //带开SCM管理器失败成功
        //printf("OpenSCManager() ok ! \n");
    }
    //打开驱动所对应的服务
    hServiceDDK = OpenService(hServiceMgr, szSvrName, SERVICE_ALL_ACCESS);

    if (hServiceDDK == NULL)
    {
        //打开驱动所对应的服务失败
        //printf("OpenService() Faild %d ! \n", GetLastError());
        bRet = FALSE;
        goto BeforeLeave;
    }
    else
    {
        //printf("OpenService() ok ! \n");
    }
    //停止驱动程序，如果停止失败，只有重新启动才能，再动态加载。  
    if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta))
    {
        //printf("ControlService() Faild %d !\n", GetLastError());
    }
    else
    {
        //打开驱动所对应的失败
        //printf("ControlService() ok !\n");
    }
    //动态卸载驱动程序。  
    if (!DeleteService(hServiceDDK))
    {
        //卸载失败
        //printf("DeleteSrevice() Faild %d !\n", GetLastError());
    }
    else
    {
        //卸载成功
        //printf("DelServer:eleteSrevice() ok !\n");
    }
    bRet = TRUE;
BeforeLeave:
    //离开前关闭打开的句柄
    if (hServiceDDK)
    {
        CloseServiceHandle(hServiceDDK);
    }
    if (hServiceMgr)
    {
        CloseServiceHandle(hServiceMgr);
    }
    return bRet;
}

inline BOOL
ZiyuReadMemory(IN DWORD pid, IN DWORD addr, IN DWORD ReadSize, OUT void* pOutBuff)
{
    if (!pOutBuff)
    {
        return FALSE;
    }
    //测试驱动程序  
    HANDLE hDevice = CreateFile(ZIYU_DEVICE_FILE,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    char InputBuffer[0xc] = { 0 };
    *(DWORD*)InputBuffer = pid;
    *(DWORD*)(&InputBuffer[0x4]) = addr;
    *(DWORD*)(&InputBuffer[0x8]) = ReadSize;
    
    DWORD dwOutput = 0;
    BOOL bRet;
    bRet = DeviceIoControl(hDevice, IOCTL_READ, InputBuffer, 0xc, pOutBuff, ReadSize, &dwOutput, NULL);
    CloseHandle(hDevice);
    return bRet;
}

inline BOOL
ZiyuWriteMemory(IN DWORD pid, IN DWORD addr, IN void* pWriteBuff, IN DWORD WriteSize)
{
    if (!pWriteBuff)
    {
        return FALSE;
    }
    //测试驱动程序  
    HANDLE hDevice = CreateFile(ZIYU_DEVICE_FILE,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    //char InputBuffer[12] = { 0 };
    void* InputBuffer = malloc(0xc + WriteSize);
    if (!InputBuffer)
    {
        CloseHandle(hDevice);
        return FALSE;
    }
    *(DWORD*)InputBuffer = pid;
    *(DWORD*)((DWORD)InputBuffer+0x4) = addr;
    *(DWORD*)((DWORD)InputBuffer + 0x8) = WriteSize;
    memcpy((void*)((DWORD)InputBuffer + 0xc), pWriteBuff, WriteSize);
    DWORD OutputBuffer = 0;
    DWORD dwOutput = 0;
    BOOL bRet;
    bRet = DeviceIoControl(hDevice, IOCTL_WRITE, InputBuffer, 0xc + WriteSize, InputBuffer, 0xc + WriteSize, &dwOutput, NULL);
    CloseHandle(hDevice);
    free(InputBuffer);
    DP0("ZiyuWriteMemory end！\n");
    return bRet;
}

inline BOOL
ZiyuReadDWORD(IN DWORD pid, IN DWORD addr, OUT DWORD* pValue)
{
    return ZiyuReadMemory(pid, addr, sizeof(DWORD), pValue);
}

inline BOOL
ZiyuReadQWORD(IN DWORD pid, IN DWORD addr, OUT QWORD* pValue)
{
    return ZiyuReadMemory(pid, addr, sizeof(QWORD), pValue);
}

inline BOOL
ZiyuReadBYTE(IN DWORD pid, IN DWORD addr, OUT BYTE* pValue)
{
    return ZiyuReadMemory(pid, addr, sizeof(BYTE), pValue);
}

inline BOOL
ZiyuReadSTR(IN DWORD pid, IN DWORD addr, OUT char* pValue, IN DWORD readSize)
{
    return ZiyuReadMemory(pid, addr, readSize, pValue);
}

inline BOOL
ZiyuReadFloat(IN DWORD pid, IN DWORD addr, OUT float* pValue)
{
    return ZiyuReadMemory(pid, addr, sizeof(float), pValue);
}

inline BOOL
ZiyuReadDOUBLE(IN DWORD pid, IN DWORD addr, OUT double* pValue)
{
    return ZiyuReadMemory(pid, addr, sizeof(double), pValue);
}

inline BOOL
ZiyuWriteDWORD(IN DWORD pid, IN DWORD addr, IN DWORD value)
{
    DWORD tempValue = value;
    return ZiyuWriteMemory(pid, addr, &tempValue, sizeof(DWORD));
}

inline BOOL
ZiyuWriteQWORD(IN DWORD pid, IN DWORD addr, IN QWORD value)
{
    QWORD tempValue = value;
    return ZiyuWriteMemory(pid, addr, &tempValue, sizeof(QWORD));
}

inline BOOL
ZiyuWriteBYTE(IN DWORD pid, IN DWORD addr, IN BYTE value)
{
    BYTE tempValue = value;
    return ZiyuWriteMemory(pid, addr, &tempValue, sizeof(BYTE));
}

inline BOOL
ZiyuWriteSTR(IN DWORD pid, IN DWORD addr, IN CHAR* value)
{
    return ZiyuWriteMemory(pid, addr, value, strlen(value));
}

inline BOOL
ZiyuWriteFloat(IN DWORD pid, IN DWORD addr, IN float value)
{
    float tempValue = value;
    return ZiyuWriteMemory(pid, addr, &tempValue, sizeof(float));
}

inline BOOL
ZiyuWriteDOUBLE(IN DWORD pid, IN DWORD addr, IN double value)
{
    double tempValue = value;
    return ZiyuWriteMemory(pid, addr, &tempValue, sizeof(double));
}

#endif
