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



//װ��NT��������
BOOL LoadNTDriver(char* lpszDriverName, char* lpszDriverPath)
{
    char szDriverImagePath[256];
    //�õ�����������·��
    GetFullPathName(lpszDriverPath, 256, szDriverImagePath, NULL);

    BOOL bRet = FALSE;

    SC_HANDLE hServiceMgr = NULL;//SCM�������ľ��
    SC_HANDLE hServiceDDK = NULL;//NT��������ķ�����

    //�򿪷�����ƹ�����
    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (hServiceMgr == NULL)
    {
        //OpenSCManagerʧ��
        //printf("OpenSCManager() Faild %d ! \n", GetLastError());
        bRet = FALSE;
        goto BeforeLeave;
    }
    else
    {
        ////OpenSCManager�ɹ�
        //printf("OpenSCManager() ok ! \n");
    }

    //������������Ӧ�ķ���
    hServiceDDK = CreateService(hServiceMgr,
        lpszDriverName, //�����������ע����е�����  
        lpszDriverName, // ע������������ DisplayName ֵ  
        SERVICE_ALL_ACCESS, // ������������ķ���Ȩ��  
        SERVICE_KERNEL_DRIVER,// ��ʾ���صķ�������������  
        SERVICE_DEMAND_START, // ע������������ Start ֵ  
        SERVICE_ERROR_IGNORE, // ע������������ ErrorControl ֵ  
        szDriverImagePath, // ע������������ ImagePath ֵ  
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);

    DWORD dwRtn;
    //�жϷ����Ƿ�ʧ��
    if (hServiceDDK == NULL)
    {
        dwRtn = GetLastError();
        if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
        {
            //��������ԭ�򴴽�����ʧ��
            //printf("CrateService() Faild %d ! \n", dwRtn);
            bRet = FALSE;
            goto BeforeLeave;
        }
        else
        {
            //���񴴽�ʧ�ܣ������ڷ����Ѿ�������
            //printf("CrateService() Faild Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n");
        }

        // ���������Ѿ����أ�ֻ��Ҫ��  
        hServiceDDK = OpenService(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
        if (hServiceDDK == NULL)
        {
            //����򿪷���Ҳʧ�ܣ�����ζ����
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

    //�����������
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
                //�豸����ס
                //printf("StartService() Faild ERROR_IO_PENDING ! \n");
                bRet = FALSE;
                goto BeforeLeave;
            }
            else
            {
                //�����Ѿ�����
                //printf("StartService() Faild ERROR_SERVICE_ALREADY_RUNNING ! \n");
                bRet = TRUE;
                goto BeforeLeave;
            }
        }
    }
    bRet = TRUE;
    //�뿪ǰ�رվ��
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

//ж����������  
BOOL UnloadNTDriver(char * szSvrName)
{
    BOOL bRet = FALSE;
    SC_HANDLE hServiceMgr = NULL;//SCM�������ľ��
    SC_HANDLE hServiceDDK = NULL;//NT��������ķ�����
    SERVICE_STATUS SvrSta;
    //��SCM������
    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hServiceMgr == NULL)
    {
        //����SCM������ʧ��
        //printf("OpenSCManager() Faild %d ! \n", GetLastError());
        bRet = FALSE;
        goto BeforeLeave;
    }
    else
    {
        //����SCM������ʧ�ܳɹ�
        //printf("OpenSCManager() ok ! \n");
    }
    //����������Ӧ�ķ���
    hServiceDDK = OpenService(hServiceMgr, szSvrName, SERVICE_ALL_ACCESS);

    if (hServiceDDK == NULL)
    {
        //����������Ӧ�ķ���ʧ��
        //printf("OpenService() Faild %d ! \n", GetLastError());
        bRet = FALSE;
        goto BeforeLeave;
    }
    else
    {
        //printf("OpenService() ok ! \n");
    }
    //ֹͣ�����������ֹͣʧ�ܣ�ֻ�������������ܣ��ٶ�̬���ء�  
    if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta))
    {
        //printf("ControlService() Faild %d !\n", GetLastError());
    }
    else
    {
        //����������Ӧ��ʧ��
        //printf("ControlService() ok !\n");
    }
    //��̬ж����������  
    if (!DeleteService(hServiceDDK))
    {
        //ж��ʧ��
        //printf("DeleteSrevice() Faild %d !\n", GetLastError());
    }
    else
    {
        //ж�سɹ�
        //printf("DelServer:eleteSrevice() ok !\n");
    }
    bRet = TRUE;
BeforeLeave:
    //�뿪ǰ�رմ򿪵ľ��
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
    //������������  
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
    //������������  
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
    DP0("ZiyuWriteMemory end��\n");
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
