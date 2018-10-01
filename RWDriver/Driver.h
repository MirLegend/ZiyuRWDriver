/************************************************************************
* �ļ�����:Driver.h                                                 
* ��    ��:mirlegend
* �������:2017-11-1
*************************************************************************/
#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
#include <NTDDK.h>
//#include <intrin.h>WINXP32
#ifdef __cplusplus
}
#endif 

#ifdef _WIN732
#include "SAL/WIN732.h"
#else
#include "SAL/WIN732.h"
#endif

#define PAGEDCODE code_seg("PAGE")
#define LOCKEDCODE code_seg()
#define INITCODE code_seg("INIT")

#define PAGEDDATA data_seg("PAGE")
#define LOCKEDDATA data_seg()
#define INITDATA data_seg("INIT")

#define arraysize(p) (sizeof(p)/sizeof((p)[0]))

#define  MAX_HIDDEN_PROCESS 10  //���֧��10�����ؽ���

typedef struct _STORE_PROCESS_HANDLE
{
    PTR processCode; // Ҫȥ������λ����eprocess
    PTR handleAddr; //������ַ
}STORE_PROCESS_HANDLE, *PSTORE_PROCESS_HANDLE;

typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING ustrDeviceName;	//�豸����
	//UNICODE_STRING ustrSymLinkName;	//����������
    /*PAGED_LOOKASIDE_LIST pageList;*/
    PTR hidenPidArray[MAX_HIDDEN_PROCESS];
    STORE_PROCESS_HANDLE hiddenProcessHandles[MAX_HIDDEN_PROCESS];

    //�ں�ģ�����
    PLIST_ENTRY pKernelModuleList;
    LIST_ENTRY HiddenModuleList;

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// ��������

NTSTATUS CreateDevice (IN PDRIVER_OBJECT pDriverObject);
VOID ZiyuDDKUnload (IN PDRIVER_OBJECT pDriverObject);
NTSTATUS ZiyuDDKDispatchRoutin(IN PDEVICE_OBJECT pDevObj,
								 IN PIRP pIrp);
NTSTATUS ZiyuDDKRead(IN PDEVICE_OBJECT pDevObj,
    IN PIRP pIrp);
NTSTATUS ZiyuDDWrite(IN PDEVICE_OBJECT pDevObj,
    IN PIRP pIrp);
NTSTATUS ZiyuDDKDeviceIOControl(IN PDEVICE_OBJECT pDevObj,
    IN PIRP pIrp);
