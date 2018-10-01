/************************************************************************
* 文件名称:Driver.h                                                 
* 作    者:mirlegend
* 完成日期:2017-11-1
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

#define  MAX_HIDDEN_PROCESS 10  //最多支持10个隐藏进程

typedef struct _STORE_PROCESS_HANDLE
{
    PTR processCode; // 要去掉低三位才是eprocess
    PTR handleAddr; //句柄表地址
}STORE_PROCESS_HANDLE, *PSTORE_PROCESS_HANDLE;

typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING ustrDeviceName;	//设备名称
	//UNICODE_STRING ustrSymLinkName;	//符号链接名
    /*PAGED_LOOKASIDE_LIST pageList;*/
    PTR hidenPidArray[MAX_HIDDEN_PROCESS];
    STORE_PROCESS_HANDLE hiddenProcessHandles[MAX_HIDDEN_PROCESS];

    //内核模块相关
    PLIST_ENTRY pKernelModuleList;
    LIST_ENTRY HiddenModuleList;

} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// 函数声明

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
