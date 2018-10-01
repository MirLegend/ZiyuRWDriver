// IOCTLS.H -- IOCTL code definitions for fileio driver
// Copyright (C) 1999 by Walter Oney
// All rights reserved

#ifndef WINXP_H
#define WINXP_H
#include "../Driver.h"
//32:  char:1, short:2, int:4, long:4, long long:8, ptr:4
//64:  char:1, short:2, int:4, long:4, long long:8, ptr:8

#define BOOL ULONG
typedef unsigned char BYTE;
typedef unsigned int DWORD;
typedef unsigned long PTR;
//_OBJECT_HEADER�ṹ�Լ����ڸýṹʵ�ִӶ����壩ָ���ö���ͷ��ָ��ĺ�
typedef struct _OBJECT_HEADER {
    
    struct {
        LONG PointerCount;  //0x0
        union {
            LONG HandleCount; //0x4
            PVOID NextToFree; //0x4
        };
    };
    
    POBJECT_TYPE Type; //0x8
    UCHAR NameInfoOffset; //0xc
    UCHAR HandleInfoOffset; //0xd
    UCHAR QuotaInfoOffset; //0xe
    UCHAR Flags; //0xf

    union {
        //POBJECT_CREATE_INFORMATION ObjectCreateInfo; //0x10
        PVOID QuotaBlockCharged; //0x10
    };

    PSECURITY_DESCRIPTOR SecurityDescriptor; //0x14

    QUAD Body; //0x18
} OBJECT_HEADER, *POBJECT_HEADER;

typedef struct _HANDLE_TABLE {
    ULONG TableCode; //0x0
    PEPROCESS QuotaProcess; //0x4
    PVOID UniqueProcessId; //0x8
    ULONG HandleTableLock[4];// _EX_PUSH_LOCK 0xc
    LIST_ENTRY HandleTableList; //0x1c
    ULONG HandleContentionEvent; //0x24 _EX_PUSH_LOCK
    PULONG DebugInfo; //0x28 _HANDLE_TRACE_DEBUG_INFO
    int ExtraInfoPages; //0x2c
    ULONG FirstFree; //0x30
    ULONG LastFree; //0x34
    ULONG NextHandleNeedingPool; //0x38
    int HandleCount; //0x3c
    union {
        ULONG Flags; //0x40
        BYTE StrictFIFO : 1; //0x40
    };
} HANDLE_TABLE, *PHANDLE_TABLE;

typedef struct _HANDLE_TABLE_ENTRY {
    union{
        PTR Object; //0x0
        ULONG ObAttributes; //0x0
        PVOID InfoTable; //0x0
        ULONG Value; //0x0
    };
    union{
        ULONG GrantedAccess; //0x4
        struct  
        {
            USHORT GrantedAccessIndex; //0x4
            USHORT CreatorBackTraceIndex; //0x6
        };
        ULONG NextFreeTableEntry; //0x4
    };

} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _KAPC_STATE{
    LIST_ENTRY        ApcListHead[2]; //0X0
    PEPROCESS        Process; //0x10
    UCHAR                KernelApcInProgress; //0x14
    UCHAR                KernelApcPending; //0x15
    UCHAR                UserApcPending; //0x16
}KAPC_STATE, *PKAPC_STATE;

//�ں�ģ����ؽṹ
typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    // ULONG padding on IA64
    PVOID GpValue;
    /*PNON_PAGED_DEBUG_INFO*/ULONG NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5;
    PVOID SectionPointer;
    ULONG CheckSum;
    // ULONG padding on IA64
    PVOID LoadedImports;
    PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;


#define OBJECT_TO_OBJECT_HEADER(obj)         CONTAINING_RECORD( (obj), OBJECT_HEADER, Body )
#define GET_PROCESS_FROM_HANDLE(obj)        (obj & 0xfffffff8)

#define SYSTEMPID 4 //ϵͳ����pid
//#define ProcessNameOffset  0x1fc
#define DIRECTORY_TABLE_BASE  0x18//_EPROCESS�е�ƫ��
#define TYPE 0X08               //_OBJECT_HEADER�е�ƫ��
//#define NEXTFREETABLEENTRY 0X04 //_HANDLE_TABLE_ENTRY�е�ƫ��
#define UNIQUEPROCESSID 0X84    //_EPROCESS�е�ƫ��
#define FLICKOFFSET 0x088        //_EPROCESS�е�ƫ��
#define IMAGEFILENAME 0X174     //_EPROCESS�е�ƫ��
#define FLAGS 0x248             //_EPROCESS�е�ƫ��
#define PIDOFFSET 0x84          //_EPROCESS�е�ƫ��

#define MASKLAST2BIT 0x3          //TbaleCode ����λ��λ
#define NORMASKLAST2BIT 0xfffffffc          //TbaleCode ����λ��λ
//ͨ����ǰ���̻�ȡ���̶��������ָ��
ULONG GetProcessType()
{
    ULONG eproc;
    ULONG type;
    ULONG total;
    eproc = (ULONG)PsGetCurrentProcess();//PsGetCurrentProcess��ȡ��ǰ����̵ĵ�ַ��ʵ���Ͼ��Ƕ����壩ָ��
    eproc = (ULONG)OBJECT_TO_OBJECT_HEADER(eproc);
    type = *(PULONG)(eproc + TYPE);
    return type;
}

ULONG ObGetObjectType(PVOID obj)
{
    ULONG eproc;
    ULONG type;
    eproc = (ULONG)OBJECT_TO_OBJECT_HEADER(obj);
    type = *(PULONG)(eproc + TYPE);
    return type;
}

PVOID GetPspCidTable()
{
    UNICODE_STRING uniPsLookup;
    PUCHAR psLookbyidAddr;
    PVOID pspCidTableAddr = NULL;
    PUCHAR cPtr;
    RtlInitUnicodeString(&uniPsLookup, L"PsLookupProcessByProcessId");
    psLookbyidAddr = (PUCHAR)MmGetSystemRoutineAddress(&uniPsLookup);

    for (;; psLookbyidAddr++)
    {
        //0x3d8b
        //xp => 0x35ff
        if ((0x35ff == (*(PUSHORT)psLookbyidAddr)) && (0xe8 == (*(PUCHAR)(psLookbyidAddr + 6))))
        {
            pspCidTableAddr = *(PVOID *)(psLookbyidAddr + 2);
            break;
        }
    }
    KdPrint(("GetPspCidTable pspCidTableAddr:%x", pspCidTableAddr));
    return (PVOID)pspCidTableAddr;
}

PVOID GetPsLoadedModuleList1()
{
    UNICODE_STRING uniPsLookup;
    PUCHAR psLookbyidAddr;
    PUCHAR psLookbyidAddrT;
    PVOID pspCidTableAddr = NULL;
    PUCHAR cPtr;
    BOOL find = FALSE;
    RtlInitUnicodeString(&uniPsLookup, L"MmLoadSystemImage");
    psLookbyidAddrT = psLookbyidAddr = (PUCHAR)MmGetSystemRoutineAddress(&uniPsLookup);
    if (NULL == psLookbyidAddr)
    {
        return NULL;
    }
    for (; psLookbyidAddr<psLookbyidAddrT+0x50; psLookbyidAddr++)
    {
        //0x3d8b
        //xp => 0x35ff
        if ((0x8b3d == (*(PUSHORT)psLookbyidAddr)) && (0x81 == (*(PUCHAR)(psLookbyidAddr + 6))))
        {
            pspCidTableAddr = *(PVOID *)(psLookbyidAddr + 2);
            find = TRUE;
            break;
        }
    }
    KdPrint(("GetPspCidTable pspCidTableAddr:%x", pspCidTableAddr));
    return find?(PVOID)pspCidTableAddr:NULL;
}

PVOID GetPsLoadedModuleList(IN PDRIVER_OBJECT pDriverObject)
{
    PKLDR_DATA_TABLE_ENTRY entry;
    PKLDR_DATA_TABLE_ENTRY testEntry;
    PLIST_ENTRY nextEntry;
    entry = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
    nextEntry = entry->InLoadOrderLinks.Blink;
   

    while (nextEntry != &entry->InLoadOrderLinks)
    {
        testEntry = CONTAINING_RECORD(nextEntry,
            KLDR_DATA_TABLE_ENTRY,
            InLoadOrderLinks);
        if (testEntry->DllBase == NULL
            && testEntry->EntryPoint == NULL)
        {
            return nextEntry;
            //break;
        }
        nextEntry = testEntry->InLoadOrderLinks.Blink;
    }
    return  NULL;
}


#endif
