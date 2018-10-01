// IOCTLS.H -- IOCTL code definitions for fileio driver
// Copyright (C) 1999 by Walter Oney
// All rights reserved

#ifndef WIN732_H
#define WIN732_H
#include "../Driver.h"
//32:  char:1, short:2, int:4, long:4, long long:8, ptr:4
//64:  char:1, short:2, int:4, long:4, long long:8, ptr:8

#define BOOL ULONG
typedef unsigned char BYTE;
typedef unsigned int DWORD;
typedef unsigned long PTR;

extern "C" NTKERNELAPI PVOID NTAPI
ObGetObjectType(
IN PVOID pObject
);

typedef struct _OBJECT_HEADER {

    struct {
        LONG PointerCount;  //0x0
        union {
            LONG HandleCount; //0x4
            PVOID NextToFree; //0x4
        };
    };
    PVOID Lock; //_EX_PUSH_LOCK //0x8
    UCHAR TypeIndex; //0xc
    UCHAR TraceFlags; //0xd
    UCHAR InfoMask; //0xe
    UCHAR Flags; //0xf

    union {
        //POBJECT_CREATE_INFORMATION ObjectCreateInfo; //0x10
        PVOID QuotaBlockCharged; //0x10
    };

    PSECURITY_DESCRIPTOR SecurityDescriptor; //0x14

    QUAD Body; //0x18
} OBJECT_HEADER, *POBJECT_HEADER;

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

typedef struct _HANDLE_TABLE {
    ULONG TableCode; //0x0
    PEPROCESS QuotaProcess; //0x4
    PVOID UniqueProcessId; //0x8
    ULONG HandleLock;// _EX_PUSH_LOCK 0xc
    LIST_ENTRY HandleTableList; //0x10
    ULONG HandleContentionEvent; //0x18 _EX_PUSH_LOCK
    PULONG DebugInfo; //0x1c _HANDLE_TRACE_DEBUG_INFO
    int ExtraInfoPages; //0x20
    union {
        ULONG Flags; //0x24
        BYTE StrictFIFO : 1; //0x24
    };
    ULONG FirstFreeHandle; //0x28
    PHANDLE_TABLE_ENTRY LastFreeHandleEntry; //0x2c
    ULONG HandleCount; //0x30
    ULONG NextHandleNeedingPool; //0x34
    ULONG HandleCountHighWatermark; //0x38
} HANDLE_TABLE, *PHANDLE_TABLE;

typedef struct _KAPC_STATE{
    LIST_ENTRY        ApcListHead[2]; //0X0
    PEPROCESS        Process; //0x10
    UCHAR                KernelApcInProgress; //0x14
    UCHAR                KernelApcPending; //0x15
    UCHAR                UserApcPending; //0x16
}KAPC_STATE, *PKAPC_STATE;

//内核模块相关结构
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
//系统偏移量（因系统而异，可使用Windbg查询）
#define SYSTEMPID 4 //系统进程pid
//#define ProcessNameOffset  0x1fc
#define DIRECTORY_TABLE_BASE  0x18//_EPROCESS中的偏移
#define TYPE 0X0c               //_OBJECT_HEADER中的偏移
//#define NEXTFREETABLEENTRY 0X04 //_HANDLE_TABLE_ENTRY中的偏移
#define UNIQUEPROCESSID 0x0b4    //_EPROCESS中的偏移
#define FLICKOFFSET 0xb8        //_EPROCESS中的偏移
#define IMAGEFILENAME 0x16c     //_EPROCESS中的偏移
#define FLAGS 0x270             //_EPROCESS中的偏移
#define PIDOFFSET 0x0b4          //_EPROCESS中的偏移

#define MASKLAST2BIT 0x3          //TbaleCode 后两位掩位
#define NORMASKLAST2BIT 0xfffffffc          //TbaleCode 后两位掩位
//通过当前进程获取进程对象的类型指针
PVOID GetProcessType()
{
    PVOID eproc;
    UCHAR type;
    eproc =/* (ULONG)*/PsGetCurrentProcess();//PsGetCurrentProcess获取当前活动进程的地址，实际上就是对象（体）指针
    return ObGetObjectType(eproc);
    //eproc = (ULONG)OBJECT_TO_OBJECT_HEADER(eproc);
    //type = *(UCHAR*)(eproc + TYPE);
    //return type;
}

PVOID GetPspCidTable()
{
    UNICODE_STRING uniPsLookup;
    PUCHAR psLookbyidAddr;
    PVOID pspCidTableAddr = NULL;
    PUCHAR cPtr;
    RtlInitUnicodeString(&uniPsLookup, L"PsLookupProcessByProcessId");
    psLookbyidAddr = (PUCHAR)MmGetSystemRoutineAddress(&uniPsLookup);
    if (NULL == psLookbyidAddr)
    {
        KdPrint(("GetPspCidTable MmGetSystemRoutineAddress.pspCidTableAddr:null"));
        return NULL;
    }
    for (;; psLookbyidAddr++)
    {
        //0x3d8b
        //xp => 0x35ff
        if ((0x8b3d == (*(PUSHORT)psLookbyidAddr)) && (0xe8 == (*(PUCHAR)(psLookbyidAddr + 6))))
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

    for (; psLookbyidAddr < psLookbyidAddrT + 0x50; psLookbyidAddr++)
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
    return find ? (PVOID)pspCidTableAddr : NULL;
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
