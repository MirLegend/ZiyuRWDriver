/************************************************************************
* 文件名称:Driver.cpp                                                 
* 作    者:mirlegend
* 完成日期:2017-11-1
*************************************************************************/

#include "Driver.h"
#include "Ioctls.h"

#define  DEVICENAME L"\\Device\\ZiyuDevice"
#define  LINKNAME L"\\??\\ZiyuDDK"

//NTKERNELAPI void KeStackAttachProcess(IN PRKPROCESS  Process, OUT PKAPC_STATE ApcState);
//NTKERNELAPI void KeUnstackDetachProcess(IN PKAPC_STATE ApcState);
//NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(IN ULONG ulProcId, OUT PEPROCESS * pEProcess);
typedef void (*KeStackAttachProcess)(IN PRKPROCESS  Process, OUT PKAPC_STATE ApcState);
typedef void(*KeUnstackDetachProcess)(IN PKAPC_STATE ApcState);
typedef NTSTATUS(*PsLookupProcessByProcessId)(IN ULONG ulProcId, OUT PEPROCESS * pEProcess);

PVOID GetFunc(PCWSTR funName)
{
    UNICODE_STRING uniPsLookup;
    PVOID psLookbyidAddr = NULL;
    RtlInitUnicodeString(&uniPsLookup, funName);
    psLookbyidAddr = (PVOID)MmGetSystemRoutineAddress(&uniPsLookup);
    return psLookbyidAddr;
}
PTR GetPtrValue(PVOID p)
{
    if (MmIsAddressValid(p) == FALSE)
        return 0;
    return *(PTR*)p;
}
//void KReadProcessMemory(IN PEPROCESS Process, IN PVOID Address, IN UINT32 Length, OUT PVOID Buffer)
//{
//    PTR pDTB = 0, OldCr3 = 0, vAddr = 0;
//    //Get DTB  
//    pDTB = GetPtrValue((UCHAR*)Process + DIRECTORY_TABLE_BASE);
//    if (pDTB == 0)
//    {
//        DbgPrint("[x32Drv] Can not get PDT");
//        return;
//    }
//    //Record old cr3 and set new cr3  
//    _disable();
//    OldCr3 = __readcr3();
//    __writecr3(pDTB);
//    _enable();
//    //Read process memory  
//    if (MmIsAddressValid(Address))
//    {
//        RtlCopyMemory(Buffer, Address, Length);
//        DbgPrint("[x64Drv] Date read: %ld", *(PDWORD)Buffer);
//    }
//    //Restore old cr3  
//    _disable();
//    __writecr3(OldCr3);
//    _enable();
//}

//void KWriteProcessMemory(IN PEPROCESS Process, IN PVOID Address, IN UINT32 Length, IN PVOID Buffer)
//{
//    ULONG64 pDTB = 0, OldCr3 = 0, vAddr = 0;
//    //Get DTB  
//    pDTB = Get64bitValue((UCHAR*)Process + DIRECTORY_TABLE_BASE);
//    if (pDTB == 0)
//    {
//        DbgPrint("[x64Drv] Can not get PDT");
//        return;
//    }
//    //Record old cr3 and set new cr3  
//    _disable();
//    OldCr3 = __readcr3();
//    __writecr3(pDTB);
//    _enable();
//    //Read process memory  
//    if (MmIsAddressValid(Address))
//    {
//        RtlCopyMemory(Address, Buffer, Length);
//        DbgPrint("[x64Drv] Date wrote.");
//    }
//    //Restore old cr3  
//    _disable();
//    __writecr3(OldCr3);
//    _enable();
//}

NTSTATUS
ZiyuReadMemory(IN ULONG pid, IN PVOID BaseAddress, OUT PVOID Buffer, IN ULONG BufferSize, OUT PULONG NumberOfBytesRead)
{
    KeStackAttachProcess p = (KeStackAttachProcess)GetFunc(L"KeStackAttachProcess");
    KeUnstackDetachProcess u = (KeUnstackDetachProcess)GetFunc(L"KeUnstackDetachProcess");
    PsLookupProcessByProcessId l = (PsLookupProcessByProcessId)GetFunc(L"PsLookupProcessByProcessId");
    if (!p || !u || !l)
    {
        KdPrint(("KeStackAttachProcess or KeUnstackDetachProcess or PsLookupProcessByProcessId not get"));
        return STATUS_UNSUCCESSFUL;
    }
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS EProcess = NULL/*(PEPROCESS)pid*/;
    status = l(pid, &EProcess);
    if (!NT_SUCCESS(status) || !EProcess)
    {
        KdPrint(("PsLookupProcessByProcessId error pid:%d", pid));
        return STATUS_UNSUCCESSFUL;
    }

    //
    /* KReadProcessMemory(EProcess, BaseAddress, BufferSize, Buffer);
     ObDereferenceObject(EProcess);
     return status;*/
    //

    KAPC_STATE ApcState;
    PVOID readbuffer = NULL;
    readbuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, 'Sys');

    if (readbuffer == NULL)
    {
        KdPrint(("ExAllocatePoolWithTag fail"));
        //ObDereferenceObject(EProcess);
        //ExFreePool(readbuffer);
        status = STATUS_UNSUCCESSFUL;
        goto ENDPOS;
    }

   // p((PRKPROCESS)EProcess, &ApcState);
    PTR uOldCr3 = 0;
    PTR uCurrentCr3 = *(PTR*)((PTR)EProcess + DIRECTORY_TABLE_BASE);
    PTR oldCR0 = 0;
    __asm
    {
            cli
            push eax
            mov eax, cr0
            mov oldCR0, eax
            and eax, not 10000h
            mov cr0, eax
    }
    __asm
    {
            mov eax, cr3
            mov uOldCr3, eax

            mov eax, uCurrentCr3
            mov cr3, eax
            pop eax
    }
   
    if (MmIsAddressValid(BaseAddress))
    {
        __try
        {
            ProbeForRead((CONST PVOID)BaseAddress, BufferSize, sizeof(CHAR));
            RtlCopyMemory(readbuffer, BaseAddress, BufferSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            KdPrint(("ProbeForRead fail BaseAddress:0x%x", BaseAddress));
            
            status = STATUS_UNSUCCESSFUL;
        }
    }
    else
    {
        status = STATUS_UNSUCCESSFUL;
    }
    //u(&ApcState);
    __asm
    {
            push eax
            mov eax, uOldCr3
            mov cr3, eax
    }
    __asm
    {
            mov eax, oldCR0
            //or eax, 10000h
            mov cr0, eax
            pop eax
            sti
    }

    if (NT_SUCCESS(status))
    {
        if (MmIsAddressValid(Buffer))
        {
            __try
            {
                //ProbeForWrite(Buffer, BufferSize, sizeof(CHAR));
                RtlCopyMemory(Buffer, readbuffer, BufferSize);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                KdPrint(("ProbeForWrite fail Buffer:0x%x", Buffer));
                status = STATUS_UNSUCCESSFUL;
            }
        }
        else
        {
            status = STATUS_UNSUCCESSFUL;
        }
    }
    ExFreePool(readbuffer);
ENDPOS:
    ObDereferenceObject(EProcess);
    return status;
}

NTSTATUS
ZiyuWriteMemory(IN ULONG pid, IN PVOID BaseAddress, IN PVOID Pbuff, IN ULONG BufferSize, OUT PULONG NumberOfBytesWritten)
{
    KeStackAttachProcess p = (KeStackAttachProcess)GetFunc(L"KeStackAttachProcess");
    KeUnstackDetachProcess u = (KeUnstackDetachProcess)GetFunc(L"KeUnstackDetachProcess");
    PsLookupProcessByProcessId l = (PsLookupProcessByProcessId)GetFunc(L"PsLookupProcessByProcessId");
    if (!p || !u || !l)
    {
        KdPrint(("KeStackAttachProcess or KeUnstackDetachProcess or PsLookupProcessByProcessId not get"));
        return STATUS_UNSUCCESSFUL;
    }
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS EProcess = NULL/*(PEPROCESS)pid*/;
    status = l(pid, &EProcess);
    if (!NT_SUCCESS(status) || !EProcess)
    {
        KdPrint(("PsLookupProcessByProcessId error pid:%d", pid));
        return STATUS_UNSUCCESSFUL;
    }
    KAPC_STATE ApcState;
    PVOID writebuffer = NULL;
    //if (!NT_SUCCESS(status))
    //{
    //    return STATUS_UNSUCCESSFUL;
    //}
    writebuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, 'Sys');

    if (writebuffer == NULL)
    {
        KdPrint(("ExAllocatePoolWithTag fail"));
        //ExFreePool(writebuffer);
        status = STATUS_UNSUCCESSFUL;
        goto ENDPOS;
    }
    //*(ULONG*)writebuffer = (ULONG)0x1;

    if (MmIsAddressValid(Pbuff))
    {
        __try
        {
            //ProbeForRead((CONST PVOID)Pbuff, BufferSize, sizeof(CHAR));
            RtlCopyMemory(writebuffer, Pbuff, BufferSize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            KdPrint(("ProbeForRead fail"));
            status = STATUS_UNSUCCESSFUL;
        }
    }
    else
    {
        KdPrint(("MmIsAddressValid fail pbuff:0x%x", Pbuff));
        status = STATUS_UNSUCCESSFUL;
    }
    
    if (NT_SUCCESS(status))
    {
        PTR uOldCr3 = 0;
        PTR uCurrentCr3 = *(PTR*)((PTR)EProcess + DIRECTORY_TABLE_BASE);
        PTR oldCR0 = 0;
        //p((PRKPROCESS)EProcess, &ApcState);
        __asm
        {
            cli
                push eax
                mov eax, cr0
                mov oldCR0, eax
                and eax, not 10000h
                mov cr0, eax
        }
        __asm
        {
            mov eax, cr3
                mov uOldCr3, eax

                mov eax, uCurrentCr3
                mov cr3, eax
                pop eax
        }
        if (MmIsAddressValid(BaseAddress))
        {
            __try
            {
                ProbeForWrite((CONST PVOID)BaseAddress, BufferSize, sizeof(CHAR));
                RtlCopyMemory(BaseAddress, writebuffer, BufferSize);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                KdPrint(("ProbeForWrite fail"));
                status = STATUS_UNSUCCESSFUL;
            }
        }
        else
        {
            KdPrint(("MmIsAddressValid fail BaseAddress:0x%x", BaseAddress));
            status = STATUS_UNSUCCESSFUL;
        }
        //u(&ApcState);
        __asm
        {
            push eax
                mov eax, uOldCr3
                mov cr3, eax
        }
        __asm
        {
            mov eax, oldCR0
                //or eax, 10000h
                mov cr0, eax
                pop eax
                sti
        }
    }
    ExFreePool(writebuffer);

ENDPOS:
    ObDereferenceObject(EProcess);
    return status;
}

PTR FindProcessInEPROCESS(PTR hidePid)
{
    PTR eproc = 0x0;
    PTR currentPid = 0;
    PTR startPid = 0;
    int cout = 0;
    PLIST_ENTRY pListActiveProcs;

    if (0 == hidePid)
    {
        return eproc;
    }

    //遍历ActiveList
    eproc = (PTR)PsGetCurrentProcess();
    startPid = *((PTR*)(eproc + PIDOFFSET));
    currentPid = startPid;

    while (TRUE)
    {
        if (hidePid == currentPid)
        {
            return eproc;
        }
        else if ((cout >= 1) && (startPid == currentPid))
        {
            //没有找到
            return 0x0;
        }
        else{
            pListActiveProcs = (LIST_ENTRY *)(eproc + FLICKOFFSET);
            eproc = (PTR)pListActiveProcs->Flink;
            eproc = eproc - FLICKOFFSET;
            if ((MmIsAddressValid(PVOID(eproc + PIDOFFSET)))) //有种情况要除去， 就是表头
            {
                currentPid = *(PTR*)(eproc + PIDOFFSET);
            }
            
        }
    }
}



PVOID BrowerTableL3_P(PVOID TableAddr, PTR pid)
{
    PHANDLE_TABLE_ENTRY pArray = (PHANDLE_TABLE_ENTRY)TableAddr;
    PVOID result = NULL;
    PHANDLE_TABLE_ENTRY pEntry = 0;
    ULONG ItemCount = 511;
    PTR dwProcessId = 0;
    ULONG flags;
    ULONG n = 0;
    PTR Object = 0;

    do{
        //TableAddr += 8;
        n++;
        pEntry = &pArray[n] /**(PULONG)TableAddr*/;
        //pEntry->Object = ((PTR)pEntry->Object & 0xfffffff8/*(~0x7)*/);  //Object最后三位置0，Object即为EPROCESS的地址
        Object = GET_PROCESS_FROM_HANDLE(pEntry->Object);// (pEntry->Object & (~0x7));

        if (Object == 0)
        {
            continue;
        }

        if (!MmIsAddressValid((PVOID)Object))
        {
            continue;
        }

        if (GetProcessType() == /**(PULONG)*/ObGetObjectType((PVOID)Object))
        {
            dwProcessId = *(PTR*)(Object + PIDOFFSET);
            if (dwProcessId < 65536 && dwProcessId != 0)
            {
                flags = *(PLONG)(Object + FLAGS);
                //flags显示进程没有退出
                if ((flags & 0xc) != 0xc)
                {
                    if (dwProcessId == pid)
                    {
                        result = (PVOID)Object;
                        break;
                    }
                    //DbgPrint("ProcessId:  %d\r\n", dwProcessId);
                    //DbgPrint("ProcessName:  %s\r\n", (char*)Object + IMAGEFILENAME);
                    /*if(dwProcessId == 960)
                    {
                    InterlockedExchangePointer(&((PHANDLE_TABLE_ENTRY)TableAddr)->Object, NULL);
                    }*/
                    //进程退出时会调用ExDestroyHandle()销毁句柄，若找不到就会蓝屏，所以要小心在进程退出的时候恢复
                }
            }
        }
    } while (--ItemCount > 0);

    return result;
}
PVOID BrowerTableL2_P(PVOID TableAddr, PTR pid)
{
    PVOID* pArray = (PVOID*)TableAddr;
    PVOID result = 0;
    ULONG i = 0;
    do{
        result = BrowerTableL3_P(pArray[i]/**(PULONG)TableAddr*/, pid);
        if (result>0)
        {
            break;
        }
        /*TableAddr += 4*/i++;
    } while (pArray[i]/*(*(PULONG)TableAddr)*/ != 0);

    return result;
}
PVOID BrowerTableL1_P(PVOID TableAddr, PTR pid)
{
    PVOID* pArray = (PVOID*)TableAddr;
    PVOID result = 0;
    ULONG i = 0;
    do{
        result = BrowerTableL2_P(pArray[i]/**(PULONG)TableAddr*/, pid);
        if (result>0)
        {
            break;
        }
        /*TableAddr += 4*/i++;
    } while (pArray[i]/*(*(PULONG)TableAddr)*/ != 0);

    return result;
}
PVOID FindProcessInPspCidTable(PTR pid)
{
    PHANDLE_TABLE PspCidTable = 0;
    PVOID HandleTable = 0;
    PTR TableCode = 0;
    PTR flag = 0;
    PEPROCESS    pCsrssEprocess = NULL;

    HandleTable = GetPspCidTable();
    PspCidTable = (PHANDLE_TABLE)(*(PTR *)HandleTable);

    TableCode = PspCidTable->TableCode;//*(PTR *)HandleTable;
    KdPrint(("PspCidTable.TableCode:%u", TableCode));
    flag = TableCode & MASKLAST2BIT;   //最后两位
    TableCode &= NORMASKLAST2BIT;

    switch (flag)
    {
    case 0:   //一层表
        return BrowerTableL3_P((PVOID)TableCode, pid);
        break;
    case 1:  //二层表
        return BrowerTableL2_P((PVOID)TableCode, pid);
        break;
    case 2:  //三层表
        return BrowerTableL1_P((PVOID)TableCode, pid);
        break;
    }
    return 0;
}

PTR HideProcessByEPROCESSLink(PTR hidePid)
{
    PLIST_ENTRY pListActiveProcs = NULL;
    //PLIST_ENTRY pHandleTable = NULL;
    PTR eproc = (PTR)FindProcessInPspCidTable(hidePid);//FindProcessInEPROCESS(hidePid);// 在EPROCESS结构中找到这个进程
    if (!eproc) //没有找到该进程
    {
        KdPrint(("HideProcess not find the pid:%u process, eproc: 0x%x", hidePid, eproc));
        return 0;
    }
    pListActiveProcs = (LIST_ENTRY*)(eproc + FLICKOFFSET);
    PLIST_ENTRY Flink = pListActiveProcs->Flink;
    PLIST_ENTRY Blink = pListActiveProcs->Blink;
    Flink->Blink = Blink;
    Blink->Flink = Flink;
    pListActiveProcs->Flink = pListActiveProcs;
    pListActiveProcs->Blink = pListActiveProcs;
    KdPrint(("HideProcessByEPROCESSLink Success pid:%u", hidePid));
    return eproc;
}
BOOL HideTableL3_P(PVOID TableAddr, PTR pid, OUT STORE_PROCESS_HANDLE* handleRcord)
{
    if (!handleRcord)
    {
        return FALSE;
    }
    PHANDLE_TABLE_ENTRY pArray = (PHANDLE_TABLE_ENTRY)TableAddr;
    BOOL result = FALSE;
    PHANDLE_TABLE_ENTRY pEntry = 0;
    ULONG ItemCount = 511;
    PTR dwProcessId = 0;
    ULONG flags;
    ULONG n = 0;
    PTR Object = 0;

    do{
        //TableAddr += 8;
        n++;
        pEntry = &pArray[n] /**(PULONG)TableAddr*/;
        //pEntry->Object = ((PTR)pEntry->Object & 0xfffffff8/*(~0x7)*/);  //Object最后三位置0，Object即为EPROCESS的地址
        Object = GET_PROCESS_FROM_HANDLE(pEntry->Object);//(pEntry->Object & 0xfffffff8/*(~0x7)*/);

        if (Object == 0)
        {
            continue;
        }

        if (!MmIsAddressValid((PVOID)Object))
        {
            continue;
        }

        if (GetProcessType() == /**(PULONG)*/ObGetObjectType((PVOID)Object))
        {
            dwProcessId = *(PTR*)(Object + PIDOFFSET);
            if (dwProcessId < 65536 && dwProcessId != 0)
            {
                flags = *(PLONG)(Object + FLAGS);
                //flags显示进程没有退出
                if ((flags & 0xc) != 0xc)
                {
                    if (dwProcessId == pid)
                    {
                        handleRcord->processCode = pEntry->Object;
                        handleRcord->handleAddr = (PTR)pEntry;
                        pEntry->Object = 0; //隐藏掉吧
                        result = TRUE;// (PVOID)pEntry->Object;
                        break;
                    }
                    //DbgPrint("ProcessId:  %d\r\n", dwProcessId);
                    //DbgPrint("ProcessName:  %s\r\n", (char*)Object + IMAGEFILENAME);
                    /*if(dwProcessId == 960)
                    {
                    InterlockedExchangePointer(&((PHANDLE_TABLE_ENTRY)TableAddr)->Object, NULL);
                    }*/
                    //进程退出时会调用ExDestroyHandle()销毁句柄，若找不到就会蓝屏，所以要小心在进程退出的时候恢复
                }
            }
        }
    } while (--ItemCount > 0);

    return result;
}

BOOL HideTableL2_P(PVOID TableAddr, PTR pid, OUT STORE_PROCESS_HANDLE* handleRcord)
{
    PVOID* pArray = (PVOID*)TableAddr;
    BOOL result = FALSE;
    ULONG i = 0;
    do{
        result = HideTableL3_P(pArray[i]/**(PULONG)TableAddr*/, pid, handleRcord);
        if (result)
        {
            break;
        }
        /*TableAddr += 4*/i++;
    } while (pArray[i]/*(*(PULONG)TableAddr)*/ != 0);

    return result;
}

BOOL HideTableL1_P(PVOID TableAddr, PTR pid, OUT STORE_PROCESS_HANDLE* handleRcord)
{
    PVOID* pArray = (PVOID*)TableAddr;
    BOOL result = FALSE;
    ULONG i = 0;
    do{
        result = HideTableL2_P(pArray[i]/**(PULONG)TableAddr*/, pid, handleRcord);
        if (result)
        {
            break;
        }
        /*TableAddr += 4*/i++;
    } while (pArray[i]/*(*(PULONG)TableAddr)*/ != 0);

    return result;
}

BOOL HideProcessByPspCidTable(IN PTR hidePid, OUT STORE_PROCESS_HANDLE* handleRcord)
{
    PHANDLE_TABLE PspCidTable = 0;
    PVOID HandleTable = 0;
    PTR TableCode = 0;
    PTR flag = 0;
    PEPROCESS    pCsrssEprocess = NULL;

    HandleTable = GetPspCidTable();
    PspCidTable = (PHANDLE_TABLE)(*(PTR *)HandleTable);

    TableCode = PspCidTable->TableCode;//*(PTR *)HandleTable;
    KdPrint(("PspCidTable.TableCode:%u", TableCode));
    flag = TableCode & MASKLAST2BIT;   //最后两位
    TableCode &= NORMASKLAST2BIT;

    switch (flag)
    {
    case 0:   //一层表
        return HideTableL3_P((PVOID)TableCode, hidePid, handleRcord);
        break;
    case 1:  //二层表
        return HideTableL2_P((PVOID)TableCode, hidePid, handleRcord);
        break;
    case 2:  //三层表
        return HideTableL1_P((PVOID)TableCode, hidePid, handleRcord);
        break;
    }
    return FALSE;
}

BOOL HideProcessByPid(PDEVICE_EXTENSION pDevExt, PTR hidePid)
{
    int i = 0;
    BOOL bFind = FALSE;
    for (; i < MAX_HIDDEN_PROCESS; i++)
    {
        if (NULL == pDevExt->hidenPidArray[i])
        {
            bFind = TRUE;
            break;
        }
    }
    if (FALSE == bFind)
    {
        return FALSE;
    }
    PTR process = HideProcessByEPROCESSLink(hidePid);
    if (NULL == process)
    {
        return FALSE;
    }
    STORE_PROCESS_HANDLE handleRecord;
    handleRecord.handleAddr = 0;
    handleRecord.processCode = 0;
    BOOL bRtn = HideProcessByPspCidTable(hidePid, &handleRecord);
    if (bRtn) //记录
    {
        pDevExt->hidenPidArray[i] = hidePid;
        pDevExt->hiddenProcessHandles[i] = handleRecord;
        ObReferenceObject((PVOID)process);
    }
    return bRtn;
}

BOOL RestoreProcessByPid(PDEVICE_EXTENSION pDevExt, PTR hidePid)
{
    int i = 0;
    BOOL bFind = FALSE;
    for (; i < MAX_HIDDEN_PROCESS; i++)
    {
        if (hidePid == pDevExt->hidenPidArray[i])
        {
            bFind = TRUE;
            break;
        }
    }
    if (FALSE == bFind)
    {
        return FALSE;
    }
    PTR process = NULL;
    process = (PTR)FindProcessInPspCidTable(SYSTEMPID);
    if (NULL == process)
    {
        return FALSE;
    }
    PTR eporc = GET_PROCESS_FROM_HANDLE(pDevExt->hiddenProcessHandles[i].processCode);
    PLIST_ENTRY pListActiveProcs = NULL;
    pListActiveProcs = (LIST_ENTRY*)(process + FLICKOFFSET);
    PLIST_ENTRY pRestoreActiveProcs = (LIST_ENTRY*)(eporc + FLICKOFFSET);
    PLIST_ENTRY Flink = pListActiveProcs;
    PLIST_ENTRY Blink = pListActiveProcs->Blink;

    Flink->Blink = pRestoreActiveProcs;
    Blink->Flink = pRestoreActiveProcs;
    pRestoreActiveProcs->Flink = Flink;
    pRestoreActiveProcs->Blink = Blink;
    KdPrint(("RestoreProcessByPid Success pid:%u", hidePid));

    //BOOL bRtn = HideProcessByPspCidTable(hidePid);
    PHANDLE_TABLE_ENTRY pEntry = (PHANDLE_TABLE_ENTRY)pDevExt->hiddenProcessHandles[i].handleAddr;
    pEntry->Object = pDevExt->hiddenProcessHandles[i].processCode;
    {
        ObDereferenceObject((PVOID)eporc);
        pDevExt->hidenPidArray[i] = NULL;
        pDevExt->hiddenProcessHandles[i].handleAddr = NULL;
        pDevExt->hiddenProcessHandles[i].processCode = NULL;
    }
    return TRUE;
}

VOID EnumKernelModule(IN PDRIVER_OBJECT pDriverObject, PDEVICE_EXTENSION pDevExt)
{
    PLIST_ENTRY pPsLoadedModuleList;
    PLIST_ENTRY NextEntry;
    PKLDR_DATA_TABLE_ENTRY DataTableEntry;
    pPsLoadedModuleList = (PLIST_ENTRY)GetPsLoadedModuleList(pDriverObject);
    if (NULL == pPsLoadedModuleList)
    {
        KdPrint(("EnumKernelModule error GetPsLoadedModuleList null!"));
        return;
    }
    KdPrint(("EnumKernelModule GetPsLoadedModuleList ox%x !", pPsLoadedModuleList));
    pDevExt->pKernelModuleList = pPsLoadedModuleList;

    NextEntry = pPsLoadedModuleList->Blink;
    DataTableEntry = NULL;
    while (NextEntry != pPsLoadedModuleList)
    {
        DataTableEntry = CONTAINING_RECORD(NextEntry,
            KLDR_DATA_TABLE_ENTRY,
            InLoadOrderLinks);
        KdPrint(("EnumKernelModule GetPsLoadedModuleList Load Module FullDllName:%wZ, BaseDllName:%wZ !", &DataTableEntry->FullDllName, &DataTableEntry->BaseDllName));
        NextEntry = NextEntry->Blink;
    }

}

BOOL HideDriver(PDEVICE_EXTENSION pDevExt)
{
    PLIST_ENTRY pPsLoadedModuleList;
    PLIST_ENTRY NextEntry;
    PKLDR_DATA_TABLE_ENTRY DataTableEntry;
    UNICODE_STRING uniDriverName1;
    UNICODE_STRING uniDriverName2;
   
    pPsLoadedModuleList = pDevExt->pKernelModuleList;
    if (NULL == pPsLoadedModuleList)
    {
        KdPrint(("HideDriver error pPsLoadedModuleList null!"));
        return FALSE;
    }
    // 初始化要隐藏驱动的驱动名  
    RtlInitUnicodeString(&uniDriverName1, L"ZIYUDIVER.sys");
    // 初始化要隐藏驱动的驱动名  
    RtlInitUnicodeString(&uniDriverName2, L"Dbgv.sys");
    NextEntry = pPsLoadedModuleList->Blink;
    DataTableEntry = NULL;
    while (NextEntry != pPsLoadedModuleList)
    {
        DataTableEntry = CONTAINING_RECORD(NextEntry,
            KLDR_DATA_TABLE_ENTRY,
            InLoadOrderLinks);
        //KdPrint(("EnumKernelModule GetPsLoadedModuleList Load Module FullDllName:%wZ, BaseDllName:%wZ !", &DataTableEntry->FullDllName, &DataTableEntry->BaseDllName));
        if (DataTableEntry->FullDllName.Buffer != 0)
        {
            if (RtlCompareUnicodeString(&uniDriverName1, &(DataTableEntry->BaseDllName), FALSE) == 0 
                || RtlCompareUnicodeString(&uniDriverName1, &(DataTableEntry->BaseDllName), FALSE) == 0)
            {
                KdPrint(("隐藏驱动 %wZ 成功!\n", &DataTableEntry->BaseDllName));
                NextEntry = NextEntry->Blink;
                // 修改 Flink 和 Blink 指针, 以跳过我们要隐藏的驱动  
                DataTableEntry->InLoadOrderLinks.Blink->Flink = DataTableEntry->InLoadOrderLinks.Flink;
                DataTableEntry->InLoadOrderLinks.Flink->Blink = DataTableEntry->InLoadOrderLinks.Blink;

                /*
                使被隐藏驱动LIST_ENTRY结构体的Flink, Blink域指向自己
                因为此节点本来在链表中, 那么它邻接的节点驱动被卸载时,
                系统会把此节点的Flink, Blink域指向它相邻节点的下一个节点.
                但是, 它此时已经脱离链表了, 如果现在它原本相邻的节点驱动被
                卸载了, 那么此节点的Flink, Blink域将有可能指向无用的地址, 而
                造成随机性的BSoD.
                */
                //放入隐藏列表里面
                
                PLIST_ENTRY tblink = pDevExt->HiddenModuleList.Blink;
                pDevExt->HiddenModuleList.Blink = &DataTableEntry->InLoadOrderLinks;
                DataTableEntry->InLoadOrderLinks.Flink = &pDevExt->HiddenModuleList;
                tblink->Flink = &DataTableEntry->InLoadOrderLinks;
                DataTableEntry->InLoadOrderLinks.Blink = tblink;
                continue;
                /*break;*/
            }
        }
       
        NextEntry = NextEntry->Blink;
    }
}

BOOL RestoreDriver(PDEVICE_EXTENSION pDevExt)
{
    PLIST_ENTRY pPsLoadedModuleList;
    PLIST_ENTRY NextEntry;
    PKLDR_DATA_TABLE_ENTRY DataTableEntry;
    UNICODE_STRING uniDriverName1;
    UNICODE_STRING uniDriverName2;

    pPsLoadedModuleList = &pDevExt->HiddenModuleList;//pDevExt->pKernelModuleList;
    if (NULL == pPsLoadedModuleList)
    {
        KdPrint(("RestoreDriver error pPsLoadedModuleList null!"));
        return FALSE;
    }
    // 初始化要恢复驱动的驱动名  
    RtlInitUnicodeString(&uniDriverName1, L"ZIYUDIVER.sys");
    // 初始化要恢复驱动的驱动名  
    RtlInitUnicodeString(&uniDriverName2, L"Dbgv.sys");
    NextEntry = pPsLoadedModuleList->Blink;
    DataTableEntry = NULL;
    while (NextEntry != pPsLoadedModuleList)
    {
        DataTableEntry = CONTAINING_RECORD(NextEntry,
            KLDR_DATA_TABLE_ENTRY,
            InLoadOrderLinks);
        //KdPrint(("EnumKernelModule GetPsLoadedModuleList Load Module FullDllName:%wZ, BaseDllName:%wZ !", &DataTableEntry->FullDllName, &DataTableEntry->BaseDllName));
        if (DataTableEntry->FullDllName.Buffer != 0)
        {
            if (RtlCompareUnicodeString(&uniDriverName1, &(DataTableEntry->BaseDllName), FALSE) == 0
                || RtlCompareUnicodeString(&uniDriverName1, &(DataTableEntry->BaseDllName), FALSE) == 0)
            {
                KdPrint(("恢复驱动 %wZ 成功!\n", &DataTableEntry->BaseDllName));
                NextEntry = NextEntry->Blink;
                // 修改 Flink 和 Blink 指针, 以跳过我们要隐藏的驱动  
                DataTableEntry->InLoadOrderLinks.Blink->Flink = DataTableEntry->InLoadOrderLinks.Flink;
                DataTableEntry->InLoadOrderLinks.Flink->Blink = DataTableEntry->InLoadOrderLinks.Blink;

                /*
                使被隐藏驱动LIST_ENTRY结构体的Flink, Blink域指向自己
                因为此节点本来在链表中, 那么它邻接的节点驱动被卸载时,
                系统会把此节点的Flink, Blink域指向它相邻节点的下一个节点.
                但是, 它此时已经脱离链表了, 如果现在它原本相邻的节点驱动被
                卸载了, 那么此节点的Flink, Blink域将有可能指向无用的地址, 而
                造成随机性的BSoD.
                */
                //放入隐藏列表里面

                PLIST_ENTRY tblink = pDevExt->pKernelModuleList->Blink;
                pDevExt->pKernelModuleList->Blink = &DataTableEntry->InLoadOrderLinks;
                DataTableEntry->InLoadOrderLinks.Flink = pDevExt->pKernelModuleList;
                tblink->Flink = &DataTableEntry->InLoadOrderLinks;
                DataTableEntry->InLoadOrderLinks.Blink = tblink;
                continue;
                /*break;*/
            }
        }

        NextEntry = NextEntry->Blink;
    }
}

//PVOID BrowerTableL3(PVOID TableAddr, char* imageName)
//{
//    PHANDLE_TABLE_ENTRY* pArray = (PHANDLE_TABLE_ENTRY*)TableAddr;
//    PVOID result = 0;
//    PHANDLE_TABLE_ENTRY pEntry = 0;
//    ULONG ItemCount = 511;
//    PTR dwProcessId = 0;
//    ULONG flags;
//    ULONG n = 0;
//
//    do{
//        //TableAddr += 8;
//        n++;
//        pEntry = pArray[n] /**(PULONG)TableAddr*/;
//        pEntry->Object = ((PTR)pEntry->Object & (~0x7));  //Object最后三位置0，Object即为EPROCESS的地址
//
//        if (pEntry->Object == 0)
//        {
//            continue;
//        }
//
//        if (!MmIsAddressValid((PVOID)pEntry->Object))
//        {
//            continue;
//        }
//
//        if (GetProcessType() == /**(PULONG)*/ObGetObjectType((PVOID)pEntry->Object))
//        {
//            dwProcessId = *(PTR*)(pEntry->Object + PIDOFFSET);
//            if (dwProcessId < 65536 && dwProcessId != 0)
//            {
//                flags = *(PLONG)(pEntry->Object + FLAGS);
//                //flags显示进程没有退出
//                if ((flags & 0xc) != 0xc)
//                {
//                    //DbgPrint("ProcessId:  %d\r\n", dwProcessId);
//                    //DbgPrint("ProcessName:  %s\r\n", (char*)Object + IMAGEFILENAME);
//                    if (strncmp((char*)(pEntry->Object + IMAGEFILENAME), imageName, 8) == 0)
//                    {
//                        DbgPrint("HAHA Get The Process:  %s\r\n", (char*)(pEntry->Object + IMAGEFILENAME));
//                        result = (PVOID)pEntry->Object;
//                        break;
//                    }
//                    /*if(dwProcessId == 960)
//                    {
//                    InterlockedExchangePointer(&((PHANDLE_TABLE_ENTRY)TableAddr)->Object, NULL);
//                    }*/
//                    //进程退出时会调用ExDestroyHandle()销毁句柄，若找不到就会蓝屏，所以要小心在进程退出的时候恢复
//                }
//            }
//        }
//    } while (--ItemCount > 0);
//
//    return result;
//}
//PVOID BrowerTableL2(PVOID TableAddr, char* imageName)
//{
//    PVOID* pArray = (PVOID*)TableAddr;
//    PVOID result = 0;
//    ULONG i = 0;
//    do{
//        result = BrowerTableL3(pArray[i]/**(PULONG)TableAddr*/, imageName);
//        if (result>0)
//        {
//            break;
//        }
//        /*TableAddr += 4*/i++;
//    } while (pArray[i]/*(*(PULONG)TableAddr)*/ != 0);
//
//    return result;
//}
//PVOID BrowerTableL1(PVOID TableAddr, char* imageName)
//{
//    PVOID* pArray = (PVOID*)TableAddr;
//    PVOID result = 0;
//    ULONG i = 0;
//    do{
//        result = BrowerTableL2(pArray[i]/**(PULONG)TableAddr*/, imageName);
//        if (result>0)
//        {
//            break;
//        }
//        /*TableAddr += 4*/i++;
//    } while (pArray[i]/*(*(PULONG)TableAddr)*/ != 0);
//
//    return result;
//}
//VOID RefreshProcessByPspCidTable(char* imageName)
//{
//    PHANDLE_TABLE PspCidTable = 0;
//    PVOID HandleTable = 0;
//    PTR TableCode = 0;
//    PTR flag = 0;
//    PEPROCESS    pCsrssEprocess = NULL;
//
//    HandleTable = GetPspCidTable();
//    PspCidTable = (PHANDLE_TABLE)(*(PTR *)HandleTable);
//
//    TableCode = PspCidTable->TableCode;//*(PTR *)HandleTable;
//    KdPrint(("PspCidTable.TableCode:%u", TableCode));
//    flag = TableCode & MASKLAST2BIT;   //最后两位
//    TableCode &= NORMASKLAST2BIT;
//
//    switch (flag)
//    {
//    case 0:   //一层表
//        BrowerTableL3((PVOID)TableCode, imageName);
//        break;
//    case 1:  //二层表
//        BrowerTableL2((PVOID)TableCode, imageName);
//        break;
//    case 2:  //三层表
//        BrowerTableL1((PVOID)TableCode, imageName);
//        break;
//    }
//}
//PVOID GetProcessByImageName(char* imageName)
//{
//    PHANDLE_TABLE PspCidTable = 0;
//    PVOID HandleTable = 0;
//    PTR TableCode = 0;
//    PTR flag = 0;
//    PEPROCESS    pCsrssEprocess = NULL;
//
//    HandleTable = GetPspCidTable();
//    PspCidTable = (PHANDLE_TABLE)(*(PTR *)HandleTable);
//
//    TableCode = PspCidTable->TableCode;//*(PTR *)HandleTable;
//    KdPrint(("PspCidTable.TableCode:%u", TableCode));
//    flag = TableCode & MASKLAST2BIT;   //最后两位
//    TableCode &= NORMASKLAST2BIT;
//
//    switch (flag)
//    {
//    case 0:   //一层表
//        return BrowerTableL3((PVOID)TableCode, imageName);
//        break;
//    case 1:  //二层表
//        return BrowerTableL2((PVOID)TableCode, imageName);
//        break;
//    case 2:  //三层表
//        return BrowerTableL1((PVOID)TableCode, imageName);
//        break;
//    }
//    return 0;
//}

/************************************************************************
* 函数名称:DriverEntry
* 功能描述:初始化驱动程序，定位和申请硬件资源，创建内核对象
* 参数列表:
      pDriverObject:从I/O管理器中传进来的驱动对象
      pRegistryPath:驱动程序在注册表的中的路径
* 返回 值:返回初始化驱动状态
*************************************************************************/
#pragma INITCODE
extern "C" NTSTATUS DriverEntry (
			IN PDRIVER_OBJECT pDriverObject,
			IN PUNICODE_STRING pRegistryPath	) 
{
	NTSTATUS status;
	KdPrint(("Enter DriverEntry\n"));

	//设置卸载函数
	pDriverObject->DriverUnload = ZiyuDDKUnload;

	//设置派遣函数
    pDriverObject->MajorFunction[IRP_MJ_WRITE] = ZiyuDDWrite;
    pDriverObject->MajorFunction[IRP_MJ_READ] = ZiyuDDKRead;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ZiyuDDKDeviceIOControl;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = 
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = 
	pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = 
	pDriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = 
	pDriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = 
    pDriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = ZiyuDDKDispatchRoutin;
	
	//创建驱动设备对象
	status = CreateDevice(pDriverObject);
    //RefreshProcessByPspCidTable("System");
	KdPrint(("Leave DriverEntry\n"));
	return status;
}

/************************************************************************
* 函数名称:CreateDevice
* 功能描述:初始化设备对象
* 参数列表:
      pDriverObject:从I/O管理器中传进来的驱动对象
* 返回 值:返回初始化状态
*************************************************************************/
#pragma INITCODE
NTSTATUS CreateDevice (
		IN PDRIVER_OBJECT	pDriverObject) 
{
	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;
	
	//创建设备名称
	UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, DEVICENAME);
	
	//创建设备
	status = IoCreateDevice( pDriverObject,
						sizeof(DEVICE_EXTENSION),
						&(UNICODE_STRING)devName,
						FILE_DEVICE_UNKNOWN,
						0, TRUE,
						&pDevObj );
	if (!NT_SUCCESS(status))
		return status;

	pDevObj->Flags |= DO_BUFFERED_IO;
	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
	pDevExt->pDevice = pDevObj;
    RtlZeroMemory(pDevExt->hidenPidArray, sizeof(pDevExt->hidenPidArray));
    RtlZeroMemory(pDevExt->hiddenProcessHandles, sizeof(pDevExt->hiddenProcessHandles));
    pDevExt->pKernelModuleList = NULL;
    pDevExt->HiddenModuleList.Blink = &pDevExt->HiddenModuleList;
    pDevExt->HiddenModuleList.Flink = &pDevExt->HiddenModuleList;
    EnumKernelModule(pDriverObject, pDevExt);

	//pDevExt->ustrDeviceName = devName;
	//创建符号链接
	UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&symLinkName, LINKNAME);
	//pDevExt->ustrSymLinkName = symLinkName;
	status = IoCreateSymbolicLink( &symLinkName,&devName );
	if (!NT_SUCCESS(status)) 
	{
        KdPrint(("err IoCreateSymbolicLink\n"));
		IoDeleteDevice( pDevObj );
		return status;
	}
	return STATUS_SUCCESS;
}

/************************************************************************
* 函数名称:HelloDDKUnload
* 功能描述:负责驱动程序的卸载操作
* 参数列表:
      pDriverObject:驱动对象
* 返回 值:返回状态
*************************************************************************/
#pragma PAGEDCODE
VOID ZiyuDDKUnload(IN PDRIVER_OBJECT pDriverObject)
{
	PDEVICE_OBJECT	pNextObj;
	KdPrint(("Enter DriverUnload\n"));
	pNextObj = pDriverObject->DeviceObject;
	while (pNextObj != NULL) 
	{
		PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)
			pNextObj->DeviceExtension;

        for (int i = 0; i < MAX_HIDDEN_PROCESS; i++)
        {
            //解除隐藏
            if (NULL != pDevExt->hidenPidArray[i])
            {
                RestoreProcessByPid(pDevExt, pDevExt->hidenPidArray[i]);
                /*pDevExt->hidenPidArray[i] = NULL;
                ObDereferenceObject((PVOID)pDevExt->hidenEprocessArray[i]);
                pDevExt->hidenEprocessArray[i] = NULL;*/
            }
        }

		//删除符号链接
		//UNICODE_STRING pLinkName = pDevExt->ustrSymLinkName;
        UNICODE_STRING symLinkName;
        RtlInitUnicodeString(&symLinkName, LINKNAME);
        __try{
            KdPrint(("Try IoDeleteSymbolicLink %S\n", symLinkName.Buffer));
            IoDeleteSymbolicLink(&symLinkName);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            KdPrint(("Try IoDeleteSymbolicLink ERROR! %S\n", symLinkName.Buffer));
        }
		pNextObj = pNextObj->NextDevice;
		IoDeleteDevice( pDevExt->pDevice );
	}
}

/************************************************************************
* 函数名称:HelloDDKDispatchRoutin
* 功能描述:对读IRP进行处理
* 参数列表:
      pDevObj:功能设备对象
      pIrp:从IO请求包
* 返回 值:返回状态
*************************************************************************/
#pragma PAGEDCODE
NTSTATUS ZiyuDDKDispatchRoutin(IN PDEVICE_OBJECT pDevObj,
								 IN PIRP pIrp) 
{
	KdPrint(("Enter ZiyuDDKDispatchRoutin\n"));

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
	//建立一个字符串数组与IRP类型对应起来
	static char* irpname[] = 
	{
		"IRP_MJ_CREATE",
		"IRP_MJ_CREATE_NAMED_PIPE",
		"IRP_MJ_CLOSE",
		"IRP_MJ_READ",
		"IRP_MJ_WRITE",
		"IRP_MJ_QUERY_INFORMATION",
		"IRP_MJ_SET_INFORMATION",
		"IRP_MJ_QUERY_EA",
		"IRP_MJ_SET_EA",
		"IRP_MJ_FLUSH_BUFFERS",
		"IRP_MJ_QUERY_VOLUME_INFORMATION",
		"IRP_MJ_SET_VOLUME_INFORMATION",
		"IRP_MJ_DIRECTORY_CONTROL",
		"IRP_MJ_FILE_SYSTEM_CONTROL",
		"IRP_MJ_DEVICE_CONTROL",
		"IRP_MJ_INTERNAL_DEVICE_CONTROL",
		"IRP_MJ_SHUTDOWN",
		"IRP_MJ_LOCK_CONTROL",
		"IRP_MJ_CLEANUP",
		"IRP_MJ_CREATE_MAILSLOT",
		"IRP_MJ_QUERY_SECURITY",
		"IRP_MJ_SET_SECURITY",
		"IRP_MJ_POWER",
		"IRP_MJ_SYSTEM_CONTROL",
		"IRP_MJ_DEVICE_CHANGE",
		"IRP_MJ_QUERY_QUOTA",
		"IRP_MJ_SET_QUOTA",
		"IRP_MJ_PNP",
	};

	UCHAR type = stack->MajorFunction;
	if (type >= arraysize(irpname))
		KdPrint((" - Unknown IRP, major type %X\n", type));
	else
		KdPrint(("\t%s\n", irpname[type]));


	//对一般IRP的简单操作，后面会介绍对IRP更复杂的操作
	NTSTATUS status = STATUS_SUCCESS;
	// 完成IRP
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;	// bytes xfered
	IoCompleteRequest( pIrp, IO_NO_INCREMENT );

	KdPrint(("Leave ZiyuDDKDispatchRoutin\n"));

	return status;
}

NTSTATUS ZiyuDDKRead(IN PDEVICE_OBJECT pDevObj,
    IN PIRP pIrp)
{
    KdPrint(("Enter ZiyuDDKRead\n"));
    PEPROCESS pEprocess = 0;//  (PEPROCESS)GetProcessByImageName("TargetExe.exe");
    if (0 == pEprocess)
    {
        KdPrint(("GetProcessByImageName not find\n"));
        return STATUS_FILE_INVALID;
    }
    else
    {
        KdPrint(("GetProcessByImageName ok pid:%d\n", pEprocess));
    }
    PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
    NTSTATUS status = STATUS_SUCCESS;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    ULONG ulReadLength = stack->Parameters.Read.Length;
    ULONG ulReadOffset = (ULONG)stack->Parameters.Read.ByteOffset.QuadPart;
    KdPrint(("try ZiyuDDKRead addr: 0x%x\n", ulReadOffset));
    ULONG testValue = 55;
    
    {
        //将数据存储在AssociatedIrp.SystemBuffer，以便应用程序使用
        memcpy(pIrp->AssociatedIrp.SystemBuffer, &testValue, sizeof(ULONG)/*ulReadLength*/);
        status = STATUS_SUCCESS;
    }

    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = sizeof(ULONG)/*ulReadLength*/;	// bytes xfered
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    KdPrint(("Leave ZiyuDDKRead\n"));

    return status;
}

NTSTATUS ZiyuDDWrite(IN PDEVICE_OBJECT pDevObj,
    IN PIRP pIrp)
{
    KdPrint(("Enter ZiyuDDWrite\n"));
    PEPROCESS pEprocess = 0;// (PEPROCESS)GetProcessByImageName("TargetExe.exe");
    if (0 == pEprocess)
    {
        KdPrint(("GetProcessByImageName not find\n"));
        return STATUS_FILE_INVALID;
    }
    else
    {
        KdPrint(("GetProcessByImageName ok pid:%d\n", pEprocess));
    }
    NTSTATUS status = STATUS_SUCCESS;

    PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    //获取存储的长度
    ULONG ulWriteLength = stack->Parameters.Write.Length;
    //获取存储的偏移量
    ULONG ulWriteOffset = (ULONG)stack->Parameters.Write.ByteOffset.QuadPart;
    ULONG testValue = 0;
    memcpy(&testValue, pIrp->AssociatedIrp.SystemBuffer, sizeof(ULONG)/*ulWriteLength*/);
    KdPrint(("try ZiyuDDWrite addr: 0x%x, write value:%d\n", ulWriteOffset, testValue));
   
    //{
    //    //将写入的数据，存储在缓冲区内
    //    memcpy(pDevExt->buffer + ulWriteOffset, pIrp->AssociatedIrp.SystemBuffer, ulWriteLength);
    //    status = STATUS_SUCCESS;
    //    //设置新的文件长度
    //    if (ulWriteLength + ulWriteOffset > pDevExt->file_length)
    //    {
    //        pDevExt->file_length = ulWriteLength + ulWriteOffset;
    //    }
    //}
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = sizeof(ULONG)/*ulWriteLength*/;	// bytes xfered
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    KdPrint(("Leave ZiyuDDWrite\n"));
    return status;
}

#pragma PAGEDCODE
NTSTATUS ZiyuDDKDeviceIOControl(IN PDEVICE_OBJECT pDevObj,
    IN PIRP pIrp)
{
    NTSTATUS status = STATUS_SUCCESS;
    KdPrint(("Enter HelloDDKDeviceIOControl\n"));
    /* PEPROCESS pEprocess = (PEPROCESS)GetProcessByImageName("TargetExe.exe");
     if (0 == pEprocess)
     {
     KdPrint(("GetProcessByImageName not find\n"));
     return STATUS_FILE_INVALID;
     }
     else
     {
     KdPrint(("GetProcessByImageName ok pid:%d\n", pEprocess));
     }*/
    //得到当前堆栈
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    //得到输入缓冲区大小
    ULONG cbin = stack->Parameters.DeviceIoControl.InputBufferLength;
    //得到输出缓冲区大小
    ULONG cbout = stack->Parameters.DeviceIoControl.OutputBufferLength;
    //得到IOCTL码
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;

    ULONG info = 0;

    switch (code)
    {						// process request
    case IOCTL_READ:
    {
                        KdPrint(("IOCTL_READ\n"));
                        //缓冲区方式IOCTL
                        //显示输入缓冲区数据
                        if (cbin</*0xc*/sizeof(ULONG)+sizeof(PVOID)+sizeof(ULONG))  //pid + addr + size
                        {
                            KdPrint(("IOCTL_READ error cbin should not less than 12\n"));
                            status = STATUS_INVALID_VARIANT;
                            break;
                        }
                        UCHAR* InputBuffer = (UCHAR*)pIrp->AssociatedIrp.SystemBuffer;

                        ULONG pid = *(ULONG*)InputBuffer;
                        PVOID addr = *(PVOID*)(InputBuffer + sizeof(ULONG));
                        ULONG readsize = *(ULONG*)(InputBuffer + sizeof(ULONG)+sizeof(PVOID));
                        KdPrint(("IOCTL_READ pid:%d, addr: 0x%x, size:%d", pid, addr, readsize));
                        if (cbout<readsize)
                        {
                            KdPrint(("IOCTL_READ error cbout should not less than %d\n", readsize));
                            status = STATUS_INVALID_VARIANT;
                            break;
                        }
                        //操作输出缓冲区
                        UCHAR* OutputBuffer = (UCHAR*)pIrp->AssociatedIrp.SystemBuffer;
                        /*KdPrint(("ZiyuReadMemory BaseAddress:0x%x", OutputBuffer));*/
                        status = ZiyuReadMemory(pid/*(ULONG)pEprocess*/, (PVOID)addr, OutputBuffer, readsize, &info);
                        if (!NT_SUCCESS(status))
                        {
                            status = STATUS_INVALID_VARIANT;
                            KdPrint(("Read error!!\n"));
                            break;
                        }
                        //memset(OutputBuffer, 0xAA, cbout);
                        //设置实际操作输出缓冲区长度
                        /**(ULONG*)OutputBuffer = 66;*/
                        info = readsize;
                        break;
    }
    case IOCTL_WRITE:
    {
                        KdPrint(("IOCTL_WRITE\n"));
                        //缓冲区方式IOCTL
                        //显示输入缓冲区数据

                        //缓冲区方式IOCTL
                        //显示输入缓冲区数据
                        if (cbin < sizeof(ULONG)+sizeof(PVOID)+sizeof(ULONG))
                        {
                            KdPrint(("IOCTL_WRITE error cbin should not less than 12\n"));
                            status = STATUS_INVALID_VARIANT;
                            break;
                        }
                        UCHAR* InputBuffer = (UCHAR*)pIrp->AssociatedIrp.SystemBuffer;

                        ULONG pid = *(ULONG*)InputBuffer;
                        ULONG addr = *(ULONG*)(InputBuffer + sizeof(ULONG));
                        ULONG writesize = *(ULONG*)(InputBuffer + sizeof(ULONG)+sizeof(PVOID));
                        if (cbin < sizeof(ULONG)+sizeof(PVOID)+sizeof(ULONG)+writesize)
                        {
                            KdPrint(("IOCTL_WRITE error cbin should not less than %d\n", 0xc + writesize));
                            status = STATUS_INVALID_VARIANT;
                            break;
                        }
                        KdPrint(("IOCTL_WRITE addr: 0x%x, size:%d", addr, writesize));
                        UCHAR* writeBuffer = InputBuffer + sizeof(ULONG)+sizeof(PVOID)+sizeof(ULONG);
                        if (writesize==4)
                        {
                            KdPrint(("IOCTL_WRITE value:%d", *(ULONG*)writeBuffer));
                        }
                        else if (writesize == 8)
                        {
                            KdPrint(("IOCTL_WRITE value:%lld", *(QUAD*)writeBuffer));
                        }
                        //pIrp->MdlAddress为DeviceIoControl输出缓冲区地址相同
                        //KdPrint(("User Address:0X%08X\n", MmGetMdlVirtualAddress(pIrp->MdlAddress)));

                        //UCHAR* OutputBuffer = (UCHAR*)MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
                        //InputBuffer被映射到内核模式下的内存地址，必定在0X80000000-0XFFFFFFFF之间
                        //memset(OutputBuffer, 0xAA, cbout);
                        //设置实际操作输出缓冲区长度
                        status = ZiyuWriteMemory(pid/*(ULONG)pEprocess*/, (PVOID)addr, writeBuffer, writesize, &info);
                        if (!NT_SUCCESS(status))
                        {
                            status = STATUS_INVALID_VARIANT;
                            KdPrint(("Write error!!\n"));
                            break;
                        }
                        info = writesize;
                        break;
    }
    case IOCTL_GETIMAGE:
    {
                           KdPrint(("IOCTL_GETIMAGE\n"));
                           if (cbin < sizeof(ULONG))
                           {
                               KdPrint(("IOCTL_READ error cbin should not less than 4\n"));
                               status = STATUS_INVALID_VARIANT;
                               break;
                           }
                           UCHAR* InputBuffer = (UCHAR*)pIrp->AssociatedIrp.SystemBuffer;

                           ULONG pid = *(ULONG*)InputBuffer;
                           KdPrint(("IOCTL_GETIMAGE pid:%d", pid));

                           PsLookupProcessByProcessId l = (PsLookupProcessByProcessId)GetFunc(L"PsLookupProcessByProcessId");
                           if (!l)
                           {
                               KdPrint(("PsLookupProcessByProcessId not get"));
                               status = STATUS_INVALID_VARIANT;
                               break;
                           }
                           PEPROCESS lProcess = NULL/*(PEPROCESS)pid*/;
                           status = l(pid, &lProcess);
                           if (!NT_SUCCESS(status) || !lProcess)
                           {
                               KdPrint(("PsLookupProcessByProcessId error pid:%d", pid));
                               status = STATUS_INVALID_VARIANT;
                               break;
                           }
                           char* OutputBuffer = (char*)pIrp->AssociatedIrp.SystemBuffer;
                           strncpy(OutputBuffer, (char*)lProcess + IMAGEFILENAME, cbout);
                           //memset(OutputBuffer, 0xAA, cbout);
                           //设置实际操作输出缓冲区长度
                           /**(ULONG*)OutputBuffer = 66;*/
                           ObDereferenceObject(lProcess);
                           info = cbout;

                        //KdPrint(("IOCTL_GETIMAGE\n"));
                        ////缓冲区方式IOCTL
                        ////缓冲区方式IOCTL
                        ////显示输入缓冲区数据
                        //UCHAR* UserInputBuffer = (UCHAR*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
                        //KdPrint(("UserInputBuffer:0X%0X\n", UserInputBuffer));
                        ////得到用户模式地址
                        //PVOID UserOutputBuffer = pIrp->UserBuffer;
                        //KdPrint(("UserOutputBuffer:0X%0X\n", UserOutputBuffer));
                        //__try
                        //{
                        //    KdPrint(("Enter __try block\n"));
                        //    //判断指针是否可读
                        //    ProbeForRead(UserInputBuffer, cbin, 4);
                        //    //显示输入缓冲区内容
                        //    for (ULONG i = 0; i < cbin; i++)
                        //    {
                        //        KdPrint(("%X\n", UserInputBuffer[i]));
                        //    }
                        //    //判断指针是否可写
                        //    ProbeForWrite(UserOutputBuffer, cbout, 4);
                        //    //操作输出缓冲区
                        //    memset(UserOutputBuffer, 0xAA, cbout);
                        //    //由于在上面引发异常，所以以后语句不会被执行!
                        //    info = cbout;
                        //    KdPrint(("Leave __try block\n"));
                        //}
                        //__except (EXCEPTION_EXECUTE_HANDLER)
                        //{
                        //    KdPrint(("Catch the exception\n"));
                        //    KdPrint(("The program will keep going\n"));
                        //    status = STATUS_UNSUCCESSFUL;
                        //}
                        //info = cbout;
                        break;
    }
    case IOCTL_HIDE_PROCESS:
    {
                           KdPrint(("IOCTL_HIDE_PROCESS\n"));
                           PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)
                               pDevObj->DeviceExtension;
                           if (cbin < sizeof(ULONG))
                           {
                               KdPrint(("IOCTL_HIDE_PROCESS error cbin should not less than 4\n"));
                               status = STATUS_INVALID_VARIANT;
                               break;
                           }
                           UCHAR* InputBuffer = (UCHAR*)pIrp->AssociatedIrp.SystemBuffer;

                           ULONG pid = *(ULONG*)InputBuffer;
                           KdPrint(("IOCTL_HIDE_PROCESS pid:%d", pid));

                           BOOL result = HideProcessByPid(pDevExt, pid);
                           if (!result)
                           {
                               status = STATUS_INVALID_VARIANT;
                               break;
                           }
                           info = cbout;
                           break;
    }
    case IOCTL_RESTORE_PROCESS:
    {
                               KdPrint(("IOCTL_RESTORE_PROCESS\n"));
                               PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)
                                   pDevObj->DeviceExtension;
                               if (cbin < sizeof(ULONG))
                               {
                                   KdPrint(("IOCTL_RESTORE_PROCESS error cbin should not less than 4\n"));
                                   status = STATUS_INVALID_VARIANT;
                                   break;
                               }
                               UCHAR* InputBuffer = (UCHAR*)pIrp->AssociatedIrp.SystemBuffer;

                               ULONG pid = *(ULONG*)InputBuffer;
                               KdPrint(("IOCTL_RESTORE_PROCESS pid:%d", pid));

                               BOOL result = RestoreProcessByPid(pDevExt, pid);
                               if (!result)
                               {
                                   status = STATUS_INVALID_VARIANT;
                                   break;
                               }
                               info = cbout;
                               break;
    }
    case IOCTL_HIDE_DRIVER:
    {
                                  KdPrint(("IOCTL_HIDE_DRIVER\n"));
                                  PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)
                                      pDevObj->DeviceExtension;
                                  BOOL result = HideDriver(pDevExt);
                                  if (!result)
                                  {
                                      status = STATUS_INVALID_VARIANT;
                                      break;
                                  }
                                  info = 0;
                                  break;
    }
    case IOCTL_RESTORE_DRIVER:
    {
                              KdPrint(("IOCTL_RESTORE_DRIVER\n"));
                              PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)
                                  pDevObj->DeviceExtension;
                              BOOL result = RestoreDriver(pDevExt);
                              if (!result)
                              {
                                  status = STATUS_INVALID_VARIANT;
                                  break;
                              }
                              info = 0;
                              break;
    }
    default:
        status = STATUS_INVALID_VARIANT;
    }

    // 完成IRP
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = info;	// bytes xfered
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    KdPrint(("Leave HelloDDKDeviceIOControl\n"));

    return status;
}

//extern "C" NTKERNELAPI PVOID NTAPI
//ObGetObjectType(
//IN PVOID pObject
//);
//
//extern "C" NTKERNELAPI UCHAR*
//PsGetProcessImageFileName(
//IN PEPROCESS Process
//);
//
//#define   MAX_ENTRY_COUNT (0x1000/16)  //一级表中的 HANDLE_TABLE_ENTRY个数  
//#define   MAX_ADDR_COUNT   (0x1000/8) //二级表和 三级表中的地址个数  
//
//ULONG g_ProcessCount = 0;
//
//typedef struct _EX_PUSH_LOCK                 // 7 elements, 0x8 bytes (sizeof)   
//{
//    union                                    // 3 elements, 0x8 bytes (sizeof)   
//    {
//        struct                               // 5 elements, 0x8 bytes (sizeof)   
//        {
//            /*0x000*/             UINT64       Locked : 1;         // 0 BitPosition                    
//            /*0x000*/             UINT64       Waiting : 1;        // 1 BitPosition                    
//            /*0x000*/             UINT64       Waking : 1;         // 2 BitPosition                    
//            /*0x000*/             UINT64       MultipleShared : 1; // 3 BitPosition                    
//            /*0x000*/             UINT64       Shared : 60;        // 4 BitPosition                    
//        };
//        /*0x000*/         UINT64       Value;
//        /*0x000*/         VOID*        Ptr;
//    };
//}EX_PUSH_LOCK, *PEX_PUSH_LOCK;
//
//typedef struct _HANDLE_TRACE_DB_ENTRY // 4 elements, 0xA0 bytes (sizeof)   
//{
//    /*0x000*/     struct _CLIENT_ID ClientId;       // 2 elements, 0x10 bytes (sizeof)   
//    /*0x010*/     VOID*        Handle;
//    /*0x018*/     ULONG32      Type;
//    /*0x01C*/     UINT8        _PADDING0_[0x4];
//    /*0x020*/     VOID*        StackTrace[16];
//}HANDLE_TRACE_DB_ENTRY, *PHANDLE_TRACE_DB_ENTRY;
//
//
//
//typedef struct _HANDLE_TRACE_DEBUG_INFO       // 6 elements, 0xF0 bytes (sizeof)   
//{
//    /*0x000*/     LONG32       RefCount;
//    /*0x004*/     ULONG32      TableSize;
//    /*0x008*/     ULONG32      BitMaskFlags;
//    /*0x00C*/     UINT8        _PADDING0_[0x4];
//    /*0x010*/     struct _FAST_MUTEX CloseCompactionLock;   // 5 elements, 0x38 bytes (sizeof)   
//    /*0x048*/     ULONG32      CurrentStackIndex;
//    /*0x04C*/     UINT8        _PADDING1_[0x4];
//    /*0x050*/     struct _HANDLE_TRACE_DB_ENTRY TraceDb[];
//}HANDLE_TRACE_DEBUG_INFO, *PHANDLE_TRACE_DEBUG_INFO;
//
//
//typedef struct _HANDLE_TABLE_ENTRY                  // 8 elements, 0x10 bytes (sizeof)   
//{
//    union                                           // 4 elements, 0x8 bytes (sizeof)    
//    {
//        /*0x000*/         VOID*        Object;
//        /*0x000*/         ULONG32      ObAttributes;
//        /*0x000*/         struct _HANDLE_TABLE_ENTRY_INFO* InfoTable;
//        /*0x000*/         UINT64       Value;
//    };
//    union                                           // 3 elements, 0x8 bytes (sizeof)    
//    {
//        /*0x008*/         ULONG32      GrantedAccess;
//        struct                                      // 2 elements, 0x8 bytes (sizeof)    
//        {
//            /*0x008*/             UINT16       GrantedAccessIndex;
//            /*0x00A*/             UINT16       CreatorBackTraceIndex;
//            /*0x00C*/             UINT8        _PADDING0_[0x4];
//        };
//        /*0x008*/         ULONG32      NextFreeTableEntry;
//    };
//}HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;
//
//
//
//typedef struct _HANDLE_TABLE
//{
//    ULONG64 TableCode;
//    PEPROCESS QuotaProcess;
//    PVOID UniqueProcessId;
//    EX_PUSH_LOCK HandleLock;
//    LIST_ENTRY HandleTableList;
//    EX_PUSH_LOCK HandleContentionEvent;
//    PHANDLE_TRACE_DEBUG_INFO DebugInfo;
//    LONG ExtraInfoPages;
//    ULONG Flags;
//    //ULONG StrictFIFO : 1;  
//    LONG64 FirstFreeHandle;
//    PHANDLE_TABLE_ENTRY LastFreeHandleEntry;
//    LONG HandleCount;
//    ULONG NextHandleNeedingPool;
//} HANDLE_TABLE, *PHANDLE_TABLE;
//
//
//typedef BOOLEAN(*MY_ENUMERATE_HANDLE_ROUTINE)(
//    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
//    IN HANDLE Handle,
//    IN PVOID EnumParameter);
//
//SIZE_T FindCidTable()
//{
//    SIZE_T  CidTableAddr = 0;
//    UNICODE_STRING ustPsFuncName;
//    RtlInitUnicodeString(&ustPsFuncName, L"PsLookupProcessByProcessId");
//    PUCHAR startAddr = (PUCHAR)MmGetSystemRoutineAddress(&ustPsFuncName);
//
//    for (ULONG64 i = 0; i < 100; i++)
//    {
//        if (*(startAddr + i) == 0x48 &&
//            *(startAddr + i + 1) == 0x8b &&
//            *(startAddr + i + 2) == 0x0d)
//        {
//            CidTableAddr = (SIZE_T)(*(PULONG)(startAddr + i + 3) + (startAddr + i + 3 + 4)) & 0xFFFFFFFEFFFFFFFF;
//            DbgPrint("CidTableAddr:%p\n", CidTableAddr);
//            break;
//        }
//    }
//    return CidTableAddr;
//}
//
//
//BOOLEAN MyEnumerateHandleRoutine(
//    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
//    IN HANDLE Handle,
//    IN PVOID EnumParameter
//    )
//{
//    BOOLEAN Result = FALSE;
//    ULONG64 ProcessObject;
//    POBJECT_TYPE ObjectType;
//    PVOID Object;
//    UNICODE_STRING ustObjectName;
//
//    UNREFERENCED_PARAMETER(EnumParameter);
//    UNREFERENCED_PARAMETER(ustObjectName);
//    ProcessObject = (HandleTableEntry->Value)&~7; //掩去低三位  
//    Object = (PVOID)((ULONG64)HandleTableEntry->Object&~7);
//
//    ObjectType = (POBJECT_TYPE)ObGetObjectType(Object);
//    if (MmIsAddressValid(HandleTableEntry))
//    {
//        if (ObjectType == *PsProcessType)//判断是否为Process  
//        {
//            //注意PID其实就是Handle,而 不是从EPROCESS中取,可以对付伪pid  
//            g_ProcessCount++;
//            DbgPrint("PID=%4d\t EPROCESS=0x%p %s\n", Handle, ProcessObject, PsGetProcessImageFileName((PEPROCESS)ProcessObject));
//        }
//    }
//    return Result;//返回FALSE继续  
//}
//
//
////自己实现一个山寨的MyEnumHandleTable,接口和ExEnumHandleTable一样  
//BOOLEAN
//MyEnumHandleTable(
//PHANDLE_TABLE HandleTable,
//MY_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
//PVOID EnumParameter,
//PHANDLE Handle
//)
//{
//    ULONG64 i, j, k;
//    ULONG_PTR CapturedTable;
//    ULONG64 TableLevel;
//    PHANDLE_TABLE_ENTRY TableLevel1, *TableLevel2, **TableLevel3;
//    BOOLEAN CallBackRetned = FALSE;
//    BOOLEAN ResultValue = FALSE;
//    ULONG64 MaxHandle;
//    //判断几个参数是否有效  
//    if (!HandleTable
//        && !EnumHandleProcedure
//        && !MmIsAddressValid(Handle))
//    {
//        return ResultValue;
//    }
//    //取表基址和表的级数  
//    CapturedTable = (HandleTable->TableCode)&~3;
//    TableLevel = (HandleTable->TableCode) & 3;
//    MaxHandle = HandleTable->NextHandleNeedingPool;
//    DbgPrint("句柄上限值为0x%X\n", MaxHandle);
//    //判断表的等级  
//    switch (TableLevel)
//    {
//    case 0:
//    {
//              //一级表  
//              TableLevel1 = (PHANDLE_TABLE_ENTRY)CapturedTable;
//              DbgPrint("解析一级表 0x%p...\n", TableLevel1);
//              for (i = 0; i < MAX_ENTRY_COUNT; i++)
//              {
//                  *Handle = (HANDLE)(i * 4);
//                  if (TableLevel1[i].Object && MmIsAddressValid(TableLevel1[i].Object))
//                  {
//                      //对象有效时，再调用回调函数  
//                      CallBackRetned = EnumHandleProcedure(&TableLevel1[i], *Handle, EnumParameter);
//                      if (CallBackRetned)  break;
//                  }
//              }
//              ResultValue = TRUE;
//
//    }
//        break;
//    case 1:
//    {
//              //二级表  
//              TableLevel2 = (PHANDLE_TABLE_ENTRY*)CapturedTable;
//              DbgPrint("解析二级表 0x%p...\n", TableLevel2);
//              DbgPrint("二级表的个 数:%d\n", MaxHandle / (MAX_ENTRY_COUNT * 4));
//              for (j = 0; j < MaxHandle / (MAX_ENTRY_COUNT * 4); j++)
//              {
//                  TableLevel1 = TableLevel2[j];
//                  if (!TableLevel1)
//                      break; //为零则跳出  
//                  for (i = 0; i < MAX_ENTRY_COUNT; i++)
//                  {
//                      *Handle = (HANDLE)(j*MAX_ENTRY_COUNT * 4 + i * 4);
//                      if (TableLevel1[i].Object && MmIsAddressValid(TableLevel1[i].Object))
//                      {
//                          //对象有效时，再调用回调函数  
//                          CallBackRetned = EnumHandleProcedure(&TableLevel1[i], *Handle, EnumParameter);
//                          if (CallBackRetned)  break;
//                      }
//                  }
//              }
//              ResultValue = TRUE;
//    }
//        break;
//    case 2:
//    {
//              //三级表  
//              TableLevel3 = (PHANDLE_TABLE_ENTRY**)CapturedTable;
//              DbgPrint("解析三级表 0x%p...\n", TableLevel3);
//              DbgPrint("三级表的个 数:%d\n", MaxHandle / (MAX_ENTRY_COUNT * 4 * MAX_ADDR_COUNT));
//              for (k = 0; k < MaxHandle / (MAX_ENTRY_COUNT * 4 * MAX_ADDR_COUNT); k++)
//              {
//                  TableLevel2 = TableLevel3[k];
//                  if (!TableLevel2)
//                      break; //为零则跳出  
//                  for (j = 0; j < MaxHandle / (MAX_ENTRY_COUNT * 4); j++)
//                  {
//                      TableLevel1 = TableLevel2[j];
//                      if (!TableLevel1)
//                          break; //为零则跳出  
//                      for (i = 0; i < MAX_ENTRY_COUNT; i++)
//                      {
//                          *Handle = (HANDLE)(k*MAX_ENTRY_COUNT*MAX_ADDR_COUNT + j*MAX_ENTRY_COUNT + i * 4);
//                          if (TableLevel1[i].Object && MmIsAddressValid(TableLevel1[i].Object))
//                          {
//                              //对象有效时，再调用回调函数  
//                              CallBackRetned = EnumHandleProcedure(&TableLevel1[i], *Handle, EnumParameter);
//                              if (CallBackRetned)  break;
//                          }
//                      }
//                  }
//              }
//              ResultValue = TRUE;
//    }
//        break;
//    default:
//    {
//               DbgPrint("BOOM!\n");
//    }
//        break;
//    }
//    DbgPrint("ProcessCount:0x%x", g_ProcessCount);
//    return ResultValue;
//}
//
//
//void EnumProcessByPspCidTable()
//{
//    PHANDLE_TABLE pHandleTable = NULL;
//    pHandleTable = (PHANDLE_TABLE)*(PSIZE_T)FindCidTable();
//    HANDLE hHanel;
//    UNICODE_STRING usObGetObjectType;
//    DbgPrint("pHandleTable:%p\n", pHandleTable);
//    MyEnumHandleTable(pHandleTable, MyEnumerateHandleRoutine, NULL, &hHanel);
//}
//
//void DriverUnload(PDRIVER_OBJECT pDriverObject)
//{
//    UNREFERENCED_PARAMETER(pDriverObject);
//    DbgPrint("GoodBye!\n");
//}
//
//extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
//{
//    UNREFERENCED_PARAMETER(pRegPath);
//
//    pDriverObject->DriverUnload = DriverUnload;
//
//    DbgPrint("DriverEntry!\n");
//
//    EnumProcessByPspCidTable();
//
//    return STATUS_SUCCESS;
//}

