#include "nic.h"
#include "Spoof.h"
#include <ntstrsafe.h>

NIC_LIST NICs = { 0 };


#define MAX_NIC_MACS 16
#define MAC_ADDRESS_LENGTH 6

struct NIC_MAC_DATA {
    UCHAR orig[MAC_ADDRESS_LENGTH];
    UCHAR spoofed[MAC_ADDRESS_LENGTH];
};

NIC_MAC_DATA gMacAddresses[MAX_NIC_MACS];
int gMacAddressCount = 0;

EXTERN_C
NTKERNELAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);


EXTERN_C
NTKERNELAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);


const unsigned char JmpBuffer[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, 0xDEADBEEFBABECOF0
                                    0xFF, 0xE0 };


bool CheckDriverMajorFunctions(PDRIVER_OBJECT pDriverObject) {
    bool IsInDriverObject = Util::IsMajorFunctionInDriverObject(pDriverObject);
    return IsInDriverObject;
}


void randomize_mac(UCHAR* pMac, int length) {
    static ULONG seed = GetBootSeed(); // Seed for generating unique MAC on each restart
    auto getRandomByte = [&]() -> UCHAR {
        seed = 1664525 * seed + 1013904223;
        return (UCHAR)(seed % 256);
        };

    for (int i = 0; i < length; i++) {
        pMac[i] = getRandomByte();
    }

    // Ensuring a locally administered address by setting the second-least-significant bit of the first byte
    pMac[0] = (pMac[0] & 0xFE) | 0x02;
}

bool FindFakeFakeNICMac(char* pOriginal) {
    if (!MmIsAddressValid(pOriginal)) {
        return false;
    }

    // Check if the original MAC exists in our spoof list
    for (int i = 0; i < gMacAddressCount; i++) {
        if (RtlCompareMemory(gMacAddresses[i].orig, pOriginal, MAC_ADDRESS_LENGTH) == MAC_ADDRESS_LENGTH) {
            Util::WriteToReadOnly(pOriginal, gMacAddresses[i].spoofed, MAC_ADDRESS_LENGTH);
            return true;
        }
        else if (RtlCompareMemory(gMacAddresses[i].spoofed, pOriginal, MAC_ADDRESS_LENGTH) == MAC_ADDRESS_LENGTH) {
            Util::WriteToReadOnly(pOriginal, gMacAddresses[i].spoofed, MAC_ADDRESS_LENGTH);
            return true;
        }
    }

    if (gMacAddressCount < MAX_NIC_MACS) {
        NIC_MAC_DATA macData = { 0 };

        // Store original MAC
        RtlCopyMemory(macData.orig, pOriginal, MAC_ADDRESS_LENGTH);

        randomize_mac(macData.spoofed, MAC_ADDRESS_LENGTH);

        // Store spoofed MAC in global list
        gMacAddresses[gMacAddressCount++] = macData;

        // Overwrite the original MAC with spoofed MAC in the provided buffer
        RtlCopyMemory(pOriginal, macData.spoofed, MAC_ADDRESS_LENGTH);
        Util::WriteToReadOnly(pOriginal, macData.spoofed, MAC_ADDRESS_LENGTH);
    }

    return true;
}

PWCHAR TrimGUID(PWCHAR guid, DWORD max) {
    DWORD i = 0;
    PWCHAR start = guid;

    --max;
    for (; i < max && *start != L'{'; ++i, ++start);
    for (; i < max && guid[i++] != L'}';);

    guid[i] = 0;
    return start;
}

NTSTATUS TCPHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);

    if (!MmIsAddressValid(StackLocation))
        return OriginalHandlers::gOriginalTcpDeviceControl(pDeviceObject, Irp);

        switch (StackLocation->Parameters.DeviceIoControl.IoControlCode)
        {
        case IOCTL_TCP_QUERY_INFORMATION_EX: {
            NTSTATUS Status = OriginalHandlers::gOriginalTcpDeviceControl(pDeviceObject, Irp);

            if (NT_SUCCESS(Status)) {
                IFEntry* Ifentry = (IFEntry*)Irp->UserBuffer;
                if (MmIsAddressValid(Ifentry) && !Util::IsNtosKrnlAddress((DWORD64)Ifentry)) {
                    FindFakeFakeNICMac((char*)Ifentry->if_physaddr);
                }
                return Status;

            }
            break;
        }
        default:
            return OriginalHandlers::gOriginalTcpDeviceControl(pDeviceObject, Irp);
            break;
        }



    return OriginalHandlers::gOriginalTcpDeviceControl(pDeviceObject, Irp);
}

#define IS_VALID_POINTER(ptr) (ptr && MmIsAddressValid((PVOID)(ptr)))

BOOLEAN IsMacAddress(PUCHAR addr) {
    for (int i = 0; i < 6; i++) {
        if (addr[i] > 0xFF)
            return FALSE;
    }
    return TRUE;
}

BOOLEAN ShouldSpoofMacAddress(PUCHAR macAddr) {
    // Check for broadcast address (ff-ff-ff-ff-ff-ff)
    if (macAddr[0] == 0xff && macAddr[1] == 0xff && macAddr[2] == 0xff &&
        macAddr[3] == 0xff && macAddr[4] == 0xff && macAddr[5] == 0xff) {
        return FALSE;
    }

    // Check for multicast address (starting with 01-00-5e)
    if (macAddr[0] == 0x01 && macAddr[1] == 0x00 && macAddr[2] == 0x5e) {
        return FALSE;  
    }

    int zeroCount = 0;
    for (int i = 0; i < 6; i++) {
        if (macAddr[i] == 0x00) {
            zeroCount++;
        }
    }
    if (zeroCount > 1) {
        return FALSE;  
    }

    return TRUE;
}


VOID SpoofARPTable(PNSI_PARAMS Params) {
    if (!IS_VALID_POINTER(Params)) {
        return;
    }

    if (!IS_VALID_POINTER(Params->NeighborTable)) {
        return;
    }


    PUCHAR neighborTableBase = (PUCHAR)Params->NeighborTable;
    int entrySize = Params->NeighborTableEntrySize;

    if (entrySize <= 0 || entrySize > 256) { 
        return;
    }

    for (int i = 0; i < Params->Count; i++) { 
        PUCHAR macAddress = neighborTableBase + (i * entrySize);
       // PrintMACAddress(macAddress, 6);
        if (IS_VALID_POINTER(macAddress) && IsMacAddress(macAddress) && ShouldSpoofMacAddress(macAddress)) {
            FindFakeFakeNICMac((char*)macAddress);
        }
    }
}


NTSTATUS GetProcessImageFileName(PEPROCESS Process, WCHAR* Buffer, SIZE_T BufferSize) {
    if (!Buffer || BufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    HANDLE ProcessHandle;
    NTSTATUS Status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, GENERIC_READ, *PsProcessType, KernelMode, &ProcessHandle);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    ULONG ReturnLength = 0;
    UNICODE_STRING* ProcessName = (UNICODE_STRING*)ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING) + BufferSize, 'prnm');

    if (!ProcessName) {
        ZwClose(ProcessHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, ProcessName, sizeof(UNICODE_STRING) + BufferSize, &ReturnLength);
    if (NT_SUCCESS(Status)) {
        RtlCopyMemory(Buffer, ProcessName->Buffer, min(BufferSize, ProcessName->Length));
        Buffer[min(BufferSize - 1, ProcessName->Length / sizeof(WCHAR))] = L'\0'; // Null-terminate
    }

    ExFreePoolWithTag(ProcessName, 'prnm');
    ZwClose(ProcessHandle);

    return Status;
}


NTSTATUS NSIHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);

    if (!MmIsAddressValid(StackLocation))
        return OriginalHandlers::gOriginalNsiProxyDeviceControl(pDeviceObject, Irp);

    NTSTATUS Status = STATUS_SUCCESS;

    PEPROCESS CurrProc = PsGetCurrentProcess();
    WCHAR ProcessNameBuffer[260] = { 0 };
    Status = GetProcessImageFileName(CurrProc, ProcessNameBuffer, sizeof(ProcessNameBuffer));
    if (NT_SUCCESS(Status)) {
        if (wcsstr(ProcessNameBuffer, L"svchost.exe") || wcsstr(ProcessNameBuffer, L"steam"))
            return OriginalHandlers::gOriginalNsiProxyDeviceControl(pDeviceObject, Irp);
    }
        switch (StackLocation->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_NSI_GETALLPARAM: {
            DWORD LengthOutput = StackLocation->Parameters.DeviceIoControl.OutputBufferLength;
            Status = OriginalHandlers::gOriginalNsiProxyDeviceControl(pDeviceObject, Irp);

            if (NT_SUCCESS(Status) && LengthOutput > 0 && MmIsAddressValid(Irp->UserBuffer) && !Util::IsNtosKrnlAddress((DWORD64)Irp->UserBuffer)) {
                PNSI_PARAMS Params = (PNSI_PARAMS)Irp->UserBuffer;

                    if (MmIsAddressValid(Params) && Params->Type == NSI_GET_IP_NET_TABLE) {
                        SpoofARPTable(Params);
                    }

                    else if (MmIsAddressValid(Params) && Params->Type == NSI_GET_ADAPTERS_INFO) {
                        PNSI_ENUMERATE_OBJECTS_ALL_PRAMETERS_EX Param = (PNSI_ENUMERATE_OBJECTS_ALL_PRAMETERS_EX)Params;
                        ULONG i = 0;
                        PNSI_ADAPTERINFO_ROW row;
                        for (i = 0; i < Params->Count; i++) {
                            row = (PNSI_ADAPTERINFO_ROW)(Param->EntryPointer_3 + i * Param->EntrySize_3);

                            if (!MmIsAddressValid(row)) {
                                continue;
                            }

                            if (ShouldSpoofMacAddress((PUCHAR)row->MacAddress)) {
                                FindFakeFakeNICMac((char*)row->MacAddress);
                            }
                        }
                    }
                }
            return Status;
            break;
        }
        case IOCTL_NSI_GET_ARP: {
            Status = OriginalHandlers::gOriginalNsiProxyDeviceControl(pDeviceObject, Irp);


            return Status;
            break;
        }
        case IOCTL_NSI_GETPARAM: {
            DWORD LengthOut = StackLocation->Parameters.DeviceIoControl.OutputBufferLength;
            Status = OriginalHandlers::gOriginalNsiProxyDeviceControl(pDeviceObject, Irp);


            return Status;
            break;
        }
        default:
            return OriginalHandlers::gOriginalNsiProxyDeviceControl(pDeviceObject, Irp);
            break;
        }
    
    return OriginalHandlers::gOriginalNsiProxyDeviceControl(pDeviceObject, Irp);
}


//good
NTSTATUS NICIoc(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
    if (MmIsAddressValid(Context)) {

        REQUEST_STRUCT request = *(REQUEST_STRUCT*)Context;
        ExFreePool(Context);

        if (Irp->MdlAddress && !Util::IsNtosKrnlAddress((DWORD64)Irp->MdlAddress)) {
            FindFakeFakeNICMac((char*)MmGetSystemAddressForMdl(Irp->MdlAddress));
        }

        if (request.old_routine && Irp->StackCount > 1) {
            return request.old_routine(pDeviceObject, Irp, request.old_context);
       }
    }
    return STATUS_SUCCESS;
}

//good
NTSTATUS NICHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
    for (DWORD i = 0; i < NICs.Length; ++i) {
        PNIC_DRIVER Driver = &NICs.Drivers[i];

        if (Driver->Original && Driver->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] == pDeviceObject->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]) {
            PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);

            if (!MmIsAddressValid(StackLocation))
                return Driver->Original(pDeviceObject, Irp);

            switch (StackLocation->Parameters.DeviceIoControl.IoControlCode)
            {
            case IOCTL_NDIS_QUERY_GLOBAL_STATS: {
                switch (*(PDWORD)Irp->AssociatedIrp.SystemBuffer) {
                case OID_802_3_PERMANENT_ADDRESS:
                case OID_802_3_CURRENT_ADDRESS:
                case OID_802_5_PERMANENT_ADDRESS:
                case OID_802_5_CURRENT_ADDRESS:
                case OID_WAN_PERMANENT_ADDRESS:
                case OID_WAN_CURRENT_ADDRESS:
                case OID_ARCNET_PERMANENT_ADDRESS:
                case OID_ARCNET_CURRENT_ADDRESS:
                    ioctl_helper::set_completion_callback(Irp, StackLocation, NICIoc);
                    break;
                }
                break;
            }
            


            default:
                break;
            }

            return Driver->Original(pDeviceObject, Irp);

        }
    }


    return STATUS_SUCCESS;
}


bool nic::Spoof() {
	PVOID Size = 0;
    auto sNdis = skCrypt("ndis.sys");
	PVOID pNdisBase = (PVOID)Util::GetKernelModule(sNdis, Size);
    sNdis.clear();

	if (!pNdisBase) {
		return false;
	}


    auto sNdisGlobalFilterListPattern = skCrypt("\x40\x8A\xF0\x48\x8B\x05");
    auto sNdisGlobalFilterListMask = skCrypt("xxxxxx");
    PNDIS_FILTER_BLOCK ndisGlobalFilterList = (PNDIS_FILTER_BLOCK)Util::FindPatternImage((PCHAR)pNdisBase, sNdisGlobalFilterListPattern, sNdisGlobalFilterListMask);
    sNdisGlobalFilterListPattern.clear();
    sNdisGlobalFilterListMask.clear();

    if (!ndisGlobalFilterList) {
        return false;
    }

    auto sFilterIfBlockPattern = skCrypt("\x48\x85\x00\x0F\x84\x00\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x33");
    auto sFilterIfBlockMask = skCrypt("xx?xx?????x???xxx");
    PDWORD ndisFilter_IfBlock = (PDWORD)Util::FindPatternImage((PCHAR)pNdisBase, sFilterIfBlockPattern, sFilterIfBlockMask);
    sFilterIfBlockPattern.clear();
    sFilterIfBlockMask.clear();


    if (!ndisFilter_IfBlock) {
        return false;
    }

    DWORD ndisFilter_IfBlock_offset = *(PDWORD)((PBYTE)ndisFilter_IfBlock + 12);

    ndisGlobalFilterList = (PNDIS_FILTER_BLOCK)((PBYTE)ndisGlobalFilterList + 3);
    ndisGlobalFilterList = *(PNDIS_FILTER_BLOCK*)((PBYTE)ndisGlobalFilterList + 7 + *(PINT)((PBYTE)ndisGlobalFilterList + 3));

    DWORD Count = 0;
    for (PNDIS_FILTER_BLOCK filter = ndisGlobalFilterList; filter; filter = filter->NextFilter) {
        PNDIS_IF_BLOCK block = *(PNDIS_IF_BLOCK*)((PBYTE)filter + ndisFilter_IfBlock_offset);
        if (block) {

            PWCHAR copy = (PWCHAR)Util::SafeCopy(filter->FilterInstanceName->Buffer, MAX_PATH);
            if (copy) {
                WCHAR adapter[MAX_PATH] = { 0 };

                RtlStringCchPrintfW(adapter, MAX_PATH, L"\\Device\\%ws", TrimGUID(copy, MAX_PATH / 2));
                ExFreePool(copy);


                UNICODE_STRING name = { 0 };
                RtlInitUnicodeString(&name, adapter);

                PFILE_OBJECT file = 0;
                PDEVICE_OBJECT device = 0;

                NTSTATUS status = IoGetDeviceObjectPointer(&name, FILE_READ_DATA, &file, &device);
                if (NT_SUCCESS(status)) {
                    PDRIVER_OBJECT driver = device->DriverObject;
                    if (driver) {
                        BOOL exists = FALSE;
                        for (DWORD i = 0; i < NICs.Length; ++i) {
                            if (NICs.Drivers[i].DriverObject == driver) {
                                exists = TRUE;
                                break;
                            }
                        }

                        if (exists) {
                            continue;
                        }
                        else {
                            PNIC_DRIVER nic = &NICs.Drivers[NICs.Length];
                            nic->DriverObject = driver;

                            

                            PIMAGE_SECTION_HEADER DiscardableSectionHeader = Util::GetDiscardableSectionHeader(nic->DriverObject);

                            if (DiscardableSectionHeader == nullptr) {
                                ObDereferenceObject(nic->DriverObject);
                                nic->DriverObject = nullptr;
                                return false;
                            }

                            const auto DiscardableSectionAddress = Util::GetDiscardableSectionAddress(nic->DriverObject, DiscardableSectionHeader);
                            PTE_64* DiscardableSectionPte = Util::GetPteForAddress(DiscardableSectionAddress);

                            nic->HookBuffer = ExAllocatePool(NonPagedPool, ROUND_TO_PAGES(DiscardableSectionHeader->Misc.VirtualSize));
                            PTE_64* AllocatedBufferPte = Util::GetPteForAddress(nic->HookBuffer);

                            if (DiscardableSectionPte == nullptr || AllocatedBufferPte == nullptr || nic->HookBuffer == nullptr) {
                                if (nic->HookBuffer) {
                                    ExFreePool(nic->HookBuffer);
                                }
                                ObDereferenceObject(nic->DriverObject);
                                nic->DriverObject = nullptr;
                                return false;
                            }

                            *DiscardableSectionPte = *AllocatedBufferPte;

                            if (DiscardableSectionPte->ExecuteDisable) {
                                DiscardableSectionPte->ExecuteDisable = 0;
                            }

                            memcpy(DiscardableSectionAddress, JmpBuffer, sizeof(JmpBuffer));
                            *reinterpret_cast<void**>(&reinterpret_cast<unsigned char*>(DiscardableSectionAddress)[2]) = &NICHandler;


                            nic->Original = driver->MajorFunction[IRP_MJ_DEVICE_CONTROL];
                            driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = reinterpret_cast<DRIVER_DISPATCH*>(DiscardableSectionAddress);
                            ++NICs.Length;

                            if (!CheckDriverMajorFunctions(driver)) {
                                return false;
                            }
                        }
                    }
                }
            }

        }
    }

    NTSTATUS Status;
    {
        UNICODE_STRING uNsiProxy;
        RtlInitUnicodeString(&uNsiProxy, L"\\Driver\\nsiproxy");

        Status = ObReferenceObjectByName(&uNsiProxy, OBJ_CASE_INSENSITIVE, NULL, NULL, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&OriginalHandlers::gNsiProxyDriverObject);
        if (!NT_SUCCESS(Status)) {
            return false;
        }

        PIMAGE_SECTION_HEADER DiscardableSectionHeader = Util::GetDiscardableSectionHeader(OriginalHandlers::gNsiProxyDriverObject);

        if (DiscardableSectionHeader == nullptr) {
            ObDereferenceObject(OriginalHandlers::gNsiProxyDriverObject);
            OriginalHandlers::gNsiProxyDriverObject = nullptr;
            return false;
        }

        const auto DiscardableSectionAddress = Util::GetDiscardableSectionAddress(OriginalHandlers::gNsiProxyDriverObject, DiscardableSectionHeader);
        PTE_64* DiscardableSectionPte = Util::GetPteForAddress(DiscardableSectionAddress);

        NICMemory::gNsiHookBuffer = ExAllocatePool(NonPagedPool, ROUND_TO_PAGES(DiscardableSectionHeader->Misc.VirtualSize));
        PTE_64* AllocatedBufferPte = Util::GetPteForAddress(NICMemory::gNsiHookBuffer);

        if (DiscardableSectionPte == nullptr || AllocatedBufferPte == nullptr || NICMemory::gNsiHookBuffer == nullptr) {
            if (NICMemory::gNsiHookBuffer) {
                ExFreePool(NICMemory::gNsiHookBuffer);
            }
            ObDereferenceObject(OriginalHandlers::gNsiProxyDriverObject);
            OriginalHandlers::gNsiProxyDriverObject = nullptr;
            return false;
        }

        *DiscardableSectionPte = *AllocatedBufferPte;

        if (DiscardableSectionPte->ExecuteDisable) {
            DiscardableSectionPte->ExecuteDisable = 0;
        }

        memcpy(DiscardableSectionAddress, JmpBuffer, sizeof(JmpBuffer));
        *reinterpret_cast<void**>(&reinterpret_cast<unsigned char*>(DiscardableSectionAddress)[2]) = &NSIHandler;


        OriginalHandlers::gOriginalNsiProxyDeviceControl = OriginalHandlers::gNsiProxyDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
        OriginalHandlers::gNsiProxyDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = reinterpret_cast<DRIVER_DISPATCH*>(DiscardableSectionAddress);

        if (!CheckDriverMajorFunctions(OriginalHandlers::gNsiProxyDriverObject)) {
            return false;
        }
    }


    {
        UNICODE_STRING uTcpDevice;
        RtlInitUnicodeString(&uTcpDevice, L"\\Device\\Tcp");

        PFILE_OBJECT file = 0;
        PDEVICE_OBJECT device = 0;

        Status = IoGetDeviceObjectPointer(&uTcpDevice, FILE_READ_DATA, &file, &device);
        if (!NT_SUCCESS(Status)) {
            return false;
        }

        OriginalHandlers::gTcpDriverObject = device->DriverObject;

        PIMAGE_SECTION_HEADER DiscardableSectionHeader = Util::GetDiscardableSectionHeader(OriginalHandlers::gTcpDriverObject);

        if (DiscardableSectionHeader == nullptr) {
            ObDereferenceObject(OriginalHandlers::gTcpDriverObject);
            OriginalHandlers::gTcpDriverObject = nullptr;
            return false;
        }

        const auto DiscardableSectionAddress = Util::GetDiscardableSectionAddress(OriginalHandlers::gTcpDriverObject, DiscardableSectionHeader);
        PTE_64* DiscardableSectionPte = Util::GetPteForAddress(DiscardableSectionAddress);

        NICMemory::gTcpHookBuffer = ExAllocatePool(NonPagedPool, ROUND_TO_PAGES(DiscardableSectionHeader->Misc.VirtualSize));
        PTE_64* AllocatedBufferPte = Util::GetPteForAddress(NICMemory::gTcpHookBuffer);

        if (DiscardableSectionPte == nullptr || AllocatedBufferPte == nullptr || NICMemory::gTcpHookBuffer == nullptr) {
            if (NICMemory::gTcpHookBuffer) {
                ExFreePool(NICMemory::gTcpHookBuffer);
            }
            ObDereferenceObject(OriginalHandlers::gTcpDriverObject);
            OriginalHandlers::gTcpDriverObject = nullptr;
            return false;
        }

        *DiscardableSectionPte = *AllocatedBufferPte;

        if (DiscardableSectionPte->ExecuteDisable) {
            DiscardableSectionPte->ExecuteDisable = 0;
        }

        memcpy(DiscardableSectionAddress, JmpBuffer, sizeof(JmpBuffer));
        *reinterpret_cast<void**>(&reinterpret_cast<unsigned char*>(DiscardableSectionAddress)[2]) = &TCPHandler;


        OriginalHandlers::gOriginalTcpDeviceControl = OriginalHandlers::gTcpDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
        OriginalHandlers::gTcpDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = reinterpret_cast<DRIVER_DISPATCH*>(DiscardableSectionAddress);

        if (!CheckDriverMajorFunctions(OriginalHandlers::gTcpDriverObject)) {
            return false;
        }
    }




    return true;
}
