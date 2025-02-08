#include "usbserials.h"
#include "Spoof.h"
#include <usbioctl.h>
#include <hidport.h>


#define MAX_USB_DEVICES 127

const unsigned char JmpBuffer[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, 0xDEADBEEFBABECOF0
                                    0xFF, 0xE0 };

PDEVICE_OBJECT GetDeviceFromIName(UNICODE_STRING DeviceName) {
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    PFILE_OBJECT LocalFileObject;
    HANDLE DeviceHandle;
    PDEVICE_OBJECT pDeviceObject = nullptr;




    /* Open a file object handle to the device */
    InitializeObjectAttributes(&ObjectAttributes,
        &DeviceName,
        OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    Status = ZwCreateFile(&DeviceHandle,
        FILE_ALL_ACCESS,
        &ObjectAttributes,
        &IoStatusBlock,
        NULL,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        0,
        NULL,
        0);
    if (NT_SUCCESS(Status))
    {
        Status = ObReferenceObjectByHandle(DeviceHandle,
            0,
            *IoFileObjectType,
            KernelMode,
            (PVOID*)&LocalFileObject,
            NULL);
        if (NT_SUCCESS(Status))
        {
            pDeviceObject = IoGetRelatedDeviceObject(LocalFileObject);
        }

        ZwClose(DeviceHandle);
    }

    return pDeviceObject;
}

bool CheckDriverMajorFunctions2(PDRIVER_OBJECT pDriverObject) {
    bool IsInDriverObject = Util::IsMajorFunctionInDriverObject(pDriverObject);
    return IsInDriverObject;
}

NTSTATUS GetNodeConnectionInfoHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
    if (MmIsAddressValid(Context)) {
        auto data = ioctl_helper::fetch_callback_data<USB_NODE_CONNECTION_INFORMATION>(Context);

        if (MmIsAddressValid(data.buffer)) {
            PUSB_NODE_CONNECTION_INFORMATION pUsbInfo = (PUSB_NODE_CONNECTION_INFORMATION)data.buffer;

            if (MmIsAddressValid(pUsbInfo)) {
                pUsbInfo->DeviceDescriptor.iSerialNumber = 0;
            }
        }

        if (data.old_routine && Irp->StackCount > 1) {
            return data.old_routine(pDeviceObject, Irp, data.old_context);
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS GetNodeConnectionInfoExHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
    if (MmIsAddressValid(Context)) {
        auto data = ioctl_helper::fetch_callback_data<USB_NODE_CONNECTION_INFORMATION_EX>(Context);

        if (MmIsAddressValid(data.buffer)) {
            PUSB_NODE_CONNECTION_INFORMATION_EX pUsbInfo = (PUSB_NODE_CONNECTION_INFORMATION_EX)data.buffer;

            if (MmIsAddressValid(pUsbInfo)) {
                pUsbInfo->DeviceDescriptor.iSerialNumber = 0;
            }

        }
        

        if (data.old_routine && Irp->StackCount > 1) {
            return data.old_routine(pDeviceObject, Irp, data.old_context);
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS GetNodeInformationHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
    if (MmIsAddressValid(Context)) {
        auto data = ioctl_helper::fetch_callback_data<USB_NODE_INFORMATION>(Context);

        if (MmIsAddressValid(data.buffer)) {
            PUSB_NODE_INFORMATION pUsbInfo = (PUSB_NODE_INFORMATION)data.buffer;

            if (!Util::IsNtosKrnlAddress((DWORD64)pUsbInfo)) {
                RtlZeroMemory(pUsbInfo, sizeof(pUsbInfo));
            }
        }

        if (data.old_routine && Irp->StackCount > 1) {
            return data.old_routine(pDeviceObject, Irp, Context);
        }


    }


    return STATUS_SUCCESS;
}


NTSTATUS UsbHUBHandler(PDEVICE_OBJECT device, PIRP irp) {
    for (size_t i = 0; i < g_USBHooks.Length; i++) {
        PUSB_DRIVER driver = &g_USBHooks.Drivers[i];
        
        if (driver->Original && MmIsAddressValid(driver->DriverObject) && driver->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] == device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]) {
            if (((size_t)irp >> (62))) {
                PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(irp);
                if (!MmIsAddressValid(StackLocation)) {
                    return driver->Original(device, irp);
                }

                switch (StackLocation->Parameters.DeviceIoControl.IoControlCode)
                {
                case IOCTL_USB_GET_NODE_CONNECTION_INFORMATION: {
                    ioctl_helper::set_completion_callback(irp, StackLocation, GetNodeConnectionInfoHandler);
                    break;
                }
                case IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX: {
                    ioctl_helper::set_completion_callback(irp, StackLocation, GetNodeConnectionInfoExHandler);
                    break;
                }
                case IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION: {
                    return STATUS_SUCCESS;
                }
                case IOCTL_USB_GET_NODE_INFORMATION: {
                    ioctl_helper::set_completion_callback(irp, StackLocation, GetNodeInformationHandler);
                    break;
                }

                default:
                    break;
                }


            }


            return driver->Original(device, irp);
        }

        
    }

    return STATUS_UNSUCCESSFUL;
}

NTSTATUS HidHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
        PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);
        if (!MmIsAddressValid(StackLocation)) {
            return OriginalHandlers::gOriginalHidDeviceControl(pDeviceObject, Irp);
        }



        switch (StackLocation->Parameters.DeviceIoControl.IoControlCode)
        {
        case IOCTL_HID_GET_SERIALNUMBER_STRING: {
            return STATUS_INVALID_PARAMETER;
            break;
        }
        case IOCTL_HID_GET_DEVICE_DESCRIPTOR: {
            return STATUS_INVALID_PARAMETER;
            break;
        }
        case IOCTL_HID_GET_PRODUCT_STRING: {
            return STATUS_INVALID_PARAMETER;
            break;
        }
        case IOCTL_HID_GET_HARDWARE_ID: {
            return STATUS_INVALID_PARAMETER;
            break;
        }
        case IOCTL_HID_GET_COLLECTION_INFORMATION:
            return STATUS_INVALID_PARAMETER;
            break;
        default:
            break;
        }


        return STATUS_SUCCESS;

}



bool usb::Spoof() {
    const GUID GUID_USB_HUB = { 0xf18a0e88, 0xc30c, 0x11d0, 0x88, 0x15, 0x00, 0xa0, 0xc9, 0x06, 0xbe, 0xd8 };
    PWCHAR pDeviceNames = nullptr;
    NTSTATUS Status = IoGetDeviceInterfaces(&GUID_USB_HUB, nullptr, DEVICE_INTERFACE_INCLUDE_NONACTIVE, &pDeviceNames);

    if (!NT_SUCCESS(Status)) {
        return false;
    }

    PWCHAR usbInterfaces[MAX_USB_DEVICES] = { nullptr };
    int DeviceCount = 0;

    while (true) {
        int strLen = wcslen(pDeviceNames);
        if (!strLen || DeviceCount >= MAX_USB_DEVICES) {
            break;
        }

        usbInterfaces[DeviceCount] = pDeviceNames;
        pDeviceNames += (strLen)+1;
        DeviceCount++;
    }


    for (int i = 0; i < DeviceCount; i++) {

        UNICODE_STRING uDeviceName = {};
        RtlInitUnicodeString(&uDeviceName, usbInterfaces[i]);

        PDEVICE_OBJECT pCurrDeviceObject = 0;
        if (uDeviceName.Buffer) {
            pCurrDeviceObject = GetDeviceFromIName(uDeviceName);
        }
        else {
            pCurrDeviceObject = 0;
        }
        


        if (!pCurrDeviceObject) {
            continue;
        }

        if (!pCurrDeviceObject->DriverObject) {
            ObDereferenceObject(pCurrDeviceObject);
            continue;
        }

        bool alreadyHooked = false;
        for (DWORD j = 0; j < g_USBHooks.Length; j++) {
            if (g_USBHooks.Drivers[j].DriverObject == pCurrDeviceObject->DriverObject) {
                alreadyHooked = true;
                break;
            }
        }

        if (alreadyHooked) {
            continue;
        }

        ObReferenceObject(pCurrDeviceObject->DriverObject);

        auto usb = &g_USBHooks.Drivers[g_USBHooks.Length];
        usb->DriverObject = pCurrDeviceObject->DriverObject;

        PIMAGE_SECTION_HEADER DiscardableSectionHeader = Util::GetDiscardableSectionHeader(usb->DriverObject);

        if (DiscardableSectionHeader == nullptr) {
            ObDereferenceObject(usb->DriverObject);
            usb->DriverObject = nullptr;
            return false;
        }

        const auto DiscardableSectionAddress = Util::GetDiscardableSectionAddress(usb->DriverObject, DiscardableSectionHeader);
        PTE_64* DiscardableSectionPte = Util::GetPteForAddress(DiscardableSectionAddress);

        usb->HookBuffer = ExAllocatePool(NonPagedPool, ROUND_TO_PAGES(DiscardableSectionHeader->Misc.VirtualSize));
        PTE_64* AllocatedBufferPte = Util::GetPteForAddress(usb->HookBuffer);

        if (DiscardableSectionPte == nullptr || AllocatedBufferPte == nullptr || usb->HookBuffer == nullptr) {
            if (usb->HookBuffer) {
                ExFreePool(usb->HookBuffer);
            }
            ObDereferenceObject(usb->DriverObject);
            usb->DriverObject = nullptr;
            return false;
        }

        *DiscardableSectionPte = *AllocatedBufferPte;

        if (DiscardableSectionPte->ExecuteDisable) {
            DiscardableSectionPte->ExecuteDisable = 0;
        }

        memcpy(DiscardableSectionAddress, JmpBuffer, sizeof(JmpBuffer));
        *reinterpret_cast<void**>(&reinterpret_cast<unsigned char*>(DiscardableSectionAddress)[2]) = &UsbHUBHandler;


        usb->Original = usb->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
        usb->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = reinterpret_cast<DRIVER_DISPATCH*>(DiscardableSectionAddress);
        ++NICs.Length;

        if (!CheckDriverMajorFunctions2(usb->DriverObject)) {
            return false;
        }

        g_USBHooks.Length++;
    }

    return true;
}

bool usb::SpoofHID() {
   
    UNICODE_STRING uDriverName;
    NTSTATUS status;

    RtlInitUnicodeString(&uDriverName, L"\\Driver\\hidusb");

    status = ObReferenceObjectByName(
        &uDriverName,              
        OBJ_CASE_INSENSITIVE,      
        NULL,                      
        0,                         
        *IoDriverObjectType,       
        KernelMode,                
        NULL,                      
        (PVOID*)&OriginalHandlers::gHidDriverObject     
    );

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(OriginalHandlers::gHidDriverObject);
    }

    PIMAGE_SECTION_HEADER DiscardableSectionHeader = Util::GetDiscardableSectionHeader(OriginalHandlers::gHidDriverObject);

    if (DiscardableSectionHeader == nullptr) {
        ObDereferenceObject(OriginalHandlers::gHidDriverObject);
        OriginalHandlers::gHidDriverObject = nullptr;
        return false;
    }

    const auto DiscardableSectionAddress = Util::GetDiscardableSectionAddress(OriginalHandlers::gHidDriverObject, DiscardableSectionHeader);
    PTE_64* DiscardableSectionPte = Util::GetPteForAddress(DiscardableSectionAddress);

    HIDMemory::gHidHookBuffer = ExAllocatePool(NonPagedPool, ROUND_TO_PAGES(DiscardableSectionHeader->Misc.VirtualSize));
    PTE_64* AllocatedBufferPte = Util::GetPteForAddress(HIDMemory::gHidHookBuffer);

    if (DiscardableSectionPte == nullptr || AllocatedBufferPte == nullptr || HIDMemory::gHidHookBuffer == nullptr) {
        if (HIDMemory::gHidHookBuffer) {
            ExFreePool(HIDMemory::gHidHookBuffer);
        }
        ObDereferenceObject(OriginalHandlers::gHidDriverObject);
        OriginalHandlers::gHidDriverObject = nullptr;
        return false;
    }

    *DiscardableSectionPte = *AllocatedBufferPte;

    if (DiscardableSectionPte->ExecuteDisable) {
        DiscardableSectionPte->ExecuteDisable = 0;
    }

    memcpy(DiscardableSectionAddress, JmpBuffer, sizeof(JmpBuffer));
    *reinterpret_cast<void**>(&reinterpret_cast<unsigned char*>(DiscardableSectionAddress)[2]) = &HidHandler;

    OriginalHandlers::gOriginalHidDeviceControl = OriginalHandlers::gHidDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    OriginalHandlers::gHidDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = reinterpret_cast<DRIVER_DISPATCH*>(DiscardableSectionAddress);

    if (!CheckDriverMajorFunctions2(OriginalHandlers::gHidDriverObject)) {
        return false;
    }


    return true;
}





