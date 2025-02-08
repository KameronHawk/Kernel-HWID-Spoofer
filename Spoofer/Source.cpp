#include "Spoof.h"

PDEVICE_OBJECT g_DeviceObject;
UNICODE_STRING g_DosName;
UNICODE_STRING g_DeviceName;

VOID CleanupDriver(PDRIVER_OBJECT pDriverObject) {
    UNREFERENCED_PARAMETER(pDriverObject);


    if (g_DeviceObject) {
        IoDeleteSymbolicLink(&g_DosName);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = nullptr;
    }

    if (OriginalHandlers::gFltMgrObject) {
        OriginalHandlers::gFltMgrObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = OriginalHandlers::gOriginalFltMgrDeviceControl;
        ObDereferenceObject(OriginalHandlers::gFltMgrObject);
        OriginalHandlers::gFltMgrObject = nullptr;

        if(OriginalHandlers::gFltMgrHookBuffer)
            ExFreePool(OriginalHandlers::gFltMgrHookBuffer);
    }

    if (OriginalHandlers::gHidDriverObject) {
        OriginalHandlers::gHidDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OriginalHandlers::gOriginalHidDeviceControl;

        if (HIDMemory::gHidHookBuffer)
            ExFreePool(HIDMemory::gHidHookBuffer);

    }

    if (OriginalHandlers::gTcpDriverObject) {
        OriginalHandlers::gTcpDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OriginalHandlers::gOriginalTcpDeviceControl;
        OriginalHandlers::gTcpDriverObject = nullptr;

        if (NICMemory::gTcpHookBuffer)
            ExFreePool(NICMemory::gTcpHookBuffer);
    }

    if (OriginalHandlers::gNsiProxyDriverObject) {
        OriginalHandlers::gNsiProxyDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OriginalHandlers::gOriginalNsiProxyDeviceControl;
        ObDereferenceObject(OriginalHandlers::gNsiProxyDriverObject);
        OriginalHandlers::gNsiProxyDriverObject = nullptr;

        if (NICMemory::gNsiHookBuffer)
            ExFreePool(NICMemory::gNsiHookBuffer);

    }

    if (NICs.Length > 0) {
        for (DWORD i = 0; i < NICs.Length; ++i) {
            PDRIVER_OBJECT driver = NICs.Drivers[i].DriverObject;

            if (driver) {
                driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NICs.Drivers[i].Original;

            }

            if (NICs.Drivers[i].HookBuffer) {
                ExFreePool(NICs.Drivers[i].HookBuffer);
            }

        }
        NICs.Length = 0;
    }

    if (OriginalHandlers::gMountMgrDriverObject) {
        OriginalHandlers::gMountMgrDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OriginalHandlers::gOriginalMountMgrDeviceControl;
        ObDereferenceObject(OriginalHandlers::gMountMgrDriverObject);
        OriginalHandlers::gMountMgrDriverObject = nullptr;

        if (OriginalHandlers::gMountMgrHookBuffer)
            ExFreePool(OriginalHandlers::gMountMgrHookBuffer);

    }

    if (OriginalHandlers::gPartMgrDriverObject) {
        OriginalHandlers::gPartMgrDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OriginalHandlers::gOriginalPartMgrDeviceControl;
        ObDereferenceObject(OriginalHandlers::gPartMgrDriverObject);
        OriginalHandlers::gPartMgrDriverObject = nullptr;

        if (DiskMemory::gPartMgrHookBuffer)
            ExFreePool(DiskMemory::gPartMgrHookBuffer);

    }

    if (OriginalHandlers::gNvmeDriverObject) {
        OriginalHandlers::gNvmeDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OriginalHandlers::gOriginalNvmeDeviceControl;
        ObDereferenceObject(OriginalHandlers::gNvmeDriverObject);
        OriginalHandlers::gNvmeDriverObject = nullptr;

        if (DiskMemory::gStorNvmeHookBuffer)
            ExFreePool(DiskMemory::gStorNvmeHookBuffer);

    }

    if (OriginalHandlers::gStorahciObject) {
        OriginalHandlers::gStorahciObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OriginalHandlers::gOriginalStorahciDeviceControl;
        ObDereferenceObject(OriginalHandlers::gStorahciObject);
        OriginalHandlers::gStorahciObject = nullptr;

        if (DiskMemory::gStorahciHookBuffer)
            ExFreePool(DiskMemory::gStorahciHookBuffer);

    }

    if (g_DiskHooks.HookInfo[0].DeviceObject) {
        for (ULONG i = 0; i < g_DiskHooks.Length; ++i) {
            PDEVICE_OBJECT Device = g_DiskHooks.HookInfo[i].DeviceObject;

            Device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = g_DiskHooks.HookInfo[i].OriginalHandler;

            if (g_DiskHooks.HookInfo[i].HookBuffer) {
                ExFreePool(g_DiskHooks.HookInfo[i].HookBuffer);
            }



        }
    }

    if (Devices && DiskMemory::DiskMDL) {
        MmUnmapLockedPages(Devices, DiskMemory::DiskMDL);
        MmFreePagesFromMdl(DiskMemory::DiskMDL);
        ExFreePool(DiskMemory::DiskMDL);
    }
    
    if (g_USBHooks.Drivers->DriverObject) {
        for (DWORD i = 0; i < g_USBHooks.Length; i++) {
            auto usb = &g_USBHooks.Drivers[i];
            if (usb->DriverObject) {
                usb->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = usb->Original;
                ObDereferenceObject(usb->DriverObject);
                usb->DriverObject = nullptr;
                usb->Original = nullptr;
            }

            if (g_USBHooks.Drivers[i].HookBuffer)
                ExFreePool(g_USBHooks.Drivers[i].HookBuffer);

        }
        g_USBHooks.Length = 0;
        RtlZeroMemory(&g_USBHooks, sizeof(g_USBHooks));
    }


}


NTSTATUS MyDriverCreateClose(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(pDeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}



extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
    UNREFERENCED_PARAMETER(pRegistryPath);
    pDriverObject->DriverUnload = CleanupDriver;

    pDriverObject->MajorFunction[IRP_MJ_CREATE] = MyDriverCreateClose;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = MyDriverCreateClose;
    pDriverObject->MajorFunction[IRP_MJ_CLEANUP] = MyDriverCreateClose;


    
    if (!NT_SUCCESS(Spoofer::SpoofEverything())) {
        CleanupDriver(pDriverObject);
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}