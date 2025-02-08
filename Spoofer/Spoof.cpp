#include "Spoof.h"


DWORD64 Spoofer::Seed = 0;
DISK_HOOKS g_DiskHooks = {0};
USBS g_USBHooks = { 0 };
USBS g_HIDHooks = {0};




namespace OriginalHandlers {

    /// <summary>
    /// Disk.sys Handlers for spoofing hdd
    /// </summary>
    PDRIVER_DISPATCH OriginalHandlers::gOriginalDiskDeviceControl = nullptr;
    PDRIVER_OBJECT OriginalHandlers::gDiskDriverObject = nullptr;

    /// <summary>
    /// ScsiPort0.sys for spoofing SMART hdd's
    /// </summary>
    PDRIVER_DISPATCH OriginalHandlers::gOriginalScsPortDeviceControl = nullptr;
    PDEVICE_OBJECT OriginalHandlers::gScsPortDeviceObject = nullptr;
    PDRIVER_OBJECT OriginalHandlers::gScsPortDriverObject = nullptr;

    /// <summary>
    /// MountMgr Device for spoofing Volume ID's
    /// </summary>
    PDRIVER_DISPATCH OriginalHandlers::gOriginalMountMgrDeviceControl = nullptr;
    PDRIVER_OBJECT OriginalHandlers::gMountMgrDriverObject = nullptr;
    PVOID OriginalHandlers::gMountMgrHookBuffer = nullptr;

    /// <summary>
    /// PartMgr Driver for spoofing Volume ID's
    /// </summary>
    PDRIVER_DISPATCH OriginalHandlers::gOriginalPartMgrDeviceControl = nullptr;
    PDRIVER_OBJECT OriginalHandlers::gPartMgrDriverObject = nullptr;

    /// <summary>
    /// Nic Driver for spoofing NIC
    /// </summary>
    PDRIVER_DISPATCH OriginalHandlers::gOriginalNsiProxyDeviceControl = nullptr;
    PDRIVER_OBJECT OriginalHandlers::gNsiProxyDriverObject = nullptr;

    /// <summary>
    /// StorNvme for spoofing NVME drives
    /// </summary>
    PDRIVER_DISPATCH OriginalHandlers::gOriginalNvmeDeviceControl = nullptr;
    PDRIVER_OBJECT OriginalHandlers::gNvmeDriverObject = nullptr;

    /// <summary>
    /// Storachi for misc ways to get hdd info
    /// </summary>
    PDRIVER_DISPATCH OriginalHandlers::gOriginalStorahciDeviceControl = nullptr;
    PDRIVER_OBJECT OriginalHandlers::gStorahciObject = nullptr;

    PDRIVER_DISPATCH OriginalHandlers::gOriginalTcpDeviceControl = nullptr;
    PDRIVER_OBJECT OriginalHandlers::gTcpDriverObject = nullptr;

    PDRIVER_DISPATCH OriginalHandlers::gOriginalHidDeviceControl = nullptr;
    PDRIVER_OBJECT OriginalHandlers::gHidDriverObject = nullptr;



    PDRIVER_DISPATCH OriginalHandlers::gOriginalFltMgrDeviceControl = nullptr;
    PDRIVER_OBJECT OriginalHandlers::gFltMgrObject = nullptr;
    PVOID OriginalHandlers::gFltMgrHookBuffer = nullptr;




};

namespace DiskMemory {
    PMDL DiskMDL = nullptr;

    PVOID gPartMgrHookBuffer = nullptr;

    PVOID gStorNvmeHookBuffer = nullptr;

    PVOID gStorahciHookBuffer = nullptr;
};

namespace NICMemory {
    PVOID gNsiHookBuffer = nullptr;

    PVOID gTcpHookBuffer = nullptr;
};

namespace HIDMemory {
    PVOID gHidHookBuffer = nullptr;
};


ULONG GetBootSeed() {
    LARGE_INTEGER bootTime{};
    bootTime.QuadPart = KeQueryInterruptTime();
    return (ULONG)(bootTime.QuadPart & 0xFFFFFFFF);  
}


ULONG GenerateNumber(ULONG seed) {
    return 8253729 * seed + 2396403;  
}


NTSTATUS Spoofer::SpoofEverything() {

    if (!volumes::Spoof()) {
        return STATUS_UNSUCCESSFUL;
    }

   if (!disk::Spoof()) {
        return STATUS_UNSUCCESSFUL;
    }

   if (!nic::Spoof()) {
       return STATUS_UNSUCCESSFUL;
   }
    
   if (!usb::Spoof()) {
       return STATUS_UNSUCCESSFUL;
   }

   if (!usb::SpoofHID()) {
       return STATUS_UNSUCCESSFUL;
   }

   if (!smbios::Spoof()) {
       return STATUS_UNSUCCESSFUL;
   }

    return STATUS_SUCCESS;
}
