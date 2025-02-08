#pragma once
#include "nic.h"
#include "disk.h"
#include "smbios.h"
#include "volumes.h"
#include "usbserials.h"
#include <hidport.h>
#include "SkCrypt.h"


EXTERN_C
NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE AccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext OPTIONAL, PVOID* Object);
EXTERN_C
__declspec(dllimport) POBJECT_TYPE* IoDriverObjectType;





ULONG GetBootSeed();


ULONG GenerateNumber(ULONG seed);


#define MAX_HARDDRIVES 10

typedef struct _DISK_HOOK_INFO {
    PDEVICE_OBJECT DeviceObject;
    PDRIVER_DISPATCH OriginalHandler;   
    PVOID HookBuffer;
} DISK_HOOK_INFO;

typedef struct _DISK_HOOKS {
    DISK_HOOK_INFO HookInfo[MAX_HARDDRIVES];
    ULONG Length;
    ULONG Capacity;
} DISK_HOOKS;

typedef struct _USB_DRIVER {
	PDRIVER_OBJECT DriverObject;
	PDRIVER_DISPATCH Original;
    PVOID HookBuffer;
} USB_DRIVER, * PUSB_DRIVER;

typedef struct _USBS {
	DWORD Length;
	USB_DRIVER Drivers[0xFF];
}USBS, *PUSBS;

extern USBS g_USBHooks;
extern USBS g_HIDHooks;


extern DISK_HOOKS g_DiskHooks; // Global variable to store hooks




namespace Spoofer {
	NTSTATUS SpoofEverything();

    extern DWORD64 Seed;
};



namespace OriginalHandlers {

/// <summary>
/// Disk.sys Handlers for spoofing hdd
/// </summary>
extern PDRIVER_DISPATCH gOriginalDiskDeviceControl;
extern PDRIVER_OBJECT gDiskDriverObject;

/// <summary>
/// ScsiPort0.sys for spoofing SMART hdd's
/// </summary>
extern PDRIVER_DISPATCH gOriginalScsPortDeviceControl;
extern PDEVICE_OBJECT gScsPortDeviceObject;
extern PDRIVER_OBJECT gScsPortDriverObject;

/// <summary>
/// MountMgr Device for spoofing Volume ID's
/// </summary>
extern PDRIVER_DISPATCH gOriginalMountMgrDeviceControl;
extern PDRIVER_OBJECT gMountMgrDriverObject;
extern PVOID gMountMgrHookBuffer;

/// <summary>
/// PartMgr Driver for spoofing Volume ID's
/// </summary>
extern PDRIVER_DISPATCH gOriginalPartMgrDeviceControl;
extern PDRIVER_OBJECT gPartMgrDriverObject;

/// <summary>
/// Nic Driver for spoofing NIC
/// </summary>
extern PDRIVER_DISPATCH gOriginalNsiProxyDeviceControl;
extern PDRIVER_OBJECT gNsiProxyDriverObject;

/// <summary>
/// StorNvme for spoofing NVME drives
/// </summary>
extern PDRIVER_DISPATCH gOriginalNvmeDeviceControl;
extern PDRIVER_OBJECT gNvmeDriverObject;

/// <summary>
/// Storachi for misc ways to get hdd info
/// </summary>
extern PDRIVER_DISPATCH gOriginalStorahciDeviceControl;
extern PDRIVER_OBJECT gStorahciObject;

extern PDRIVER_DISPATCH gOriginalTcpDeviceControl;
extern PDRIVER_OBJECT gTcpDriverObject;

extern PDRIVER_DISPATCH gOriginalHidDeviceControl;
extern PDRIVER_OBJECT gHidDriverObject;




extern PDRIVER_DISPATCH gOriginalFltMgrDeviceControl;
extern PDRIVER_OBJECT gFltMgrObject;
extern PVOID gFltMgrHookBuffer;


};



namespace DiskMemory {
    extern PMDL DiskMDL;

    extern PVOID gPartMgrHookBuffer;

    extern PVOID gStorNvmeHookBuffer;

    extern PVOID gStorahciHookBuffer;
};


namespace NICMemory {
    extern PVOID gNsiHookBuffer;

    extern PVOID gTcpHookBuffer;


};

namespace HIDMemory {
    extern PVOID gHidHookBuffer;
};