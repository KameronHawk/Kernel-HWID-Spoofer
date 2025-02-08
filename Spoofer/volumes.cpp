#include "volumes.h"
#include <mountmgr.h>
#include <mountdev.h>
#include <ntstrsafe.h>
#include "Spoof.h"
#include <fltKernel.h>



VOLUME_SERIAL_DATA gVolumeSerials[MAX_VOLUME_SERIALS];
int gVolumeSerialCount = 0;


EXTERN_C
NTKERNELAPI
NTSTATUS
NTAPI
ZwQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);


const unsigned char JmpBuffer[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, 0xDEADBEEFBABECOF0
									0xFF, 0xE0 };												  // jmp rax


#define MAX_MOUNT_POINTS 128

static wchar_t spoofedGuids[MAX_MOUNT_POINTS][38];

EXTERN_C const char* PsGetProcessImageFileName(PEPROCESS Process);

void GenerateVolumeGUID(PWSTR buffer, size_t bufferSize, DWORD32 index) {
	static ULONG bootSeed = 0;
	static BOOLEAN initialized = FALSE;

	if (!initialized) {
		bootSeed = GetBootSeed();
		initialized = TRUE;
	}

	ULONG modifiedSeed = bootSeed + index;

	ULONG part1 = GenerateNumber(modifiedSeed);
	ULONG part2 = GenerateNumber(part1);
	ULONG part3 = GenerateNumber(part2);
	ULONG part4 = GenerateNumber(part3);
	ULONG part5 = GenerateNumber(part4);

	RtlStringCbPrintfW(buffer, bufferSize, L"{%08X-%04X-%04X-%04X-%012X}",
		part1 & 0xFFFFFFFF,           // 8 digits
		part2 & 0xFFFF,               // 4 digits
		part3 & 0xFFFF,               // 4 digits
		part4 & 0xFFFF,               // 4 digits
		part5 & 0xFFFFFFFFFFFF);      // 12 digits

	for (size_t i = 0; i < bufferSize / sizeof(wchar_t); ++i) {
		buffer[i] = towlower(buffer[i]);
	}
}

bool FindFakeVolumeGUID(wchar_t* pOriginal, DWORD32 index) {
	if (index >= MAX_MOUNT_POINTS) {
		return false;
	}

	// Ghetto way of checking if any data is inside spoofed ID based on volume index.
	if (wcslen(spoofedGuids[index]) > 0) {
		Util::WriteToReadOnly(pOriginal, spoofedGuids[index], VOLUME_GUID_MAX_LENGTH * 2);
		return true;
	}

	wchar_t newGuid[38];  
	GenerateVolumeGUID(newGuid, sizeof(newGuid), index);  

	wcscpy(spoofedGuids[index], newGuid);
	Util::WriteToReadOnly(pOriginal, newGuid, VOLUME_GUID_MAX_LENGTH * 2);
	return true;
}

ULONG generate_random_10_digit_number() {
	ULONG randomSerial = 0;

	randomSerial = (ULONG)((RtlRandomEx((PULONG)&Spoofer::Seed) % 9000000000) + 1000000000);

	return randomSerial;
}

bool FindFakeVolumeSerial(ULONG* pOriginal) {
	bool bFound = false;

	if (!MmIsAddressValid(pOriginal) || *pOriginal == 0) {
		return false;
	}

	for (int i = 0; i < gVolumeSerialCount; i++) {

		if (gVolumeSerials[i].Original == *pOriginal) {
			Util::WriteToReadOnly(pOriginal, &gVolumeSerials[i].Spoofed, sizeof(ULONG));
			bFound = true;
			break;
		}
		else if (gVolumeSerials[i].Spoofed == *pOriginal) {
			Util::WriteToReadOnly(pOriginal, &gVolumeSerials[i].Spoofed, sizeof(ULONG));
			bFound = true;
			break;
		}
	}

	if (!bFound && gVolumeSerialCount < MAX_VOLUME_SERIALS) {
		VOLUME_SERIAL_DATA data = { 0 };

		data.Original = *pOriginal;

		data.Spoofed = generate_random_10_digit_number();

		while (data.Spoofed == data.Original) {
			data.Spoofed = generate_random_10_digit_number();
		}

		gVolumeSerials[gVolumeSerialCount++] = data;

		Util::WriteToReadOnly(pOriginal, &data.Spoofed, sizeof(ULONG));
	}

	return bFound;
}

NTSTATUS MountMgrPointsCallback(PDEVICE_OBJECT DeviceObject, PIRP Irp, void* Context) {
	if (MmIsAddressValid(Context)) {
		const auto data = ioctl_helper::fetch_callback_data<MOUNTMGR_MOUNT_POINTS>(Context);
		if (data.buffer_length >= sizeof(MOUNTMGR_MOUNT_POINTS)) {
			PMOUNTMGR_MOUNT_POINTS Points = (PMOUNTMGR_MOUNT_POINTS)data.buffer;
			if (MmIsAddressValid(Points)) {
				for (DWORD32 i = 0; i < Points->NumberOfMountPoints; ++i) {
					volatile PMOUNTMGR_MOUNT_POINT Point = Points->MountPoints + i;
					if (Point->SymbolicLinkNameOffset > 0) {
						wchar_t* potentialGuid = (wchar_t*)((DWORD64)Points + Point->SymbolicLinkNameOffset);
						if (MmIsAddressValid(potentialGuid)) {
								wchar_t* guidStart = potentialGuid + 10;
								if (*guidStart == '{') {
									FindFakeVolumeGUID(guidStart, i);
								}
						}
					}
				}
			}
		}

		if (Irp->StackCount > 1 && data.old_routine) {
			return data.old_routine(DeviceObject, Irp, data.old_context);
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS MountMgrUniqueIDCallback(PDEVICE_OBJECT DeviceObject, PIRP Irp, void* Context) {
	if (MmIsAddressValid(Context)) {
		auto Data = ioctl_helper::fetch_callback_data<MOUNTDEV_UNIQUE_ID>(Context);

		if (Data.buffer_length >= sizeof(MOUNTDEV_UNIQUE_ID)) {
			PMOUNTDEV_UNIQUE_ID Point = (PMOUNTDEV_UNIQUE_ID)Data.buffer;
			if (MmIsAddressValid(Point)) {
				FindFakeVolumeGUID((wchar_t*)Point->UniqueId, 69);
			}
		}
		if (Irp->StackCount > 1 && Data.old_routine) {
			return Data.old_routine(DeviceObject, Irp, Data.old_context);
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS MountManagerHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	PIO_STACK_LOCATION irpSp;
	irpSp = IoGetCurrentIrpStackLocation(Irp);
	if (irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
		ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;

		switch (ioControlCode) {
		case IOCTL_MOUNTMGR_QUERY_POINTS:
		{
			if (Irp && Irp->AssociatedIrp.SystemBuffer)
				ioctl_helper::set_completion_callback(Irp, irpSp, MountMgrPointsCallback);
			else
				return STATUS_INVALID_PARAMETER;
			break;
		}
		case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
		{
			ioctl_helper::set_completion_callback(Irp, irpSp, MountMgrUniqueIDCallback);
			break;
		}
		default:
			break;
		}
	}
	return OriginalHandlers::gOriginalMountMgrDeviceControl(DeviceObject, Irp);
}

NTSTATUS GetProcessImageFileName2(PEPROCESS Process, WCHAR* Buffer, SIZE_T BufferSize) {
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

NTSTATUS FltMgrHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS Status;

	if (StackLocation->MajorFunction == IRP_MJ_QUERY_VOLUME_INFORMATION) {

		PFLT_PARAMETERS FltParams = (PFLT_PARAMETERS)&StackLocation->Parameters;
		FS_INFORMATION_CLASS FsInfoClass = FltParams->QueryVolumeInformation.FsInformationClass;

		Status = OriginalHandlers::gOriginalFltMgrDeviceControl(DeviceObject, Irp);

		if (!NT_SUCCESS(Status)) {
			return Status;
		}

		if (FsInfoClass == FileFsVolumeInformation) {

			PFILE_FS_VOLUME_INFORMATION VolInfo = (PFILE_FS_VOLUME_INFORMATION)Irp->AssociatedIrp.SystemBuffer;
			if (VolInfo)
				FindFakeVolumeSerial(&VolInfo->VolumeSerialNumber);
		}
	}

	return Status;
}

bool volumes::Spoof() {

	UNICODE_STRING MountMgrName;
	RtlInitUnicodeString(&MountMgrName, L"\\Driver\\mountmgr");

	NTSTATUS Status = ObReferenceObjectByName(
		&MountMgrName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID*)&OriginalHandlers::gMountMgrDriverObject
	);

	if (!NT_SUCCESS(Status)) {
		return false;
	}

	PIMAGE_SECTION_HEADER DiscardableSectionHeader = Util::GetDiscardableSectionHeader(OriginalHandlers::gMountMgrDriverObject);

	if (DiscardableSectionHeader == nullptr) {
		ObDereferenceObject(OriginalHandlers::gMountMgrDriverObject);
		OriginalHandlers::gMountMgrDriverObject = nullptr;
		return false;
	}

	const auto DiscardableSectionAddress = Util::GetDiscardableSectionAddress(OriginalHandlers::gMountMgrDriverObject, DiscardableSectionHeader);
	PTE_64* DiscardableSectionPte = Util::GetPteForAddress(DiscardableSectionAddress);

	OriginalHandlers::gMountMgrHookBuffer = ExAllocatePool(NonPagedPool, ROUND_TO_PAGES(DiscardableSectionHeader->Misc.VirtualSize));
	PTE_64* AllocatedBufferPte = Util::GetPteForAddress(OriginalHandlers::gMountMgrHookBuffer);

	if (DiscardableSectionPte == nullptr || AllocatedBufferPte == nullptr || OriginalHandlers::gMountMgrHookBuffer == nullptr) {
		if (OriginalHandlers::gMountMgrHookBuffer) {
			ExFreePool(OriginalHandlers::gMountMgrHookBuffer);
		}
		ObDereferenceObject(OriginalHandlers::gMountMgrDriverObject);
		OriginalHandlers::gMountMgrDriverObject = nullptr;
		return false;
	}

	*DiscardableSectionPte = *AllocatedBufferPte;

	if (DiscardableSectionPte->ExecuteDisable) {
		DiscardableSectionPte->ExecuteDisable = 0;
	}

	memcpy(DiscardableSectionAddress, JmpBuffer, sizeof(JmpBuffer));
	*reinterpret_cast<void**>(&reinterpret_cast<unsigned char*>(DiscardableSectionAddress)[2]) = &MountManagerHandler;

	OriginalHandlers::gOriginalMountMgrDeviceControl = OriginalHandlers::gMountMgrDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	OriginalHandlers::gMountMgrDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = reinterpret_cast<DRIVER_DISPATCH*>(DiscardableSectionAddress);

	// ---------- FLTMGR HOOK START ----------
	UNICODE_STRING FltMgrName;
	RtlInitUnicodeString(&FltMgrName, L"\\FileSystem\\FltMgr");

	Status = ObReferenceObjectByName(
		&FltMgrName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		(PVOID*)&OriginalHandlers::gFltMgrObject
	);

	if (!NT_SUCCESS(Status)) {
		return false;
	}

	PIMAGE_SECTION_HEADER FltMgrDiscardableSectionHeader = Util::GetDiscardableSectionHeader(OriginalHandlers::gFltMgrObject);

	if (FltMgrDiscardableSectionHeader == nullptr) {
		return false;
	}

	const auto FltMgrDiscardableSectionAddress = Util::GetDiscardableSectionAddress(OriginalHandlers::gFltMgrObject, FltMgrDiscardableSectionHeader);
	PTE_64* FltMgrDiscardableSectionPte = Util::GetPteForAddress(FltMgrDiscardableSectionAddress);

	OriginalHandlers::gFltMgrHookBuffer = ExAllocatePool(NonPagedPool, ROUND_TO_PAGES(FltMgrDiscardableSectionHeader->Misc.VirtualSize));
	PTE_64* FltMgrAllocatedBufferPte = Util::GetPteForAddress(OriginalHandlers::gFltMgrHookBuffer);

	if (FltMgrDiscardableSectionPte == nullptr || FltMgrAllocatedBufferPte == nullptr || OriginalHandlers::gFltMgrHookBuffer == nullptr) {
		return false;
	}

	*FltMgrDiscardableSectionPte = *FltMgrAllocatedBufferPte;

	if (FltMgrDiscardableSectionPte->ExecuteDisable) {
		FltMgrDiscardableSectionPte->ExecuteDisable = 0;
	}

	memcpy(FltMgrDiscardableSectionAddress, JmpBuffer, sizeof(JmpBuffer));
	*reinterpret_cast<void**>(&reinterpret_cast<unsigned char*>(FltMgrDiscardableSectionAddress)[2]) = &FltMgrHandler;

	OriginalHandlers::gOriginalFltMgrDeviceControl = OriginalHandlers::gFltMgrObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION];
	OriginalHandlers::gFltMgrObject->MajorFunction[IRP_MJ_QUERY_VOLUME_INFORMATION] = reinterpret_cast<DRIVER_DISPATCH*>(FltMgrDiscardableSectionAddress);



	return true;
}
