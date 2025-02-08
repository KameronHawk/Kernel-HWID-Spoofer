#include "disk.h"
#include <nvme.h>
#include <stddef.h>
#include <ata.h>
#include "Spoof.h"



#define NVME_STORPORT_DRIVER 0xe000
#define NVME_PASS_THROUGH_SRB_IO_CODE CTL_CODE(NVME_STORPORT_DRIVER, 0x0800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INTEL_NVME_PASS_THROUGH CTL_CODE(0xf000, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)

/// <summary>
/// Global Variables
/// </summary>
ULONG NumOfDisk = NULL;
PDEVICE_OBJECT* Devices = nullptr;



static GUID spoofedGuids[MAX_PARTITIONS] = { 0 };
static BOOLEAN guidInitialized[MAX_PARTITIONS] = { FALSE };  

struct DISK_SERIAL_DATA {
	char orig[DISK_SERIAL_MAX_LENGTH + 1];
	char spoofed[DISK_SERIAL_MAX_LENGTH + 1];
	int sz;
};
DISK_SERIAL_DATA gDiskSerials[MAX_DISK_SERIALS];

int gDiskSerialCount = 0;

#define MAX_DISK_ENTRIES 128

struct SPOOFED_DISK_DATA {
	DISK_GEOMETRY originalGeometry;
	DISK_GEOMETRY_EX originalGeometryEx;
	DISK_GEOMETRY spoofedGeometry;
	DISK_GEOMETRY_EX spoofedGeometryEx;
};

SPOOFED_DISK_DATA gSpoofedDiskEntries[MAX_DISK_ENTRIES] = { 0 };
int gSpoofedDiskEntryCount = 0;

const unsigned char JmpBuffer[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, 0xDEADBEEFBABECOF0
									0xFF, 0xE0 };


void randomize_serial(char* pStr, int sz, const char* ignore = "", int ignoreLen = 0) {
	auto is_alphanumeric = [](char c) {
		return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
		};

	char alphanumeric_chars[DISK_SERIAL_MAX_LENGTH];
	int alphanumeric_count = 0;

	for (int i = 0; i < sz; ++i) {
		if (is_alphanumeric(pStr[i])) {
			alphanumeric_chars[alphanumeric_count++] = pStr[i];
		}
	}

	static ULONG seed = GetBootSeed();
	auto getRandom = [&](int begin, int end) {
		seed = 1664525 * seed + 1013904223; 
		return begin + (seed % (end - begin + 1));
		};

	for (int i = alphanumeric_count - 1; i >= 0; --i) {
		int rndSelect = getRandom(0, i);
		char temp = alphanumeric_chars[i];
		alphanumeric_chars[i] = alphanumeric_chars[rndSelect];
		alphanumeric_chars[rndSelect] = temp;
	}

	int alphanumeric_idx = 0;
	for (int i = 0; i < sz; ++i) {
		if (is_alphanumeric(pStr[i])) {
			pStr[i] = alphanumeric_chars[alphanumeric_idx++];
		}
	}
}
bool FindFakeDiskSerial(char* pOriginal, bool bCappedString = true) {
	bool bFound = false;

	if (!MmIsAddressValid(pOriginal) || !pOriginal[0]) {
		return false;
	}

	if (pOriginal[0] == 0) {
		pOriginal++;
	}

	size_t originalLen = strlen(pOriginal);

	// Ensure length does not exceed the maximum allowed
	if (originalLen > DISK_SERIAL_MAX_LENGTH) {
		originalLen = DISK_SERIAL_MAX_LENGTH;
	}

	for (int i = 0; i < gDiskSerialCount; i++) {
		// Compare using the actual length of the serial
		if (memcmp(gDiskSerials[i].orig, pOriginal, originalLen) == 0) {
			// Found original serial match, write spoofed value
			Util::WriteToReadOnly(pOriginal, gDiskSerials[i].spoofed, originalLen);
			bFound = true;
			break;
		}
		else if (memcmp(gDiskSerials[i].spoofed, pOriginal, originalLen) == 0) {
			// Found spoofed serial match, write the same spoofed value
			Util::WriteToReadOnly(pOriginal, gDiskSerials[i].spoofed, originalLen);
			bFound = true;
			break;
		}
	}

	if (!bFound && gDiskSerialCount < MAX_DISK_SERIALS) {
		DISK_SERIAL_DATA data = { 0 };

		size_t serialLen = originalLen;

		// Copy the original serial
		RtlZeroMemory(data.orig, DISK_SERIAL_MAX_LENGTH + 1);
		RtlZeroMemory(data.spoofed, DISK_SERIAL_MAX_LENGTH + 1);
		data.sz = serialLen;

		RtlCopyMemory(data.orig, pOriginal, serialLen);
		RtlCopyMemory(data.spoofed, pOriginal, serialLen);

		// Randomize the remaining space for spoofing
		randomize_serial(data.spoofed, serialLen, (char*)" _-.", 4);

		// Store in global array
		gDiskSerials[gDiskSerialCount++] = data;

		// Write back the spoofed serial
		Util::WriteToReadOnly(pOriginal, data.spoofed, serialLen);
	}

	return bFound;
}
void GeneratePartitionGUID(GUID* pGuid, DWORD32 index) {
	static ULONG bootSeed = 0;
	static BOOLEAN seedInitialized = FALSE;

	if (!seedInitialized) {
		bootSeed = GetBootSeed();
		seedInitialized = TRUE;
	}

	ULONG seed = bootSeed + index;  // Different seed for each partition
	ULONG part1 = GenerateNumber(seed);
	ULONG part2 = GenerateNumber(part1);
	ULONG part3 = GenerateNumber(part2);
	ULONG part4 = GenerateNumber(part3);

	// Fill the GUID fields
	pGuid->Data1 = part1;
	pGuid->Data2 = (USHORT)(part2 & 0xFFFF);
	pGuid->Data3 = (USHORT)(part3 & 0xFFFF);

	for (int i = 0; i < 8; ++i) {
		pGuid->Data4[i] = (UCHAR)((part4 >> (i * 8)) & 0xFF);
	}
}
void GetSpoofedPartitionGUID(DWORD32 index, GUID* pGuid) {
	if (index < MAX_PARTITIONS) {
		if (!guidInitialized[index]) {
			GeneratePartitionGUID(&spoofedGuids[index], index);
			guidInitialized[index] = TRUE;
		}
		RtlCopyMemory(pGuid, &spoofedGuids[index], sizeof(GUID));
	}
}

void randomize_cylinders(LARGE_INTEGER* cylinders) {
	static ULONG seed = GetBootSeed();

	// Helper to generate believable random values
	auto getRandom = [&](int min, int max) {
		seed = 1664525 * seed + 1013904223; // Linear Congruential Generator (LCG)
		return min + (seed % (max - min + 1));
		};

	// Generate a random value for cylinders (e.g., between 10,000 and 1,000,000)
	cylinders->QuadPart = getRandom(10000, 1000000);
}

LARGE_INTEGER FindOrGenerateCylinders(LARGE_INTEGER originalCylinders) {
	for (int i = 0; i < gSpoofedDiskEntryCount; i++) {
		if (gSpoofedDiskEntries[i].originalGeometry.Cylinders.QuadPart == originalCylinders.QuadPart) {
			return gSpoofedDiskEntries[i].spoofedGeometry.Cylinders;
		}
	}

	// Generate new random cylinder value
	LARGE_INTEGER spoofedCylinders;
	randomize_cylinders(&spoofedCylinders);
	return spoofedCylinders;
}

LARGE_INTEGER GenerateRandomDiskSize() {
	LARGE_INTEGER size;
	ULONG seed = GetBootSeed(); // Random seed logic
	auto getRandom = [&](int begin, int end) {
		seed = 1664525 * seed + 1013904223; // Linear Congruential Generator (LCG)
		return begin + (seed % (end - begin + 1));
		};
	// Random size between 500GB and 1TB
	size.QuadPart = getRandom(500LL * 1024 * 1024 * 1024, 1024LL * 1024 * 1024 * 1024);
	return size;
}

bool FindOrSpoofDiskGeometry(PDISK_GEOMETRY pGeometry) {
	if (!MmIsAddressValid(pGeometry)) {
		return false;
	}

	// Check existing spoofed entries
	for (int i = 0; i < gSpoofedDiskEntryCount; i++) {
		if (RtlCompareMemory(&gSpoofedDiskEntries[i].originalGeometry, pGeometry, sizeof(DISK_GEOMETRY)) == sizeof(DISK_GEOMETRY)) {
			// Found match, apply spoofed data
			RtlCopyMemory(pGeometry, &gSpoofedDiskEntries[i].spoofedGeometry, sizeof(DISK_GEOMETRY));
			return true;
		}
	}

	if (gSpoofedDiskEntryCount < MAX_DISK_ENTRIES) {
		// Create a new spoofed entry
		SPOOFED_DISK_DATA newEntry = { 0 };
		RtlCopyMemory(&newEntry.originalGeometry, pGeometry, sizeof(DISK_GEOMETRY));
		RtlCopyMemory(&newEntry.spoofedGeometry, pGeometry, sizeof(DISK_GEOMETRY));

		// Spoof cylinder values
		newEntry.spoofedGeometry.Cylinders = FindOrGenerateCylinders(pGeometry->Cylinders);

		gSpoofedDiskEntries[gSpoofedDiskEntryCount++] = newEntry;
		RtlCopyMemory(pGeometry, &newEntry.spoofedGeometry, sizeof(DISK_GEOMETRY));
		return true;
	}

	return false;
}


void FindOrSpoofDiskGeometryEx(PDISK_GEOMETRY_EX pGeometryEx) {
	if (!MmIsAddressValid(pGeometryEx)) {
		return;
	}

	for (int i = 0; i < gSpoofedDiskEntryCount; i++) {
		if (memcmp(&gSpoofedDiskEntries[i].originalGeometryEx.Geometry, &pGeometryEx->Geometry, sizeof(DISK_GEOMETRY)) == 0) {
			RtlCopyMemory(pGeometryEx, &gSpoofedDiskEntries[i].spoofedGeometryEx, sizeof(DISK_GEOMETRY_EX));
			return;
		}
	}

	if (gSpoofedDiskEntryCount < MAX_DISK_ENTRIES) {
		SPOOFED_DISK_DATA newEntry = { 0 };
		RtlCopyMemory(&newEntry.originalGeometryEx, pGeometryEx, sizeof(DISK_GEOMETRY_EX));
		RtlCopyMemory(&newEntry.spoofedGeometryEx, pGeometryEx, sizeof(DISK_GEOMETRY_EX));

		newEntry.spoofedGeometryEx.DiskSize = GenerateRandomDiskSize();
		newEntry.spoofedGeometryEx.Geometry.Cylinders = FindOrGenerateCylinders(pGeometryEx->Geometry.Cylinders);

		newEntry.spoofedGeometryEx.Geometry.Cylinders.QuadPart = newEntry.spoofedGeometryEx.DiskSize.QuadPart /
			(pGeometryEx->Geometry.TracksPerCylinder *
				pGeometryEx->Geometry.SectorsPerTrack *
				pGeometryEx->Geometry.BytesPerSector);

		gSpoofedDiskEntries[gSpoofedDiskEntryCount++] = newEntry;
		RtlCopyMemory(pGeometryEx, &newEntry.spoofedGeometryEx, sizeof(DISK_GEOMETRY_EX));
	}
}



NTSTATUS NvmePassthroughHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (MmIsAddressValid(Context)) {
		auto data = ioctl_helper::fetch_callback_data<INTEL_NVME_PASS_THROUGH>(Context);

		if (MmIsAddressValid(data.buffer) && !Util::IsNtosKrnlAddress((DWORD64)data.buffer)) {
			NVME_IDENTIFY_DEVICE* nvmeID = (NVME_IDENTIFY_DEVICE*)data.buffer->DataBuffer;

			char serialNBuff[21] = { 0 };
			RtlCopyMemory(serialNBuff, nvmeID->SerialNumber, 20);
			FindFakeDiskSerial(serialNBuff);
			RtlCopyMemory(nvmeID->SerialNumber, serialNBuff, 20);
		}


		if (data.old_routine && Irp->StackCount > 1) {
			return data.old_routine(pDeviceObject, Irp, data.old_context);
		}


	}
	return STATUS_SUCCESS;
}

NTSTATUS ScsiMiniportIdentifyHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (MmIsAddressValid(Context)) {
		auto data = ioctl_helper::fetch_callback_data<SENDCMDOUTPARAMS>(Context);

		if (MmIsAddressValid(data.buffer) && !Util::IsNtosKrnlAddress((DWORD64)data.buffer)) {
			const auto params = reinterpret_cast<SENDCMDOUTPARAMS*>(data.buffer->bBuffer + sizeof(SRB_IO_CONTROL));
			if (!MmIsAddressValid(params)) {
				goto _end;
			}
			const auto info = reinterpret_cast<IDINFO*>(params->bBuffer);
			if (!MmIsAddressValid(info)) {
				goto _end;
			}

			auto serial = reinterpret_cast<char*>(info->sSerialNumber);
			if (!MmIsAddressValid(serial)) {
				goto _end;
			}
			FindFakeDiskSerial(serial);
		}

	_end:
		if (data.old_routine && Irp->StackCount > 1) {
			return data.old_routine(pDeviceObject, Irp, data.old_context);
		}
	}

	return STATUS_SUCCESS;
}

// Good
NTSTATUS ScsiMiniportIdentifyThroughExHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (MmIsAddressValid(Context)) {
		auto data = ioctl_helper::fetch_callback_data<SCSI_PASS_THROUGH_EX>(Context);
		if (MmIsAddressValid(data.buffer)) {

			UCHAR* dataBufferAddress = (UCHAR*)data.buffer->DataInBufferOffset + (ULONG_PTR)data.buffer;

			if (MmIsAddressValid(dataBufferAddress) && !Util::IsNtosKrnlAddress((DWORD64)dataBufferAddress)) {
				NVME_IDENTIFY_DEVICE* nvmeIdentify = (NVME_IDENTIFY_DEVICE*)dataBufferAddress;
				if (MmIsAddressValid(nvmeIdentify)) {
					FindFakeDiskSerial(nvmeIdentify->SerialNumber);
				}
			}
		}
	_end:
		if (data.old_routine && Irp->StackCount > 1) {
			data.old_routine(pDeviceObject, Irp, data.old_context);
		}
		
	}
	return STATUS_SUCCESS;
}

//good
NTSTATUS ScsiMiniportIdentifyThroughDirectExHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (MmIsAddressValid(Context)) {
		auto data = ioctl_helper::fetch_callback_data<SCSI_PASS_THROUGH_DIRECT_EX>(Context);
		if (MmIsAddressValid(data.buffer)) {

			UCHAR* dataBufferAddress = (UCHAR*)data.buffer->DataInBuffer;

			if (MmIsAddressValid(dataBufferAddress) && !Util::IsNtosKrnlAddress((DWORD64)dataBufferAddress)) {
				NVME_IDENTIFY_DEVICE* nvmeIdentify = (NVME_IDENTIFY_DEVICE*)dataBufferAddress;

				if (MmIsAddressValid(nvmeIdentify)) {
					FindFakeDiskSerial(nvmeIdentify->SerialNumber);
				}
			}
		}

		if (data.old_routine && Irp->StackCount > 1) {
			return data.old_routine(pDeviceObject, Irp, data.old_context);
		}
	}

	return STATUS_SUCCESS;
}

//Good
NTSTATUS ScsiMiniportIdentifyThroughHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (MmIsAddressValid(Context)) {
		auto data = ioctl_helper::fetch_callback_data<SCSI_PASS_THROUGH_WITH_BUFFERS>(Context);

		PSCSI_PASS_THROUGH_WITH_BUFFERS ptwb = (PSCSI_PASS_THROUGH_WITH_BUFFERS)data.buffer;

		if (MmIsAddressValid(ptwb)) {
			
			UCHAR* dataBufferAddress = (UCHAR*)ptwb + ptwb->Spt.DataBufferOffset;

			if (MmIsAddressValid(dataBufferAddress) && !Util::IsNtosKrnlAddress((DWORD64)dataBufferAddress)) {

				NVME_IDENTIFY_DEVICE* nvmeIdentify = (NVME_IDENTIFY_DEVICE*)dataBufferAddress;

				if (MmIsAddressValid(nvmeIdentify)) {
					FindFakeDiskSerial(nvmeIdentify->SerialNumber);
				}
			}
		}

		if (data.old_routine && Irp->StackCount > 1) {
			return data.old_routine(pDeviceObject, Irp, data.old_context);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS SendIoctl(PDEVICE_OBJECT pDeviceObj, DWORD64 dwIoctlCode, PVOID pInBuf, ULONG ulInBufLen, PVOID pOutBuffer, ULONG ulOutBufLen) {
	IO_STATUS_BLOCK StatusBlock;
	PIRP Irp;
	KEVENT Event;

	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	Irp = IoBuildDeviceIoControlRequest(
		(ULONG)dwIoctlCode,
		pDeviceObj,
		pInBuf,
		ulInBufLen,
		pOutBuffer,
		ulOutBufLen,
		FALSE,
		&Event,
		&StatusBlock
	);

	if (!Irp)
		return STATUS_UNSUCCESSFUL;

	NTSTATUS ntStatus = IoCallDriver(pDeviceObj, Irp);

	if (ntStatus == STATUS_PENDING)
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, 0);

	ObDereferenceObject(pDeviceObj);

	return ntStatus;
}

BOOLEAN disk::PrintAndSaveSerialATA(PDEVICE_OBJECT pDevice) {
	if (!pDevice)
		return FALSE;

	BOOLEAN bRes = FALSE;
	ULONG aptelen;
	ATA_PASS_THROUGH_EX* apte;
	NTSTATUS Status;
	IDENTIFY_DEVICE_DATA* idd;

	aptelen = sizeof(ATA_PASS_THROUGH_EX) + 512;

	// Allocate memory from the system pool instead of using kmalloc
	apte = (ATA_PASS_THROUGH_EX*)ExAllocatePoolWithTag(NonPagedPool, aptelen, 'AtAp'); // 'AtAp' is a tag for your pool allocation
	if (apte == NULL) {
		return FALSE;
	}

	RtlZeroMemory(apte, aptelen);
	apte->Length = sizeof(ATA_PASS_THROUGH_EX);
	apte->AtaFlags = ATA_FLAGS_DATA_IN;
	apte->DataTransferLength = aptelen - sizeof(ATA_PASS_THROUGH_EX);
	apte->TimeOutValue = 3;
	apte->DataBufferOffset = apte->Length;
	apte->CurrentTaskFile[6] = IDE_COMMAND_IDENTIFY;

	// Send the IOCTL to the device
	Status = SendIoctl(pDevice, IOCTL_ATA_PASS_THROUGH, apte, aptelen, apte, aptelen);

	if (NT_SUCCESS(Status)) {
		idd = (IDENTIFY_DEVICE_DATA*)((char*)apte + sizeof(ATA_PASS_THROUGH_EX));

		bRes = TRUE;
	}

	ExFreePoolWithTag(apte, 'AtAp');
	STATUS_SUCCESS;
	return bRes;
}


NTSTATUS AtaPassDirectHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (MmIsAddressValid(Context)) {
		auto data = ioctl_helper::fetch_callback_data<ATA_PASS_THROUGH_DIRECT>(Context);

		if (data.buffer_length >= (sizeof(ATA_PASS_THROUGH_DIRECT) + sizeof(IDENTIFY_DEVICE_DATA))) {
			PATA_PASS_THROUGH_DIRECT PassThrough = (PATA_PASS_THROUGH_DIRECT)data.buffer;
			if(MmIsAddressValid(PassThrough) && !Util::IsNtosKrnlAddress((DWORD64)PassThrough)){
				PIDENTIFY_DEVICE_DATA pDeviceData = (PIDENTIFY_DEVICE_DATA)PassThrough->DataBuffer;
				PCHAR Serial = (PCHAR)pDeviceData->SerialNumber;
				FindFakeDiskSerial(Serial);
				char serialBuff[31] = { 0 };
				memcpy(serialBuff, pDeviceData->CurrentMediaSerialNumber, 30);
				FindFakeDiskSerial(serialBuff);
				memcpy(pDeviceData->CurrentMediaSerialNumber, serialBuff, 30);
				//WWN* pWorldWideName = (WWN*)&pDeviceData->WorldWideName;
			}
		}

		if (data.old_routine && Irp->StackCount > 1) {
			return data.old_routine(pDeviceObject, Irp, data.old_context);
		}

	}
	return STATUS_SUCCESS;
}

NTSTATUS AtaPassHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (MmIsAddressValid(Context)) {
		auto data = ioctl_helper::fetch_callback_data<ATA_PASS_THROUGH_EX>(Context);

		if (!MmIsAddressValid(data.buffer)) {
			goto _end;
		}
		if (data.buffer_length == (sizeof(ATA_PASS_THROUGH_EX) + sizeof(PIDENTIFY_DEVICE_DATA))) {
			PATA_PASS_THROUGH_EX pte = (PATA_PASS_THROUGH_EX)data.buffer;

			ULONG offset = (ULONG)pte->DataBufferOffset;
			if (MmIsAddressValid(pte) && offset && offset < data.buffer_length && !Util::IsNtosKrnlAddress((DWORD64)pte)) {
				PIDENTIFY_DEVICE_DATA pDeviceData = ((PIDENTIFY_DEVICE_DATA)((PBYTE)data.buffer + offset));
				PCHAR serial = (PCHAR)pDeviceData->SerialNumber;
				FindFakeDiskSerial(serial);


				char serialBuff[31] = { 0 };
				memcpy(serialBuff, pDeviceData->CurrentMediaSerialNumber, 30);
				FindFakeDiskSerial(serialBuff);
				memcpy(pDeviceData->CurrentMediaSerialNumber, serialBuff, 30);
			}
		}
		else if((offsetof(ATA_PASS_THROUGH_EX_WITH_BUFFERS, ucDataBuf) + SMART_LOG_SECTOR_SIZE) == data.buffer_length && !Util::IsNtosKrnlAddress((DWORD64)data.buffer)) {
			ATA_PASS_THROUGH_EX_WITH_BUFFERS* ab = (ATA_PASS_THROUGH_EX_WITH_BUFFERS*)data.buffer;
			if (ab->apt.AtaFlags == ATA_FLAGS_DATA_IN && ab->apt.DataTransferLength == SMART_LOG_SECTOR_SIZE) {
				ata_identify_device* aid = (ata_identify_device*)((DWORD64)data.buffer + ab->apt.DataBufferOffset);
				FindFakeDiskSerial((char*)aid->serial_no);
			}
		}



	_end:
		if (data.old_routine && Irp->StackCount > 1) {
			return data.old_routine(pDeviceObject, Irp, data.old_context);
		}
	}



	return STATUS_SUCCESS;
}

NTSTATUS SmartDataHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (MmIsAddressValid(Context)) {

		if (Context == nullptr)
		{

			return STATUS_SUCCESS;
		}

		const auto data = ioctl_helper::fetch_callback_data<SENDCMDOUTPARAMS>(Context);
		if (data.buffer_length >= sizeof(SENDCMDOUTPARAMS) && !Util::IsNtosKrnlAddress((DWORD64)data.buffer)) {
			PCHAR serial = ((PIDINFO)((PSENDCMDOUTPARAMS)data.buffer)->bBuffer)->sSerialNumber;
			FindFakeDiskSerial(serial);
		}
	_end:
		if (data.old_routine && Irp->StackCount > 1) {
			return data.old_routine(pDeviceObject, Irp, data.old_context);
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS ScsiMiniportIdentifyThroughDirectHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (MmIsAddressValid(Context)) {
		auto data = ioctl_helper::fetch_callback_data<SCSI_PASS_THROUGH_DIRECT>(Context);

		PSCSI_PASS_THROUGH_DIRECT sptd = (PSCSI_PASS_THROUGH_DIRECT)data.buffer;

		if (MmIsAddressValid(sptd)) {

			UCHAR* dataBufferAddress = (UCHAR*)sptd->DataBuffer;

			if (MmIsAddressValid(dataBufferAddress) && !Util::IsNtosKrnlAddress((DWORD64)dataBufferAddress)) {

				NVME_IDENTIFY_DEVICE* nvmeIdentify = (NVME_IDENTIFY_DEVICE*)dataBufferAddress;

				if (MmIsAddressValid(nvmeIdentify)) {
					FindFakeDiskSerial(nvmeIdentify->SerialNumber);
				}
			}
		}

		if (data.old_routine && Irp->StackCount > 1) {
			return data.old_routine(pDeviceObject, Irp, data.old_context);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS StorageQueryNameHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (MmIsAddressValid(Context)) {
		auto data = ioctl_helper::fetch_callback_data<STORAGE_DEVICE_DESCRIPTOR>(Context);

		if (data.buffer_length < FIELD_OFFSET(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties)) {
			return STATUS_INVALID_PARAMETER;
		}

		if (data.buffer->SerialNumberOffset < FIELD_OFFSET(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties)) {
			return STATUS_INVALID_PARAMETER;
		}

		if (data.buffer_length < FIELD_OFFSET(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties) + data.buffer->RawPropertiesLength ||
			data.buffer->SerialNumberOffset >= data.buffer_length) {
			return STATUS_INVALID_PARAMETER;
		}

		auto protocolDataDescr = reinterpret_cast<PSTORAGE_PROTOCOL_DATA_DESCRIPTOR>(Irp->AssociatedIrp.SystemBuffer);
		if (!protocolDataDescr) {
			return STATUS_INVALID_PARAMETER;
		}

		auto protocolData = &protocolDataDescr->ProtocolSpecificData;

		if (protocolData->ProtocolType == ProtocolTypeNvme && !Util::IsNtosKrnlAddress((DWORD64)protocolDataDescr)) {
			if (protocolData->DataType == NVMeDataTypeIdentify) {
				PNVME_IDENTIFY_CONTROLLER_DATA identifyControllerData =
					(PNVME_IDENTIFY_CONTROLLER_DATA)((PCHAR)protocolData + protocolData->ProtocolDataOffset);

				FindFakeDiskSerial((char*)identifyControllerData->SN);
				//FindFakeDiskIEEE((char*)ieee);
			}
		}
		else {
			// This will be the case when it's not NVMe, but still a storage device
			if (protocolData->ProtocolType != ProtocolTypeNvme || protocolData->DataType != NVMeDataTypeIdentify && !Util::IsNtosKrnlAddress((DWORD64)protocolData)) {
				if (data.buffer_length < FIELD_OFFSET(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties))
				{
					return STATUS_NOT_IMPLEMENTED;
				}
				else if (data.buffer->SerialNumberOffset < FIELD_OFFSET(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties))
				{
					return STATUS_NOT_IMPLEMENTED;
				}
				else if (data.buffer_length < FIELD_OFFSET(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties) + data.buffer->RawPropertiesLength || data.buffer->SerialNumberOffset >= data.buffer_length)
				{
					return STATUS_NOT_IMPLEMENTED;
				}
				else
				{
					auto serial = reinterpret_cast<unsigned char*>(data.buffer) + data.buffer->SerialNumberOffset;

					FindFakeDiskSerial((char*)serial);

				}
			}
		}
	_end:
		if (data.old_routine && Irp->StackCount > 1) {
			return data.old_routine(pDeviceObject, Irp, data.old_context);
		}
	}



	return STATUS_SUCCESS;
}

NTSTATUS StorageQueryPropertyHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (MmIsAddressValid(Context)) {
		auto data = ioctl_helper::fetch_callback_data<PSTORAGE_PROTOCOL_DATA_DESCRIPTOR>(Context);

		PSTORAGE_PROTOCOL_DATA_DESCRIPTOR DataDesc = (PSTORAGE_PROTOCOL_DATA_DESCRIPTOR)data.buffer;

		if (MmIsAddressValid(Context) && data.buffer_length >= sizeof(PSTORAGE_PROTOCOL_DATA_DESCRIPTOR) && !Util::IsNtosKrnlAddress((DWORD64)DataDesc)) {
			DWORD64 DataOffset = DataDesc->ProtocolSpecificData.ProtocolDataOffset;
			DWORD64 DataLength = DataDesc->ProtocolSpecificData.ProtocolDataLength;

			char* SerialNumber = (char*)((DWORD64)DataDesc + DataOffset);

			if (DataDesc->ProtocolSpecificData.ProtocolType != ProtocolTypeNvme || DataDesc->ProtocolSpecificData.ProtocolType != NVMeDataTypeIdentify) {
				if (data.old_routine && Irp->StackCount > 1) {
					data.old_routine(pDeviceObject, Irp, Context);
				}
			}
			if (SerialNumber[12]) {
				FindFakeDiskSerial(SerialNumber + 12);
			}
		}


		if (data.old_routine && Irp->StackCount > 1) {
			return data.old_routine(pDeviceObject, Irp, data.old_context);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS DiskGeoHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (!MmIsAddressValid(Context)) {
		return STATUS_INVALID_PARAMETER;
	}

	auto data = ioctl_helper::fetch_callback_data<DISK_GEOMETRY>(Context);

	if (MmIsAddressValid(data.buffer) && !Util::IsNtosKrnlAddress((DWORD64)data.buffer)) {
		PDISK_GEOMETRY pGeometry = (PDISK_GEOMETRY)data.buffer;
		if (MmIsAddressValid(pGeometry)) {
			FindOrSpoofDiskGeometry(pGeometry);
		}
	}

	if (data.old_routine && Irp->StackCount > 1) {
		return data.old_routine(pDeviceObject, Irp, data.old_context);
	}

	return STATUS_SUCCESS;
}

NTSTATUS DiskGeoExHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (!MmIsAddressValid(Context)) {
		return STATUS_INVALID_PARAMETER;
	}

	auto data = ioctl_helper::fetch_callback_data<DISK_GEOMETRY_EX>(Context);

	if (MmIsAddressValid(data.buffer) && !Util::IsNtosKrnlAddress((DWORD64)data.buffer)) {
		PDISK_GEOMETRY_EX pGeometry = (PDISK_GEOMETRY_EX)data.buffer;
		if (MmIsAddressValid(pGeometry)) {
			FindOrSpoofDiskGeometry(&pGeometry->Geometry);
		}
	}

	if (data.old_routine && Irp->StackCount > 1) {
		return data.old_routine(pDeviceObject, Irp, data.old_context);
	}

	return STATUS_SUCCESS;
}


NTSTATUS MasterDiskControl(PDRIVER_DISPATCH pOriginal, PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	if (Irp->CurrentLocation <= 1)
		return STATUS_STACK_OVERFLOW;

	if (pOriginal == nullptr|| !MmIsAddressValid(pOriginal))
		return STATUS_NOT_IMPLEMENTED;

	if(!MmIsAddressValid(Irp))
		return pOriginal(pDeviceObject, Irp);


	PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(Irp);


	if(!MmIsAddressValid(StackLocation))
		return pOriginal(pDeviceObject, Irp);

	switch (StackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_ATA_PASS_THROUGH_DIRECT: {
		ioctl_helper::set_completion_callback(Irp, StackLocation, AtaPassDirectHandler);
		break;
	}
	case IOCTL_ATA_PASS_THROUGH: { // Good
		ioctl_helper::set_completion_callback(Irp, StackLocation, AtaPassHandler);
		break;
	}
	case IOCTL_STORAGE_QUERY_PROPERTY: {  // Good
		auto* pQuery = reinterpret_cast<PSTORAGE_PROPERTY_QUERY>(Irp->AssociatedIrp.SystemBuffer);


		if (MmIsAddressValid(pQuery)) {
			if (pQuery->PropertyId == StorageDeviceProperty ||
				pQuery->PropertyId == StorageAdapterProtocolSpecificProperty ||
				pQuery->PropertyId == StorageDeviceProtocolSpecificProperty) {


				if (pQuery->QueryType == PropertyStandardQuery) {
					ioctl_helper::set_completion_callback(Irp, StackLocation, StorageQueryNameHandler);
				}
				else {
					ioctl_helper::set_completion_callback(Irp, StackLocation, StorageQueryPropertyHandler);
				}
			}
		}

		break;
	}
	case IOCTL_STORAGE_PROTOCOL_COMMAND: {
		break;
	}
	case SMART_RCV_DRIVE_DATA: {
		ioctl_helper::set_completion_callback(Irp, StackLocation, SmartDataHandler);
		break;
	}
	case IOCTL_SCSI_PASS_THROUGH_DIRECT: {
		ioctl_helper::set_completion_callback(Irp, StackLocation, ScsiMiniportIdentifyThroughDirectHandler);
		break;
	}
	case IOCTL_SCSI_PASS_THROUGH: {
		ioctl_helper::set_completion_callback(Irp, StackLocation, ScsiMiniportIdentifyThroughHandler);
		break;
	}
	case IOCTL_SCSI_PASS_THROUGH_DIRECT_EX: {
		ioctl_helper::set_completion_callback(Irp, StackLocation, ScsiMiniportIdentifyThroughDirectExHandler);
		break;
	}
	case IOCTL_SCSI_PASS_THROUGH_EX: {
		ioctl_helper::set_completion_callback(Irp, StackLocation, ScsiMiniportIdentifyThroughExHandler);
		break;
	}
	/*case IOCTL_IDE_PASS_THROUGH: {
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
		IofCompleteRequest(Irp, 0);
		return STATUS_NOT_SUPPORTED;
		break;
	}*/
	case IOCTL_SCSI_MINIPORT: {
		PSRB_IO_CONTROL MiniPortQuery = (PSRB_IO_CONTROL)(Irp->AssociatedIrp.SystemBuffer);

		if (MmIsAddressValid(MiniPortQuery)) {
			switch (MiniPortQuery->ControlCode)
			{
			case IOCTL_SCSI_MINIPORT_IDENTIFY: { // check this
				ioctl_helper::set_completion_callback(Irp, StackLocation, ScsiMiniportIdentifyHandler);
				break;
			}
			case IOCTL_INTEL_NVME_PASS_THROUGH: { // check this
				ioctl_helper::set_completion_callback(Irp, StackLocation, NvmePassthroughHandler);
				break;
			}
			/*case NVME_PASS_THROUGH_SRB_IO_CODE: { // check this
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
				IofCompleteRequest(Irp, 0);
				return STATUS_NOT_SUPPORTED;
			}*/
			default:
				break;
			}
		}

		break;
	}
	case IOCTL_DISK_GET_DRIVE_GEOMETRY: {
		ioctl_helper::set_completion_callback(Irp, StackLocation, DiskGeoHandler);
		break;
	}
	case IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: {
		ioctl_helper::set_completion_callback(Irp, StackLocation, DiskGeoExHandler);
		break;
	}

	default:
		break;
	}
	return pOriginal(pDeviceObject, Irp);
}

NTSTATUS NvmeStorHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	return MasterDiskControl(OriginalHandlers::gOriginalNvmeDeviceControl, pDeviceObject, Irp);
}

NTSTATUS StorahciHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	return MasterDiskControl(OriginalHandlers::gOriginalStorahciDeviceControl, pDeviceObject, Irp);
}

NTSTATUS DiskControl(PDEVICE_OBJECT pDeviceObject, PIRP Irp) {
	for (ULONG i = 0; i < g_DiskHooks.Length; i++) {
		DISK_HOOK_INFO HookInfo = g_DiskHooks.HookInfo[i];

		if (HookInfo.DeviceObject == pDeviceObject) {
			return MasterDiskControl(HookInfo.OriginalHandler, pDeviceObject, Irp);
		}
	}
	return STATUS_NOT_SUPPORTED;
}




bool DisableFailurePrediction() {
	NTSTATUS Status;
	ULONG success = 0, total = 0;

	for (ULONG i = 0; i < NumOfDisk; ++i) {
		PDEVICE_OBJECT Device = Devices[i];
		if (!Device) {
			continue;
		}
	
		if (g_DiskHooks.Length >= MAX_HARDDRIVES) {
			continue;
		}

		Status = SendIoctl(Device, IOCTL_DISK_UPDATE_PROPERTIES, nullptr, 0, nullptr, 0);
		if (!NT_SUCCESS(Status)) {
			continue;
		}
		
		PIMAGE_SECTION_HEADER DiscardableSectionHeader = Util::GetDiscardableSectionHeader(Device->DriverObject);

		if (DiscardableSectionHeader == nullptr) {
			ObDereferenceObject(Device->DriverObject);
			Device->DriverObject = nullptr;
			return false;
		}
		
		const auto DiscardableSectionAddress = Util::GetDiscardableSectionAddress(Device->DriverObject, DiscardableSectionHeader);
		PTE_64* DiscardableSectionPte = Util::GetPteForAddress(DiscardableSectionAddress);

		g_DiskHooks.HookInfo[g_DiskHooks.Length].HookBuffer = ExAllocatePool(NonPagedPool, ROUND_TO_PAGES(DiscardableSectionHeader->Misc.VirtualSize));
		PTE_64* AllocatedBufferPte = Util::GetPteForAddress(g_DiskHooks.HookInfo[g_DiskHooks.Length].HookBuffer);

		if (DiscardableSectionPte == nullptr || AllocatedBufferPte == nullptr || g_DiskHooks.HookInfo[g_DiskHooks.Length].HookBuffer == nullptr) {
			if (g_DiskHooks.HookInfo[g_DiskHooks.Length].HookBuffer) {
				ExFreePool(g_DiskHooks.HookInfo[g_DiskHooks.Length].HookBuffer);
			}
			ObDereferenceObject(Device->DriverObject);
			Device->DriverObject = nullptr;
			return false;
		}

		*DiscardableSectionPte = *AllocatedBufferPte;

		if (DiscardableSectionPte->ExecuteDisable) {
			DiscardableSectionPte->ExecuteDisable = 0;
		}

		memcpy(DiscardableSectionAddress, JmpBuffer, sizeof(JmpBuffer));
		*reinterpret_cast<void**>(&reinterpret_cast<unsigned char*>(DiscardableSectionAddress)[2]) = &DiskControl;

		g_DiskHooks.HookInfo[g_DiskHooks.Length].DeviceObject = Device;

		g_DiskHooks.HookInfo[g_DiskHooks.Length].OriginalHandler = Device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
		Device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = reinterpret_cast<DRIVER_DISPATCH*>(DiscardableSectionAddress);
		g_DiskHooks.Length++;

	}

	return true;
}


/// <summary>
/// Part Manager Spoofing
/// </summary>
/// <param name="pDeviceObject"></param>
/// <param name="Irp"></param>
/// <param name="Context"></param>
/// <returns></returns>

NTSTATUS PartInfoHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (MmIsAddressValid(Context)) {
		auto data = ioctl_helper::fetch_callback_data<PARTITION_INFORMATION_EX>(Context);

		if (data.buffer_length >= sizeof(PARTITION_INFORMATION_EX)) {
			PPARTITION_INFORMATION_EX PartitionInfo = (PPARTITION_INFORMATION_EX)data.buffer;

			if (MmIsAddressValid(PartitionInfo) && PartitionInfo->PartitionStyle == PARTITION_STYLE_GPT && !Util::IsNtosKrnlAddress((DWORD64)PartitionInfo)) {
				GUID spoofedGuid;
				GetSpoofedPartitionGUID(PartitionInfo->PartitionNumber, &spoofedGuid);
				if (Util::IsNtosKrnlAddress((DWORD64)&PartitionInfo->Gpt.PartitionId) == false) {
					Util::WriteToReadOnly(&PartitionInfo->Gpt.PartitionId, &spoofedGuid, sizeof(spoofedGuid));
				}
			}
		}

		if (data.old_routine && Irp->StackCount > 1) {
			return data.old_routine(pDeviceObject, Irp, data.old_context);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS PartLayoutHandler(PDEVICE_OBJECT pDeviceObject, PIRP Irp, PVOID Context) {
	if (MmIsAddressValid(Context)) {
		auto data = ioctl_helper::fetch_callback_data<DRIVE_LAYOUT_INFORMATION_EX>(Context);
		if (data.buffer_length >= sizeof(DRIVE_LAYOUT_INFORMATION_EX)) {
			PDRIVE_LAYOUT_INFORMATION_EX DriveLayoutInfo = (PDRIVE_LAYOUT_INFORMATION_EX)data.buffer;
			if (MmIsAddressValid(DriveLayoutInfo) && DriveLayoutInfo->PartitionStyle == PARTITION_STYLE_GPT && !Util::IsNtosKrnlAddress((DWORD64)DriveLayoutInfo)) {
				for (ULONG i = 0; i < DriveLayoutInfo->PartitionCount; i++) {
					if (DriveLayoutInfo->PartitionEntry[i].PartitionStyle == PARTITION_STYLE_GPT) {
						GUID spoofedGuid;
						GetSpoofedPartitionGUID(DriveLayoutInfo->PartitionEntry[i].PartitionNumber, &spoofedGuid);
						if (Util::IsNtosKrnlAddress((DWORD64)&DriveLayoutInfo->PartitionEntry[i].Gpt.PartitionId) == FALSE) {
							Util::WriteToReadOnly(&DriveLayoutInfo->PartitionEntry[i].Gpt.PartitionId, &spoofedGuid, sizeof(spoofedGuid));
						}
					}
				}
			}
			if (data.old_routine && Irp->StackCount > 1) {

				return data.old_routine(pDeviceObject, Irp, data.old_context);
			}
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS PartmgrHandler(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	if (MmIsAddressValid(pIrp)) {
		PIO_STACK_LOCATION StackLocation = IoGetCurrentIrpStackLocation(pIrp);

		switch (StackLocation->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_DISK_GET_PARTITION_INFO_EX: {
			ioctl_helper::set_completion_callback(pIrp, StackLocation, PartInfoHandler);
			break;
		}
		case IOCTL_DISK_GET_DRIVE_LAYOUT_EX: {
			ioctl_helper::set_completion_callback(pIrp, StackLocation, PartLayoutHandler);
			break;
		}
		default:
			break;
		}
	}




	return OriginalHandlers::gOriginalPartMgrDeviceControl(pDeviceObject, pIrp);
}


bool disk::Spoof() {

	UNICODE_STRING uDiskDeviceName;
	RtlInitUnicodeString(&uDiskDeviceName, L"\\Driver\\Disk");
	NTSTATUS Status = ObReferenceObjectByName(&uDiskDeviceName, OBJ_CASE_INSENSITIVE, NULL, NULL, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&OriginalHandlers::gDiskDriverObject);
	if (!NT_SUCCESS(Status)) {
		return false;
	}
	Status = IoEnumerateDeviceObjectList(OriginalHandlers::gDiskDriverObject, NULL, NULL, &NumOfDisk);
	if (!(STATUS_BUFFER_TOO_SMALL == Status) && NumOfDisk) {
		return false;
	}

	
	ULONG Size = NumOfDisk * sizeof(PDEVICE_OBJECT);
	Devices = (PDEVICE_OBJECT*)Util::AllocMDLMemory(Size, PAGE_READWRITE, DiskMemory::DiskMDL);
	RtlZeroMemory(Devices, Size);
	Status = IoEnumerateDeviceObjectList(OriginalHandlers::gDiskDriverObject, Devices, Size, &NumOfDisk);
	if (!NT_SUCCESS(Status)) {
		return false;
	}

										// Partition GUIDs
	UNICODE_STRING uDriverName{};
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	{
		RtlInitUnicodeString(&uDriverName, L"\\Driver\\partmgr");
		Status = ObReferenceObjectByName(&uDriverName, OBJ_CASE_INSENSITIVE, NULL, NULL, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&OriginalHandlers::gPartMgrDriverObject);
		if (!NT_SUCCESS(Status)) {
			return false;
		}

		PIMAGE_SECTION_HEADER DiscardableSectionHeader = Util::GetDiscardableSectionHeader(OriginalHandlers::gPartMgrDriverObject);

		if (DiscardableSectionHeader == nullptr) {
			ObDereferenceObject(OriginalHandlers::gPartMgrDriverObject);
			OriginalHandlers::gPartMgrDriverObject = nullptr;
			return false;
		}

		const auto DiscardableSectionAddress = Util::GetDiscardableSectionAddress(OriginalHandlers::gPartMgrDriverObject, DiscardableSectionHeader);
		PTE_64* DiscardableSectionPte = Util::GetPteForAddress(DiscardableSectionAddress);

		DiskMemory::gPartMgrHookBuffer = ExAllocatePool(NonPagedPool, ROUND_TO_PAGES(DiscardableSectionHeader->Misc.VirtualSize));
		PTE_64* AllocatedBufferPte = Util::GetPteForAddress(DiskMemory::gPartMgrHookBuffer);

		if (DiscardableSectionPte == nullptr || AllocatedBufferPte == nullptr || DiskMemory::gPartMgrHookBuffer == nullptr) {
			if (DiskMemory::gPartMgrHookBuffer) {
				ExFreePool(DiskMemory::gPartMgrHookBuffer);
			}
			ObDereferenceObject(OriginalHandlers::gPartMgrDriverObject);
			OriginalHandlers::gPartMgrDriverObject = nullptr;
			return false;
		}

		*DiscardableSectionPte = *AllocatedBufferPte;

		if (DiscardableSectionPte->ExecuteDisable) {
			DiscardableSectionPte->ExecuteDisable = 0;
		}

		memcpy(DiscardableSectionAddress, JmpBuffer, sizeof(JmpBuffer));
		*reinterpret_cast<void**>(&reinterpret_cast<unsigned char*>(DiscardableSectionAddress)[2]) = &PartmgrHandler;

		OriginalHandlers::gOriginalPartMgrDeviceControl = OriginalHandlers::gPartMgrDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
		OriginalHandlers::gPartMgrDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = reinterpret_cast<DRIVER_DISPATCH*>(DiscardableSectionAddress);
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


																// NVME serials
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	{
		RtlInitUnicodeString(&uDriverName, L"\\Driver\\stornvme");
		Status = ObReferenceObjectByName(&uDriverName, OBJ_CASE_INSENSITIVE, NULL, NULL, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&OriginalHandlers::gNvmeDriverObject);
		if (!NT_SUCCESS(Status) || !OriginalHandlers::gNvmeDriverObject) {
			goto storahci;
		}
		else {

			PIMAGE_SECTION_HEADER DiscardableSectionHeader = Util::GetDiscardableSectionHeader(OriginalHandlers::gNvmeDriverObject);

			if (DiscardableSectionHeader == nullptr) {
				ObDereferenceObject(OriginalHandlers::gNvmeDriverObject);
				OriginalHandlers::gNvmeDriverObject = nullptr;
				return false;
			}

			const auto DiscardableSectionAddress = Util::GetDiscardableSectionAddress(OriginalHandlers::gNvmeDriverObject, DiscardableSectionHeader);
			PTE_64* DiscardableSectionPte = Util::GetPteForAddress(DiscardableSectionAddress);

			DiskMemory::gStorNvmeHookBuffer = ExAllocatePool(NonPagedPool, ROUND_TO_PAGES(DiscardableSectionHeader->Misc.VirtualSize));
			PTE_64* AllocatedBufferPte = Util::GetPteForAddress(DiskMemory::gStorNvmeHookBuffer);

			if (DiscardableSectionPte == nullptr || AllocatedBufferPte == nullptr || DiskMemory::gStorNvmeHookBuffer == nullptr) {
				if (DiskMemory::gStorNvmeHookBuffer) {
					ExFreePool(DiskMemory::gStorNvmeHookBuffer);
				}
				ObDereferenceObject(OriginalHandlers::gNvmeDriverObject);
				OriginalHandlers::gNvmeDriverObject = nullptr;
				return false;
			}

			*DiscardableSectionPte = *AllocatedBufferPte;

			if (DiscardableSectionPte->ExecuteDisable) {
				DiscardableSectionPte->ExecuteDisable = 0;
			}

			memcpy(DiscardableSectionAddress, JmpBuffer, sizeof(JmpBuffer));
			*reinterpret_cast<void**>(&reinterpret_cast<unsigned char*>(DiscardableSectionAddress)[2]) = &NvmeStorHandler;

			OriginalHandlers::gOriginalNvmeDeviceControl = OriginalHandlers::gNvmeDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
			OriginalHandlers::gNvmeDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = reinterpret_cast<DRIVER_DISPATCH*>(DiscardableSectionAddress);
		}
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



																	// HDD, NVME, SSD serials
	storahci:
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	{
		RtlInitUnicodeString(&uDriverName, L"\\Driver\\storahci");
		Status = ObReferenceObjectByName(&uDriverName, OBJ_CASE_INSENSITIVE, NULL, NULL, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&OriginalHandlers::gStorahciObject);
		if (!NT_SUCCESS(Status) || !OriginalHandlers::gStorahciObject) {
			goto end;
		}
		else {
			PIMAGE_SECTION_HEADER DiscardableSectionHeader = Util::GetDiscardableSectionHeader(OriginalHandlers::gStorahciObject);

			if (DiscardableSectionHeader == nullptr) {
				ObDereferenceObject(OriginalHandlers::gStorahciObject);
				OriginalHandlers::gStorahciObject = nullptr;
				return false;
			}

			const auto DiscardableSectionAddress = Util::GetDiscardableSectionAddress(OriginalHandlers::gStorahciObject, DiscardableSectionHeader);
			PTE_64* DiscardableSectionPte = Util::GetPteForAddress(DiscardableSectionAddress);

			DiskMemory::gStorahciHookBuffer = ExAllocatePool(NonPagedPool, ROUND_TO_PAGES(DiscardableSectionHeader->Misc.VirtualSize));
			PTE_64* AllocatedBufferPte = Util::GetPteForAddress(DiskMemory::gStorahciHookBuffer);

			if (DiscardableSectionPte == nullptr || AllocatedBufferPte == nullptr || DiskMemory::gStorahciHookBuffer == nullptr) {
				if (DiskMemory::gStorahciHookBuffer) {
					ExFreePool(DiskMemory::gStorahciHookBuffer);
				}
				ObDereferenceObject(OriginalHandlers::gStorahciObject);
				OriginalHandlers::gStorahciObject = nullptr;
				return false;
			}

			*DiscardableSectionPte = *AllocatedBufferPte;

			if (DiscardableSectionPte->ExecuteDisable) {
				DiscardableSectionPte->ExecuteDisable = 0;
			}

			memcpy(DiscardableSectionAddress, JmpBuffer, sizeof(JmpBuffer));
			*reinterpret_cast<void**>(&reinterpret_cast<unsigned char*>(DiscardableSectionAddress)[2]) = &StorahciHandler;

			OriginalHandlers::gOriginalStorahciDeviceControl = OriginalHandlers::gStorahciObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
			OriginalHandlers::gStorahciObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = reinterpret_cast<DRIVER_DISPATCH*>(DiscardableSectionAddress);
		}
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	



	end:
	

	DisableFailurePrediction();

	bool bIsDiskDriverValid = Util::IsMajorFunctionInDriverObject(OriginalHandlers::gDiskDriverObject);

	if (!bIsDiskDriverValid) {
		return false;
	}

	bool bIsPartMgrDriverValid = Util::IsMajorFunctionInDriverObject(OriginalHandlers::gPartMgrDriverObject);
	if (!bIsPartMgrDriverValid) {
		return false;
	}




	bool bIsNvmeDriverValid = true;
	if (OriginalHandlers::gNvmeDriverObject) {
		bIsNvmeDriverValid = Util::IsMajorFunctionInDriverObject(OriginalHandlers::gNvmeDriverObject);

		if (!bIsNvmeDriverValid)
			return false;
	}


	bool bIsStorahciDriverValid = true;
	if (OriginalHandlers::gStorahciObject) {
		bIsStorahciDriverValid = Util::IsMajorFunctionInDriverObject(OriginalHandlers::gStorahciObject);

		if (!bIsStorahciDriverValid) {
			return false;
		}
	}



	return (bIsDiskDriverValid && bIsPartMgrDriverValid && bIsStorahciDriverValid && bIsNvmeDriverValid);
}
