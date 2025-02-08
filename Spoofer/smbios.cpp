#include "smbios.h"
#include "Spoof.h"

void randomize_serial_smbios(char* pStr, int sz, const char* ignore = "", int ignoreLen = 0) {
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
		seed = 1664525 * seed + 1013904223; // Linear Congruential Generator (LCG)
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

void GenerateRandomBytes(BYTE* buffer, size_t size) {
	ULONG seed = GetBootSeed(); 
	for (size_t i = 0; i < size; ++i) {
		seed = 1664525 * seed + 1013904223; 
		buffer[i] = (BYTE)(seed & 0xFF);
	}
}

void RandomizeGUID(GUID* guid) {
	if (!MmIsAddressValid(guid)) {
		return;
	}

	GenerateRandomBytes(reinterpret_cast<BYTE*>(guid), sizeof(GUID));

	guid->Data3 = (guid->Data3 & 0x0FFF) | 0x4000; // Version 4 (randomly generated)
	guid->Data4[0] = (guid->Data4[0] & 0x3F) | 0x80; // Variant 1 (standard variant)
}

char* GetString(SMBIOS_HEADER* header, SMBIOS_STRING string)
{
	const auto* start = reinterpret_cast<const char*>(header) + header->Length;

	if (!string || *start == 0)
		return nullptr;

	while (--string)
	{
		start += strlen(start) + 1;
	}

	return const_cast<char*>(start);
}

NTSTATUS ProcessTable(SMBIOS_HEADER* header)
{
	if (!header->Length)
		return STATUS_UNSUCCESSFUL;

	if (header->Type == 1) // System Information
	{
		SMBIOS_TYPE1* type1 = reinterpret_cast<SMBIOS_TYPE1*>(header);

		
		GUID OriginalUUID = { 0 };
		OriginalUUID = type1->Uuid;
		RandomizeGUID(&OriginalUUID);
		RtlCopyMemory(&type1->Uuid, &OriginalUUID, sizeof(GUID));

		// Get the serial number
		char* SerialNum = GetString(header, type1->SerialNumber);

		// Safety check for "Default String" or "System Serial Number"
		if (SerialNum &&
			strcmp(SerialNum, skCrypt("Default String")) != 0 &&
			strcmp(SerialNum, skCrypt("System Serial Number")) != 0 &&
			strcmp(SerialNum, skCrypt("To be filled by O.E.M")) != 0)
		{
			randomize_serial_smbios(SerialNum, strlen(SerialNum), " _-.");
		}
	}

	if (header->Type == 2) // baseboard information
	{
		auto* type2 = reinterpret_cast<SMBIOS_TYPE2*>(header);
		char* SerialNum = GetString(header, type2->SerialNumber);

		if (SerialNum &&
			strcmp(SerialNum, skCrypt("Default String")) != 0 &&
			strcmp(SerialNum, skCrypt("System Serial Number")) != 0 &&
			strcmp(SerialNum, skCrypt("To be filled by O.E.M")) != 0)
		{
			randomize_serial_smbios(SerialNum, strlen(SerialNum), " _-.");
		}
	}

	if (header->Type == 3) 
	{
		auto* type3 = reinterpret_cast<SMBIOS_TYPE3*>(header);
		char* SerialNum = GetString(header, type3->SerialNumber);

		if (SerialNum &&
			strcmp(SerialNum, skCrypt("Default String")) != 0 &&
			strcmp(SerialNum, skCrypt("System Serial Number")) != 0 &&
			strcmp(SerialNum, skCrypt("To be filled by O.E.M")) != 0)
		{
			randomize_serial_smbios(SerialNum, strlen(SerialNum), " _-.");
		}
		
	}

	if (header->Type == 4) // processor information
	{
		
		auto* type4 = reinterpret_cast<SMBIOS_TYPE4*>(header);
		char* SerialNum = GetString(header, type4->SerialNumber);

		if (SerialNum &&
			strcmp(SerialNum, skCrypt("Default String")) != 0 &&
			strcmp(SerialNum, skCrypt("System Serial Number")) != 0 &&
			strcmp(SerialNum, skCrypt("To be filled by O.E.M")) != 0)
		{
			randomize_serial_smbios(SerialNum, strlen(SerialNum), " _-.");
		}
		
	}

	if (header->Type == 17) // memory device information
	{
		auto* type17 = reinterpret_cast<SMBIOS_TYPE17*>(header);

		char* SerialNum = GetString(header, type17->SerialNumber);

		if (SerialNum &&
			strcmp(SerialNum, skCrypt("Default String")) != 0 &&
			strcmp(SerialNum, skCrypt("System Serial Number")) != 0 &&
			strcmp(SerialNum, skCrypt("To be filled by O.E.M")) != 0)
		{
			randomize_serial_smbios(SerialNum, strlen(SerialNum), " _-.");
		}
	}

	return STATUS_SUCCESS;
}


NTSTATUS LoopTables(void* mapped, ULONG size)
{
	auto* endAddress = static_cast<char*>(mapped) + size;
	while (true)
	{
		auto* header = static_cast<SMBIOS_HEADER*>(mapped);
		if (header->Type == 127 && header->Length == 4)
			break;

		ProcessTable(header);
		auto* end = static_cast<char*>(mapped) + header->Length;
		while (0 != (*end | *(end + 1))) end++;
		end += 2;
		if (end >= endAddress)
			break;

		mapped = end;
	}

	return STATUS_SUCCESS;
}

NTSTATUS DeleteRegistryKey(PUNICODE_STRING regPath) {
	OBJECT_ATTRIBUTES objAttrs;
	InitializeObjectAttributes(&objAttrs, regPath, OBJ_KERNEL_HANDLE | OBJ_OPENIF, NULL, NULL);

	HANDLE regKey;
	NTSTATUS status = ZwOpenKey(&regKey, KEY_WRITE, &objAttrs);
	if (NT_SUCCESS(status)) {
		status = ZwDeleteValueKey(regKey, NULL); // delete the whole key
		ZwClose(regKey);
	}
	return status;
}

NTSTATUS SetRegistryKeyValue(PUNICODE_STRING regPath, PUNICODE_STRING valueName, PVOID data, ULONG dataLength) {
	OBJECT_ATTRIBUTES objAttrs;
	InitializeObjectAttributes(&objAttrs, regPath, OBJ_KERNEL_HANDLE | OBJ_OPENIF, NULL, NULL);

	HANDLE regKey;
	NTSTATUS status = ZwOpenKey(&regKey, KEY_WRITE, &objAttrs);
	if (NT_SUCCESS(status)) {
		status = ZwSetValueKey(regKey, valueName, 0, REG_BINARY, data, dataLength);
		ZwClose(regKey);
	}
	return status;
}

bool smbios::Spoof() {
	PVOID OutSize = 0;
	uintptr_t NtosBase = Util::GetKernelModule(skCrypt("ntoskrnl.exe"), OutSize);

	if (!NtosBase) {
		return false;
	}

	auto* PhysicalAddress = static_cast<PPHYSICAL_ADDRESS>(Util::FindPatternImage((PCHAR)NtosBase, skCrypt("\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15"), skCrypt("xxx????xxxx?xx")));

	if (!PhysicalAddress) {
		return false;
	}

	PhysicalAddress = reinterpret_cast<PPHYSICAL_ADDRESS>(reinterpret_cast<char*>(PhysicalAddress) + 7 + *reinterpret_cast<int*>(reinterpret_cast<char*>(PhysicalAddress) + 3));

	if (!PhysicalAddress) {
		return false;
	}

	auto* sizeScan = Util::FindPatternImage((PCHAR)NtosBase, skCrypt("\x8B\x1D\x00\x00\x00\x00\x48\x8B\xD0\x44\x8B\xC3\x48\x8B\xCD\xE8\x00\x00\x00\x00\x8B\xD3\x48\x8B"), skCrypt("xx????xxxxxxxxxx????xxxx"));

	if (!sizeScan) {
		return false;
	}

	const auto size = *reinterpret_cast<ULONG*>(static_cast<char*>(sizeScan) + 6 + *reinterpret_cast<int*>(static_cast<char*>(sizeScan) + 2));
	if (!size) {
		return false;
	}

	auto* mapped = MmMapIoSpace((PHYSICAL_ADDRESS)*PhysicalAddress, size, MmNonCached);
	if (!mapped) {
		return false;
	}

	if (!NT_SUCCESS(LoopTables((void*)mapped, size))) {
		MmUnmapIoSpace((void*)mapped, size);
		return false;
	}

	/*char* temp = (char*)ExAllocatePool(NonPagedPool, size + 8);
	memcpy(temp, &size, 4); 
	memcpy(temp + 4, mapped, size); 

	UNICODE_STRING regPath;
	RtlInitUnicodeString(&regPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data");
	DeleteRegistryKey(&regPath);

	UNICODE_STRING valueName;
	RtlInitUnicodeString(&valueName, L"SMBiosData");
	NTSTATUS status = SetRegistryKeyValue(&regPath, &valueName, temp, size + 8);

	ExFreePool(temp);
	MmUnmapIoSpace((void*)mapped, size);

	}*/

	return true;
}
