#include "Util.h"
#include "SkCrypt.h"
#include <intrin.h>
#define to_lower_c(Char) ((Char >= (char*)'A' && Char <= (char*)'Z') ? (Char + 32) : Char)

#define win10_1803 17134
#define win10_1809 17763
#define win10_1903 18362
#define win10_1909 18363
#define win10_2004 19041
#define win10_20h2 19042
#define win10_21h1 19043
#define win10_21h2 19044
#define win10_22h2 19045
#define win11_21h2 22000
#define win11_22h2 22621
#define win11_23h2 22631



namespace crt
{
	template <typename t>
	__forceinline int strlen(t str) {
		if (!str)
		{
			return 0;
		}

		t buffer = str;

		while (*buffer)
		{
			*buffer++;
		}

		return (int)(buffer - str);
	}

	bool strcmp(const char* src, const char* dst)
	{
		if (!src || !dst)
		{
			return true;
		}

		const auto src_sz = crt::strlen(src);
		const auto dst_sz = crt::strlen(dst);

		if (src_sz != dst_sz)
		{
			return true;
		}

		for (int i = 0; i < src_sz; i++)
		{
			if (src[i] != dst[i])
			{
				return true;
			}
		}

		return false;
	}
}

BOOL Util::CheckMask(PCHAR Base, PCHAR Pattern, PCHAR Mask) {
	for (; *Mask; ++Base, ++Pattern, ++Mask) {
		if (*Mask == 'x' && *Base != *Pattern) {
			return FALSE;
		}
	}
	return TRUE;
}

PVOID Util::FindPattern(PCHAR Base, unsigned long Length, PCHAR Pattern, PCHAR Mask) {
	auto checkMask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL
		{
			for (auto x = buffer; *mask; pattern++, mask++, x++) {
				auto addr = *(BYTE*)(pattern);
				if (addr != *x && *mask != '?')
					return FALSE;
			}

			return TRUE;
		};

	for (auto x = 0; x < Length - strlen(Mask); x++) {

		auto addr = (PBYTE)Base + x;
		if (checkMask(addr, Pattern, Mask))
			return addr;
	}

	return NULL;
}

PVOID Util::FindPatternImage(PCHAR Base, PCHAR Pattern, PCHAR Mask) {
	PVOID Match = 0;

	PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);
	for (DWORD i = 0; i < Headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER Section = &Sections[i];
		if (!memcmp(Section->Name, "PAGE", 4) || !memcmp(Section->Name, ".text", 5)) {
			Match = FindPattern(Base + Section->VirtualAddress, Section->Misc.VirtualSize, Pattern, Mask);
			if (Match) {
				break;
			}
		}
	}

	return Match;
}

PVOID Util::GetSystemInformation(SYSTEM_INFORMATION_CLASS information_class) {
	unsigned long size = 32;
	char buffer[32];

	ZwQuerySystemInformation(information_class, buffer, size, &size);

	void* info = ExAllocatePoolZero(NonPagedPool, size, 7265746172);

	if (!info)
		return nullptr;

	if (!NT_SUCCESS(ZwQuerySystemInformation(information_class, info, size, &size)))
	{
		ExFreePool(info);
		return nullptr;
	}

	return info;
}

uintptr_t Util::GetKernelModule(const char* name, PVOID& pOutSize) {
	const auto to_lower = [](char* string) -> const char*
		{
			for (char* pointer = string; *pointer != '\0'; ++pointer)
			{
				*pointer = (char)(short)tolower(*pointer);
			}

			return string;
		};

	const PRTL_PROCESS_MODULES info = (PRTL_PROCESS_MODULES)GetSystemInformation(SystemModuleInformation);

	if (!info)
		return NULL;

	for (size_t i = 0; i < info->NumberOfModules; ++i)
	{
		const auto& mod = info->Modules[i];



		if (crt::strcmp(to_lower_c((char*)mod.FullPathName + mod.OffsetToFileName), name) == 0)
		{
			const void* address = mod.ImageBase;
			pOutSize = 	(PVOID)mod.ImageSize;
			ExFreePool(info);
			return (uintptr_t)address;
		}
	}

	ExFreePool(info);
	return NULL;
}

bool Util::IsNtosKrnlAddress(DWORD64 Address) {
	DWORD64 max = 0;
	DWORD64 min = 0;

	PVOID NtosSize = 0;
	uintptr_t NtosBase = GetKernelModule(skCrypt("ntoskrnl.exe"), NtosSize);

	max = NtosBase + (DWORD64)NtosSize;
	min = NtosBase;
	return (Address < max) && (Address >= min);
	
}

BOOLEAN Util::WriteToReadOnly(PVOID Dst, PVOID Buff, SIZE_T Size) {
	PMDL Mdl = IoAllocateMdl(Dst, Size, FALSE, FALSE, 0);

	if (!Mdl)
		return FALSE;

	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	MmProtectMdlSystemAddress(Mdl, PAGE_EXECUTE_READWRITE);

	auto MmMap = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	memcpy(MmMap, Buff, Size);

	MmUnmapLockedPages(MmMap, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);



	return TRUE;
}

/*BOOLEAN Util::IsFirstByteNullSafely(PVOID baseAddress) {
	BOOLEAN Result = MmIsAddressValid(baseAddress);
	
	
	return Result;
}

BOOLEAN Util::IsMemoryPagedOut(PVOID baseAddress) {

	__try {
		ProbeForRead(baseAddress, sizeof(CHAR), sizeof(CHAR));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}

	return FALSE;
}*/

/*BOOLEAN Util::IsWindows11() {
	RTL_OSVERSIONINFOW VersionInfo = { 0 };

	NTSTATUS Status = RtlGetVersion(&VersionInfo);

	

	if (!NT_SUCCESS(Status)) {
		return FALSE;
	}

	if (VersionInfo.dwBuildNumber < win11_21h2) {
		return FALSE;
	}
	else {
		return TRUE;
	}



	return TRUE;
}*/

PVOID Util::SafeCopy(PVOID src, DWORD size) {

	PCHAR buffer = (PCHAR)ExAllocatePool(NonPagedPool, size);
	if (buffer) {
		MM_COPY_ADDRESS addr = { 0 };
		addr.VirtualAddress = src;

		SIZE_T read = 0;
		if (NT_SUCCESS(MmCopyMemory(buffer, addr, size, MM_COPY_MEMORY_VIRTUAL, &read)) && read == size) {
			return buffer;
		}

		ExFreePool(buffer);
	}

	return 0;
}


PVOID Util::AllocMDLMemory(SIZE_T Size, ULONG Protect = PAGE_READWRITE, PMDL OutMDL = nullptr) {

	LARGE_INTEGER LowAddress, HighAddress;
	LowAddress.QuadPart = 0;
	HighAddress.QuadPart = MAXULONG64;

	PMDL pMdl = MmAllocatePagesForMdl(LowAddress, HighAddress, LowAddress, Size);
	if (pMdl == nullptr) {
		return nullptr;
	}
	if (pMdl->ByteCount < Size) {
		MmFreePagesFromMdl(pMdl);
		ExFreePool(pMdl);
		return nullptr;
	}
	void* p = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MEMORY_CACHING_TYPE::MmCached, NULL, FALSE, HighPagePriority);
	NTSTATUS ntStatus = MmProtectMdlSystemAddress(pMdl, Protect);
	if (!NT_SUCCESS(ntStatus)) {
		MmUnmapLockedPages(p, pMdl);
		MmFreePagesFromMdl(pMdl);
		ExFreePool(pMdl);
		return nullptr;
	}

	if (!p) {
	}

	OutMDL = pMdl;
	


	return p;
}

NTSTATUS Util::GetPTE(PVOID Address, PTE_64** pOut){

	CR3 HostCR3{};
	HostCR3.Flags = __readcr3();

	ADDRESS_TRANSLATION_HELPER Helper;
	UINT32 level;
	PT_ENTRY_64* finalEntry;
	PML4E_64* pml4;
	PML4E_64* pml4e;
	PDPTE_64* pdpt;
	PDPTE_64* pdpte;
	PDE_64* pd;
	PDE_64* pde;
	PTE_64* pt;
	PTE_64* pte;

	Helper.AsUInt64 = (UINT64)Address;

	PHYSICAL_ADDRESS    addr;

	addr.QuadPart = HostCR3.AddressOfPageDirectory << PAGE_SHIFT;

	pml4 = (PML4E_64*)MmGetVirtualForPhysical(addr);

	pml4e = &pml4[Helper.AsIndex.Pml4];

	if (pml4e->Present == FALSE)
	{
		finalEntry = (PT_ENTRY_64*)pml4e;
		goto Exit;
	}

	addr.QuadPart = pml4e->PageFrameNumber << PAGE_SHIFT;

	pdpt = (PDPTE_64*)MmGetVirtualForPhysical(addr);

	pdpte = &pdpt[Helper.AsIndex.Pdpt];

	if ((pdpte->Present == FALSE) || (pdpte->LargePage != FALSE))
	{
		finalEntry = (PT_ENTRY_64*)pdpte;
		goto Exit;
	}

	addr.QuadPart = pdpte->PageFrameNumber << PAGE_SHIFT;

	pd = (PDE_64*)MmGetVirtualForPhysical(addr);

	pde = &pd[Helper.AsIndex.Pd];

	if ((pde->Present == FALSE) || (pde->LargePage != FALSE))
	{
		finalEntry = (PT_ENTRY_64*)pde;
		goto Exit;
	}

	addr.QuadPart = pde->PageFrameNumber << PAGE_SHIFT;

	pt = (PTE_64*)MmGetVirtualForPhysical(addr);

	pte = &pt[Helper.AsIndex.Pt];
	*pOut = pte;


Exit:
	return FALSE;
}

PIMAGE_SECTION_HEADER Util::GetDiscardableSectionHeader(PDRIVER_OBJECT DriverObject) {
	const auto Headers = RtlImageNtHeader(DriverObject->DriverStart);
	const auto FirstSection = IMAGE_FIRST_SECTION(Headers);

	for (PIMAGE_SECTION_HEADER Section = FirstSection; Section < FirstSection + Headers->FileHeader.NumberOfSections; Section++) {
		if ((Section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
			(Section->Misc.VirtualSize > 0) &&
			(Section->Misc.VirtualSize <= PAGE_SIZE)) {
			return Section;
		}
	}

	return nullptr;
}

void* Util::GetDiscardableSectionAddress(PDRIVER_OBJECT DriverObject, PIMAGE_SECTION_HEADER SectionHeader) {
	return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(DriverObject->DriverStart) + SectionHeader->VirtualAddress);
}

PTE_64* Util::GetPteForAddress(void* Address) {
	PTE_64* Pte = nullptr;
	Util::GetPTE(Address, &Pte);
	return Pte;
}

bool Util::IsMajorFunctionInDriverObject(PDRIVER_OBJECT DriverObject) {
	if (!DriverObject) {
		return false;
	}

	ULONG_PTR DriverObjectStart = (ULONG_PTR)DriverObject;
	ULONG_PTR DriverObjectEnd = DriverObjectStart + sizeof(DRIVER_OBJECT);

	ULONG_PTR FunctionPtrAddress = (ULONG_PTR)&DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];

	bool bIsInside = (FunctionPtrAddress >= DriverObjectStart && FunctionPtrAddress < DriverObjectEnd);


	return bIsInside;
}


