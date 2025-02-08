#pragma once
#include "ntapi.h"
#include "ia32.h"

/*#define MM_ALLOC_INDE_PAGES_10_PATTERN skCrypt("\x48\x8B\xC4\x48\x89\x58\x10\x44\x89\x48\x20\x55\x56\x57\x41\x54")
#define MM_ALLOC_INDE_PAGES_10_MASK skCrypt("xxxxxxxxxxxxxxxx")

#define MM_ALLOC_INDE_PAGES_11_PATTERN skCrypt("\x4C\x8B\xDC\x49\x89\x5B\x10\x45\x89\x4B\x20")
#define MM_ALLOC_INDE_PAGES_11_MASK skCrypt("xxxxxxxxxxx")

#define MM_FREE_INDE_PAGES_10_PATTERN skCrypt("\x48\x89\x5C\x24\x08\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8B\xEC\x48\x83\xEC\x60\x48\x83\x65\xD0")
#define MM_FREE_INDE_PAGES_10_MASK skCrypt("xxxxxxxxxxxxxxxxxxxxxxxxxxx") 

#define MM_FREE_INDE_PAGES_11_PATTERN skCrypt("\x48\x89\x5C\x24\x08\x55\x56\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x8B\xEC\x48\x83\xEC\x60\x33\xC0\x0F\x57\xC0\x48") // resolve
#define MM_FREE_INDE_PAGES_11_MASK skCrypt("xxxxxxxxxxxxxxxxxxxxxxxxxxxxx")


#define MM_SET_PAGE_PROT_10_PATTERN skCrypt("\x48\x89\x5C\x24\x20\x55\x56\x57\x41\x56\x41\x57\x48\x81\xEC\x00")
#define MM_SET_PAGE_PROT_10_MASK skCrypt("xxxxxxxxxxxxxxxx")

#define MM_SET_PAGE_PROT_11_PATTERN skCrypt("\x48\x89\x5C\x24\x20\x55\x56\x57\x41\x56\x41\x57\x48\x81\xEC\x00\x01\x00\x00\x48\x8B\x05\xCC\xCC\xCC\xCC\x48\x33\xC4\x48\x89\x84\x24\xF0\x00\x00\x00\x41") 
#define MM_SET_PAGE_PROT_11_MASK skCrypt("xxxxxxxxxxxxxxxxxxxxxx????xxxxxxxxxxxx")
*/

#define RELATIVE_ADDR(addr, size) ((PVOID)((PBYTE)(addr) + *(PINT)((PBYTE)(addr) + ((size) - (INT)sizeof(INT))) + (size)))

extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);



/*struct ModuleInfo
{
	uintptr_t address;
	SIZE_T size;
};*/

namespace Util {
	


	BOOL CheckMask(PCHAR Base, PCHAR Pattern, PCHAR Mask);

	PVOID FindPattern(PCHAR Base, unsigned long Length, PCHAR Pattern, PCHAR Mask);

	PVOID FindPatternImage(PCHAR Base, PCHAR Pattern, PCHAR Mask);

	PVOID GetSystemInformation(SYSTEM_INFORMATION_CLASS information_class);

	uintptr_t GetKernelModule(const char* name, PVOID& pOutSize);

	bool IsNtosKrnlAddress(DWORD64 Address);

	BOOLEAN WriteToReadOnly(PVOID Dst, PVOID Buff, SIZE_T Size);

	//BOOLEAN IsFirstByteNullSafely(PVOID baseAddress);
	//BOOLEAN IsMemoryPagedOut(PVOID baseAddress);

	//BOOLEAN IsWindows11();

	PVOID SafeCopy(PVOID src, DWORD size);

	PVOID AllocMDLMemory(SIZE_T Size, ULONG Protect, PMDL OutMDL);

	NTSTATUS GetPTE(PVOID Address, PTE_64** pOut);

	PIMAGE_SECTION_HEADER GetDiscardableSectionHeader(PDRIVER_OBJECT DriverObject);

	void* GetDiscardableSectionAddress(PDRIVER_OBJECT DriverObject, PIMAGE_SECTION_HEADER SectionHeader);

	PTE_64* GetPteForAddress(void* Address);

	bool IsMajorFunctionInDriverObject(PDRIVER_OBJECT DriverObject);

};