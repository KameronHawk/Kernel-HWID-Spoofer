#pragma once
#include "IOCTLHelper.h"

typedef struct
{
	UINT8   Type;
	UINT8   Length;
	UINT8   Handle[2];
} SMBIOS_HEADER;

typedef UINT8   SMBIOS_STRING;

typedef struct
{
	SMBIOS_HEADER   Hdr;
	SMBIOS_STRING   Vendor;
	SMBIOS_STRING   BiosVersion;
	UINT8           BiosSegment[2];
	SMBIOS_STRING   BiosReleaseDate;
	UINT8           BiosSize;
	UINT8           BiosCharacteristics[8];
	UINT8           BIOSCharacteristicsExtensionBytes[2];
	UINT8           SystemBiosMajorRelease;
	UINT8           SystemBiosMinorRelease;
	UINT8           EmbeddedControllerFirmwareMajorRelease;
	UINT8           EmbeddedControllerFirmwareMinorRelease;
} SMBIOS_TYPE0;

typedef struct
{
	SMBIOS_HEADER   Hdr;
	SMBIOS_STRING   Manufacturer;
	SMBIOS_STRING   ProductName;
	SMBIOS_STRING   Version;
	SMBIOS_STRING   SerialNumber;

	//
	// always byte copy this data to prevent alignment faults!
	//
	GUID			Uuid; // EFI_GUID == GUID?

	UINT8           WakeUpType;
	SMBIOS_STRING   SKUNumber;
	SMBIOS_STRING   Family;
} SMBIOS_TYPE1;

typedef struct
{
	SMBIOS_HEADER   Hdr;
	SMBIOS_STRING         Manufacturer;
	SMBIOS_STRING         ProductName;
	SMBIOS_STRING         Version;
	SMBIOS_STRING         SerialNumber;
	SMBIOS_STRING         AssetTag;
	SMBIOS_STRING         LocationInChassis;
} SMBIOS_TYPE2;

typedef struct
{
	SMBIOS_HEADER   Hdr;
	SMBIOS_STRING   Manufacturer;
	UINT8           Type;
	SMBIOS_STRING   Version;
	SMBIOS_STRING   SerialNumber;
	SMBIOS_STRING   AssetTag;
	UINT8           BootupState;
	UINT8           PowerSupplyState;
	UINT8           ThermalState;
	UINT8           SecurityStatus;
	UINT8           OemDefined[4];
} SMBIOS_TYPE3;

typedef struct
{
	SMBIOS_HEADER   Hdr;
	SMBIOS_STRING    Socket; //UINT8 before?
	UINT8           ProcessorType;
	UINT8           ProcessorFamily;
	SMBIOS_STRING   ProcessorManufacture;
	UINT8           ProcessorId[8];
	SMBIOS_STRING   ProcessorVersion;
	UINT8           Voltage;
	UINT8           ExternalClock[2];
	UINT8           MaxSpeed[2];
	UINT8           CurrentSpeed[2];
	UINT8           Status;
	UINT8           ProcessorUpgrade;
	UINT8           L1CacheHandle[2];
	UINT8           L2CacheHandle[2];
	UINT8           L3CacheHandle[2];
	SMBIOS_STRING    SerialNumber;
	SMBIOS_STRING    AssetTag;
	SMBIOS_STRING    PartNumber;
} SMBIOS_TYPE4;

typedef struct
{
	SMBIOS_HEADER   Hdr;
	UINT16                                     MemoryArrayHandle;
	UINT16                                     MemoryErrorInformationHandle;
	UINT16                                     TotalWidth;
	UINT16                                     DataWidth;
	UINT16                                     Size;
	UINT8                                      FormFactor;        ///< The enumeration value from MEMORY_FORM_FACTOR.
	UINT8                                      DeviceSet;
	SMBIOS_STRING                        DeviceLocator;
	SMBIOS_STRING                        BankLocator;
	UINT8                                      MemoryType;        ///< The enumeration value from MEMORY_DEVICE_TYPE.
	//MEMORY_DEVICE_TYPE_DETAIL                  TypeDetail;
	UINT16                                     Speed;
	SMBIOS_STRING                        Manufacturer;
	SMBIOS_STRING                        SerialNumber;
	SMBIOS_STRING                        AssetTag;
	SMBIOS_STRING                        PartNumber;
	//
	// Add for smbios 2.6
	//
	UINT8                                      Attributes;
	//
	// Add for smbios 2.7
	//
	UINT32                                     ExtendedSize;
	//
	// Keep using name "ConfiguredMemoryClockSpeed" for compatibility
	// although this field is renamed from "Configured Memory Clock Speed"
	// to "Configured Memory Speed" in smbios 3.2.0.
	//
	UINT16                                     ConfiguredMemoryClockSpeed;
	//
	// Add for smbios 2.8.0
	//
	UINT16                                     MinimumVoltage;
	UINT16                                     MaximumVoltage;
	UINT16                                     ConfiguredVoltage;
	//
	// Add for smbios 3.2.0
	//
	UINT8                                      MemoryTechnology;  ///< The enumeration value from MEMORY_DEVICE_TECHNOLOGY
	//MEMORY_DEVICE_OPERATING_MODE_CAPABILITY    MemoryOperatingModeCapability;
	SMBIOS_STRING                        FirmwareVersion;
	UINT16                                     ModuleManufacturerID;
	UINT16                                     ModuleProductID;
	UINT16                                     MemorySubsystemControllerManufacturerID;
	UINT16                                     MemorySubsystemControllerProductID;
	UINT64                                     NonVolatileSize;
	UINT64                                     VolatileSize;
	UINT64                                     CacheSize;
	UINT64                                     LogicalSize;
	//
	// Add for smbios 3.3.0
	//
	UINT32                                     ExtendedSpeed;
	UINT32                                     ExtendedConfiguredMemorySpeed;
} SMBIOS_TYPE17;

typedef union
{
	SMBIOS_HEADER* Hdr;
	SMBIOS_TYPE0* Type0;
	SMBIOS_TYPE1* Type1;
	SMBIOS_TYPE2* Type2;
	SMBIOS_TYPE3* Type3;
	SMBIOS_TYPE4* Type4;
	UINT8* Raw;
} SMBIOS_STRUCTURE_POINTER;

typedef struct
{
	UINT8   AnchorString[4];
	UINT8   EntryPointStructureChecksum;
	UINT8   EntryPointLength;
	UINT8   MajorVersion;
	UINT8   MinorVersion;
	UINT16  MaxStructureSize;
	UINT8   EntryPointRevision;
	UINT8   FormattedArea[5];
	UINT8   IntermediateAnchorString[5];
	UINT8   IntermediateChecksum;
	UINT16  TableLength;
	UINT32  TableAddress;
	UINT16  NumberOfSmbiosStructures;
	UINT8   SmbiosBcdRevision;
} SMBIOS_STRUCTURE_TABLE;

typedef struct
{
	BOOLEAN Used20CallingMethod;
	UCHAR SMBiosMajorVersion;
	UCHAR SMBiosMinorVersion;
	UCHAR DMIBiosRevision;
} SMBIOSVERSIONINFO, * PSMBIOSVERSIONINFO;


namespace smbios {
	bool Spoof();
}