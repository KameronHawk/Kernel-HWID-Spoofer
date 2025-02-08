#pragma once
#include "IOCTLHelper.h"


#define IOCTL_NDIS_QUERY_GLOBAL_STATS \
    CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, 0, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)





#define OID_802_3_PERMANENT_ADDRESS			0x01010101
#define OID_802_3_CURRENT_ADDRESS			0x01010102
#define OID_802_5_PERMANENT_ADDRESS         0x02010101
#define OID_802_5_CURRENT_ADDRESS           0x02010102
#define OID_WAN_PERMANENT_ADDRESS		   	0x04010101
#define OID_WAN_CURRENT_ADDRESS			 	0x04010102
#define OID_ARCNET_PERMANENT_ADDRESS		0x06010101
#define OID_ARCNET_CURRENT_ADDRESS		  	0x06010102
#define IOCTL_NSI_GETALLPARAM (0x0012001B)
#define IOCTL_NSI_GETPARAM (0x120007)
#define IOCTL_NSI_GET_ARP (0x12000F)
#define IOCTL_TCP_ENUMERATE_SECURITY_FILTER (0x12001B)

#define IOCTL_TCP_QUERY_INFORMATION_EX \
	    CTL_CODE(FILE_DEVICE_NETWORK, 0, METHOD_NEITHER, FILE_ANY_ACCESS)

#define MAX_PHYSADDR_SIZE					8
typedef struct IFEntry
{
	ULONG if_index;
	ULONG if_type;
	ULONG if_mtu;
	ULONG if_speed;
	ULONG if_physaddrlen;
	UCHAR if_physaddr[MAX_PHYSADDR_SIZE];
	ULONG if_adminstatus;
	ULONG if_operstatus;
	ULONG if_lastchange;
	ULONG if_inoctets;
	ULONG if_inucastpkts;
	ULONG if_innucastpkts;
	ULONG if_indiscards;
	ULONG if_inerrors;
	ULONG if_inunknownprotos;
	ULONG if_outoctets;
	ULONG if_outucastpkts;
	ULONG if_outnucastpkts;
	ULONG if_outdiscards;
	ULONG if_outerrors;
	ULONG if_outqlen;
	ULONG if_descrlen;
	UCHAR if_descr[1];
} IFEntry;

#define IF_MAX_PHYS_ADDRESS_LENGTH 32

typedef struct _IF_PHYSICAL_ADDRESS_LHH {
	USHORT Length;
	UCHAR  Address[IF_MAX_PHYS_ADDRESS_LENGTH];
} IF_PHYSICAL_ADDRESS_LHH, * PIF_PHYSICAL_ADDRESS_LHH;

typedef struct _NDIS_IF_BLOCK {
	char _padding_0[0x464];
	IF_PHYSICAL_ADDRESS_LHH ifPhysAddress; // 0x464
	IF_PHYSICAL_ADDRESS_LHH PermanentPhysAddress; // 0x486
} NDIS_IF_BLOCK, * PNDIS_IF_BLOCK;

typedef struct _KSTRING {
	char _padding_0[0x10];
	WCHAR Buffer[1]; 
} KSTRING, * PKSTRING;

typedef struct _NDIS_FILTER_BLOCK {
	char _padding_0[0x8];
	struct _NDIS_FILTER_BLOCK* NextFilter; 
	char _padding_1[0x18];
	PKSTRING FilterInstanceName; 
} NDIS_FILTER_BLOCK, * PNDIS_FILTER_BLOCK;


#define MAX_NICS 64 

typedef struct _NIC_DRIVER {
	PDRIVER_OBJECT DriverObject;    
	PDRIVER_DISPATCH Original;       
	PVOID HookBuffer;                 
} NIC_DRIVER, * PNIC_DRIVER;


typedef struct _NIC_LIST {
	NIC_DRIVER Drivers[MAX_NICS];     
	ULONG Length;                     
} NIC_LIST, * PNIC_LIST;


extern NIC_LIST NICs;  
#define NSI_GET_IP_NET_TABLE   (11)

typedef struct _NSI_PARAMS {
	__int64 field_0;                // 0x00
	__int64 field_8;                // 0x08
	__int64 field_10;               // 0x10
	int Type;                       // 0x18
	int field_1C;                   // 0x1C
	int field_20;                   // 0x20
	int field_24;                   // 0x24
	char field_28[0x10];            // 0x28 (padding/unknown fields who gives af)
	__int64 NeighborTable;          // 0x38
	int NeighborTableEntrySize;     // 0x40
	int field_44;                   // 0x44
	__int64 StateTable;             // 0x48
	int StateTableEntrySize;        // 0x50
	int field_54;                   // 0x54
	__int64 OwnerTable;             // 0x58
	int OwnerTableEntrySize;        // 0x60
	int field_64;                   // 0x64
	int Count;                      // 0x68 (Number of entries in NeighborTable)
	int field_6C;                   // 0x6C
} NSI_PARAMS, * PNSI_PARAMS;

#define NSI_GET_ADAPTERS_INFO 0x1

#pragma pack(1)
typedef struct _NSI_ENUMERATE_OBJECTS_ALL_PRAMETERS_EX {
	ULONGLONG Unknown1;
	ULONG Unknown2;
	ULONG __unused1;
	ULONGLONG Unknown3;
	ULONG Type;
	ULONG __unused2;
	ULONG Unknown4;
	ULONG Unknown5;
	ULONGLONG EntryPointer_1;
	ULONG EntrySize_1;
	ULONG __unused3;
	ULONGLONG EntryPointer_2;
	ULONG EntrySize_2;
	ULONG __unused4;
	ULONGLONG EntryPointer_3;
	ULONG EntrySize_3;
	ULONG __unused5;
	ULONGLONG EntryPointer_4;
	ULONG EntrySize_4;
	ULONG __unused6;
	ULONG Count;
	ULONG __unused7;
} NSI_ENUMERATE_OBJECTS_ALL_PRAMETERS_EX, * PNSI_ENUMERATE_OBJECTS_ALL_PRAMETERS_EX;

typedef struct _NSI_ADAPTER_INFO_ROW {
	UCHAR __unused1[0x224];
	USHORT MacAddressLength;
	UCHAR MacAddress[6];
} *PNSI_ADAPTERINFO_ROW;

#pragma pack(pop)

// Structure to represent an entry in the NeighborTable for Type 0x10
typedef struct _NEIGHBOR_ENTRY {
	char padding[0x198];             // 0x00 - 0x197 (unknown or irrelevant data)
	unsigned char MacAddress[6];    // 0x198 (Offset for MAC address within NeighborTable entries)
	char padding2[2];               // Padding to align struct to 0x1A0
} NEIGHBOR_ENTRY, * PNEIGHBOR_ENTRY;




namespace nic {
	bool Spoof();

};