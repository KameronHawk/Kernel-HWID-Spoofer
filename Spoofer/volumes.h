#pragma once
#include "IOCTLHelper.h"

#define MAX_VOLUME_SERIALS 10
#define VOLUME_GUID_MAX_LENGTH (0x24)
#define GUID_OFFSET				10

struct VOLUME_SERIAL_DATA {
    ULONG Original;
    ULONG Spoofed;
};


namespace volumes {
	bool Spoof();
};
