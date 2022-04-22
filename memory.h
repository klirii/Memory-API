#pragma once
#include <iostream>
#include <Windows.h>

using namespace std;

struct RegionAttributes {
    DWORD AllocationProtect;
    DWORD State;
    DWORD Protect;
    DWORD Type;

    MEMORY_BASIC_INFORMATION mbi;

    RegionAttributes(DWORD AllocationProtect, DWORD State, DWORD Protect, DWORD Type) {
        this->AllocationProtect = AllocationProtect;
        this->State = State;
        this->Protect = Protect;
        this->Type = Type;
    }

    bool isTrue() {
        if (mbi.AllocationProtect == this->AllocationProtect && mbi.State == this->State && mbi.Protect == this->Protect && mbi.Type == this->Type)
            return true;
        return false;
    }
};

struct ScanArgs {
	PBYTE pattern;
	PCHAR patternMask;

	LPVOID* writeBuffer;
	RegionAttributes* regAttributes;

	LPVOID minAddr;
	LPVOID maxAddr;

	bool multiThreaded;
	SIZE_T areaSize;

	UINT8* count;

	ScanArgs(PBYTE pattern, PCHAR patternMask, LPVOID* writeBuffer, RegionAttributes* regAttributes = nullptr, LPVOID minAddr = nullptr, LPVOID maxAddr = nullptr, UINT8* count = nullptr, bool multiThreaded = false, SIZE_T areaSize = 0) {
		this->pattern = pattern;
		this->patternMask = patternMask;

		this->writeBuffer = writeBuffer;
		this->regAttributes = regAttributes;

		this->minAddr = minAddr;
		this->maxAddr = maxAddr;

		this->areaSize = areaSize;
		this->multiThreaded = multiThreaded;

		this->count = count;
	}
};

class MemoryAPI {
public:
    static HWND hWindow;
    static string getStrAddress(LPVOID address);

    static void hexStrToBytes(string hexStr, PBYTE writeBuf);
    static string byteToHexStr(PBYTE data);

    static char getHalfOfByte(PBYTE data, PCHAR dataMask);
    static bool compareBytes(PBYTE data, PBYTE pattern, PCHAR patternMask);

    static void scanPattern(ScanArgs* scanArgs);

    static bool checkAddressElem(LPVOID address, char elem, UINT8 elemNumber);
};