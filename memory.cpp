#include "memory.h"
#include <sstream>
#include <iomanip>
#include <math.h>
#include <string>

HWND MemoryAPI::hWindow = nullptr;

string MemoryAPI::getStrAddress(LPVOID address) {
    stringstream ss;
    ss << address;
    return ss.str();
}

void MemoryAPI::hexStrToBytes(string hexStr, PBYTE writeBuf) {
    stringstream converter;
    for (int i = 0; i < hexStr.length(); i += 2) {
        converter << hex << hexStr.substr(i, 2);
        int byte;
        converter >> byte;
        writeBuf[i / 2] = byte & 0xFF;
        converter.str(string());
        converter.clear();
    }
}

string MemoryAPI::byteToHexStr(PBYTE data) {
    static const char characters[] = "0123456789ABCDEF";

    // Zeroes out the buffer unnecessarily, can't be avoided for std::string.
    string ret(1 * 2, 0);

    // Hack... Against the rules but avoids copying the whole buffer.
    auto buf = const_cast<char*>(ret.data());

    BYTE inputByte = (BYTE)*data;
    *buf++ = characters[inputByte >> 4];
    *buf++ = characters[inputByte & 0x0F];
    return ret;
}

char MemoryAPI::getHalfOfByte(PBYTE data, PCHAR dataMask) {
    if (*dataMask == '1')
        return MemoryAPI::byteToHexStr(data)[0];
    if (*dataMask == '2')
        return MemoryAPI::byteToHexStr(data)[1];
}

bool MemoryAPI::compareBytes(PBYTE data, PBYTE pattern, PCHAR patternMask) {
    for (; *patternMask; data++, pattern++, patternMask++) {
        if (*patternMask == 'x' && *data != *pattern)
            return false;
        if ((*patternMask == '1' || *patternMask == '2') && (MemoryAPI::getHalfOfByte(data, patternMask) != MemoryAPI::getHalfOfByte(pattern, patternMask)))
            return false;
    }
    return true;
}

void MemoryAPI::scanPattern(ScanArgs* scanArgs) {
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);

	MEMORY_BASIC_INFORMATION mbi;
	UINT64 offset = 0;
	PBYTE currentAddr = nullptr;

	LPVOID selectedMinAddr = nullptr;
	LPVOID selectedMaxAddr = scanArgs->maxAddr != nullptr ? scanArgs->maxAddr : sysInfo.lpMaximumApplicationAddress;

	// For multithreading scan
	const UINT8 areaCount = 4;
	HANDLE hThreads[areaCount];
	ScanArgs* args[areaCount];
	// For multithreading scan

	while (selectedMinAddr < selectedMaxAddr) {
		selectedMinAddr = scanArgs->minAddr != nullptr ? (LPVOID)((UINT64)scanArgs->minAddr + offset) : (LPVOID)((UINT64)sysInfo.lpMinimumApplicationAddress + offset);
		VirtualQuery(selectedMinAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

		if (scanArgs->regAttributes != nullptr)
			scanArgs->regAttributes->mbi = mbi;

		if (scanArgs->regAttributes != nullptr ? scanArgs->regAttributes->isTrue() : mbi.State != MEM_FREE && mbi.State != MEM_RESERVE) {
			if (scanArgs->multiThreaded) {
				SIZE_T areaSize = ceil(static_cast<double>(mbi.RegionSize / areaCount));

				// Creating threads and allocating areas
				for (int i = 0; i < areaCount; i++) {
					args[i] = new ScanArgs(scanArgs->pattern, scanArgs->patternMask, scanArgs->writeBuffer, scanArgs->regAttributes, nullptr, nullptr, scanArgs->count);
					args[i]->minAddr = (LPVOID)((UINT64)mbi.BaseAddress + (areaSize * i));
					args[i]->maxAddr = (LPVOID)((UINT64)mbi.BaseAddress + (areaSize * (i + 1)));
					args[i]->areaSize = areaSize;

					hThreads[i] = CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(MemoryAPI::scanPattern), args[i], NULL, nullptr);
				}

				// Wait functions work ending
				for (int i = 0; i < areaCount; i++)
					WaitForSingleObject(hThreads[i], INFINITE);

				// Clean
				for (int i = 0; i < areaCount; i++) {
					delete args[i];
					CloseHandle(hThreads[i]);
				}

				return;
			}
			else if (!scanArgs->multiThreaded) {
				for (int i = 0, j = 0; i < (!scanArgs->areaSize ? mbi.RegionSize : scanArgs->areaSize); i++) {
					currentAddr = (PBYTE)((UINT64)mbi.BaseAddress + i);
					if (MemoryAPI::compareBytes(currentAddr, scanArgs->pattern, scanArgs->patternMask)) {
						scanArgs->writeBuffer[scanArgs->count == nullptr ? j : *(scanArgs->count)] = (LPVOID)currentAddr;
						scanArgs->count == nullptr ? j++ : (*scanArgs->count)++;
					}
				}
			}
		}

		offset += mbi.RegionSize;
	}
}

bool MemoryAPI::checkAddressElem(LPVOID address, char elem, UINT8 elemNumber) {
    stringstream ss;
    ss << address;

    if (ss.str()[elemNumber] == elem)
        return true;
    if (ss.str()[elemNumber] != elem)
        return false;
}

		static PVOID GetRegionForAlloc(PVOID address) {
			map<uint64_t, PVOID> reservedRegions;
			vector<uint64_t> keys;

			SYSTEM_INFO sysInfo;
			GetSystemInfo(&sysInfo);

			PVOID current = nullptr;
			MEMORY_BASIC_INFORMATION mbi;

			uint64_t offset = 0;
			uint64_t offsetFromAddress = 0;
			while (current < sysInfo.lpMaximumApplicationAddress) {
				current = reinterpret_cast<PVOID>(reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress) + offset);
				VirtualQuery(current, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

				if (mbi.State == MEM_RESERVE) {
					if (current > address) offsetFromAddress = reinterpret_cast<uintptr_t>(current) - reinterpret_cast<uintptr_t>(address);
					else offsetFromAddress = reinterpret_cast<uintptr_t>(address) - reinterpret_cast<uintptr_t>(current);
					reservedRegions.insert(pair<uint64_t, PVOID>(offsetFromAddress, current));
				}

				offset += mbi.RegionSize;
			}

			for (map<uint64_t, PVOID>::iterator it = reservedRegions.begin(); it != reservedRegions.end(); ++it) keys.push_back(it->first);
			return reservedRegions[*min_element(keys.begin(), keys.end())];
		}
