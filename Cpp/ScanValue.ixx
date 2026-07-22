module;
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <vector>

export module ScanValue;

export namespace ScanValue
{
    union ScanValueType
    {
        int    intValue;
        float  floatValue;
        double doubleValue;
    };

	std::vector<uintptr_t> foundAddresses;

	void StartScanningForValue(HANDLE, const ScanValueType&, const SIZE_T&, const char&);
	void ContinueScanningForValue(HANDLE, const ScanValueType&, const char&, const SIZE_T&);

    const std::vector<uintptr_t>& GetFoundAddresses();
}