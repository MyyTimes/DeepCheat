module;
#include <windows.h>

module ScanValue;

import std;

void ScanValue::StartScanningForValue(HANDLE hProc, const ScanValueType& targetValue, const SIZE_T& scanningStepSize, const char& type)
{
    MEMORY_BASIC_INFORMATION mbi;
    auto* offsetAddress = static_cast<BYTE*>(nullptr);

    foundAddresses.clear();

    while (VirtualQueryEx(hProc, offsetAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE))
        {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead))
            {
                for (SIZE_T i = 0; i + scanningStepSize <= bytesRead; i += scanningStepSize)
                {
                    uintptr_t addr = reinterpret_cast<uintptr_t>(static_cast<BYTE*>(mbi.BaseAddress) + i);

                    if (type == 'i')
                    {
                        int current = *reinterpret_cast<const int*>(buffer.data() + i);
                        if (current == targetValue.intValue)
                        {
                            foundAddresses.push_back(addr);
                            std::print("Found address: {:#x} | Value: {}\n", addr, current);
                        }
                    }
                    else if (type == 'd')
                    {
                        double current = *reinterpret_cast<const double*>(buffer.data() + i);
                        if (std::fabs(current - targetValue.doubleValue) < 0.0001)
                        {
                            foundAddresses.push_back(addr);
                            std::print("Found address: {:#x} | Value: {}\n", addr, current);
                        }
                    }
                    else if (type == 'f')
                    {
                        float current = *reinterpret_cast<const float*>(buffer.data() + i);
                        if (std::fabs(current - targetValue.floatValue) < 0.01f)
                        {
                            foundAddresses.push_back(addr);
                            std::print("Found address: {:#x} | Value: {}\n", addr, current);
                        }
                    }
                }
            }
            else
            {
                std::print("Failed to read memory at address {:#x}\n",
                    reinterpret_cast<uintptr_t>(mbi.BaseAddress));
            }
        }
        offsetAddress = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
    }
    std::println(">>Ended (Start)");
}

void ScanValue::ContinueScanningForValue(HANDLE hProc, const ScanValueType& targetValue, const char& type, const SIZE_T& scanningStepSize)
{
    if (hProc == nullptr || hProc == INVALID_HANDLE_VALUE)
    {
        std::println("Invalid Handle!");
        return;
    }

    for (size_t i = 0; i < foundAddresses.size();)
    {
        uintptr_t address = foundAddresses[i];
        ScanValueType readValue{};
        SIZE_T bytesRead = 0;

        if (ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(address), &readValue, scanningStepSize, &bytesRead))
        {
            if (bytesRead == scanningStepSize)
            {
                bool isMatch = false;

                if (type == 'i' && readValue.intValue == targetValue.intValue)
                    isMatch = true;
                else if (type == 'f' && readValue.floatValue == targetValue.floatValue)
                    isMatch = true;
                else if (type == 'd' && readValue.doubleValue == targetValue.doubleValue)
                    isMatch = true;

                if (!isMatch && !foundAddresses.empty())
                {
                    foundAddresses[i] = foundAddresses.back();
                    foundAddresses.pop_back();
                }
                else
                {
                    i++;
                }
            }
        }
    }
    std::println(">>Ended (Continue)");
}

const std::vector<uintptr_t>& ScanValue::GetFoundAddresses()
{
    return foundAddresses; 
}
