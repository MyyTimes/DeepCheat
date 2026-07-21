module;
#include <windows.h>

module MemoryRegion;

import std;
import DebugTerminal;

using namespace Terminal;

void ListMemoryRegions(HANDLE hProc)
{
    std::ofstream file{ std::string(REGION_FILE_NAME) };
    if (!file.is_open())
    {
        PrintError("FILE ERROR: Regions could not be saved! Create 'Outputs' folder!\n");
        return;
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    auto* startAddress = static_cast<BYTE*>(si.lpMinimumApplicationAddress);
    auto* endAddress = static_cast<BYTE*>(si.lpMaximumApplicationAddress);
    auto* currentAddress = startAddress;

    MEMORY_BASIC_INFORMATION mbi;

    while (currentAddress < endAddress)
    {
        if (VirtualQueryEx(hProc, currentAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
        {
            file << std::format(
                "Base: {:#018x} | Protect: {:>20} | Type: {:>10} | Size: {:#010x}\n",
                reinterpret_cast<uintptr_t>(mbi.BaseAddress),
                ProtectToString(mbi.Protect),
                TypeToString(mbi.Type),
                mbi.RegionSize
            );

            currentAddress += mbi.RegionSize;
        }
        else
        {
            currentAddress += SMALL_MEMORY_STEP;
        }
    }

    PrintInfo("Regions saved: {}\n", REGION_FILE_NAME);
}

std::string_view TypeToString(DWORD type)
{
    switch (type)
    {
        case MEM_IMAGE:   return "IMAGE";
        case MEM_MAPPED:  return "MAPPED";
        case MEM_PRIVATE: return "PRIVATE";
        default:          return "-";
    }
}

std::string_view ProtectToString(DWORD protect)
{
    switch (protect)
    {
        case PAGE_NOACCESS:          return "NO ACCESS";
        case PAGE_READONLY:          return "READ";
        case PAGE_READWRITE:         return "READ + WRITE";
        case PAGE_WRITECOPY:         return "WRITE + COPY";
        case PAGE_EXECUTE:           return "EXECUTE";
        case PAGE_EXECUTE_READ:      return "EXECUTE READ";
        case PAGE_EXECUTE_READWRITE: return "EXECUTE READ + WRITE";
        case PAGE_EXECUTE_WRITECOPY: return "EXECUTE WRITE + COPY";
        case PAGE_GUARD:             return "GUARD";
        default:                     return "-";
    }
}

void FindReadableRegions(HANDLE hProc)
{
    std::ofstream file{ std::string(DUMP_FILE_NAME) };
    if (!file.is_open())
    {
        PrintError("FILE ERROR: Dump file could not be opened! Create 'Outputs' folder!\n");
        return;
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    auto* startAddress = static_cast<BYTE*>(si.lpMinimumApplicationAddress);
    auto* endAddress = static_cast<BYTE*>(si.lpMaximumApplicationAddress);
    auto* currentAddress = startAddress;

    MEMORY_BASIC_INFORMATION mbi;

    while (currentAddress < endAddress)
    {
        if (VirtualQueryEx(hProc, currentAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
        {
            /* show readable region */
            if (IsReadable(mbi.Protect))
            {
                PrintInfo("Region address [{:#018x}] is being saved...\n",
                    reinterpret_cast<uintptr_t>(currentAddress));

                file << std::format("\nRegion address: {:#018x}\n",
                    reinterpret_cast<uintptr_t>(currentAddress));

                DumpMemoryRegion(file, hProc, currentAddress, mbi.RegionSize);
            }

            currentAddress += mbi.RegionSize;
        }
        else
        {
            currentAddress += SMALL_MEMORY_STEP;
        }
    }
}

void DumpMemoryRegion(std::ofstream& file, HANDLE hProc, BYTE* startAddress, SIZE_T regionSize)
{
    constexpr SIZE_T rowSize = sizeof(uintptr_t); /* pointer boyutunda satır */

    std::vector<BYTE> buffer(regionSize);
    SIZE_T bytesRead = 0;

    if (!ReadProcessMemory(hProc, startAddress, buffer.data(), regionSize, &bytesRead) || bytesRead == 0)
        return;

    for (SIZE_T i = 0; i < regionSize; ++i)
    {
        if (i % rowSize == 0)
        {
            if (i != 0)
            {
                file << "| ";
                for (SIZE_T j = 0; j < rowSize; ++j)
                {
                    unsigned char c = buffer[i - rowSize + j];
                    file << (c >= 32 && c <= 126 ? static_cast<char>(c) : '.');
                }
                file << " | ";
            }
            file << std::format("\n{:#018x}: ", reinterpret_cast<uintptr_t>(startAddress + i));
        }

        if (i < bytesRead)
            file << std::format("{:02X} ", buffer[i]);
        else
            file << "   "; 
    }

    // last line
    if (regionSize >= rowSize)
    {
        file << "| ";
        for (SIZE_T j = 0; j < rowSize; ++j)
        {
            unsigned char c = buffer[regionSize - rowSize + j];
            file << (c >= 32 && c <= 126 ? static_cast<char>(c) : '.');
        }
        file << " | ";
    }
}

bool IsReadable(DWORD protect)
{
    return protect == PAGE_READONLY          ||
           protect == PAGE_READWRITE         ||
           protect == PAGE_WRITECOPY         ||
           protect == PAGE_EXECUTE_READ      ||
           protect == PAGE_EXECUTE_READWRITE ||
           protect == PAGE_EXECUTE_WRITECOPY;
}
