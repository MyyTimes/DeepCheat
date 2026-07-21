module;
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

export module MemoryRegion;

import std;

export 
{
    inline constexpr std::string_view REGION_FILE_NAME = "Outputs/MemoryRegions.txt";
    inline constexpr std::string_view DUMP_FILE_NAME = "Outputs/DumpMemory.txt";
    inline constexpr SIZE_T SMALL_MEMORY_STEP = 0x1000;

    void ListMemoryRegions(HANDLE hProc); // List all memory regions (with protect, type, size)
    [[nodiscard]] std::string_view TypeToString(DWORD type); // mbi.Type -> str
    [[nodiscard]] std::string_view ProtectToString(DWORD protect); // mbi.Protect -> str

    void FindReadableRegions(HANDLE hProc); // find readable regions and call dump func
    void DumpMemoryRegion(std::ofstream& file, HANDLE hProc, BYTE* startAddress, SIZE_T regionSize); /* print memory cells */
    [[nodiscard]] bool IsReadable(DWORD protect); /* detect mbi.Protect */
} 
