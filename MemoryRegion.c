#include "include/MemoryRagion.h"
#include "include/DebugTerminal.h"

void ShowMemoryRegions(HANDLE hProc)
{
    FILE *file = fopen(REGION_FILE_NAME, "w");
    if(file == NULL)
    {
        PrintError("FILE ERROR: Regions could not be saved!\n");
        return;
    }

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    BYTE* startAddress = (BYTE*)si.lpMinimumApplicationAddress;
    BYTE* endAddress = (BYTE*)si.lpMaximumApplicationAddress;
    BYTE* currentAddress = startAddress;

    MEMORY_BASIC_INFORMATION mbi;

    while(currentAddress < endAddress)
    {
        if(VirtualQueryEx(hProc, currentAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
        {            
            fprintf(file, "Base: 0x%p | Protect: %25s | Type: %10s | Size: 0x%Ix\n", mbi.BaseAddress, ProtectToString(mbi.Protect), TypeToString(mbi.Type), mbi.RegionSize);

            currentAddress += mbi.RegionSize;
        }
        else
        {
            currentAddress += SMALL_MEMORY_STEP;
        }
    }

    PrintInfo("Regions saved: %s\n", REGION_FILE_NAME);
}

const char* TypeToString(DWORD type)
{
    switch(type)
    {
        case MEM_IMAGE: return "IMAGE";
        case MEM_MAPPED: return "MAPPED";
        case MEM_PRIVATE: return "PRIVATE";
        default: return "-";
    }
}

const char* ProtectToString(DWORD protect)
{
    switch(protect)
    {
        case PAGE_NOACCESS: return "NO ACCESS";
        case PAGE_READONLY: return "READ";
        case PAGE_READWRITE: return "READ + WRITE";
        case PAGE_WRITECOPY: return "WRITE + COPY";
        case PAGE_EXECUTE: return "EXECUTE";
        case PAGE_EXECUTE_READ: return "EXECUTE READ";
        case PAGE_EXECUTE_READWRITE: return "EXECUTE READ + WRITE";
        case PAGE_EXECUTE_WRITECOPY: return "EXECUTE WRITE + COPY";
        default: return "-";
    }
}
