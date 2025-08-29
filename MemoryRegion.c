#include "include/MemoryRegion.h"
#include "include/DebugTerminal.h"

void ListMemoryRegions(HANDLE hProc)
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
            fprintf(file, "Base: 0x%p | Protect: %20s | Type: %10s | Size: 0x%Ix\n", mbi.BaseAddress, ProtectToString(mbi.Protect), TypeToString(mbi.Type), mbi.RegionSize);

            currentAddress += mbi.RegionSize;
        }
        else
        {
            currentAddress += SMALL_MEMORY_STEP;
        }
    }

    PrintInfo("Regions saved: %s\n", REGION_FILE_NAME);
    fclose(file);
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
        case PAGE_GUARD: return "GUARD";
        default: return "-";
    }
}

void FindReadableRegions(HANDLE hProc)
{
    FILE *file = fopen(DUMP_FILE_NAME, "w");

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    BYTE *startAddress = (BYTE*)si.lpMinimumApplicationAddress;
    BYTE *endAddress = (BYTE*)si.lpMaximumApplicationAddress;
    BYTE *currentAddress = startAddress;

    MEMORY_BASIC_INFORMATION mbi;

    while(currentAddress < endAddress)
    {
        if(VirtualQueryEx(hProc, currentAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
        {    
            /* show readable region */
            if(IsReadable(mbi.Protect))
            {
                PrintInfo("Region address [%p] is being saved...\n", currentAddress);
                fprintf(file, "\nRegion address: %p", currentAddress);
                DumpMemoryRegion(file, hProc, currentAddress, mbi.RegionSize);
            }   

            currentAddress += mbi.RegionSize;
        }
        else
        {
            currentAddress += SMALL_MEMORY_STEP;
        }
    }

    fclose(file);
}

void DumpMemoryRegion(FILE *file, HANDLE hProc, BYTE *startAddress, SIZE_T regionSize)
{
    const SIZE_T rowSize = READ_ROW_SIZE;
    SIZE_T bytesRead, i;
    BYTE *buffer;

    buffer = (BYTE*)malloc(regionSize);
                
    if(buffer != NULL)
    {
        if(ReadProcessMemory(hProc, startAddress, buffer, regionSize, &bytesRead) && bytesRead > 0)
        {
            for(i = 0; i < regionSize; i++)
            {
                if(i % rowSize == 0)
                {
                    fprintf(file, "\n%p: ", startAddress + i);
                }

                if(i < bytesRead)
                    fprintf(file, "%02X ", *(buffer + i));
                else
                    fprintf(file, "   ");

                if((i % rowSize) == sizeof(uintptr_t) - 1)
                    fprintf(file, "| ");
            }
        }

        free(buffer);
    }
}

BOOL IsReadable(DWORD protect)
{
    return (
        protect == PAGE_READONLY ||
        protect == PAGE_READWRITE ||
        protect == PAGE_WRITECOPY ||
        protect == PAGE_EXECUTE_READ ||
        protect == PAGE_EXECUTE_READWRITE ||
        protect == PAGE_EXECUTE_WRITECOPY
    );
}