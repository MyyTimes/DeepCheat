#ifndef MEMORY_REGION_H
#define MEMORY_REGION_H

#include <windows.h>
#include <stdio.h>

#define SMALL_MEMORY_STEP 0x1000 /* scanning memory to show regions */
#define REGION_FILE_NAME "Outputs/MemoryRegions.txt"

void ShowMemoryRegions(HANDLE);
const char* TypeToString(DWORD);
const char* ProtectToString(DWORD);

#endif