#ifndef MEMORY_REGION_H
#define MEMORY_REGION_H

#include <windows.h>
#include <stdio.h>

#define SMALL_MEMORY_STEP 0x1000 /* scanning memory to show regions */
#define REGION_FILE_NAME "Outputs/MemoryRegions.txt" /* memory regions info */
#define DUMP_FILE_NAME "Outputs/DumpMemory.txt" /* scanning memory cells */
/*#define READ_ROW_SIZE 16*/

void ListMemoryRegions(HANDLE); /* show each memory regions (with protect, type, size) */
const char* TypeToString(DWORD); /* mbi.Type -> str */
const char* ProtectToString(DWORD); /* mbi.Protect -> str */

void FindReadableRegions(HANDLE); /* find readable regions and call dump func */
void DumpMemoryRegion(FILE*, HANDLE, BYTE*, SIZE_T); /* print memory cells */
BOOL IsReadable(DWORD); /* detect mbi.Protect */

#endif