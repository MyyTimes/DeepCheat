#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include "include/DebugTerminal.h"
#include "include/PointerChain.h"

/* Global pointers for storing data and function prototypes */
static PointerInfo *foundPointers = NULL;
static int pointerCount = 0;
static PointerChain *validChain = NULL;
static int chainCount = 0;

void FindPointerChain(FILE *chainFile, HANDLE hProc, uintptr_t targetAddress, uintptr_t offsets[], int depth)
{
    PrintInfo("Starting pointer chain search for target: 0x%llX\n", (unsigned long long)targetAddress);
    
    /* Memory allocation */ 
    foundPointers = (PointerInfo*)malloc(MAX_POINTERS_PER_LEVEL * sizeof(PointerInfo)); /* For phase 1 */
    validChain = (PointerChain*)malloc(MAX_CHAINS_TO_SAVE * sizeof(PointerChain)); /* To store valid chains */
    
    if (!foundPointers || !validChain) 
    {
        printf("Memory allocation failed!\n");
        CleanupPointerData();
        return;
    }
    
    pointerCount = 0;
    chainCount = 0;
    
    /* Phase 1: Collect all pointers pointing to the target address */
    printf("Phase 1: Collecting pointers to target...\n");
    if (!CollectPointersToTarget(hProc, targetAddress)) 
    {
        PrintError("Failed to collect pointers to target.\n");
        CleanupPointerData();
        return;
    }
    printf("Found %d pointers pointing to target area.\n", pointerCount);
    
    /* Phase 2: Find static pointers among collected pointers */
    printf("Phase 2: Finding static base pointers...\n");
    if (!CountStaticPointers(hProc)) 
    {
        PrintError("Failed to find static pointers.\n");
        CleanupPointerData();
        return;
    }
    
    /* Phase 3: Create chains from 'static bases' */
    printf("Phase 3: Building chains from static bases...\n");
    if (!BuildChainsFromStatic(hProc, targetAddress)) 
    {
        PrintError("Failed to build chains from static bases.\n");
        CleanupPointerData();
        return;
    }
    
    /* Phase 4: Validate and save chains */
    printf("Phase 4: Validating and saving chains...\n");
    SaveValidChains(chainFile);
    
    printf("\nFound %d valid pointer chains.\n\n", chainCount);
    CleanupPointerData();
}

/* PHASE 1 */
/* Returns TRUE if at least one pointer is found */
BOOL CollectPointersToTarget(HANDLE hProc, uintptr_t targetAddr)
{
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *currentAddress = 0;
    BYTE *buffer;
    SIZE_T bytesRead, i;
    uintptr_t ptrValue, ptrAddress, offset, moduleBase; /* pointer addresses*/
    long long diff; /* target - prtValue */
    BOOL isDuplicate;
    int j;

    while (VirtualQueryEx(hProc, currentAddress, &mbi, sizeof(mbi)) == sizeof(mbi) && pointerCount < MAX_POINTERS_PER_LEVEL) 
    {
        /* Readable region */
        if(mbi.State == MEM_COMMIT && 
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            
            buffer = (BYTE*)malloc(mbi.RegionSize);
            if(buffer == NULL)
            {
                currentAddress = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
                continue;
            }
            
            if(ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) 
            {
                for(i = 0; i + sizeof(uintptr_t) <= bytesRead; i += sizeof(uintptr_t)) 
                {
                    ptrValue = *(uintptr_t*)(buffer + i);
                    
                    /* Check if ptrValue points to targetAddr within a reasonable offset (valid iterval) */
                    diff = (long long)targetAddr - (long long)ptrValue;
                    
                    if(abs(diff) <= MAX_OFFSET && diff % sizeof(uintptr_t) == 0) /* diff == 0 */
                    {
                        offset = (uintptr_t)diff;
                        ptrAddress = (uintptr_t)((BYTE*)mbi.BaseAddress + i);
                        
                        isDuplicate = FALSE;
                        for(j = 0; j < pointerCount; j++) 
                        {
                            if(foundPointers[j].address == ptrAddress) 
                            {
                                isDuplicate = TRUE;
                                break;
                            }
                        }
                        
                        if (!isDuplicate) 
                        {
                            /* Save pointer info */
                            foundPointers[pointerCount].address = ptrAddress;
                            foundPointers[pointerCount].pointedValue = ptrValue;
                            foundPointers[pointerCount].offset = offset;
                            foundPointers[pointerCount].isStatic = (mbi.Type == MEM_IMAGE); /* .exe and .dll regions */
                            
                            /* Get module info */
                            if(!GetModuleInfo(hProc, ptrAddress, foundPointers[pointerCount].moduleName, &moduleBase)) 
                            {
                                strcpy(foundPointers[pointerCount].moduleName, "Unknown");
                            }
                            
                            /*
                            printf("Found pointer: [0x%llX] = 0x%llX, offset: %s0x%llX, static: %s\n", (unsigned long long)ptrAddress, (unsigned long long)ptrValue, diff >= 0 ? "+" : "", (unsigned long long)offset, foundPointers[pointerCount].isStatic ? "YES" : "NO");
                            */

                            pointerCount++;
                            if(pointerCount >= MAX_POINTERS_PER_LEVEL)
                            {
                                PrintError("Max pointer count reached!\n");
                                break;
                            }
                        }
                    }
                }
            }
            free(buffer);
        }
        currentAddress = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    
    PrintInfo("Collected %d total pointers.\n", pointerCount);
    return pointerCount > 0;
}

/* PHASE 2 */
/* Returns TRUE if at least one static pointer is found */
BOOL CountStaticPointers(HANDLE hProc)
{
    /* Note: Static pointers are already marked during COLLECTION (Phase 1) */
    int staticCount = 0, i;
    for(i = 0; i < pointerCount; i++) 
    {
        if (foundPointers[i].isStatic)
            staticCount++;
    }
    
    printf("Found %d static pointers out of %d total pointers.\n", staticCount, pointerCount);
    return staticCount > 0;
}

/* PHASE 3 */
/* Build chains starting from static pointers */
BOOL BuildChainsFromStatic(HANDLE hProc, uintptr_t targetAddress)
{
    DWORD pid = GetProcessId(hProc);
    if (pid == 0) return FALSE;

    int depth, i, j;
    PointerChain chain;
    DWORD_PTR moduleBase;
    uintptr_t nextTarget;

    for(i = 0; i < pointerCount && chainCount < MAX_CHAINS_TO_SAVE; i++) 
    {
        if(!foundPointers[i].isStatic) continue;

        memset(&chain, 0, sizeof(chain));

        chain.baseAddress = foundPointers[i].address;
        chain.offsets[0] = foundPointers[i].offset; 
        strcpy(chain.moduleName, foundPointers[i].moduleName);

        moduleBase = GetModuleBaseAddress(pid, chain.moduleName);
        if(moduleBase != 0)
            chain.staticOffset = chain.baseAddress - moduleBase;
        
        nextTarget = foundPointers[i].pointedValue + foundPointers[i].offset;

        if(BuildChainRecursive(hProc, nextTarget, targetAddress, &chain, 1)) 
        {
            if(ValidateChain(hProc, &chain, targetAddress)) 
            {
                validChain[chainCount] = chain;
                chainCount++;
                PrintInfo("Found valid chain: [%s + 0x%llX]", chain.moduleName, (unsigned long long)chain.staticOffset);
                for(j = 0; j < chain.depth; j++) 
                {
                    PrintInfo(" + 0x%llX", (unsigned long long)chain.offsets[j]);
                    if(j < chain.depth - 1) printf(" ->");
                }
                printf("\n");
            }
        }
    }

    return chainCount > 0;
}

BOOL BuildChainRecursive(HANDLE hProc, uintptr_t currentTarget, uintptr_t finalTarget, PointerChain* chain, int currentDepth)
{
    uintptr_t ptrValue, nextTarget;
    long long diff;
    int i;

    /* Reached the target */
    if (currentTarget == finalTarget) 
    {
        chain->depth = currentDepth;
        return TRUE;
    }
    
    /* Chain length limit */
    if (currentDepth >= MAX_DEPTH) 
    {
        PrintError("Reached max depth without finding target!\n");
        return FALSE;
    }

    // currentTarget'e point eden pointer'ları ara
    for(i = 0; i < pointerCount; i++) 
    {
        ptrValue = foundPointers[i].pointedValue;
        
        // Bu pointer currentTarget'e ulaşabiliyor mu?
        diff = (long long)currentTarget - (long long)ptrValue;
        
        if (abs(diff) <= MAX_OFFSET && diff % sizeof(uintptr_t) == 0) 
        {
            chain->offsets[currentDepth] = (uintptr_t)diff; /* add to chain */

            //nextTarget = foundPointers[i].address;  
            nextTarget = ptrValue + chain->offsets[currentDepth];

            if(BuildChainRecursive(hProc, nextTarget, finalTarget, chain, currentDepth + 1)) 
            {
                return TRUE; /* chain found */
            }
        }
    }

    return FALSE; /* chain not found */
}

/* PHASE 4 */
/* Validate a pointer chain by dereferencing it step-by-step */
BOOL ValidateChain(HANDLE hProc, PointerChain *chain, uintptr_t expectedTarget)
{
    uintptr_t currentAddr = chain->baseAddress;
    uintptr_t value, nextAddress;
    SIZE_T bytesRead;
    
    int i;

    for(i = 0; i < chain->depth; i++) 
    {        
        if(!ReadProcessMemory(hProc, (LPCVOID)currentAddr, &value, sizeof(value), &bytesRead) || bytesRead != sizeof(value)) 
        {
            printf("Failed to read memory at 0x%llX\n", (unsigned long long)currentAddr);
            return FALSE;
        }
        
        printf("  Level %d: [0x%llX] = 0x%llX, offset = 0x%llX\n", 
               i, (unsigned long long)currentAddr, (unsigned long long)value, 
               (unsigned long long)chain->offsets[i]);
        
        /* Calculate next address */
        nextAddress = value + chain->offsets[i];
        
        /* If this is the last level, check if we reached the target */
        if(i == chain->depth - 1) 
        {
            /* Is last level the expected target? */
            return nextAddress == expectedTarget ? TRUE : FALSE;
        } 
        else 
        {
            /* Move to next level */
            currentAddr = nextAddress;
        }
    }
    
    return FALSE;
}

// Geçerli chain'leri dosyaya kaydet
void SaveValidChains(FILE *chainFile)
{
    PointerChain *chain = NULL;
    int i, j;

    fprintf(chainFile, "=== VALID POINTER CHAINS ===\n\n");
    for(i = 0; i < chainCount; i++) 
    {
        chain = &validChain[i];
        
        fprintf(chainFile, "Chain %d:\n", i + 1);
        fprintf(chainFile, "Module: %s\n", chain->moduleName);
        fprintf(chainFile, "Module Base Address: 0x%llX\n", (unsigned long long)(chain->baseAddress - chain->staticOffset));
        fprintf(chainFile, "Chain Base Address: 0x%llX\n", (unsigned long long)chain->baseAddress);
        fprintf(chainFile, "Depth: %d\n", chain->depth);
        fprintf(chainFile, "Chain: [\"%s\" + 0x%llX]", chain->moduleName, (unsigned long long)chain->staticOffset);
        
        for(j = 0; j < chain->depth; j++) 
        {
            fprintf(chainFile, " + 0x%llX", (unsigned long long)chain->offsets[j]);
            
            if (j < chain->depth - 1)
                fprintf(chainFile, " -> ");
        }
        fprintf(chainFile, "\n\n");
    }
    
    fprintf(chainFile, "Total valid chains found: %d\n", chainCount);
}

/* Clear memory */
void CleanupPointerData()
{
    if (foundPointers) 
    {
        free(foundPointers);
        foundPointers = NULL;
    }
    if (validChain) 
    {
        free(validChain);
        validChain = NULL;
    }
    pointerCount = 0;
    chainCount = 0;
}

/* Get module information for a given address */
BOOL GetModuleInfo(HANDLE hProc, uintptr_t address, char *moduleName, uintptr_t *moduleBase)
{
    uintptr_t modBase, modEnd;

    DWORD pid = GetProcessId(hProc);
    if (pid == 0) return FALSE;
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    if(Module32First(hSnap, &me32)) 
    {
        do{
            modBase = (uintptr_t)me32.modBaseAddr;
            modEnd = modBase + me32.modBaseSize;
            
            if (address >= modBase && address < modEnd) 
            {
                strcpy(moduleName, me32.szModule);
                if (moduleBase) *moduleBase = modBase;
                CloseHandle(hSnap);
                return TRUE;
            }

        } while(Module32Next(hSnap, &me32));
    }
    
    CloseHandle(hSnap);
    return FALSE;
}
