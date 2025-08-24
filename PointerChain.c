#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include "include/PointerChain.h"

/* Global pointers for storing data and function prototypes */
static PointerInfo *g_pointers = NULL;
static int g_pointerCount = 0;
static PointerChain *g_validChains = NULL;
static int g_chainCount = 0;

void FindPointerChain(FILE *chainFile, HANDLE hProc, uintptr_t targetAddress, uintptr_t offsets[], int depth)
{
    printf("Starting pointer chain search for target: 0x%llX\n", (unsigned long long)targetAddress);
    
    /* Memory allocation */ 
    g_pointers = (PointerInfo*)malloc(MAX_POINTERS_PER_LEVEL * sizeof(PointerInfo)); /* For phase 1 */
    g_validChains = (PointerChain*)malloc(MAX_CHAINS_TO_SAVE * sizeof(PointerChain)); /* To store valid chains */
    
    if (!g_pointers || !g_validChains) 
    {
        printf("Memory allocation failed!\n");
        CleanupPointerData();
        return;
    }
    
    g_pointerCount = 0;
    g_chainCount = 0;
    
    /* Phase 1: Collect all pointers pointing to the target address */
    printf("Phase 1: Collecting pointers to target...\n");
    if (!CollectPointersToTarget(hProc, targetAddress)) 
    {
        printf("Failed to collect pointers to target.\n");
        CleanupPointerData();
        return;
    }
    printf("Found %d pointers pointing to target area.\n", g_pointerCount);
    
    /* Phase 2: Find static pointers among collected pointers */
    printf("Phase 2: Finding static base pointers...\n");
    if (!CountStaticPointers(hProc)) 
    {
        printf("Failed to find static pointers.\n");
        CleanupPointerData();
        return;
    }
    
    /* Phase 3: Create chains from 'static bases' */
    printf("Phase 3: Building chains from static bases...\n");
    if (!BuildChainsFromStatic(hProc, targetAddress)) 
    {
        printf("Failed to build chains from static bases.\n");
        CleanupPointerData();
        return;
    }
    
    /* Phase 4: Validate and save chains */
    printf("Phase 4: Validating and saving chains...\n");
    SaveValidChains(chainFile);
    
    printf("\nFound %d valid pointer chains.\n\n", g_chainCount);
    CleanupPointerData();
}

/* PHASE 1 */
/* Returns TRUE if at least one pointer is found */
BOOL CollectPointersToTarget(HANDLE hProc, uintptr_t targetAddr)
{
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* currentAddress = 0;
    BYTE* buffer;
    SIZE_T bytesRead;
        
    while (VirtualQueryEx(hProc, currentAddress, &mbi, sizeof(mbi)) == sizeof(mbi) && g_pointerCount < MAX_POINTERS_PER_LEVEL) 
    {
        /* Readable region */
        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            
            buffer = (BYTE*)malloc(mbi.RegionSize);
            if (buffer == NULL)
            {
                currentAddress = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
                continue;
            }
            
            if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) 
            {
                for (SIZE_T i = 0; i + sizeof(uintptr_t) <= bytesRead; i += sizeof(uintptr_t)) 
                {
                    uintptr_t ptrValue = *(uintptr_t*)(buffer + i);
                    
                    /* Check if ptrValue points to targetAddr within a reasonable offset (valid iterval) */
                    long long diff = (long long)targetAddr - (long long)ptrValue;
                    
                    if (abs(diff) <= MAX_OFFSET && (diff % sizeof(uintptr_t) == 0 || diff == 0)) 
                    {
                        uintptr_t offset = (uintptr_t)diff;
                        uintptr_t ptrAddress = (uintptr_t)((BYTE*)mbi.BaseAddress + i);
                        
                        BOOL isDuplicate = FALSE;
                        for (int j = 0; j < g_pointerCount; j++) 
                        {
                            if (g_pointers[j].address == ptrAddress) 
                            {
                                isDuplicate = TRUE;
                                break;
                            }
                        }
                        
                        if (!isDuplicate) {
                            /* Save pointer info */
                            g_pointers[g_pointerCount].address = ptrAddress;
                            g_pointers[g_pointerCount].pointedValue = ptrValue;
                            g_pointers[g_pointerCount].offset = offset;
                            g_pointers[g_pointerCount].isStatic = (mbi.Type == MEM_IMAGE);
                            
                            /* Get module info */
                            uintptr_t moduleBase;
                            if(!GetModuleInfo(hProc, ptrAddress, g_pointers[g_pointerCount].moduleName, &moduleBase)) 
                            {
                                strcpy(g_pointers[g_pointerCount].moduleName, "Unknown");
                            }
                            
                            /*
                            printf("Found pointer: [0x%llX] = 0x%llX, offset: %s0x%llX, static: %s\n", (unsigned long long)ptrAddress, (unsigned long long)ptrValue, diff >= 0 ? "+" : "", (unsigned long long)offset, g_pointers[g_pointerCount].isStatic ? "YES" : "NO");
                            */

                            g_pointerCount++;
                            if(g_pointerCount >= MAX_POINTERS_PER_LEVEL) break;
                        }
                    }
                }
            }
            free(buffer);
        }
        currentAddress = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    
    printf("Collected %d total pointers.\n", g_pointerCount);
    return g_pointerCount > 0;
}

/* PHASE 2 */
/* Returns TRUE if at least one static pointer is found */
BOOL CountStaticPointers(HANDLE hProc)
{
    /* Note: Static pointers are already marked during COLLECTION (Phase 1) */
    int staticCount = 0, i;
    for(i = 0; i < g_pointerCount; i++) 
    {
        if (g_pointers[i].isStatic)
            staticCount++;
    }
    
    printf("Found %d static pointers out of %d total pointers.\n", staticCount, g_pointerCount);
    return staticCount > 0;
}

/* PHASE 3 */
/* Build chains starting from static pointers */
BOOL BuildChainsFromStatic(HANDLE hProc, uintptr_t targetAddress)
{
    DWORD pid = GetProcessId(hProc);
    if (pid == 0) return FALSE;

    int depth, i, j;

    /* Depth 1 - Start chain (finding static pointers) */
    for(i = 0; i < g_pointerCount && g_chainCount < MAX_CHAINS_TO_SAVE; i++) 
    {
        if(g_pointers[i].isStatic) 
        {
            PointerChain chain;
            memset(&chain, 0, sizeof(chain)); /* fill with zeros - clean state */
            
            chain.baseAddress = g_pointers[i].address; /* it is chain's base address */
            chain.offsets[0] = g_pointers[i].offset;
            chain.depth = 1;
            strcpy(chain.moduleName, g_pointers[i].moduleName);
            
            /* Calculate static offset */
            DWORD_PTR moduleBase = GetModuleBaseAddress(pid, chain.moduleName);
            if(moduleBase != 0) 
                chain.staticOffset = chain.baseAddress - moduleBase;
            else 
                chain.staticOffset = 0; /* module not found */
            
            /* Validate chain */
            if(ValidateChain(hProc, &chain, targetAddress)) 
            {
                g_validChains[g_chainCount] = chain;
                g_chainCount++;
                printf("Found valid chain: [%s + 0x%llX] + 0x%llX\n", 
                       chain.moduleName, 
                       (unsigned long long)chain.staticOffset,
                       (unsigned long long)chain.offsets[0]);
            }
        }
    }
    
    for(depth = 2; depth <= MAX_DEPTH && g_chainCount < MAX_CHAINS_TO_SAVE; depth++) 
    {        
        for(i = 0; i < g_pointerCount && g_chainCount < MAX_CHAINS_TO_SAVE; i++) 
        {
            if(!g_pointers[i].isStatic) continue; 
            
            PointerChain chain;
            memset(&chain, 0, sizeof(chain)); /* clean state */
            
            chain.baseAddress = g_pointers[i].address;
            chain.offsets[0] = g_pointers[i].offset;
            strcpy(chain.moduleName, g_pointers[i].moduleName);
            
            DWORD_PTR moduleBase = GetModuleBaseAddress(pid, chain.moduleName);
            if (moduleBase != 0)
                chain.staticOffset = chain.baseAddress - moduleBase;
            
            uintptr_t nextTarget = g_pointers[i].pointedValue + g_pointers[i].offset;
            
            if(BuildChainRecursive(hProc, nextTarget, targetAddress, &chain, 1, depth)) 
            {
                if(ValidateChain(hProc, &chain, targetAddress)) 
                {
                    g_validChains[g_chainCount] = chain;
                    g_chainCount++;
                    
                    printf("Found valid (depth %d) chain: [%s + 0x%llX]", 
                           depth, chain.moduleName, (unsigned long long)chain.staticOffset);
                    for (int j = 0; j < depth; j++) {
                        printf(" + 0x%llX", (unsigned long long)chain.offsets[j]);
                        if (j < depth - 1) printf(" ->");
                    }
                    printf("\n");
                }
            }
        }
    } 
    return g_chainCount > 0;
}

BOOL BuildChainRecursive(HANDLE hProc, uintptr_t currentTarget, uintptr_t finalTarget, PointerChain* chain, int currentDepth, int maxDepth)
{
    // Hedefi bulduk mu?
    if (currentTarget == finalTarget) {
        chain->depth = currentDepth;
        return TRUE;
    }
    
    // Maximum derinliğe ulaştık mı?
    if (currentDepth >= maxDepth) {
        printf("Reached max depth without finding target!\n");
        return FALSE;
    }
    
    // currentTarget'e point eden pointer'ları ara
    for (int i = 0; i < g_pointerCount; i++) {
        uintptr_t ptrValue = g_pointers[i].pointedValue;
        
        // Bu pointer currentTarget'e ulaşabiliyor mu?
        long long diff = (long long)currentTarget - (long long)ptrValue;
        
        if (abs(diff) <= MAX_OFFSET && (diff % sizeof(uintptr_t) == 0 || diff == 0)) {
            // Bu pointer'ı chain'e ekle
            chain->offsets[currentDepth] = (uintptr_t)diff;
            
            // Recursive olarak bir sonraki seviyeyi ara
            uintptr_t nextTarget = ptrValue + chain->offsets[currentDepth];
            
            if (BuildChainRecursive(hProc, nextTarget, finalTarget, chain, currentDepth + 1, maxDepth)) {
                return TRUE; // Chain bulundu
            }
        }
    }
    
    return FALSE; // Bu branch'te chain bulunamadı
}

/* PHASE 4 */
/* Validate a pointer chain by dereferencing it step-by-step */
BOOL ValidateChain(HANDLE hProc, PointerChain *chain, uintptr_t expectedTarget)
{
    uintptr_t currentAddr = chain->baseAddress;
    SIZE_T bytesRead;
    
    int i;

    for(i = 0; i < chain->depth; i++) 
    {
        uintptr_t value;
        
        if(!ReadProcessMemory(hProc, (LPCVOID)currentAddr, &value, sizeof(value), &bytesRead) || bytesRead != sizeof(value)) 
        {
            printf("Failed to read memory at 0x%llX\n", (unsigned long long)currentAddr);
            return FALSE;
        }
        
        printf("  Level %d: [0x%llX] = 0x%llX, offset = 0x%llX\n", 
               i, (unsigned long long)currentAddr, (unsigned long long)value, 
               (unsigned long long)chain->offsets[i]);
        
        /* Calculate next address */
        uintptr_t nextAddress = value + chain->offsets[i];
        
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
    fprintf(chainFile, "=== VALID POINTER CHAINS ===\n\n");
    int i, j;
    for(i = 0; i < g_chainCount; i++) 
    {
        PointerChain *chain = &g_validChains[i];
        
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
    
    fprintf(chainFile, "Total valid chains found: %d\n", g_chainCount);
}

/* Clear memory */
void CleanupPointerData()
{
    if (g_pointers) 
    {
        free(g_pointers);
        g_pointers = NULL;
    }
    if (g_validChains) 
    {
        free(g_validChains);
        g_validChains = NULL;
    }
    g_pointerCount = 0;
    g_chainCount = 0;
}

/* Get module information for a given address */
BOOL GetModuleInfo(HANDLE hProc, uintptr_t address, char *moduleName, uintptr_t *moduleBase)
{
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
            uintptr_t modBase = (uintptr_t)me32.modBaseAddr;
            uintptr_t modEnd = modBase + me32.modBaseSize;
            
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
