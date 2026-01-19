#include "PointerChain.h"
#include "DebugTerminal.h"

/* Global pointers for storing data and function prototypes */
static PointerInfo *foundPointers = NULL;
static int pointerCount = 0;
static PointerChain *validChain = NULL;
static int chainCount = 0;

/* Module filter - if set, only chains from this module will be saved */
static char targetModule[MODULE_NAME_SIZE] = {0};

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
        printf("No static pointers found in Phase 1, trying deep search...\n");
    }
    
    /* Phase 3: Create chains from 'static bases' (depth-1 chains) */
    printf("Phase 3: Building chains from static bases...\n");
    BuildChainsFromStatic(hProc, targetAddress);
    
    /* Phase 4: Deep chain search - start from target and work backwards */
    printf("Phase 4: Deep chain search (multi-level)...\n");
    FindDeepChains(hProc, targetAddress, depth);
    
    /* Phase 5: Validate and save chains */
    printf("Phase 5: Saving chains to file...\n");
    SaveValidChains(chainFile);
    
    printf("\nFound %d valid pointer chains.\n\n", chainCount);
    CleanupPointerData();
}

/* Set module filter - pass NULL or empty string to disable filtering */
void SetTargetModule(const char* moduleName)
{
    if(moduleName == NULL || moduleName[0] == '\0')
    {
        targetModule[0] = '\0';
        printf("Module filter disabled - all modules will be searched.\n");
    }
    else
    {
        strncpy(targetModule, moduleName, MODULE_NAME_SIZE - 1);
        targetModule[MODULE_NAME_SIZE - 1] = '\0';
        printf("Module filter set: Only chains from '%s' will be saved.\n", targetModule);
    }
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
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) 
        {
            
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
        
        /* Calculate where this static pointer leads to */
        nextTarget = foundPointers[i].pointedValue + foundPointers[i].offset;
        
        /* If this static pointer directly points to target, it's a depth-1 chain */
        if(nextTarget == targetAddress)
        {
            chain.depth = 1;
            if(ValidateChain(hProc, &chain, targetAddress)) 
            {
                validChain[chainCount] = chain;
                chainCount++;
                PrintInfo("Found valid chain (depth 1): [%s + 0x%llX] + 0x%llX\n", 
                    chain.moduleName, (unsigned long long)chain.staticOffset,
                    (unsigned long long)chain.offsets[0]);
            }
        }
        else
        {
            /* Need to find intermediate pointers - search from target back to this pointer's value */
            if(BuildChainRecursive(hProc, targetAddress, foundPointers[i].pointedValue, &chain, 1)) 
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
    }

    return chainCount > 0;
}

/* PHASE 4: Deep chain search - start from target and search backwards */
void FindDeepChains(HANDLE hProc, uintptr_t targetAddress, int maxDepth)
{
    PointerChain chain;
    uintptr_t offsets[MAX_DEPTH];
    
    memset(offsets, 0, sizeof(offsets));
    memset(&chain, 0, sizeof(chain));
    
    printf("Starting deep chain search from target 0x%llX (max depth: %d)...\n", 
           (unsigned long long)targetAddress, maxDepth);
    
    /* Search backwards from target */
    SearchBackwards(hProc, targetAddress, offsets, 0, maxDepth, targetAddress);
    
    printf("Deep search completed. Found %d additional chains.\n", chainCount);
}

/* Recursive backward search for pointer chains */
BOOL SearchBackwards(HANDLE hProc, uintptr_t currentAddr, uintptr_t offsets[], int currentDepth, int maxDepth, uintptr_t originalTarget)
{
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *scanAddress = 0;
    BYTE *buffer;
    SIZE_T bytesRead;
    size_t i;
    uintptr_t ptrValue, ptrAddress;
    long long diff;
    PointerChain chain;
    DWORD_PTR moduleBase;
    char moduleName[MODULE_NAME_SIZE];
    BOOL foundAny = FALSE;
    int j;
    
    if (currentDepth >= maxDepth || currentDepth >= MAX_DEPTH)
        return FALSE;
    
    if (chainCount >= MAX_CHAINS_TO_SAVE)
        return FALSE;
    
    /* Scan entire memory for pointers pointing to currentAddr */
    while (VirtualQueryEx(hProc, scanAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) 
    {
        /* Only scan readable regions */
        if(mbi.State == MEM_COMMIT && 
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) 
        {
            buffer = (BYTE*)malloc(mbi.RegionSize);
            if(buffer == NULL)
            {
                scanAddress = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
                continue;
            }
            
            if(ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) 
            {
                for(i = 0; i + sizeof(uintptr_t) <= bytesRead && chainCount < MAX_CHAINS_TO_SAVE; i += sizeof(uintptr_t)) 
                {
                    ptrValue = *(uintptr_t*)(buffer + i);
                    
                    /* Skip NULL pointers */
                    if (ptrValue == 0) continue;
                    
                    /* Check if this pointer can reach currentAddr with an offset */
                    diff = (long long)currentAddr - (long long)ptrValue;
                    
                    if(labs(diff) <= MAX_OFFSET) 
                    {
                        ptrAddress = (uintptr_t)((BYTE*)mbi.BaseAddress + i);
                        
                        /* Store this offset */
                        offsets[currentDepth] = (uintptr_t)diff;
                        
                        /* Check if this pointer is in a static module region */
                        if(mbi.Type == MEM_IMAGE && GetModuleInfo(hProc, ptrAddress, moduleName, &moduleBase))
                        {
                            /* Check module filter - skip if doesn't match target module */
                            if(targetModule[0] != '\0' && _stricmp(moduleName, targetModule) != 0)
                            {
                                /* Module doesn't match filter, continue searching */
                                if(currentDepth + 1 < maxDepth)
                                {
                                    if(SearchBackwards(hProc, ptrAddress, offsets, currentDepth + 1, maxDepth, originalTarget))
                                    {
                                        foundAny = TRUE;
                                    }
                                }
                                continue;
                            }
                            
                            /* Found a static base in target module! Build the chain */
                            memset(&chain, 0, sizeof(chain));
                            chain.baseAddress = ptrAddress;
                            strcpy(chain.moduleName, moduleName);
                            chain.staticOffset = ptrAddress - moduleBase;
                            chain.depth = currentDepth + 1;
                            
                            /* Copy offsets in reverse order (from base to target) */
                            for(j = 0; j <= currentDepth; j++)
                            {
                                chain.offsets[j] = offsets[currentDepth - j];
                            }
                            
                            /* Validate and save */
                            if(ValidateChain(hProc, &chain, originalTarget))
                            {
                                validChain[chainCount] = chain;
                                chainCount++;
                                
                                if(chain.depth > 1)
                                {
                                    PrintInfo("Found DEEP chain (depth %d): [%s + 0x%llX]", 
                                        chain.depth, chain.moduleName, (unsigned long long)chain.staticOffset);
                                    for(j = 0; j < chain.depth; j++)
                                    {
                                        PrintInfo(" + 0x%llX", (unsigned long long)chain.offsets[j]);
                                    }
                                    printf("\n");
                                }
                                
                                foundAny = TRUE;
                            }
                        }
                        else if(currentDepth + 1 < maxDepth)
                        {
                            /* Not static, continue searching backwards */
                            if(SearchBackwards(hProc, ptrAddress, offsets, currentDepth + 1, maxDepth, originalTarget))
                            {
                                foundAny = TRUE;
                            }
                        }
                    }
                }
            }
            free(buffer);
        }
        scanAddress = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    
    return foundAny;
}

BOOL BuildChainRecursive(HANDLE hProc, uintptr_t currentTarget, uintptr_t staticPointerValue, PointerChain* chain, int currentDepth)
{
    /* 
     * currentTarget: The address we're trying to reach with a pointer
     * staticPointerValue: The value that the static base pointer points to
     * We're searching backwards from target to static pointer's value
     */
    
    /* Check if currentTarget is reachable from staticPointerValue */
    long long reachDiff = (long long)currentTarget - (long long)staticPointerValue;
    if(labs(reachDiff) <= MAX_OFFSET && reachDiff % sizeof(uintptr_t) == 0)
    {
        /* Found! The static pointer can reach currentTarget directly */
        chain->offsets[currentDepth] = (uintptr_t)reachDiff;
        chain->depth = currentDepth + 1;
        return TRUE;
    }
    
    /* Chain length limit */
    if (currentDepth >= MAX_DEPTH) 
    {
        return FALSE;
    }

    /* Dynamically scan memory for pointers pointing to currentTarget */
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *scanAddress = 0;
    BYTE *buffer;
    SIZE_T bytesRead;
    size_t i;
    uintptr_t ptrValue, ptrAddress;
    long long diff;

    while (VirtualQueryEx(hProc, scanAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) 
    {
        /* Readable region - skip module regions to avoid too many results */
        if(mbi.State == MEM_COMMIT && 
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) 
        {
            buffer = (BYTE*)malloc(mbi.RegionSize);
            if(buffer == NULL)
            {
                scanAddress = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
                continue;
            }
            
            if(ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) 
            {
                for(i = 0; i + sizeof(uintptr_t) <= bytesRead; i += sizeof(uintptr_t)) 
                {
                    ptrValue = *(uintptr_t*)(buffer + i);
                    
                    /* Check if this pointer points near currentTarget */
                    diff = (long long)currentTarget - (long long)ptrValue;
                    
                    if(labs(diff) <= MAX_OFFSET && diff % sizeof(uintptr_t) == 0 && ptrValue != 0) 
                    {
                        ptrAddress = (uintptr_t)((BYTE*)mbi.BaseAddress + i);
                        
                        /* Store offset for this level */
                        chain->offsets[currentDepth] = (uintptr_t)diff;
                        
                        /* Recursively search for pointers pointing to this pointer's address */
                        if(BuildChainRecursive(hProc, ptrAddress, staticPointerValue, chain, currentDepth + 1)) 
                        {
                            free(buffer);
                            return TRUE; /* Chain found */
                        }
                    }
                }
            }
            free(buffer);
        }
        scanAddress = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }

    return FALSE; /* Chain not found at this level */
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
        fprintf(chainFile, "Chain: [\"%s\" + 0x%llX]\n", chain->moduleName, (unsigned long long)chain->staticOffset);
        fprintf(chainFile, "Offsets:\n");
        
        for(j = 0; j < chain->depth; j++) 
        {
            fprintf(chainFile, "  [%d] 0x%llX\n", j, (unsigned long long)chain->offsets[j]);
        }
        fprintf(chainFile, "\n");
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
    if (hSnap == INVALID_HANDLE_VALUE) 
        return FALSE;

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
