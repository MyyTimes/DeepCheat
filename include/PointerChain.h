#ifndef POINTER_CHAIN_H
#define POINTER_CHAIN_H

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define MAX_DEPTH 4
#define MAX_POINTERS_PER_LEVEL 1000
#define MAX_OFFSET 0x2000  // Maximum reasonable offset
#define MAX_CHAINS_TO_SAVE 50
#define MAX_FILE_NAME_SIZE 50

/* To store pointer information */
typedef struct {
    uintptr_t address;      /* Address of the pointer */
    uintptr_t pointedValue; /* Value the pointer points to (it is also address) */
    uintptr_t offset;       /* Offset from the pointer to the target */
    BOOL isStatic;          /* Is this pointer in a static (module) region? */
    char moduleName[64];    /* Module name */
} PointerInfo;

/* To store a valid pointer chain */
typedef struct {
    uintptr_t baseAddress;  /* Starting address (module base + static offset) */
    uintptr_t offsets[MAX_DEPTH]; /* Offsets in the chain */
    int depth;              /* Depth of the chain */
    char moduleName[64];    /* Base module name */
    uintptr_t staticOffset; /* From module base to static address */
} PointerChain;

void FindPointerChain(FILE*, HANDLE, uintptr_t, uintptr_t[], int);
BOOL CollectPointersToTarget(HANDLE, uintptr_t); /* PHASE 1 */
BOOL CountStaticPointers(HANDLE); /* PHASE 2 */
BOOL BuildChainsFromStatic(HANDLE, uintptr_t); /* PHASE 3 */
BOOL BuildChainRecursive(HANDLE, uintptr_t, uintptr_t, PointerChain*, int, int);
BOOL ValidateChain(HANDLE, PointerChain*, uintptr_t); /* PHASE 4 */
void SaveValidChains(FILE*);
void CleanupPointerData();
BOOL GetModuleInfo(HANDLE, uintptr_t, char*, uintptr_t*);
DWORD_PTR GetModuleBaseAddress(DWORD, const char*);

#endif /* POINTER_CHAIN_H */