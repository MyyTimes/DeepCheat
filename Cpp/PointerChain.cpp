module;
#include <windows.h>
#include <tlhelp32.h>
#include <cstring>  /* strncpy, stricmp */

module PointerChain;

import std;
import DebugTerminal;

using namespace Terminal;

// ============================================================
//  PointerChain — C++23 module implementation
//
//  C → C++ dönüşümleri:
//    static PointerInfo* foundPointers  → std::vector<PointerInfo>
//    static PointerChain* validChain    → std::vector<Chain>
//    static char targetModule[]         → std::string
//    malloc / free                      → std::vector (RAII)
//    BOOL / TRUE / FALSE                → bool / true / false
//    C-style cast (TYPE*)               → static_cast / reinterpret_cast
//    FILE*                              → std::ofstream&
//    printf                             → std::print
//    fprintf                            → file << std::format(...)
// ============================================================

namespace {
    std::vector<PointerInfo> foundPointers;
    std::vector<Chain>       validChains;
    std::string              targetModule;
}

// ─────────────────────────────────────────────────────────────
// Ana giriş noktası — tüm fazları sırayla çalıştırır
// ─────────────────────────────────────────────────────────────
void FindPointerChain(std::ofstream& chainFile, HANDLE hProc,
                      uintptr_t targetAddress, int depth)
{
    PrintInfo("Starting pointer chain search for target: {:#x}\n", targetAddress);

    foundPointers.clear();
    foundPointers.reserve(MAX_POINTERS_PER_LEVEL);
    validChains.clear();
    validChains.reserve(MAX_CHAINS_TO_SAVE);

    /* Phase 1 */
    std::print("Phase 1: Collecting pointers to target...\n");
    if (!CollectPointersToTarget(hProc, targetAddress))
    {
        PrintError("Failed to collect pointers to target.\n");
        CleanupPointerData();
        return;
    }
    std::print("Found {} pointers pointing to target area.\n", foundPointers.size());

    /* Phase 2 */
    std::print("Phase 2: Finding static base pointers...\n");
    if (!CountStaticPointers(hProc))
        std::print("No static pointers found in Phase 1, trying deep search...\n");

    /* Phase 3 */
    std::print("Phase 3: Building chains from static bases...\n");
    BuildChainsFromStatic(hProc, targetAddress);

    /* Phase 4 */
    std::print("Phase 4: Deep chain search (multi-level)...\n");
    FindDeepChains(hProc, targetAddress, depth);

    /* Phase 5 */
    std::print("Phase 5: Saving chains to file...\n");
    SaveValidChains(chainFile);

    std::print("\nFound {} valid pointer chains.\n\n", validChains.size());
    CleanupPointerData();
}

// ─────────────────────────────────────────────────────────────
void SetTargetModule(std::string_view moduleName)
{
    if (moduleName.empty())
    {
        targetModule.clear();
        std::print("Module filter disabled - all modules will be searched.\n");
    }
    else
    {
        targetModule = moduleName;
        std::print("Module filter set: Only chains from '{}' will be saved.\n", targetModule);
    }
}

// ─────────────────────────────────────────────────────────────
// PHASE 1 — Hedef adrese işaret eden tüm pointer'ları topla
// ─────────────────────────────────────────────────────────────
bool CollectPointersToTarget(HANDLE hProc, uintptr_t targetAddr)
{
    MEMORY_BASIC_INFORMATION mbi;
    auto* currentAddress = static_cast<BYTE*>(nullptr);

    while (VirtualQueryEx(hProc, currentAddress, &mbi, sizeof(mbi)) == sizeof(mbi) &&
           static_cast<int>(foundPointers.size()) < MAX_POINTERS_PER_LEVEL)
    {
        /* Okunabilir bölge filtresi */
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
        {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead))
            {
                for (SIZE_T i = 0; i + sizeof(uintptr_t) <= bytesRead; i += sizeof(uintptr_t))
                {
                    uintptr_t ptrValue = *reinterpret_cast<const uintptr_t*>(buffer.data() + i);
                    long long  diff    = static_cast<long long>(targetAddr)
                                       - static_cast<long long>(ptrValue);

                    if (std::abs(diff) <= static_cast<long long>(MAX_OFFSET) &&
                        diff % static_cast<long long>(sizeof(uintptr_t)) == 0)
                    {
                        uintptr_t offset     = static_cast<uintptr_t>(diff);
                        uintptr_t ptrAddress = reinterpret_cast<uintptr_t>(
                            static_cast<BYTE*>(mbi.BaseAddress) + i);

                        /* Tekrar eden pointer kontrolü */
                        bool isDuplicate = std::ranges::any_of(foundPointers,
                            [ptrAddress](const PointerInfo& p){ return p.address == ptrAddress; });

                        if (!isDuplicate)
                        {
                            PointerInfo info;
                            info.address      = ptrAddress;
                            info.pointedValue = ptrValue;
                            info.offset       = offset;
                            info.isStatic     = (mbi.Type == MEM_IMAGE); /* .exe ve .dll bölgeleri */

                            uintptr_t moduleBase = 0;
                            if (!GetModuleInfo(hProc, ptrAddress, info.moduleName, &moduleBase))
                                std::strncpy(info.moduleName, "Unknown", MODULE_NAME_SIZE - 1);

                            foundPointers.push_back(info);

                            if (static_cast<int>(foundPointers.size()) >= MAX_POINTERS_PER_LEVEL)
                            {
                                PrintError("Max pointer count reached!\n");
                                break;
                            }
                        }
                    }
                }
            }
        }
        currentAddress = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
    }

    PrintInfo("Collected {} total pointers.\n", foundPointers.size());
    return !foundPointers.empty();
}

// ─────────────────────────────────────────────────────────────
// PHASE 2 — Statik pointer sayısını say (zaten Phase 1'de işaretlendi)
// ─────────────────────────────────────────────────────────────
bool CountStaticPointers(HANDLE /*hProc*/)
{
    auto staticCount = std::ranges::count_if(foundPointers,
        [](const PointerInfo& p){ return p.isStatic; });

    std::print("Found {} static pointers out of {} total pointers.\n",
        staticCount, foundPointers.size());
    return staticCount > 0;
}

// ─────────────────────────────────────────────────────────────
// PHASE 3 — Statik pointer'lardan zincir oluştur
// ─────────────────────────────────────────────────────────────
bool BuildChainsFromStatic(HANDLE hProc, uintptr_t targetAddress)
{
    DWORD pid = GetProcessId(hProc);
    if (pid == 0) return false;

    for (const auto& ptr : foundPointers)
    {
        if (static_cast<int>(validChains.size()) >= MAX_CHAINS_TO_SAVE) break;
        if (!ptr.isStatic) continue;

        Chain chain{};
        chain.baseAddress = ptr.address;
        chain.offsets[0]  = ptr.offset;
        std::strncpy(chain.moduleName, ptr.moduleName, MODULE_NAME_SIZE - 1);

        uintptr_t moduleBase = GetModuleBaseAddress(pid, chain.moduleName);
        if (moduleBase != 0)
            chain.staticOffset = chain.baseAddress - moduleBase;

        uintptr_t nextTarget = ptr.pointedValue + ptr.offset;

        if (nextTarget == targetAddress)
        {
            /* Depth-1 zincir */
            chain.depth = 1;
            if (ValidateChain(hProc, &chain, targetAddress))
            {
                validChains.push_back(chain);
                PrintInfo("Found valid chain (depth 1): [{} + {:#x}] + {:#x}\n",
                    chain.moduleName, chain.staticOffset, chain.offsets[0]);
            }
        }
        else
        {
            /* Daha derin — recursive ara */
            if (BuildChainRecursive(hProc, targetAddress, ptr.pointedValue, &chain, 1))
            {
                if (ValidateChain(hProc, &chain, targetAddress))
                {
                    validChains.push_back(chain);
                    PrintInfo("Found valid chain: [{} + {:#x}]",
                        chain.moduleName, chain.staticOffset);
                    for (int j = 0; j < chain.depth; ++j)
                    {
                        PrintInfo(" + {:#x}", chain.offsets[j]);
                        if (j < chain.depth - 1) std::print(" ->");
                    }
                    std::print("\n");
                }
            }
        }
    }

    return !validChains.empty();
}

// ─────────────────────────────────────────────────────────────
// PHASE 4 — Derin geriye doğru arama
// ─────────────────────────────────────────────────────────────
void FindDeepChains(HANDLE hProc, uintptr_t targetAddress, int maxDepth)
{
    uintptr_t offsets[MAX_DEPTH] = {};

    std::print("Starting deep chain search from target {:#x} (max depth: {})...\n",
        targetAddress, maxDepth);

    SearchBackwards(hProc, targetAddress, offsets, 0, maxDepth, targetAddress);

    std::print("Deep search completed. Found {} additional chains.\n", validChains.size());
}

// ─────────────────────────────────────────────────────────────
// Recursive geriye doğru pointer arama
// ─────────────────────────────────────────────────────────────
bool SearchBackwards(HANDLE hProc, uintptr_t currentAddr, uintptr_t offsets[],
                     int currentDepth, int maxDepth, uintptr_t originalTarget)
{
    if (currentDepth >= maxDepth || currentDepth >= MAX_DEPTH) return false;
    if (static_cast<int>(validChains.size()) >= MAX_CHAINS_TO_SAVE) return false;

    MEMORY_BASIC_INFORMATION mbi;
    auto* scanAddress = static_cast<BYTE*>(nullptr);
    bool  foundAny    = false;

    while (VirtualQueryEx(hProc, scanAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
        {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead))
            {
                for (SIZE_T i = 0;
                     i + sizeof(uintptr_t) <= bytesRead &&
                     static_cast<int>(validChains.size()) < MAX_CHAINS_TO_SAVE;
                     i += sizeof(uintptr_t))
                {
                    uintptr_t ptrValue = *reinterpret_cast<const uintptr_t*>(buffer.data() + i);
                    if (ptrValue == 0) continue;

                    long long diff = static_cast<long long>(currentAddr)
                                   - static_cast<long long>(ptrValue);

                    if (std::abs(diff) <= static_cast<long long>(MAX_OFFSET))
                    {
                        uintptr_t ptrAddress = reinterpret_cast<uintptr_t>(
                            static_cast<BYTE*>(mbi.BaseAddress) + i);
                        offsets[currentDepth] = static_cast<uintptr_t>(diff);

                        char      modName[MODULE_NAME_SIZE] = {};
                        uintptr_t moduleBase                = 0;

                        if (mbi.Type == MEM_IMAGE && GetModuleInfo(hProc, ptrAddress, modName, &moduleBase))
                        {
                            /* Modül filtresi — eşleşmiyorsa daha derine in */
                            if (!targetModule.empty() &&
                                _stricmp(modName, targetModule.c_str()) != 0)
                            {
                                if (currentDepth + 1 < maxDepth)
                                    if (SearchBackwards(hProc, ptrAddress, offsets,
                                                        currentDepth + 1, maxDepth, originalTarget))
                                        foundAny = true;
                                continue;
                            }

                            /* Statik tabanda zincir kur */
                            Chain chain{};
                            chain.baseAddress  = ptrAddress;
                            std::strncpy(chain.moduleName, modName, MODULE_NAME_SIZE - 1);
                            chain.staticOffset = ptrAddress - moduleBase;
                            chain.depth        = currentDepth + 1;

                            /* Offset'leri ters sırada kopyala (tabandan hedefe) */
                            for (int j = 0; j <= currentDepth; ++j)
                                chain.offsets[j] = offsets[currentDepth - j];

                            if (ValidateChain(hProc, &chain, originalTarget))
                            {
                                validChains.push_back(chain);

                                if (chain.depth > 1)
                                {
                                    PrintInfo("Found DEEP chain (depth {}): [{} + {:#x}]",
                                        chain.depth, chain.moduleName, chain.staticOffset);
                                    for (int j = 0; j < chain.depth; ++j)
                                        PrintInfo(" + {:#x}", chain.offsets[j]);
                                    std::print("\n");
                                }
                                foundAny = true;
                            }
                        }
                        else if (currentDepth + 1 < maxDepth)
                        {
                            if (SearchBackwards(hProc, ptrAddress, offsets,
                                                currentDepth + 1, maxDepth, originalTarget))
                                foundAny = true;
                        }
                    }
                }
            }
        }
        scanAddress = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return foundAny;
}

// ─────────────────────────────────────────────────────────────
// Statik pointer değerinden hedef adrese recursive zincir kurma
// ─────────────────────────────────────────────────────────────
bool BuildChainRecursive(HANDLE hProc, uintptr_t currentTarget,
                         uintptr_t staticPointerValue, Chain* chain, int currentDepth)
{
    long long reachDiff = static_cast<long long>(currentTarget)
                        - static_cast<long long>(staticPointerValue);

    if (std::abs(reachDiff) <= static_cast<long long>(MAX_OFFSET) &&
        reachDiff % static_cast<long long>(sizeof(uintptr_t)) == 0)
    {
        chain->offsets[currentDepth] = static_cast<uintptr_t>(reachDiff);
        chain->depth = currentDepth + 1;
        return true;
    }

    if (currentDepth >= MAX_DEPTH)
        return false;

    MEMORY_BASIC_INFORMATION mbi;
    auto* scanAddress = static_cast<BYTE*>(nullptr);

    while (VirtualQueryEx(hProc, scanAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
        {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead))
            {
                for (SIZE_T i = 0; i + sizeof(uintptr_t) <= bytesRead; i += sizeof(uintptr_t))
                {
                    uintptr_t ptrValue = *reinterpret_cast<const uintptr_t*>(buffer.data() + i);
                    long long  diff    = static_cast<long long>(currentTarget)
                                       - static_cast<long long>(ptrValue);

                    if (std::abs(diff) <= static_cast<long long>(MAX_OFFSET) &&
                        diff % static_cast<long long>(sizeof(uintptr_t)) == 0 &&
                        ptrValue != 0)
                    {
                        uintptr_t ptrAddress = reinterpret_cast<uintptr_t>(
                            static_cast<BYTE*>(mbi.BaseAddress) + i);

                        chain->offsets[currentDepth] = static_cast<uintptr_t>(diff);

                        if (BuildChainRecursive(hProc, ptrAddress, staticPointerValue,
                                                chain, currentDepth + 1))
                            return true;
                    }
                }
            }
        }
        scanAddress = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return false;
}

// ─────────────────────────────────────────────────────────────
// Zinciri adım adım takip ederek doğrula
// ─────────────────────────────────────────────────────────────
bool ValidateChain(HANDLE hProc, Chain* chain, uintptr_t expectedTarget)
{
    uintptr_t currentAddr = chain->baseAddress;

    for (int i = 0; i < chain->depth; ++i)
    {
        uintptr_t value    = 0;
        SIZE_T    bytesRead = 0;

        if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(currentAddr),
                               &value, sizeof(value), &bytesRead) ||
            bytesRead != sizeof(value))
        {
            std::print("Failed to read memory at {:#x}\n", currentAddr);
            return false;
        }

        std::print("  Level {}: [{:#x}] = {:#x}, offset = {:#x}\n",
            i, currentAddr, value, chain->offsets[i]);

        uintptr_t nextAddress = value + chain->offsets[i];

        if (i == chain->depth - 1)
            return nextAddress == expectedTarget;
        else
            currentAddr = nextAddress;
    }

    return false;
}

// ─────────────────────────────────────────────────────────────
// Geçerli zincirleri dosyaya kaydet
// ─────────────────────────────────────────────────────────────
void SaveValidChains(std::ofstream& chainFile)
{
    chainFile << "=== VALID POINTER CHAINS ===\n\n";

    for (int i = 0; i < static_cast<int>(validChains.size()); ++i)
    {
        const auto& chain = validChains[i];

        chainFile << std::format("Chain {}:\n", i + 1);
        chainFile << std::format("Module: {}\n", chain.moduleName);
        chainFile << std::format("Module Base Address: {:#x}\n",
            chain.baseAddress - chain.staticOffset);
        chainFile << std::format("Chain Base Address: {:#x}\n", chain.baseAddress);
        chainFile << std::format("Depth: {}\n", chain.depth);
        chainFile << std::format("Chain: [\"{}\" + {:#x}]\n",
            chain.moduleName, chain.staticOffset);
        chainFile << "Offsets:\n";

        for (int j = 0; j < chain.depth; ++j)
            chainFile << std::format("  [{}] {:#x}\n", j, chain.offsets[j]);

        chainFile << "\n";
    }

    chainFile << std::format("Total valid chains found: {}\n", validChains.size());
}

// ─────────────────────────────────────────────────────────────
// Belleği temizle (vector RAII ile otomatik ama açık çağrı için)
// ─────────────────────────────────────────────────────────────
void CleanupPointerData()
{
    foundPointers.clear();
    foundPointers.shrink_to_fit();
    validChains.clear();
    validChains.shrink_to_fit();
}

// ─────────────────────────────────────────────────────────────
// Bir adresin hangi modülde olduğunu bul
// ─────────────────────────────────────────────────────────────
bool GetModuleInfo(HANDLE hProc, uintptr_t address,
                   char* moduleName, uintptr_t* moduleBase)
{
    DWORD pid = GetProcessId(hProc);
    if (pid == 0) return false;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE)
        return false;

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnap, &me32))
    {
        do {
            uintptr_t modBase = reinterpret_cast<uintptr_t>(me32.modBaseAddr);
            uintptr_t modEnd  = modBase + me32.modBaseSize;

            if (address >= modBase && address < modEnd)
            {
                std::strncpy(moduleName, me32.szModule, MODULE_NAME_SIZE - 1);
                moduleName[MODULE_NAME_SIZE - 1] = '\0';
                if (moduleBase) *moduleBase = modBase;
                CloseHandle(hSnap);
                return true;
            }
        } while (Module32Next(hSnap, &me32));
    }

    CloseHandle(hSnap);
    return false;
}

// ─────────────────────────────────────────────────────────────
// Modül adına göre taban adresini al
// ─────────────────────────────────────────────────────────────
uintptr_t GetModuleBaseAddress(DWORD pid, std::string_view moduleName)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE)
        return 0;

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnap, &me32))
    {
        do {
            if (_stricmp(me32.szModule, moduleName.data()) == 0)
            {
                CloseHandle(hSnap);
                return reinterpret_cast<uintptr_t>(me32.modBaseAddr);
            }
        } while (Module32Next(hSnap, &me32));
    }

    std::print("Module '{}' not found in process {}\n", moduleName, pid);
    CloseHandle(hSnap);
    return 0;
}
