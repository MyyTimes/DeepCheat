module;
#include <windows.h>
#include <tlhelp32.h>

export module PointerChain;

import std;

// ============================================================
//  PointerChain — C++23 module interface
// ============================================================

export {

    // ── Sabitler ─────────────────────────────────────────────
    inline constexpr int     MAX_DEPTH             = 10;
    inline constexpr int     MAX_POINTERS_PER_LEVEL = 10'000;
    inline constexpr SIZE_T  MAX_OFFSET            = 0x8000;
    inline constexpr int     MAX_CHAINS_TO_SAVE    = 10'000;
    inline constexpr int     MODULE_NAME_SIZE      = 64;

    // ── Veri yapıları ─────────────────────────────────────────

    /* Bir pointer'ın bulunduğu adres ve gösterdiği değer */
    struct PointerInfo
    {
        uintptr_t address      = 0;
        uintptr_t pointedValue = 0;
        uintptr_t offset       = 0;
        bool      isStatic     = false;
        char      moduleName[MODULE_NAME_SIZE] = {};
    };

    /* Geçerli bir pointer zinciri */
    struct Chain
    {
        uintptr_t baseAddress                  = 0;
        uintptr_t offsets[MAX_DEPTH]           = {};
        int       depth                        = 0;
        char      moduleName[MODULE_NAME_SIZE]  = {};
        uintptr_t staticOffset                 = 0;
    };

    // ── Ana işlevler ──────────────────────────────────────────

    void FindPointerChain(std::ofstream& chainFile, HANDLE hProc,
                          uintptr_t targetAddress, int depth);

    void SetTargetModule(std::string_view moduleName);
    void CleanupPointerData();

    // ── Faz fonksiyonları ─────────────────────────────────────

    [[nodiscard]] bool CollectPointersToTarget(HANDLE hProc, uintptr_t targetAddr);   /* Phase 1 */
    [[nodiscard]] bool CountStaticPointers(HANDLE hProc);                              /* Phase 2 */
    [[nodiscard]] bool BuildChainsFromStatic(HANDLE hProc, uintptr_t targetAddress);  /* Phase 3 */
    void               FindDeepChains(HANDLE hProc, uintptr_t targetAddress, int maxDepth); /* Phase 4 */

    [[nodiscard]] bool SearchBackwards(HANDLE hProc, uintptr_t currentAddr,
                                       uintptr_t offsets[], int currentDepth,
                                       int maxDepth, uintptr_t originalTarget);

    [[nodiscard]] bool BuildChainRecursive(HANDLE hProc, uintptr_t currentTarget,
                                           uintptr_t staticPointerValue,
                                           Chain* chain, int currentDepth);

    [[nodiscard]] bool ValidateChain(HANDLE hProc, Chain* chain, uintptr_t expectedTarget);

    void SaveValidChains(std::ofstream& chainFile);

    // ── Yardımcı işlevler ─────────────────────────────────────

    [[nodiscard]] bool        GetModuleInfo(HANDLE hProc, uintptr_t address,
                                             char* moduleName, uintptr_t* moduleBase);
    [[nodiscard]] uintptr_t   GetModuleBaseAddress(DWORD pid, std::string_view moduleName);

} // export
