module;
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

export module Program;
import std;

export class Program
{
public:
    static Program& Get()
    {
        static Program instance;
        return instance;
    }

    Program(const Program&) = delete;
    Program& operator=(const Program&) = delete;

    bool IsProgramConnected() { return m_isProgramConnected; }

    bool AttachProcess(DWORD, const std::string&);
    [[nodiscard]] uintptr_t GetBaseAddress() const;

private:
    // Const. & Dest.
    Program() = default;
    ~Program() = default;

    // Variables
    DWORD m_PID = 0;
    std::string m_moduleName = "";
    uintptr_t m_baseAddress = 0;
    HANDLE m_hProc = nullptr;

    bool m_isProgramConnected = false;

    // Functions
    uintptr_t GetModuleBaseAddress();
    HANDLE OpenProcessHandle();
};

export inline Program& g_Program = Program::Get();

