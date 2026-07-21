module;
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h> /* MODULEENTRY32W */
#include <iostream>

module Program;

import std;

bool Program::AttachProcess(DWORD in_pid, const std::string& in_moduleName) 
{
    m_PID = in_pid;
    m_moduleName = in_moduleName;

    if (GetModuleBaseAddress() && OpenProcessHandle())
    {
        m_isProgramConnected = true;
        return true;
    }
    m_isProgramConnected = false;
    return false;
}

[[nodiscard]] uintptr_t Program::GetBaseAddress() const
{
    return m_baseAddress;
}

uintptr_t Program::GetModuleBaseAddress()
{
    uintptr_t baseAddress = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_PID);

    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        std::println("Invalid Handle Value!");
        return 0;
    }

    // to convert from string to wstring
    std::wstring wModuleName(m_moduleName.begin(), m_moduleName.end());

    // Default windows unicode: W
    MODULEENTRY32W modEntry;
    modEntry.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(hSnapshot, &modEntry))
    {
        do
        {
            if (wModuleName == modEntry.szModule)
            {
                baseAddress = reinterpret_cast<uintptr_t>(modEntry.modBaseAddr);
                break;
            }
        } while (Module32NextW(hSnapshot, &modEntry));
    }

    CloseHandle(hSnapshot);

    m_baseAddress = baseAddress;
    return m_baseAddress;
}

HANDLE Program::OpenProcessHandle()
{
    m_hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_PID);
    if (m_hProc == nullptr)
    {
        std::print("Failed to open process with PID {}\n", m_PID);
    }
    else
    {
        std::print("Process opened successfully.\n");
    }

    return m_hProc;
}

