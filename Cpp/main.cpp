#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "ImGUI/imgui.h"
#include "ImGUI/imgui_impl_win32.h"
#include "ImGUI/imgui_impl_dx11.h"
#include <d3d11.h>
#include <tchar.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "d3dcompiler.lib")

import std;
import Program;
import DirectX11;
import DebugTerminal;
import MemoryRegion;

//import PointerChain;

using namespace Terminal;

inline constexpr int MAX_CHAR_SIZE = 64;

union ScanValue
{
    int    intValue;
    float  floatValue;
    double doubleValue;
};

void Menu();
void SetModule(DWORD&, std::string&);
void ScanForValue(HANDLE, ScanValue, char);
bool InputScanValue(char&, ScanValue&);
std::ofstream OpenChainFile();


int main()
{
    std::print("Welcome to DeepCheat!\n");

    // Create window
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, dx11::WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"DeepCheat_Class", nullptr };
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"DeepCheat - DirectX11", WS_OVERLAPPEDWINDOW, 100, 100, 600, 400, nullptr, nullptr, wc.hInstance, nullptr);

    // Start DiretX11
    if (!dx11::CreateDeviceD3D(hwnd))
    {
        dx11::CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    // Start ImGUI 
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsDark();

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(dx11::g_pd3dDevice, dx11::g_pd3dDeviceContext);

    // Draw the window
    bool closed = false;
    while (!closed)
    {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                closed = true;
        }
        if (closed) break;

        if (dx11::g_ResizeWidth != 0 && dx11::g_ResizeHeight != 0)
        {
            dx11::CleanupRenderTarget();
            dx11::g_pSwapChain->ResizeBuffers(0, dx11::g_ResizeWidth, dx11::g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            dx11::g_ResizeWidth = dx11::g_ResizeHeight = 0;
            dx11::CreateRenderTarget();
        }

        // Start new frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // -------------------------------------------------------------
        static int inputPid = 0;
        static char inputModuleName[128] = "GameAssembly.dll";

        ImGui::Begin("DeepCheat Control Panel");
        ImGui::Text("--- Connect Process ---");

        ImGui::InputInt("Process ID (PID)", &inputPid);
        ImGui::InputText("Modul Name", inputModuleName, sizeof(inputModuleName));

        if (ImGui::Button("Connect Process"))
        {
            g_Program.AttachProcess(inputPid, std::string(inputModuleName));
        }

        ImGui::Separator();

        if (g_Program.IsProgramConnected())
        {
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Basariyla Baglanildi!");
            ImGui::Text("Base Address: 0x%llX", static_cast<unsigned long long>(g_Program.GetBaseAddress()));
        }
        else
        {
            ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Baglanti Bekleniyor veya Basarisiz...");
        }


        ImGui::End();
        // -------------------------------------------------------------

        // Demo Window
        ImGui::ShowDemoWindow();
        
        
        // Render process
        ImGui::Render();
        const float clear_color_with_alpha[4] = { 0.15f, 0.15f, 0.15f, 1.00f };
        dx11::g_pd3dDeviceContext->OMSetRenderTargets(1, &dx11::g_mainRenderTargetView, nullptr);
        dx11::g_pd3dDeviceContext->ClearRenderTargetView(dx11::g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        dx11::g_pSwapChain->Present(1, 0);
    }

    // Shutdown
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    dx11::CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}

#if 0
void Menu()
{
    DWORD pid = 0;
    std::string moduleName;

    SetModule(pid, moduleName);
    HANDLE hProc = OpenProcessHandle(pid);
    if (hProc == nullptr)
        return;

    char type{};
    ScanValue targetValue{};
    uintptr_t targetAddress = 0;

    char choice = '0';

    while (choice != 'X' && choice != 'x')
    {
        std::print("\n------------------\n");
        std::print("Current PID: {}\n", pid);
        std::print("------------------\n");
        std::print("1. Get module base address\n"
            "2. Set PID\n"
            "3. Scan for value\n"
            "4. Find pointer chain\n"
            "5. List memory regions\n"
            "6. Print memory cells\n"
            "X. Exit\n");
        std::print("Please select an option: ");

        std::cin >> choice;

        switch (choice)
        {
        case '1':
        { // This scope is for moduleBaseAddress to initilize in case
            uintptr_t moduleBaseAddress = GetModuleBaseAddress(pid, moduleName);
            std::print("Module Base Address: {:#x}\n", moduleBaseAddress);
            break;
        }

        case '2': /* Rearrenge PID and module name */
            SetModule(pid, moduleName);
            if (hProc != nullptr) CloseHandle(hProc);
            hProc = OpenProcessHandle(pid);
            if (hProc == nullptr) return;
            break;

        case '3': /* Scan an value */
            if (InputScanValue(type, targetValue))
                ScanForValue(hProc, targetValue, type);
            break;

        case '4': /* Find pointer chain */ // --------------------------> bu kısmı revize et
        {
            /*
            std::print("Enter the target address to find pointer chain: ");
            std::cin >> targetAddress;

            int maxDepth = 0;
            std::print("Enter max chain depth (1-10, recommended: 7): ");
            std::cin >> maxDepth;
            maxDepth = std::clamp(maxDepth, 1, MAX_DEPTH);

            char filterModuleBuf[MAX_CHAR_SIZE] = {};
            std::print("Enter target module name (e.g. GameAssembly.dll) or press Enter for all: ");
            std::cin >> filterModuleBuf;
            filterModuleBuf[std::strcspn(filterModuleBuf, "\n")] = '\0';
            SetTargetModule(filterModuleBuf);

            std::ofstream chainFile = OpenChainFile();
            if (!chainFile.is_open())
                chainFile.open("Outputs/chains.txt");

            FindPointerChain(chainFile, hProc, static_cast<uintptr_t>(targetAddress), maxDepth);
            std::print("Pointer chains have been written to the file.\n");
            */
            break;
        }

        case '5': /* List memory regions */
            ListMemoryRegions(hProc);
            break;

        case '6': /* Write memory cells */
            FindReadableRegions(hProc);
            break;

        case 'X':
        case 'x':
            std::print("Exiting DeepCheat...\n");
            break;

        default:
            std::print("Invalid choice, please try again.\n");
            break;
        }
    }

    CloseHandle(hProc);
}
#endif


void ScanForValue(HANDLE hProc, ScanValue targetValue, char type)
{
    SIZE_T stepSize = 0;
    switch (type)
    {
    case 'i': stepSize = sizeof(int); break;
    case 'f': stepSize = sizeof(float); break;
    case 'd': stepSize = sizeof(double); break;
    default:  return;
    }

    MEMORY_BASIC_INFORMATION mbi;
    auto* offsetAddress = static_cast<BYTE*>(nullptr);

    while (VirtualQueryEx(hProc, offsetAddress, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE))
        {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead))
            {
                for (SIZE_T i = 0; i + stepSize <= bytesRead; i += stepSize)
                {
                    uintptr_t addr = reinterpret_cast<uintptr_t>(
                        static_cast<BYTE*>(mbi.BaseAddress) + i);

                    if (type == 'i')
                    {
                        int current = *reinterpret_cast<const int*>(buffer.data() + i);
                        if (current == targetValue.intValue)
                            std::print("Found address: {:#x} | Value: {}\n", addr, current);
                    }
                    else if (type == 'd')
                    {
                        double current = *reinterpret_cast<const double*>(buffer.data() + i);
                        if (std::fabs(current - targetValue.doubleValue) < 0.0001)
                            std::print("Found address: {:#x} | Value: {}\n", addr, current);
                    }
                    else if (type == 'f')
                    {
                        float current = *reinterpret_cast<const float*>(buffer.data() + i);
                        if (std::fabs(current - targetValue.floatValue) < 0.01f)
                            std::print("Found address: {:#x} | Value: {}\n", addr, current);
                    }
                }
            }
            else
            {
                std::print("Failed to read memory at address {:#x}\n",
                    reinterpret_cast<uintptr_t>(mbi.BaseAddress));
            }
        }
        offsetAddress = static_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
    }
}

bool InputScanValue(char& type, ScanValue& input)
{
    std::print("Enter the value to scan for (int: i, float: f, double: d): ");
    std::cin >> type;

    switch (type)
    {
    case 'i': case 'I':
        std::print("Enter integer value: ");
        std::cin >> input.intValue;
        std::print("You entered integer: {}\n", input.intValue);
        break;

    case 'f': case 'F':
        std::print("Enter float value: ");
        std::cin >> input.floatValue;
        std::print("You entered float: {}\n", input.floatValue);
        break;

    case 'd': case 'D':
        std::print("Enter double value: ");
        std::cin >> input.doubleValue;
        std::print("You entered double: {}\n", input.doubleValue);
        break;

    default:
        std::print("Invalid type selected!\n");
        return false;
    }

    if (type < 'a') type = static_cast<char>(type + 32);
    return true;
}





