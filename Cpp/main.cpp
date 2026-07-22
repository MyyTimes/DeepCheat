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
import UI;
import DebugTerminal;
import MemoryRegion;

//import PointerChain;

using namespace Terminal;

int main()
{
    std::print("Welcome to DeepCheat!\n");

    // Make process DPI aware and obtain main monitor scale
    ImGui_ImplWin32_EnableDpiAwareness();
    float main_scale = ImGui_ImplWin32_GetDpiScaleForMonitor(::MonitorFromPoint(POINT{ 0, 0 }, MONITOR_DEFAULTTOPRIMARY));

    // Create application window
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, dx11::WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"ImGui Example", nullptr };
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"Dear ImGui DirectX11 Example", WS_OVERLAPPEDWINDOW, 100, 100, (int)(1280 * main_scale), (int)(800 * main_scale), nullptr, nullptr, wc.hInstance, nullptr);

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
    //ImGui::StyleColorsLight();

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
        
        UI::RenderMainInterface();
     
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






