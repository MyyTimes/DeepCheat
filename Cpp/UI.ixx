module;
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "ImGUI/imgui.h"
#include <string>

export module UI;

import Program;
import ScanValue;

export namespace UI
{
    // Variables

    // Process Attachment
    int inputPid{};
    char inputModuleName[128] = "GameAssembly.dll";

    // Scan variable type
    int selectedScanType{}; // int: 0, float: 1, double: 2
    SIZE_T scanningStepSize{};
    bool isScanningStarted{ false };
    char type{ 'i' };
    ScanValue::ScanValueType scanValue{};
    // > address
    bool showFoundAddresses{ false };

    // Private functions

    void ShowFoundAddresses() // Saved addressed of the scanned values
    {
        // Open new window
        if (!showFoundAddresses) return;

        ImGui::Begin("Scanning Results", &showFoundAddresses);

        const auto& addresses = ScanValue::GetFoundAddresses();
        ImGui::Text("Found address number: %zu", addresses.size());
        ImGui::Separator();

        if (ImGui::BeginTable("ResultsTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY))
        {
            ImGui::TableSetupColumn("Address (Hex)");
            ImGui::TableSetupColumn("Current Value");
            ImGui::TableHeadersRow();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(addresses.size()));

            while (clipper.Step())
            {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; row++)
                {
                    uintptr_t addr = addresses[row];

                    ImGui::TableNextRow();

                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("0x%llX", static_cast<unsigned long long>(addr));

                    ImGui::TableSetColumnIndex(1);

                    ScanValue::ScanValueType liveValue{};
                    SIZE_T bytesRead = 0;

                    if (ReadProcessMemory(g_Program.GetHandle(), reinterpret_cast<LPCVOID>(addr), &liveValue, scanningStepSize, &bytesRead))
                    {
                        if (type == 'i') ImGui::Text("%d", liveValue.intValue);
                        else if (type == 'f') ImGui::Text("%f", liveValue.floatValue);
                        else if (type == 'd') ImGui::Text("%lf", liveValue.doubleValue);
                    }
                    else
                    {
                        ImGui::Text("-");
                    }
                }
            }
            ImGui::EndTable();
        }

        ImGui::End();
    }

    void DrawGetScanVariableType()
    {
        const char* buttonNames[3] = { "int", "float", "double" };

        for (int i = 0; i < 3; i++)
        {
            if (i > 0) ImGui::SameLine();

            if (selectedScanType == i) // selected color
            {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.5f, 0.9f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.6f, 1.0f, 1.0f));
            }
            else
            {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.3f, 0.3f, 0.3f, 1.0f));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.4f, 0.4f, 0.4f, 1.0f));
            }

            ImGui::PushID(i);

            if (ImGui::Button(buttonNames[i], ImVec2(80, 30)))
            {
                selectedScanType = i;
            }

            ImGui::PopID();
            ImGui::PopStyleColor(2);
        }

        switch (selectedScanType)
        {
            case 0: // int
                scanningStepSize = static_cast<SIZE_T>(sizeof(int));
                type = 'i';
                ImGui::InputInt(" ", &scanValue.intValue);
                break;

            case 1: // float
                scanningStepSize = static_cast<SIZE_T>(sizeof(float));
                type = 'f';
                ImGui::InputFloat(" ", &scanValue.floatValue, 0.1f, 1.0f, "%f");
                break;

            case 2: // double
                scanningStepSize = static_cast<SIZE_T>(sizeof(double));
                type = 'd';
                ImGui::InputDouble(" ", & scanValue.doubleValue, 0.1, 1.0, "%lf");
                break;
        }

        if (!isScanningStarted)
        {
            
            if (ImGui::Button("Start Scanning"))
            {
                isScanningStarted = true;
                ScanValue::StartScanningForValue(g_Program.GetHandle(), scanValue, scanningStepSize, type);
                showFoundAddresses = true;
            }
        }
        else
        {
            if (ImGui::Button("Continue Scanning"))
            {
                ScanValue::ContinueScanningForValue(g_Program.GetHandle(), scanValue, type, scanningStepSize);
                showFoundAddresses = true;
            }
            ImGui::SameLine(0.0f, 10.0f);
            if (ImGui::Button("Reset Scanning"))
            {
                isScanningStarted = false;
            }
        }
    }

    void DrawGetProcess()
    {
        ImGui::InputInt("Process ID (PID)", &inputPid);
        ImGui::InputText("Modul Name", inputModuleName, sizeof(inputModuleName));

        if (ImGui::Button("Connect Process"))
        {
            g_Program.AttachProcess(inputPid, std::string(inputModuleName));
        }

        if (g_Program.IsProgramConnected())
        {
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "Basariyla Baglanildi!");
            ImGui::Text("Base Address: 0x%llX", static_cast<unsigned long long>(g_Program.GetBaseAddress()));
        }
        else
        {
            ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), "Baglanti Bekleniyor veya Basarisiz...");
        }
    }

    void DrawSettingsPanel()
    {
        ImGui::Text("Interface Settings");

        // input/output object
        ImGuiIO& io = ImGui::GetIO();

        ImGui::SliderFloat("Font Size", &io.FontGlobalScale, 0.5f, 2.0f, "%.2f x");

        if (ImGui::Button("Reset Size"))
        {
            io.FontGlobalScale = 1.0f;
        }
    }

    // (export)ed main function
    export void RenderMainInterface()
    {
        //ImGui::Begin("DEEPCHEAT", nullptr, ImGuiWindowFlags_AlwaysAutoResize);
        ImGui::Begin("DeepCheat Control Panel");

        DrawSettingsPanel();

        ImGui::Separator();
        
        ImGui::Text("CONNECT PROCESS");
        DrawGetProcess();
        
        ImGui::Separator();

        ImGui::BeginDisabled(!g_Program.IsProgramConnected());
        ImGui::Text("NUMBER TO BE SCANNED");
        DrawGetScanVariableType();
        ImGui::EndDisabled();

        ImGui::End();

        // Other window -> Saved addressed of the scanned values
        ShowFoundAddresses();
    }
}