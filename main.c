#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <math.h> /* [fabs()]: Use fabs to compare floating-point values - epsilon tolerance */
#include <stdint.h> /* uintptr_t */
#include "PointerChain.h"
#include "MemoryRegion.h"

#define MAX_CHAR_SIZE 64

typedef union
{
    int intValue;
    float floatValue;
    double doubleValue;
}ScanValue;

void Menu();
void ClearBuffer();

void SetModule(DWORD *pid, char[]);
HANDLE OpenProcessHandle(DWORD);
DWORD_PTR GetModuleBaseAddress(DWORD, const char*); /* Find base addres using module name */

FILE* OpenChainFile(FILE*);

void ScanForValue(HANDLE, ScanValue, char);
BOOL InputScanValue(char*, ScanValue*);

int main()
{             
    printf("Welcome to DeepCheat!\n");

    Menu();

    CleanupPointerData(); /* set free */
    return 0;
}

void Menu()
{
    DWORD_PTR moduleBaseAddress = 0;
    HANDLE hProc;

    /* Set module - PID and module name */
    DWORD pid = 0;
    char moduleName[MAX_CHAR_SIZE] = {0};

    SetModule(&pid, moduleName);
    hProc = OpenProcessHandle(pid);
    if(hProc == NULL)
        return; /* invalid process */

    /* Variables to scan memory */
    char type;
    ScanValue targetValue;

    /* For chain variables and pointers */
    unsigned long long targetAddress;
    FILE *chainFile = NULL;
    uintptr_t chainOffsets[MAX_DEPTH] = {0};

    char choice = '0';
    while(choice != 'X' || choice != 'x')
    {        
        printf("\n------------------\n");
        printf("Current PID: %lu\n", pid);
        printf("------------------\n");
        printf("1. Get module base address\n2. Set PID\n3. Scan for value\n4. Find pointer chain\n5. List memory regions\n6. Print memory cells\nX. Exit\n");
        printf("Please select an option: ");
        
        scanf(" %c", &choice);
        ClearBuffer();

        moduleBaseAddress = GetModuleBaseAddress(pid, moduleName);
        
        switch(choice)
        {
            case '1': /* Get module address */
                printf("Module Base Address: %p\n", (void*)moduleBaseAddress);
                break;

            case '2': /* Set PID and Module Name */
                SetModule(&pid, moduleName);
                if(hProc != NULL)
                    CloseHandle(hProc);
                hProc = OpenProcessHandle(pid);
                if(hProc == NULL)
                    return; /* invalid process */

                break;

            case '3':
                if(InputScanValue(&type, &targetValue))
                {
                    ScanForValue(hProc, targetValue, type);
                }
                break;

            case '4':
                printf("Enter the target address to find pointer chain: ");
                scanf(" %llx", &targetAddress);
                ClearBuffer();

                int maxDepth = 0;
                printf("Enter max chain depth (1-10, recommended: 7): ");
                scanf(" %d", &maxDepth);
                ClearBuffer();
                if(maxDepth < 1) maxDepth = 1;
                if(maxDepth > MAX_DEPTH) maxDepth = MAX_DEPTH;

                /* Module filter */
                char filterModule[MAX_CHAR_SIZE] = {0};
                printf("Enter target module name (e.g. GameAssembly.dll) or press Enter for all: ");
                fgets(filterModule, MAX_CHAR_SIZE, stdin);
                filterModule[strcspn(filterModule, "\n")] = '\0';
                SetTargetModule(filterModule);

                chainFile = OpenChainFile(chainFile);
                if(chainFile == NULL)
                    chainFile = fopen("Outputs/chains.txt", "w");

                FindPointerChain(chainFile, hProc, (uintptr_t)targetAddress, chainOffsets, maxDepth);
                printf("Pointer chains have been written to the file.\n");
                fclose(chainFile);
                break;
            
            case '5': /* Save memory regions to text file */
                ListMemoryRegions(hProc);    
                break;

            case '6': /* Print memory cells */
                FindReadableRegions(hProc);
                break;

            case 'X': /* EXIT */
            case 'x':
                printf("Exiting DeepCheat...\n");
                break;

            default:
                printf("Invalid choice, please try again.\n");
                break;
        }
    }

    CloseHandle(hProc);
}

void ClearBuffer()
{
    int c;
    while((c = getchar()) != '\n' && c != EOF);
}

FILE* OpenChainFile(FILE *chainFile) 
{
    char *fileName = (char*)calloc(MAX_CHAR_SIZE, sizeof(char));
    strcat(fileName, "Outputs/"); /* folder name */

    printf("Enter chain file name: ");
    fgets(&fileName[8], MAX_CHAR_SIZE, stdin);

    fileName[strcspn(fileName, "\n")] = '\0'; /* Remove newline character */
    strcat(fileName, ".txt"); /* file type */

    chainFile = fopen(fileName, "w");
    if (!chainFile) 
    {
        printf("Failed to open file: %s\n", fileName);
        free(fileName);
        return NULL;
    }

    free(fileName);
    return chainFile;
}

HANDLE OpenProcessHandle(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(hProc == NULL)
        printf("Failed to open process with PID %d\n", pid);
    else
        printf("Process opened successfully.\n");

    return hProc;
}

void SetModule(DWORD *pid, char moduleName[])
{
    unsigned long tempPID = 0;
    char tempName[MAX_CHAR_SIZE] = {0};
    /*tempName[0] = '\0';*/

    /* Set PID */
    while(tempPID == 0)
    {
        printf("Please enter the PID: ");
        if(scanf(" %lu", &tempPID) == 1)
        {
            *pid = (DWORD)tempPID;
            printf("> PID is set: %lu\n", *pid);
        }
        else
        {
            tempPID = 0;
            printf("Invalid PID!\n");
        }
        ClearBuffer();
    }

    /* Set module name */
    while(tempName[0] == '\0')
    {
        printf("Enter module name: ");
        if(fgets(tempName, sizeof(tempName), stdin) != NULL) 
        {
            tempName[strcspn(tempName, "\n")] = 0;
            strcpy(moduleName, tempName);
            printf("> Module name is set: %s\n", moduleName);
        }
        else 
        {
            tempName[0] = '\0';
            printf("Invalid module name!\n");
        }
    }
}

DWORD_PTR GetModuleBaseAddress(DWORD pid, const char* moduleName) 
{
    MODULEENTRY32 me32;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid); /* bitwise OR */

    if(hSnap != INVALID_HANDLE_VALUE)
    {
        me32.dwSize = sizeof(MODULEENTRY32);
        if(Module32First(hSnap, &me32)) 
        {
            do 
            {
                if(_stricmp(me32.szModule, moduleName) == 0) /* Does not differentiate between big and small characters*/
                {
                    CloseHandle(hSnap);
                    return (DWORD_PTR)me32.modBaseAddr;
                }

            } while(Module32Next(hSnap, &me32));
        }
    }

    printf("Module %s not found in process %lu\n", moduleName, pid);
    CloseHandle(hSnap);
    return 0;
}

void ScanForValue(HANDLE hProc, ScanValue targetValue, char type)
{
    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID currentAddress = NULL;

    BYTE* offsetAddress = 0;
    BYTE* buffer;
    SIZE_T bytesRead;
    SIZE_T i;

    SIZE_T stepSize;

    switch(type)
    {
        case 'i': stepSize = sizeof(int); break;
        case 'f': stepSize = sizeof(float); break;
        case 'd': stepSize = sizeof(double); break;
    }

    while(VirtualQueryEx(hProc, offsetAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) /* Check if all fields of mbi have been read */
    {
        if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) /* This reagion can be scanned */
        {
            currentAddress = mbi.BaseAddress;
            buffer = (BYTE*)malloc(mbi.RegionSize);
            if(buffer == NULL) 
            {
                printf("Memory allocation failed\n");
                return;
            }

            if(ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead))
            {
                for(i = 0; i < bytesRead - stepSize; i += stepSize)
                /* OR for (i = 0; i < bytesRead - stepSize; i++) // read one by one */
                {
                    if(type == 'i')
                    {
                        int currentValue = *(int*)(buffer + i);
                        if(currentValue == targetValue.intValue) 
                        { 
                            printf("Found address: %p | Value: %d\n", (BYTE*)mbi.BaseAddress + i, currentValue);
                        }
                    }
                    else if(type == 'd')
                    {
                        double currentValue = *(double*)(buffer + i);
                        if(fabs(currentValue - targetValue.doubleValue) < 0.0001)
                        { 
                            printf("Found address: %p | Value: %lf\n", (BYTE*)mbi.BaseAddress + i, currentValue);
                        }
                    }
                    else if(type == 'f')
                    {
                        float currentValue = *(float*)(buffer + i);
                        if(fabs(currentValue - targetValue.floatValue) < 0.01f) 
                        { 
                            printf("Found address: %p | Value: %f\n", (BYTE*)mbi.BaseAddress + i, currentValue);
                        }
                    }
                }
            }
            else
            {
                printf("Failed to read memory at address %p\n", mbi.BaseAddress);
            }

            free(buffer);
        }
        offsetAddress += mbi.RegionSize;
    }
}

BOOL InputScanValue(char *type, ScanValue *input)
{
    BOOL flag = TRUE;

    printf("Enter the value to scan for (int: i, float: f, double: d): ");
    scanf(" %c", type);
    ClearBuffer();

    switch(*type)
    {
        case 'i':
        case 'I':
            {
                printf("Enter integer value: ");
                scanf(" %d", &input->intValue);
                ClearBuffer();
                printf("You entered integer: %d\n", input->intValue);
            }
            break;

        case 'f':
        case 'F':
            {
                printf("Enter float value: ");
                scanf(" %f", &input->floatValue);
                ClearBuffer();
                printf("You entered float: %f\n", input->floatValue);
            }
            break;

        case 'd':
        case 'D':
            {
                printf("Enter double value: ");
                scanf(" %lf", &input->doubleValue);
                ClearBuffer();
                printf("You entered double: %lf\n", input->doubleValue);
            }
            break;
        
        default:
            printf("Invalid type selected!\n");
            flag = FALSE;
            break;
    }

    if(*type < 'a') *type += 32; /* convert to lowercase if uppercase */

    return flag;
}

