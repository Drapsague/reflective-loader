#ifndef REFLECTIVE_LOADER_H
#define REFLECTIVE_LOADER_H

// #include "structPE.h"
#include <windows.h>

#define CUSTOM_DLLMAIN

typedef INT(WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

typedef LPVOID(WINAPI* VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HMODULE(WINAPI* LoadLibrary_t)(LPCSTR);
typedef FARPROC(WINAPI* GetProcAddress_t)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* DllMain_t)(HINSTANCE, DWORD, LPVOID);
// typedef INT(WINAPI* REFLECTIVE_LOADER)(void);

#define REF_LOADER __declspec(dllexport)

typedef struct PEB_LDR_DATA {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID EntryInProgress;
        BOOLEAN ShutdownInProgress;
        HANDLE ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct PEB {
        BOOLEAN InheritedAddressSpace;
        BOOLEAN ReadImageFileExecOptions;
        BOOLEAN BeingDebugged;
        union {
                BOOLEAN BitField;
                struct {
                        BOOLEAN ImageUsesLargePages : 1;
                        BOOLEAN IsProtectedProcess : 1;
                        BOOLEAN IsImageDynamicallyRelocated : 1;
                        BOOLEAN SkipPatchingUser32Forwarders : 1;
                        BOOLEAN IsPackagedProcess : 1;
                        BOOLEAN IsAppContainer : 1;
                        BOOLEAN IsProtectedProcessLight : 1;
                        BOOLEAN SpareBits : 1;
                };
        };
        HANDLE Mutant;
        PVOID ImageBaseAddress;
        PEB_LDR_DATA* Ldr;
} PEB, *PPEB;

typedef struct UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint; // PDLL_INIT_ROUTINE
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// Custom Functions
int isTargetDll(size_t nameLength, const wchar_t* buf, const wchar_t* k32) {
        int match = 1;
        for (size_t i = 0; i < nameLength; ++i) {
                wchar_t a = k32[i];
                wchar_t b = buf[i];

                // Worth Mentionning
                // L'A' != L"A"
                // L'A' is a single wide char
                // L"A" is an array of wide char because it is null terminated, so [L'A',
                // L'0']
                // ---
                // 0x20 -> 0010 0000
                // 'A' -> 0100 0001
                // 'a' -> 0110 0001
                // So 'C' | 0x20 -> c
                if (a >= L'A' && a <= L'Z')
                        a = a | 0x20;
                if (b >= L'A' && b <= L'Z')
                        b = b | 0x20;
                if (a != b) {
                        match = 0;
                        break;
                }
        }
        return match;
}

BYTE* getFunctionAddr(LDR_DATA_TABLE_ENTRY* ldrData, const char* func) {
        // TO DO
        // Need a smaller syntax, too decomposed
        BYTE* baseAddr = (BYTE*)ldrData->DllBase;
        IMAGE_DOS_HEADER* dosH = (IMAGE_DOS_HEADER*)baseAddr;
        IMAGE_NT_HEADERS64* ntH = (IMAGE_NT_HEADERS64*)(baseAddr + dosH->e_lfanew);
        IMAGE_OPTIONAL_HEADER64* opH = &ntH->OptionalHeader;
        IMAGE_DATA_DIRECTORY* exportDataDir = &opH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        IMAGE_EXPORT_DIRECTORY* exportDir =
            (IMAGE_EXPORT_DIRECTORY*)(baseAddr + exportDataDir->VirtualAddress);
        DWORD* functionsNames = (DWORD*)(baseAddr + exportDir->AddressOfNames);
        DWORD* functionsAddrs = (DWORD*)(baseAddr + exportDir->AddressOfFunctions);
        DWORD functionIndex = 0;

        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
                const char* s2 = (const char*)(baseAddr + functionsNames[i]);
                size_t j = 0;
                while (func[j] && (func[j] == s2[j])) {
                        j++;
                }
                int result = (unsigned char)(func[j]) - (unsigned char)(s2[j]);
                if (result == 0) {
                        functionIndex = i;
                        break;
                }
        }
        WORD* functionsOrdinals = (WORD*)(baseAddr + exportDir->AddressOfNameOrdinals);
        WORD functionOrdinal = functionsOrdinals[functionIndex];
        BYTE* functionAddr = (BYTE*)(baseAddr + functionsAddrs[functionOrdinal]);

        return functionAddr;
}
#endif
