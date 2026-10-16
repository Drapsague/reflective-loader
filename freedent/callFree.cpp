#include "structPE.h"
#include "callFree.h"

// #include <winternl.h>
// #include <shlwapi.h>

PEB * ProcEnvBlk = (PEB *)__readgsqword(0x60);

typedef HMODULE(WINAPI* LoadLibrary_t)(LPCSTR lpFileName);
LoadLibrary_t pLoadLibraryA = {};

// Custom functions
int c_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    // Return difference in ASCII values for the first non-matching character
    return (unsigned char)(*s1) - (unsigned char)(*s2);
}

char *c_strchr(const char *str, int c) {
    while (*str) {
        if (*str == (char)c) {
            return (char *)str;
        }
        str++;
    }
    // Also check for terminating null character
    if (c == '\0') {
        return (char *)str;
    }
    return NULL;
}

int c_wstr(const wchar_t* a, const wchar_t* b) {
    while (*a && (*a == *b)) {
        a++;
        b++;
    }
    return *a - *b;  // 0 = equal, <0 or >0 = different
}

void c_wcsncpy_s(WCHAR dst[512], const WCHAR* src, int len) {
    int i;
    for (i = 0; i < len && i < 511 && src[i] != 0; ++i) {
        dst[i] = src[i];
    }
    dst[i] = 0; // Always NUL-terminate at most at position 511
}
char* c_strdup(const char* s) {
    if (!s) return NULL;
    size_t len = 0;
    while (s[len]) len++;  // compute length
    char* copy = (char*)malloc(len + 1); // +1 for null terminator
    if (!copy) return NULL;
    for (size_t i = 0; i <= len; ++i) { // include null terminator
        copy[i] = s[i];
    }
    return copy;
}

static WCHAR my_tolower(WCHAR c) {
    if (c >= 'A' && c <= 'Z') return c + 32;
    return c;
}

// Custom, case-insensitive, wide substring search (ASCII only)
WCHAR* c_StrStrIW(const WCHAR* haystack, const WCHAR* needle) {
    if (!*needle) return (WCHAR*)haystack; // Empty needle found immediately

    for (; *haystack; ++haystack) {
        const WCHAR* h = haystack;
        const WCHAR* n = needle;
        while (*h && *n && my_tolower(*h) == my_tolower(*n)) {
            ++h;
            ++n;
        }
        if (!*n) return (WCHAR*)haystack; // Full match
    }
    return NULL;
}
// Manual implementation of GetProcAddress
FARPROC mGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {

        // Step 1
        // Base Addr
        BYTE* baseAddr = (BYTE*)hModule;
        // printf("Base Addr: %#010x\n", baseAddr);

        // Step 2
        // Get DOS Header ptr
        IMAGE_DOS_HEADER* dosH = (IMAGE_DOS_HEADER*)baseAddr;

        // Step 3
        // Get PE Header alias NT Header offset via e_lfanew
        // LONG ntOff = dosH->e_lfanew;
        IMAGE_NT_HEADERS64* ntH = (IMAGE_NT_HEADERS64*)(baseAddr + dosH->e_lfanew);

        // Step 4
        // Get Optional Header
        IMAGE_OPTIONAL_HEADER64* opH = &ntH->OptionalHeader;
	// printf("Optional Header Addr: %p\n", opH);
	// printf("Optional Header RVA & Size: %p\n", opH->NumberOfRvaAndSizes);

        // Step 5
        // Get Image Data Dir
        // DataDirectory[0] points to Export Dir
        IMAGE_DATA_DIRECTORY* exportDataDir = &opH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY*)(baseAddr + exportDataDir->VirtualAddress);
	// printf("Export Dir Addr: %p\n", exportDir);
	// printf("Export Dir Size: %p\n", exportDataDir->Size);
	// printf("Export Dir Virtual Addr: %p\n", exportDataDir->VirtualAddress);

        // Get functions names from AddressOfNames
        // AddressOfNames returns an RVA to an array of DWORD value that are each RVAs
        // to DWORDS
        DWORD* functionsNames = (DWORD*)(baseAddr + exportDir->AddressOfNames);
	// printf("Functon Names Addr: %p\n", functionsNames);
	// printf("Functon Names Addr: %p\n", exportDir->AddressOfNames);

        // Get the function address from AddressOfFunctions
        // AddressOfFunctions returns an RVA to an array of DWORD value that are each
        // RVAs to DWORDS
        DWORD* functionsAddrs = (DWORD*)(baseAddr + exportDir->AddressOfFunctions);
	// printf("Functons Addr: %p\n", functionsAddrs);

        DWORD functionIndex = 0;

        BYTE* functionAddr{};
        DWORD* functionRVA{};


        if ((ULONG_PTR)lpProcName <= 0xFFFF) {
                // The export directory has a Base param which is added to the ordinal of
                // each function
                DWORD base = exportDir->Base;

                // An ordinal is only on the two first bytes
                // ULONG_PTR convets into an int
                WORD ordinal = (WORD)(ULONG_PTR)lpProcName;

                // BYTE cast to get the raw ptr to the function
                functionAddr = (BYTE*)(baseAddr + functionsAddrs[ordinal - base]);

		// printf("Functions Addr: %#010x\n", functionAddr);
                // printf("Base: %#010x\n", base);
                // printf("Function RVA: %#010x\n", functionsAddrs[ordinal - base]);
                // printf("Functions Ordinal Addr: %#010x\n", functionAddr);

        } else {
                // Looping through every function names to find ProcName
                for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
			// printf("Nbr Names: %p\n", exportDir->NumberOfNames);
			// printf("Functions Names: %p\n", functionsNames);
			// printf("Functions Names: %p\n", functionsNames[i]);
			char* functionName = (char*)(baseAddr + functionsNames[i]);
			// printf("Functions Names: %s\n", functionName);
                        // functionsNames[i] returns an RVA to a DWORD

                        if (c_strcmp(lpProcName, functionName) == 0) {
                                // printf("Functions Names: %#010x\n", functionsNames[i]);
                                // printf("Functions Names: %s\n", functionName);

				// printf("Function Name : %s\n", functionName);
                                // Get the index of the function ordinal
                                functionIndex = i;
                                break;
                        }
                }

                // Get the function ordinal from AddressOfNamesOrdinals
                // AddressOfNamesOrdinals returns an RVA to an array of WORD
                WORD* functionsOrdinals = (WORD*)(baseAddr + exportDir->AddressOfNameOrdinals);
                WORD functionOrdinal = functionsOrdinals[functionIndex];

		// printf("Function Ordinal: %#010x\n", functionOrdinal);
                // printf("Functions Addresses: %#010x\n", functionsAddrs);
                // printf("Functions Addresses RVA: %#010x\n",
                // exportDir->AddressOfFunctions); printf("Function RVA: %#010x\n",
                // functionsAddrs[functionOrdinal]);

                // BYTE cast to get the raw ptr to the function, maybe useless
                functionAddr = (BYTE*)(baseAddr + functionsAddrs[functionOrdinal]);

                // printf("Function RVA: %#010x\n", functionsAddrs[functionOrdinal]);
                // printf("Functions Addr: %#010x\n", functionAddr);
                // printf("Functions Addr: %#010x\n", functionAddr);

                // If the function we want is not in the dll provided, the EAT returns a
                // forwarder The forwarder refers to a function in another Dll
        }

        // We need the RVA and Size of the export in case we get a forwarder
        if (functionAddr >= (BYTE*)exportDir && functionAddr < (BYTE*)(exportDir + exportDataDir->Size)) { 	

		// printf("\n[*] IN Forwarder Conditon\n");

		// Here we get the forwarder name (.e.g. NTDLL.RtlAcquireSRWLockExclusive)
		char* forwarderName = c_strdup((char*) functionAddr); 
		// printf("Forwarder Name : %s\n", forwarderName);

		// Get the function name
		char * forwarderFunction = c_strchr(forwarderName, '.');

		// Needed to split correctly <dllname> and <functionname>
		// forwarderName is now dllname
		*forwarderFunction = 0; // Now we have <dllname>0<functionname> -> two independent strings


		// Increment the ptr to point to the function name instead of the null byte
		forwarderFunction++;


		// printf("Forwarder Function : %s\n", forwarderFunction);

		// Get LoadLibrary to retrieve the handle of the target function
		pLoadLibraryA = (LoadLibrary_t)mGetProcAddress(mGetModuleHandle(L"KERNEL32.DLL"), "LoadLibraryA");

		// Get the handle of forwarderName being the DllName
        	HMODULE forwarderHandle = pLoadLibraryA(forwarderName);
		// free(forwarderHandle);

		// printf("Function Handle Addr: %#010x\n", forwarderHandle);

        	functionAddr = (BYTE*)mGetProcAddress(forwarderHandle, forwarderFunction);
        }

        // Cast to FARPROC
        return (FARPROC)functionAddr;
}

// Macro for the min function
#define min(a, b) (((a) < (b)) ? (a) : (b))

HMODULE mGetModuleHandle(LPCWSTR lpModuleName) {
        // Get the TEB
        // TEB* teb = NtCurrentTeb();
        // Get the PEB * from the ProcessEnvironmentBlock parameter
        // PEB* peb = teb->ProcessEnvironmentBlock;

        // The PEB param Ldr contains a PEB_LDR_DATA obj
        // PEB_LDR_DATA contains a LIST_ENTRY obj which points to a double linked list
        // of LIST_ENTRY (Also LDR_DATA_TABLE_ENTRY struct)
        // PEB_LDR_DATA* ldr = peb->Ldr;
        PEB_LDR_DATA* ldr = ProcEnvBlk->Ldr;
        LIST_ENTRY* moduleList = &ldr->InMemoryOrderModuleList;
	LIST_ENTRY* Flk = (LIST_ENTRY*) moduleList->Flink;
	// LDR_DATA_TABLE_ENTRY* Flk = (LDR_DATA_TABLE_ENTRY*) moduleList->Flink;

	// while(Flk != moduleList) {
	while((LIST_ENTRY*)Flk != moduleList) {
		// Get the addr of the struct
		// If not, when we Flink we arrive at the "InMemoryOrderLink" addr in the struct thus we can access it
		LDR_DATA_TABLE_ENTRY* ldrData = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(Flk, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		// The UNICODE_STRING struct has a Buffer param which retuns a WCHAR*
		// UNICODE_STRING DllName = ldrData->BaseDllName;

		// wprintf(L"FullDllName: %ls\n", ldrData->FullDllName.Buffer);
		// wprintf(L"BaseDllName: %ls\n", ldrData->BaseDllName.Buffer);
		// wprintf(L"lpProcName: %ls\n", lpModuleName);

		// Only checks the first letter of the Dll Name
		// if(c_strcmp((const char*)ldrData->BaseDllName.Buffer, (const char*)lpModuleName) == 0 ){
		if(c_strcmp((const char*)ldrData->BaseDllName.Buffer, (const char*)lpModuleName) == 0 ){
			// printf("BaseDllName: %s", (const char*)ldrData->BaseDllName.Buffer);
			// printf("lpModuleName: %s", (const char*)lpModuleName);
			return (HMODULE)((VOID*)ldrData->DllBase);
		}

	       Flk = ldrData->InMemoryOrderLinks.Flink;
	}

        return NULL;
}

/*
 *
        WCHAR buf[512];

        As it is a double linked list, looping through the table entry is cyclic
        When we end return to the first element the loop ends
			     while (moduleList->Flink != &ldr->InMemoryOrderModuleList) {
			             // Essentially when we Flink to go to the next LIST_ENTRY element we end up
			             // in the InMemoryOrderLinks of the next LIST_ENTRY element The
			             // LDR_DATA_TABLE_ENTRY struct two first element are InLoadOrderLinks and
			             // InMemoryOrderLinks that are both LIST_ENTRY objects In order to access
			             // the LDR_DATA_TABLE_ENTRY struct of this element, we need to get the
			             // address of the start of the struct Which means we have to substract the
			             // size of InLoadOrderLinks as it is the only element before the top of the
			             // struct
			             LDR_DATA_TABLE_ENTRY* Flk = (LDR_DATA_TABLE_ENTRY*)((BYTE*)(moduleList->Flink) - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
			             // Get the Dll path with FullDllName param
			             UNICODE_STRING DllName = Flk->FullDllName;
			             wprintf(L"Current word : %ls\n", DllName.Buffer ? DllName.Buffer : L"(null)");
			             // wprintf(L"Current word : %s\n", DllBaseName);
			             // printf("Current entry address : %p\n", (void*)Flk);
			             // printf("Current dll base      : %p\n", Flk->DllBase);
			             // printf("Current dll base      : %p\n", Flk->DllBase);

			             // Check if DllName is not VOID
			             if (DllName.Buffer) {
			                     // Can use the macro CONTAINING_RECORD to get the right struct address
			                     // and then get DllBase (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(Flk,
			                     // LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks) ; return (HMODULE) (BYTE*)
			                     // Flk1->DllBase;
			wprintf(L"LpName: %ls\n", (const char*)lpModuleName);

			                     // Don't know
			                     int len = (int)min(DllName.Length / sizeof(WCHAR), (SIZE_T)511);
			                     c_wcsncpy_s(buf, DllName.Buffer, len);
			                     buf[len] = L'\0';

			// wprintf(L"Current word buffer : %s\n", buf);
			                     if (StrStrIW(buf, (WCHAR*)lpModuleName) != NULL) {
			                             return (HMODULE)Flk->DllBase;
			                     }
			             }

			             // Go to the next LIST_ENTRY element
			             moduleList = Flk->InMemoryOrderLinks.Flink;
			     }

*/
