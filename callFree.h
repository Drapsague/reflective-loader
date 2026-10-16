#ifndef CALLFREE_H
#define CALLFREE_H

// #include <shlwapi.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
#include <windows.h>
// #include <winternl.h>


#ifdef __cplusplus
extern "C" {
#endif

FARPROC mGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
HMODULE mGetModuleHandle(LPCWSTR lpModuleName);

#ifdef __cplusplus
}
#endif

#endif


