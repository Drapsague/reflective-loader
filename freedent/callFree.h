#ifndef CALLFREE_H
#define CALLFREE_H

#include <stdio.h>
#include <windows.h>

FARPROC mGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
HMODULE mGetModuleHandle(LPCWSTR lpModuleName);

#endif


