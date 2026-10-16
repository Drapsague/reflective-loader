#!/bin/bash
x86_64-w64-mingw32-gcc -c refLoader.c -o refLoader.o -D_USRDLL -D_WINDLL
x86_64-w64-mingw32-g++ -c refDll.cpp -o refDll.o -D_USRDLL -D_WINDLL
x86_64-w64-mingw32-g++ -static -static-libgcc -static-libstdc++ -shared refDll.o refLoader.o -o freedent.dll
rm *.o

python3 script/xor.py freedent.dll > freedent/freedent.h

