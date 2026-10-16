#!/bin/bash
# x86_64-w64-mingw32-g++ -static -static-libgcc -static-libstdc++ -w -fno-stack-protector -DNDEBUG callFree.cpp freedent.cpp -o freedent.exe -mconsole 
x86_64-w64-mingw32-g++ -static -static-libgcc -static-libstdc++ -w -fno-stack-protector  callFree.cpp freedent.cpp -o freedent.exe -mwindows 
cp freedent.exe /home/vedlam/maldev
