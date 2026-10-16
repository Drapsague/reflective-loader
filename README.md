# reflective-loader

A hands-on study project about **reflective DLL loading** on Windows x64, written in C/C++ and built with the MinGW-w64 cross-toolchain on Linux.

The repo implements the three layers yourself:

1. **the Reflective DLL** — a `freedent.dll` that embeds its own loader and is able to relocate itself into memory without being touched by the Windows loader,
2. **the loader logic** — manual PEB walking, PE parsing, IAT resolution and relocations, all from scratch,
3. **the dropper** — an executable that decrypts the DLL from a generated header and kicks it off in memory.

> **Disclaimer:** this code was written to learn how reflective loading works under the hood. It is provided for educational and lab use only (your own machines and VMs). No warranty of any kind. Don't run anything against systems you don't own.

## Components

```
.
├── refLoader.c/.h     # ReflectiveLoader export: PEB walk, kernel32 resolution,
│                      # header/section copy, IAT fill, base relocations, DllMain call
├── structPE.h         # minimal PEB / LDR_DATA_TABLE_ENTRY structures
├── refDll.cpp         # the reflective DLL itself: DllMain spawns a thread that
│                      # de-XORs an embedded shellcode and executes it (calc.exe demo)
├── callFree.cpp/.h    # CRT-free helpers: custom strcmp/strchr/wcsncpy_s and a manual
│                      # GetProcAddress / GetModuleHandle built on the PEB & export table
├── freedent/freedent.cpp  # the dropper: de-XORs the DLL into RW memory, maps RVA → file
│                          # offset, finds the ReflectiveLoader export and calls it
├── freedent/*.cpp/.h/.sh  # local copies of callFree/structPE + the dropper build script
└── script/
    ├── xor.py                 # XOR-encrypt a payload/DLL into a C byte array (key "EiichiroOda")
    ├── ConvertToShellcode.py  # third-party (sRDI) DLL → shellcode converter
    ├── ShellcodeRDI.py        # third-party (sRDI) position-independent loader generator
    └── hex_to_b64.py          # hex byte array → base64
```

## How it works

**Reflective loader (`refLoader.c`)**

1. Get the PEB through `gs:[0x60]`, walk the in-memory-order module list and find `KERNEL32.DLL` (case-insensitive compare).
2. Parse kernel32's export table manually to get the real addresses of `VirtualAlloc`, `LoadLibraryA` and `GetProcAddress`.
3. Get the return address of the caller and scan backwards for the `MZ` magic to find the DLL's base address in memory.
4. `VirtualAlloc` a buffer of `SizeOfImage`, copy the DOS/NT headers and every section from the file image into it.
5. Walk the import descriptors and fill the IAT: by ordinal when the high bit is set, by name otherwise.
6. Process the base relocation table (`IMAGE_REL_BASED_DIR64` entries) using the delta between the preferred and the actual base.
7. Jump to the DLL entry point (`DllMain`, `DLL_PROCESS_ATTACH`).

**The DLL (`refDll.cpp`)** — `DllMain` spawns a thread that XOR-decrypts an embedded shellcode with the same scheme as `script/xor.py`, allocates RW memory, re-protects it to RX and runs it. The demo payload pops `calc.exe`.

**The dropper (`freedent/freedent.cpp`)** — the compiled `freedent.dll` is XOR-encrypted into a C header (`freedent/freedent.h`) by `script/xor.py`. The dropper decrypts it into a RW buffer, re-protects it to RX, then parses the *raw file image* export table (converting RVAs to file offsets with its `RVA_to_Offset`) to locate the `ReflectiveLoader` export and executes it at `buffer + file_offset`. The loader then completes the mapping itself (sections, IAT, relocations listed above).

## Build

Requirements:
- `x86_64-w64-mingw32-gcc` / `x86_64-w64-mingw32-g++` (MinGW-w64 cross toolchain, Debian/Ubuntu: `apt install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64`)
- Python 3

```bash
# 1) Build the reflective DLL and regenerate the encrypted header
./compile.sh

# 2) Build the dropper (edit the cp target path in freedent/compile.sh first)
cd freedent && ./compile.sh
```

`freedent/compile.sh` ends with `cp freedent.exe /home/vedlam/maldev` — a hardcoded personal path; change it to suit your setup before building.

To embed a different payload in the DLL, encrypt it with the helper and paste the output into the `payload[]` array in `refDll.cpp`:

```bash
python3 script/xor.py your_shellcode.bin
```

## Credits

- `script/ConvertToShellcode.py` and `script/ShellcodeRDI.py` are from the [sRDI](https://github.com/monoxgas/sRDI) project (Shellcode Reflective DLL Injection, based on Matt Graeber's research).

