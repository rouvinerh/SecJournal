---
description: A rough summary of techniques for now. Will be creating pages for each in future, and adding more as I go along (and when I have more time from NUS :C)
---

# Techniques

The real fun part of this is that one can combine multiple techniques together to create even better droppers. It's up to your imagination! Just note that the creation of payloads in C/C++ and C# are vastly different!

## Good Practices

1. Always encrypt / obfuscate shellcode via XOR, AES or whatever other techniques.
2. Treat security solutions as 'guards', always aim to make as little noise and impact as possible before delivering final payload.
3. Always cleanup memory that is not being used / once program finishes. For example, decrypted payloads should not be left in memory, `memset` it to NULL if needed to prevent security solutions from detecting, OR deallocate remote memory using `VirtualFreeEx`.

## Shellcode Execution

Executes shellcode in a local process. In general:

1. Allocate space for your shellcode via `VirtualAlloc` with permissions of RW via `PAGE_READWRITE` if you want to avoid RWX pages that look suspicious. Alternatively, set to RWX via `PAGE_EXECUTE_READWRITE`.
2. Write payload to allocated space via `memcpy` or other methods.
3. If need be, change permissions of the memory page via `VirtualProtect`. 
4. Execute it via `CreateThread`.

## Process Injection

### DLL Injection

Executes arbitrary DLL inside a remote process. In general:

1. Find the process you want to inject to, and search through a Windows processes snapshot taken using `CreateToolhelp32Snapshot`.
2. Process search is done iteratively using `Process32First` and `Process32Next`. 
3. Once process found, get **Process ID** (PID) and a **handle** to process via `OpenProcess`. 
4. Write the **full path** to the DLL into process via `VirtualAllocEx` and `WriteProcessMemory`.
5. Create remote thread within remote process to load and execute the DLL via `CreateRemoteThread` and either `LoadLibrary` or `LoadLibraryW`.

### Shellcode

Similar to DLL Injection, just that instead of writing a DLL Path, write shellcode instead.

1. Similar process of finding the desired process to inject to via snapshots and iterative search.
2. Allocate memory for and write shellcode via `VirtualAllocEx`, and `WriteProcessMemory`. You can choose to change permissions of page via `VirtualProtect`.
3. Execute it via `CreateRemoteThread`.

## HTTP Callbacks

Performs HTTP callback to download shellcode from remote source, better than hard coding shellcode into the program.

1. Create `HINTERNET` variable via `InternetOpenW`
2. Create `HINTERNET` variable for file via `InternetOpenUrlW.
3. Dynamically allcoate enough space on heap via `LocalAlloc` or any other method.
4. Using loop, read via `InternetReadFile` and store the shellcode bytes read into space allocated earlier. Remember to reallocate and clear space as needed to read next set of bytes. (basic socket programming via WinAPI)
5. `InternetCloseHandle` on `HINTERNET` objects, and `InternetSetOptionW` to close all.
6. Shellcode is now stored within program's memory.

## API Hashing

Avoids having suspicious entries in IAT and strings within the binary. Uses static hashes created from any hashing algorithm (Murmur for eg.) Remember that PEB uses RVAs and not absolute addresses.

In short, you want to get the pointer to a function like `CreateThread` without actually calling `CreateThread` directly, since this is highly flagged by security solutions.

1. Find out hashes for strings like `KERNEL32.DLL` and `CreateThread` (or whatever we want to call).
2. Retrieve PEB struct via `(PEB*)(__readgsqword(0x60))` for 64-bit, retrieve pointer `Ldr` member of PEB.
3. Retrieve linked list of loaded modules `PLDR_DATA_TABLE_ENTRY` via `pLdr->InMemoryOrderModuleList.Flink`.
4. Iterate through entire linked list, comparing hashes with each DLL loaded until finding the one wanted. Store a `HMODULE` variable for this DLL, used for steps 5 - 8.
5. Get DOS header, then NT header, then optional header and then Image Export Table of the DLL.
6. Get names, addresses and ordinals of the function within the struct.
7. Iterate through the entire function list and compare hashes until finding the correct one.
8. Return pointer to this function.

I haven't written the code for runtime hashing methods.

## Stomping

Prevents the usage of highly monitored WinAPIs, done through overwriting DLLs loaded within a binary. There are 2 methods, one is module stomping which overwrites an entire DLL into a process's memory. The other is function stomping which overwrites a single function from a pre-loaded DLL.

### Function Stomping

1. Find and get a handle to a remote process via `CreateToolhelp32Snapshot` method and `OpenProcess`.
2. `LoadLibraryA` for whatever DLL is loaded in the remote process (For example, load `TextShaping.dll` for `notepad.exe`).
3. `GetProcAddress` of a benign function (`TextShaping.dll` contains `ShapingGetGlyphPositions` function).
4. `VirtualProtectEx` to change the permissions of memory, then `WriteProcessMemory`.
5. `CreateRemoteThread` and `WaitForSingleObject` to execute shellcode.

### Module Stomping

WIP.

## Adding More Soon!