---
description: Rough summary of techniques and things I've picked up. Will be adding more as I go along.
---

# Techniques

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