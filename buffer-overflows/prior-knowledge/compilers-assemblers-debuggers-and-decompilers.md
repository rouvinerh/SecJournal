# Compilers, Assemblers, Debuggers and Decompilers

## Compilers

Compilers are quite similar to assemblers. These programs take high-level source code and converts that into low-level code directly into an **object file**. The end result from this is an executable file, such as .elf or .exe.&#x20;

Some compilers include `clang` or `gcc`. Some compiled languages do not **translate their code into machine code,** such as Java. C and C++ would compile into machine code directly, whereas Java would be compiled into an intermediate form known as JVM byte code. This byte code is then compiled into machine code for execution.

## Assemblers

An assembler is a program that translate **assembly code** **into machine code,** and there are severeal types of assemblers built for different operating systems and processors.

* Microsoft Macro Assembler (MASM) uses the Intel syntax for Microsoft Windows
* GNU Assembler (GAS) is used by the GNU project
* Netwide Assembler (NASM) relies on x86 architecture that is used to write 16-bit, 32-bit and 64-bit programs. This one is quite popular for Linux
* Flat Assembler (FLAT) is a x86 assembler that supports Intel-style assembly on the IA-32.

For now, we will be focusing on NASM, which is the most common one used.

When a source code file is assembled, the resulting file is called an **object file**. It's a binary representation of the program. The assembler's job is to do some further operations to refine our assembly code, such as assigning memory location to variables and instructions. It also resolves symbolic names.

The process is outlined below:

<figure><img src="../../.gitbook/assets/image (2354).png" alt=""><figcaption></figcaption></figure>

Once the assembler creates the .obj file, a **linker** is needed to create the executable file. Linkers take one or more object files and combine them together. An example of an object file is a Dynamic Link Library file (.dll) used to create a .exe file together.

## Debuggers

For debuggers, one that I recommend is **Immunity Debugger** for Windows. Make sure that you do not run **Immunity Debugger** on bare metal because it requires Windows Defender to be off (to execute and reverse engineer malicious files), so run it on a VM.

Debuggers are really useful, because they allow for us to view the memory stored within the registers, break the execution flow where needed, and so on.

I use Immunity Debugger a lot for Vanilla BOFs (for OSCP) and it's really handy to use in conjunction with **mona.py.**&#x20;

Here's how Immunity Debugger would look when a binary is loaded.

<figure><img src="../../.gitbook/assets/image (2850).png" alt=""><figcaption></figcaption></figure>

The windows are as follows:

1. Disassembler Panel
   * This is hte most important window, where all assembly code is produced or viewed when debugging stuff
   * The instructions can be viewed and reviewed to find exploits
2. Register Panel
   * This would hold information about the memory within the registers
   * As the program is executed, this window changes values a lot
3. Memory Dump Panel
   * Shows the memory location and contents in different formats.
   * For the image above, it is showing a hex dump of the binary
4. Thread Stack
   * This is the window where we can view the contents of the stack
   * Immunity Debugger attempts to include explanations of the content so we can follow it better as it's not exactly readable for humans.

## Decompilers

Decompilers are programs that attempt to translate a binary back into high-level code. I say attempt because it **cannot recreate the exact binary majority of the time**. It does however provide an easier to read format to reverse engineer code. Otherwise, you would be staring at hex or assembly.

Some popular decompilers I use are `ghidra` and `dnspy`, for Linux and Windows respectively. You can install `ghidra` using `apt` on Linux machines, and is commonly used for .elf files. This tool also lists the functions that are present within the binary for easy following.

Here's an example of `ghidra` output:

<figure><img src="../../.gitbook/assets/image (1473).png" alt=""><figcaption><p><em>Taken from HTB 0xDiablos</em></p></figcaption></figure>

Not exactly translated back into C, but very close.&#x20;

`dnspy` is used for decompiling .NET code compiled using C#. In other words, most .exe files.&#x20;

Here's another example of dnSpy decompiling code:

<figure><img src="../../.gitbook/assets/image (3390).png" alt=""><figcaption><p><em>Taken from HTB Support</em></p></figcaption></figure>

This tool tends to do a better job at decompiling it very close to the actual code written.&#x20;

{% embed url="https://github.com/dnSpy/dnSpy" %}
