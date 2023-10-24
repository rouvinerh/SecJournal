---
description: Taken from eCPPTv2.
---

# System Architecture

## CPU, ISA and Assembly

The Central Process Unit (CPU) is in charge of executing machine code of a program. For example, when we compile C code, we would need a **compiler** like `clang` or `gcc` that would convert the code into a binary (.elf or .exe), which is basically machine code that the computer can read.&#x20;

<figure><img src="../../.gitbook/assets/image (1965).png" alt=""><figcaption></figcaption></figure>

**Assembly** is the human interpretable format of machine code, which is written using a set of instructions that the CPU processes. In assembly, each instruction is a primitive command that executes specific operations, such as moving data, changing the execution flow and it performs logical operations.

CPU instructions are represented in hex, and it's impossible for humans to use this in hex format because we can't read hex (obviously). Hence, this code gets translated into **mnenomic** code using tools like `nasm`.&#x20;

<figure><img src="../../.gitbook/assets/image (3682).png" alt=""><figcaption><p><em>helloword.exe program</em></p></figcaption></figure>

Each CPU has their own set of instructions and differ from one another. This set is known as the **instruction set architecture (ISA)**, which a compiler must understand and use to write the program. The ISA is what the programmer sees, which involves the memory, regiusters, instructions and so on. This provides all the necessary instructions for someone that wants to write a program in assembly.

The most common ISA is the **x86** instruction set, which identifies 32-bit processors. The other format would be the **x64** set, for 64-bit processors. The number of bits refers to the length of the CPU registers, and each CPU has fixed sets of registers that can be accessed.

### Registers (x86)

Think of registers like variables used by the CPU to store and get data. Some registers have specific roles and instructions, while others can be used for general data storage. For example, we can take the **null register**, which basically makes the data stored in another register 0.

**General Purpose Registers (GPRs)** are a set of registers that can be used for normal assembly. They each have a specific name and purpose.

<figure><img src="../../.gitbook/assets/image (3779).png" alt=""><figcaption></figcaption></figure>

In a 32-bit system, each register is an acryonym that is prefixed with 'E', meaning extended. The E is replaced by 'R' in x64.&#x20;

<figure><img src="../../.gitbook/assets/image (4033).png" alt=""><figcaption></figcaption></figure>

**The most important register** is called the **instruction pointer or EIP.** This register controls the flow of program execution through storing a pointer to the address of the next instruction where it will be executed. The entire point of a **buffer overflow to RCE is to control this one register**.

## Process Memory

When a process runs, it is organised in a stack shape, and this is called Process Memory. When we run a binary, the data loaded in memory is shown in this diagram:

<figure><img src="../../.gitbook/assets/image (1572).png" alt=""><figcaption></figcaption></figure>

The process is divided into 4 regions:

1. .text
   * A region of memory that is fixed by the program and contains the program code
   * Marked as **read-only** and it does not change throughout the execution.
2. .data
   * Divided into initialized and uninitialized data.
   * Initialized data includes items such as static variables, which are pre-defined and can be modified.
   * Uninitialized data is called **Block Stated by Symbol (BSS),** which contains variables that are initialized to 0 or do not have any explicit initialization.
3. Heap
   * Heap is a space of memory reserved for any manual allocation through `malloc` or `calloc`.&#x20;
   * During execution, program can request more space if neede, and this size of the data region extends **downwards**.&#x20;
4. Stack
   * Where the main bulk of execution takes place
   * Grows **upwards,** meaning as more variables are declared, they are placed on top with higher memory addresses.
   * **Last in First out principle**, meaning that variables that are declared last would be cleared first when execution ends.

The **ESP register** would store a pointer that identifies the top of the stack, and it is modified each time a value is pushed in or popped out. The **EBP register** points to a memory location saved on the stack.

The most fundamental operations are the **PUSH** and **POP** instructions, which basically 'pushes' data into or 'pops' data out of the stack. The value of the ESP changes each time this instruction is called.

### PUSH

This instruction minuses 4 in 32-bit or 8 in 64-bit from the ESP and updaters the ESP. It substracts to a point with **lower memory location** on the stack.

<figure><img src="../../.gitbook/assets/image (1106).png" alt=""><figcaption></figcaption></figure>

### POP

When POP is executed, it retrieves the data from the top of the stack. Therefore the data contained at the ESP would be retrieved and stored in another register. The POP instruction would increment the value by 4 or 8 depending on the type of processors.&#x20;

**Take note that when the value is popped from the stack, it is not deleted.** Data and files in a computer cannot just be removed. They are still present in the stack, **but flagged as overwriteble**. This indicates that when new data is loaded, the memory overwrites the old data, effectively 'removing it'.

### Stack Frames

A bit of CS1010 knowledge here. When we call a function, they are stored in something called **stack frames**. Each function would contain a **prologue**, which is the start of the function that declares variables and it readies the stack. The end of the function would be called the **epilogue**, which resets the stack back to prologue settings.&#x20;

These stack frames are PUSHed when called, and POPped when they return. This allows for the function or **subroutine** to operate independently in its own location in the stack. The memory and variables within one stack frame **would not impact another directly** (unless programmed specifically to). When the function ends, the following happens:

1. Program receives the parameters passed from the subroutine.
2. The EIP is reset to the location at the time of the initial call. This means that it points back to the original location where it came from.

The stack frame keeps track of the location where each function should return to when it terminates.&#x20;

We can take a look at an example in C:

```c
int b(){ // function b
}

int a(){ //function a
    b();
    return 0;
}

int main(){ //main function where program starts
    a();
    return 0;
]
```

The stack frames would look like this for the program above:

<figure><img src="../../.gitbook/assets/image (3235).png" alt=""><figcaption></figcaption></figure>

As the stack frames are popped out, the EIP would point back to `a()` and then `main()`, changing where the execution flow starts and resumes.&#x20;

### Execution Flow

Take this snippet of code here:

```c
void func (int a, int b, int c){
    int test1 = 55;
    int test2 = 56;
}

int main (int argc, char *argv[]){
    int x = 11;
    int z = 12;
    int y = 13;
    func (30, 31, 32);
    return 0;
}
```

#### First Call

When the `main()` function is called, the stack frames would look like so:

<figure><img src="../../.gitbook/assets/image (319).png" alt=""><figcaption></figcaption></figure>

The program first needs to save its location, since if we lose it, we can't run our program anymore as we would lose the `main()` function. Specifically, the processors PUSHes the content of the EIP (which is basically a pointer to the address of memory that the variables are stored in) to the stack. The `main()` function is called via a CALL instruction, and the EIP points to the **first byte** after the CALL instruction.&#x20;

The instruction that executes the `main()` function, also known as the **caller, loses control of the execution, and the `main()` function takes over**.

A new stack frame is created, and **defined by the ESP and EBP**. Since we cannot lose the old stack frame and its information, the current EBP is saved on the stack.&#x20;

<figure><img src="../../.gitbook/assets/image (1118).png" alt=""><figcaption></figcaption></figure>

#### Prologue

Then, the **prologue** happens. The prologue is a sequence of instructions that takes place at the beginning of a function, and this occurs for all functions.

```asmatmel
push ebp
mov  ebp, esp
sub  esp, <variable>
```

Breaking it down:

1. `push ebp`
   * This saves the old base pointer onto the stack, so that it can be restored later. Recall the the EBP is used to store memoyr locations on the stack.
   * The EBP now points to the location on top of the previous stack frame.
2. `mov ebp, esp`
   * This moves the value of the ESP into the EBP. It is this instruction that creates a new stack frame on top of the stack.
   * The base of the new stack is **the top of the old stack frame**.&#x20;
3. `sub esp, <variable>`
   * This would substract the value of the ESP by a specific number (in this case, the value of the variable is an integer) to make space for the variables from `main()`.
   * This variable tends to be a multiple of 4.

<figure><img src="../../.gitbook/assets/image (165).png" alt=""><figcaption></figcaption></figure>

Once the prologue ends, the stack frame for `main()` is complete and local variables are coped onto the stack. Since the ESP is not pointing to the memory address right after the EBP, we cannot use the PUSH operation since it stores values top of the stack. **We want to store the variables where space has been allocated for it**.&#x20;

As such, the ESP would be **incremented** as variables are stored in it and it **moves downwards**. In this case, ESP + Y is a memory location somewhere between the EBP and ESP. Each time it is incremented, the variables are PUSHed into the stack.

Take note of how we declare `int x = 11` first, hence its PUSHed last.&#x20;

<figure><img src="../../.gitbook/assets/image (3948).png" alt=""><figcaption></figcaption></figure>

When we call the `func()` function, this would repeat again. The prologue changes values of the EBP to indicate the creation of another stack frame in memory would occur. This process continues until all variables are stored in their own stack frames.

<figure><img src="../../.gitbook/assets/image (2807).png" alt=""><figcaption></figcaption></figure>

Notice how the ESP keeps pointing to the top of the stack of other frames, and the old values are still stored within the stack.

#### Epilogue

Then, the **epilogue** happens. This process does the following:

* Returns execution control to the caller
* Replaces the ESP with the current EBP, and POPs the EBP out of the stack
* Returns to the caller by POPping the instruction pointer from the stack, and execution jumps to it.

There are multiple ways for epilogues to occur:

```asmatmel
mov  esp, ebp
pop  ebp
ret

OR

leave
ret
```

When the function returns **(this happens even without a return statement because it is in-built),** the ESP and EBP are 'moved' to have the same value and point to the same location.

Then, the ESP is updated through the POP instruction and now points towards the old EIP previously stored. The caller stack frame is now restored with execution flow.

The `ret` instruction POPs the value at the top of the stack to the old EIP. This gives control back to the caller, since the EIP controls where exeuction flow and hence control takes place. This instruction **only affects the EIP and ESP registers**.

After `func()` returns, the stack frames look like this:

<figure><img src="../../.gitbook/assets/image (1995).png" alt=""><figcaption></figcaption></figure>

## Endianness

Endianness refers to how storing values in memory works. There are 2 types of endianness, **big-endian and little-endian**. The endianness changes where the Most Significant Bit (MSB) and Least Significant Bit (LSB) are stored.&#x20;

* MSB refers to the largest binary number, and its usually the first number from the left
  * For example, a binary number of 100 would have an MSB of 1.
* LSB would be the inverse of MSB.

In Big Endian representation, the LSB is stored in the **highest memory address**.

<figure><img src="../../.gitbook/assets/image (2477).png" alt=""><figcaption></figcaption></figure>

For LSB, it's the opposite:

<figure><img src="../../.gitbook/assets/image (1442).png" alt=""><figcaption></figcaption></figure>

This affects the order of which a program reads code, and affects the type of payloads associated with buffer overflows.

## No Operation Instructions (NOP)

This is an assembly instruction that tells the code to skip to the next instruction. It has a hex value of \x90, and this does have use within assembly.

For instance, if we want to skip along the code and fill the stack with NOPs to begin execution elsewhere, we can just pad payloads with these instructions. This is known as an **NOP-sled**.&#x20;
