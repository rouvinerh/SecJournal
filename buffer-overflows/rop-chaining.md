# ROP Chaining

Return Oriented Programming (ROP) is technique that is able to bypass the NX security feature as well. **Technically, Ret2Libc is a subset of ROP**.&#x20;

ROP involves the creation of new stack frames through controlling of return addresses to **jump** to different fragments of code, called gadgets. Ret2libc is a type of ROP because we still create stack frames, however we are simply utilizing the `system()` function to gain a shell instead. &#x20;

For ROP Chaining, we jump to different fragments of code and sort of 'build' a program within the program by chaining the different fragments together. ROP is really cool because we can literally **program the code to execute what we want**, and create new routines that are not intended at all.&#x20;

## How it Works

We will be utilizing a binary that has ASLR, but NX enabled. Here's a sample of code that would be exploitable:

```c
#include <stdio.h>
#include <string.h>

void fun1(){
	printf("1\n");
}

void fun2(){
	printf("2\n");
}

void fun3(){
	printf("3\n");
}

void rop(char *string){
	char buffer[50];
	strcpy(buffer, string);
}

int main(int argc, char** argv){
	rop(argv[1]);
	return 0;
}
```

We can compile this program using the following commands:

```bash
echo 0 > /proc/sys/kernel/randomize_va_space # disable ASLR, which is enabled by default
gcc -m32 -fno-stack-protector -z execstack vulnerable.c -no-pie -o vuln
echo 1 > /proc/sys/kernel/randomize_va_space
```

We should end up with a binary with these features:

<figure><img src="../.gitbook/assets/image (3969).png" alt=""><figcaption></figcaption></figure>

Most importantly, for now, we will disable ASLR to allow for easier exploitation. So our binary takes in one input and does does a `strcpy()` with it. We can check that it segfaults if given too long of an input:

<figure><img src="../.gitbook/assets/image (2337).png" alt=""><figcaption></figcaption></figure>

### Code Analysis

There are 3 functions witin the code that are not meant to be executed in anyway. The program starts at `main()`, which calls the `rop()` function to execute a `strcpy(buffer, string)` instruction. We already know that `strcpy()` is vulnerable to buffer overflow because it does not check for length.&#x20;

The goal here is to trigger **all 3 of these functions using basic ROP chaining in numerical order**. First, we know to overflow the `strcpy()` function, which I want to use to call `fun1()`. Then, `fun1()` would return and call `fun2()`, and this repeats until all are called, then I would call `exit()` to let the program quit.

Our payload would look like this:

```
payload = AAAAA... + BBBB  + &fun1 + &fun2 + &fun3 + &exit
```

The 'BBBB' characters are present to overflow the EBP, and the address of `fun1()` comes right after. Recall that the stack frame looks like this at the tail end of the function.

<figure><img src="../.gitbook/assets/image (1862).png" alt=""><figcaption></figcaption></figure>

### Basic Exploit

Now, we need to open this up in `gdb` to analyse its contents.

```bash
gdb rop
b main
r
```

Then, we can find the addresses of these functions.

<figure><img src="../.gitbook/assets/image (2057).png" alt=""><figcaption></figcaption></figure>

My addresses are static because ASLR is disabled, so no worries for that. Now, we need to find the offset needed. The offset should be about 50, but I'll generate a pattern of length 70 in case.

<figure><img src="../.gitbook/assets/image (3254).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (2804).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (3580).png" alt=""><figcaption></figcaption></figure>

The offset is 62, and now we can start to construct our exploit script. Since this is a 32-bit binary (as compiled), we would need to account for the endianness of the addresses. Using python, we can create the payload and send it as the input for the function. This is done using the expression syntax `$()` for Linux terminals.

The number of As would be 58, which is offset of 62 - 4 since we need the next 4 bytes need to overwrite the EBP. Then the rest of our addresses would come after. If done correctly, the exploit would look like this:

<figure><img src="../.gitbook/assets/image (1261).png" alt=""><figcaption></figcaption></figure>

We have successfully called all other functions without the program meaning to do so. In this case, notice how it **does not cause a segmentation fault.** This is mainly because we called `exit(),`which is used to exit the program gracefully.&#x20;

In essence, this is how ROP chaining would work on an ASLR-disabled function.

## With Variables

Now suppose that we change our program a bit to have the functions take in some variable. So, after returning to the address of the function, we would need to include some bytes representing the **arguments** for the function.&#x20;

For example, a function `fun1(int a, int b)` would need to have 2 integers be passed in before we can run the function. Else the program would complain that we did not supply enough variables and end. Potentially, **these variables can be manipulated with our own variables**. Suppose a function takes in a command and passes it to a `system()` call, then we can use ROP chaining to return to that function and include the specific command we want.&#x20;

So our payload would look like this:

```
payload = AAA.... + BBBB + &fun1 + &pop;ret + <variable> + &exit
```

If we **do not wish to enter this function and want to hop around more**, then we would need to use **ROP Gadgets**.

### ROP Gadgets

ROP gadgets are basically sequences of CPU instructions that are **already present in the program** that is being run. One example of a ROP gadget is the `JMP ESP` instructions that we used in the OSCP BOF example.&#x20;

Most of the time, these gadgets can be exploited to execute **almost any code**, and commonly end with the `ret` instruction. These gadgets bypass DEP because **there is no executable code from the stack,** and instead executable code is **manipulated** to achieve the same effect.

In `gdb-peda`, there is a command `ropgadget` which can find the addresses of these gadgets for us.&#x20;

We can change the vulnerable code above to include variables needed:

```c
#include <stdio.h>
#include <string.h>

void fun1(){
	printf("1\n");
}

void fun2(int a){
	printf("%d\n", a);
}

void fun3(int a, int b){
	printf("%d %d\n",a ,b);
}

void rop(char *string){
	char buffer[50];
	strcpy(buffer, string);
}

int main(int argc, char** argv){
	rop(argv[1]);
	return 0;
}
```



Now, the objective is still the same, we want to call the functions in order as per normal. But, pur payload would look something like this:

{% code overflow="wrap" %}
```
payload = AAA... + BBBB + &fun1() + &fun2 + &pop;ret + <rop2 arg1> + &rop3() + &pop;pop;ret + <rop3 arg1> + <rop3 arg2> + &exit()
```
{% endcode %}

The reason we want to include the first `pop; ret` is because we want to first `pop` the `rop2 arg1` variable out of the stack (to remove interference with our jumping) and then hop to `rop3`.&#x20;

Afterwards, because `rop3` takes 2 arguments, we would need to have 2 `pop` instructions to remove the 2 variables passed to `rop3` from the stack and then call `exit()` as per normal afterwards.&#x20;

We can take a look at the ROP gadgets that we have on hand for this binary.

<figure><img src="../.gitbook/assets/image (738).png" alt=""><figcaption></figcaption></figure>

The exploit would work as per the regular exploit. When we key in the variables to be printed, it prints, and jumps to the next function.
