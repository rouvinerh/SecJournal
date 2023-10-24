---
description: Explanation of address manipulation
---

# Address Manipulation

## How it Works

Buffer overflows are vulnerabilities within programs that can lead to RCE and crashing of whatever program we are running.&#x20;

The term **buffer** is used to refer to any area in memory where more than one piece of data is stored. **Overflow** is when we try to fill more data than the buffer can handle. For example, if we allocate 40 bytes of memory to store 10 integers, with 4 bytes per integer, and we send 11 integers, whatever was in the 4 byte slot after the 10th slot of memory would be overwritten as the 11th integer.

Sometimes, the program would crash totally if given too much to process with a **segmentation fault**.&#x20;

We can analyse this code snippet here:

```c
int main(int argc, char *argv[]){
    argv[1] = (char*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    char buffer[10];
    strcopy(buffer, argv[1], sizeof(buffer));
    return 0;
}
```

The `buffer` variable is an array that can store up to 10 characters, however we have overflown that with our `strcopy` function because there are more than 10 characters being loaded into it.

Within the stack, this is what the program would store normally:

<figure><img src="../../.gitbook/assets/image (800).png" alt=""><figcaption></figcaption></figure>

Should we overflow the buffer variable, this would **overwrite the EBP and EIP**. The return address of the function thus changes.

<figure><img src="../../.gitbook/assets/image (195).png" alt=""><figcaption></figcaption></figure>

So when the program returns from the function, and the **epilogue** of the function tries to set the return address, it would set it as the string of 'A' instead. Thus, this crashes the program as it cannot return to normal execution flow.&#x20;

### Exploitation

We can analyse another snippet of code to see how **we can manipulate the EIP to return to another address.** Suppose for this case there are no security measures in place.

```cpp
#include <iostream>
#include <cstring>

int bf_overflow(char *str){
    char buffer[10];
    strpy(buffer, str);
    return 0;
}

int good_password(){
    printf("Valid password supplied\n");
}

int main(int argc, char *argv[]){
    int password = 0;
    bf_overflow(argv[1]);
    if (password == 1){
        good_password();
    }
    else {
    printf("Invalid Password\n");
    }
    printf("Quitting\n");
    return 0;
}
```

This bit of code here has a function that would otherwise not be able to be exploited. However, it seems to take an input, seeing as it passes arguments to the function.&#x20;

The buffer in this case is 10 characters, and we first need to find the exact number of characters used to **overwrite the EIP**.&#x20;

First we would need to find the number of characters needed to **crash the program**. For this program, when tested, should take 26 characters before crashing. This means that we need **22 garbage characters to overflow the buffer, and the next 4 would be the EIP itself**.

When we decompile the binary for this program, we get something like this:

<figure><img src="../../.gitbook/assets/image (1575).png" alt=""><figcaption></figcaption></figure>

So the `good_password()` function is at `0x00401548`. This means that our payload would be 22 characters and the address of the function appended at the back.

We can write a basic script to automate this.

```python
import sys
import os
payload = "\x41" * 22
payload += "\x48\x15\x40" # take note of endianness! reverse addresses if needed
# most of the time we do not include null bytes (\x00) which can cause corruption of memory
command = "goodpwd.exe %s" %(payload)

os.system(command)
```

When executed, this would overflow the buffer, and print the good password output.&#x20;

## Vulnerable Functions

In C, there are a lot of functions that are vulnerable to buffer overflows. The common occurrence between these functions is that **they do not have input validation or length verification**. Anyone can key in an absurdly long input and force the program to process it, which would allow for BOF to take place.

For example, we can compare the `fgets()` and `gets()` function in C. Both of which take user input and do something with it. Here's some documentation for the functions:

```c
char *fgets(char *str, int n, FILE *stream)
char *gets(char *str)
```

The `fgets()` function takes one `int n` variable, which represents the **length of the input it receives**. `gets()` on the other hand, simply takes a string in without length validation. Because one checks for length, it is **more secure** than the other. `gets()` is rather notorious for buffer overflow exploits, whereas `fgets()` is more secure **but not invulnerable**. It is still exploitable if it is used incorrectly!

Here are a list of functions that I look out for when decompiling binaries to view the code:

```
strcpy
strcat
gets
fgets
scanf
fscanf
vsprintf
printf
memcpy
```

If the length of an input is not validated properly using these functions, it would indicate that it could be vulnerable to BOF as we are able to overflow something and exploit the program.&#x20;

Apart from these functions, when looking out for BOF, we should take note of any **user-controlled input that is not sanitised and passed to a program**. In general, if we see something that isn't checked for length, it could be vulnerable, and **it is not limited to these few functions**.&#x20;

In general, to avoid BOF:

1. Check user input, make sure that the length is validated. If we accept 50 characters, then make sure the length is 50.
2. If user input is passed anywhere, ensure that there are checks in the length of input.
3. Only allow alphanumeric characters. Attackers can sometimes exploit the fact that **only length is being validated and not size**. BOF can (technically) happen using unicode characters, which contain up to 4 bytes per character.&#x20;
