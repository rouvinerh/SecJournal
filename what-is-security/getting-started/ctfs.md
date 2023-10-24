# CTFs

## CTFs

Capture-The-Flags are basically computer security competitions that involve using cybersecurity skills. The most common type of CTF is Jeopardy style, where basically it consists of individual challenges. The goal of each challenge is to find a string of text known as the flag, like **flag{this\_is\_a\_fak3\_flag}.**&#x20;

The other type of CTF is called attack/defense, which is a real-life competition where teams are actively defending and attacking a network. I don't have much experience in this kind of CTF.

### Challenge Types

1. Web
   * Challenge spawns a website, and there is a web attack vector to use to gain the flag.
   * Could be stuff like **SQL Injection, OS Command Injection, Server Side Request Forgery etc.**
2. Forensics
   * Analysis of some kind of log file or disk image and the flag is contained within it.
   * Steganography is technically part of this(?), and that involves finding hidden information in images.
   * Such files include **packet captures, images, .git repositories etc.**
3. Pwn / Binary Exploitation
   * To exploit a program running on a server to find the flag.
   * Generally, they give you the program (.exe / .elf) that is running on a port of the server, and fuzzing, decompiling and reverse engineering is needed to find the vulnerability in how the program processes user information is needed.&#x20;
   * Buffer Overflow and its variants are typically used here, and this is where Python scripting is so useful (pwntools).&#x20;
4. Cryptography
   * Decrypting or encrypting a piece of data that is basically the flag.
   * Involves math and exploiting limitations of certain algorithms.&#x20;
   * Most commonly, stuff like **insecure PRNG, RSA with tweaks (such as having a small exponent)** are tested here.
5. Reverse Engineering
   * Self-explanatory. Given a program or file, find out how it works and RE it to find exploitable vulnerabilities.&#x20;
   * Sometimes, it incorporates other fields like reverse engineering to find a binary exploitation, or reverse engineering a cryptographic algorithm.
   * `ghidra` and `dnspy` are commonly used.&#x20;
6. Misc.
   * Could be anything! The most wildcard of all the challenges.&#x20;
   * Open Source Intelligence Gathering (OSINT), which is basically intense Googling is sometimes  here, if not a category on its own.&#x20;

CTFs are insanely fun and one can learn a lot from doing them. It's a great way to start cybersecurity.

## Where to Start

### [CTF Time](ctfs.md#https-ctftime.org-ctftime)

CTF event tracker, just sign up and join one!

### [CTF Learn](ctfs.md#ctf-learn-https-ctflearn.com)

A website to practice user created CTF challenges at your own time and pace.

### [**PicoCTF**](https://portswigger.net/web-security)

CTF platform hosted by Carnegie Mellon University for everyone to learn more about security. You can either take part in the upcoming PicoCTF, or attempt challenges from the past.

### [PortSwigger Academy](https://portswigger.net/web-security)

The best possible resource to learn the OWASP 10 and all kinds of website hacking techniques, with interactive labs to test your skills. Best part is that it is absolutely free!

Apart from taking part in CTFs, **do ensure to read lots of writeups as well**. Learning how other people approach challenges and the methodologies they use to solve them is crucial in getting better.&#x20;

There are many more websites and stuff that have CTFs happening. I recommend finding a friend, or a team and tackle these challenges together.
