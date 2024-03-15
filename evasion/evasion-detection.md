---
description: A very brief walkthrough of how security solutions detect malware.
---

# Detection

Security solutions are great, but they aren't perfect and there are always new techniques being found to bypass their detections. Most of the time, security solutions send copies of potential malware samples to the cloud for further analysis, and they are added to their databases to prevent repeat attacks.

It is important to note that there is no perfect security solutions, but they are getting better each day. If there were perfect security solutions, I'd be out of a job.

## Static

Signatures are a series of bytes within malware that uniquely identifies it. Other conditions like variable names and imported functions can also be used. The most popular tool used to configure signature based detection is called YARA. Signature based detection can also involve monitoring network traffic to detect C2 beacons.

{% embed url="https://virustotal.github.io/yara/" %}

For example, a malware from the APT group APT1 has `71 30 6E 63 39 77 38 65 64 61 6F 69 75 6B 32 6D 7A 72 66 79 33 78 74 31 70 35 6C 73 36 37 67 34 62 76 68 6A` within their malware strains. When YARA picks up on a malware with this exact specific string, it flags it as malicious.

This method is one of the easiest and most direct way of identifying malware.

## Hashing

Another easy method of identifying malware is through taking its hash digest. There are databases of known malware samples, and this is one of the methods they use. If there's a positive match between the hash of a program and the security solution's hash, then it is flagged and removed.

However, this method is easily bypassed as attackers can just change 1 byte of the malware's code to completely change the hash.

## Heuristic Detection

This method is used to detect and spot suspicious characteristics of a file that can be found in new malware. For example a `.jpg` file being massive is a red flag. There are static and dynamic methods of detection.

### Static

This involves de-compiling the program and comparing parts of the code with known malware samples part of the security solution's database. If it crosses a certain threshold, then the program is flagged. Of course, this comes with false postiives and negatives as we are dealing with thresholds.

### Dynamic

The program is placed within a sandbox (like a VM) and run. Afterwards, the security solution analyses the program for any suspicious behaviors. Stuff that is 'safe' includes virtually allocating memory, creating new files and all that. 'Unsafe' stuff includes virtually allocating shellcode, and then executing the code to fetch more shellcode from the Internet.

However, malware nowadays has **anti-sandbox methods** that are used to detect if it is in a sandbox environment. If it is, it could either do nothing or execute a bunch of useless code.

## API Hooking

Endpoint Detection and Response Systems (EDR) uses API hooking to monitor process or code execution in real time for any suspicious behaviours. API Hooking works by intercepting commonly abused APIs and analysing the parameters in real time. This is otherwise known as Userland-Hooking.

In short, the security solution can see the exact parameters that is being passed to each function, and use behaviour-based analysis to flag processes.

### EDR (Brief)

EDRs in particular do 3 things:

* Data Gathering -> Gather information from endpoint devices, which includes logs, processes being executed and so on.
* Data Logging -> Logs all the data in real-time.
* Detection -> The main purpose of it.

The reason EDRs are relatively harder to bypass is because of its continuous monitoring and collection of information from all endpoints in a network. In specific, they use machine learning to determine the root cause of all incidents.

I think about EDRs as robots that are consistently checking on each computer. It is possible to bypass this robot if we use API Unhooking, Indirect Syscalls, and suspended processes.

## Behaviour

This method involves the continuous checking of the program for any funny things. If flagged, an in-memory scan is done to see what exactly is being run. If needed, it terminates the process entirely. This method can also terminate processes immediately without the scan if needed.

## Manual

The last method is a malware analyst part of the blue team manually decompiling the malware to view what it does. There are anti-reversing and anti-debugging techniques that can make this a lot harder.
