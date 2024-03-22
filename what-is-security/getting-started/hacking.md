---
description: Not just pressing the 'Hack' button and saying "we're in".
---

# Hacking

## Boxes

Boxes on platforms like HackTheBox are technically still CTFs, but instead of having a independent challenge in one category, they are more like blended CTFs. All categories in a CTF could be tested here. One box could have a web exploit for initial access and then a binary exploit to become the administrator.

The goal is the same, to get a string of text. However, the process is different. Here's how it works:&#x20;

* Enumerate the services running on the machine.
* Determine vulnerabilities within the services running, and exploit them to gain access as a low-privilege user.
* Find privilege misconfigurations when in the machine.
* Exploit those vulnerabilities to become the Administrator / Root user of the machine
* Using the current machine, pivot to other machines that are connected if needed.

## Practice

### [HackTheBox](hacking.md#https-www.hackthebox.eu-hackthebox) (HTB)

HacktheBox has a ton of machines to hack, and it's the best place to practice.This platform  **does not hold your hand**, and you are thrown into the deep end. By doing so, you learn a lot (at the cost of sanity D:).

Subscription to the VIP+ service costs US$20 a month.

### [TryHackMe](hacking.md#https-tryhackme.com-tryhackme)

A more 'hand-holding' platform. The machines here are generally easier compared to that of HTB machines.

### [VulnHub](hacking.md#https-www.vulnhub.com-vulnhub)

A website where vulnerable virtual machines can be downloaded and then hacked. It's all free too! Very useful if you don't WiFi but want to hack something.

### [Proving Grounds](hacking.md#https-portal.offensive-security.com-labs-practiceproving-grounds)

Proving Grounds machines have a more real-world feel to them and are a lot shorter as compared to HackTheBox. The main selling point is OffSec themselves make some of the machines, which is useful for preparation for the OffSec Certified Professional (OSCP) exam.
