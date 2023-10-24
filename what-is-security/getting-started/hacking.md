---
description: Not just pressing the 'Hack' button and saying "we're in".
---

# Hacking

## Boxes

Boxes are technically still CTFs, but instead of having a independent challenge in one category, they are more like incorporated CTFs. All categories in a CTF could be tested here. One box could have a web exploit for initial access and then a binary exploit to become the administrator.

The goal is the same, to get a string of text, but instead the process is different. Here's how it works:&#x20;

* Start scanning the machine.
* Determine vulnerabilities within the services running on the system, and exploit them to gain access as a low-privilege user.&#x20;
* **Read the user flag.**
* Scan within machine to find misconfigurations and vulnerabilities
* Exploit those vulnerabilities to become the Administrator / Root user of the machine
* **Read the administrator flag.**
* Using the current machine, pivot to other machines that are connected (if pivoting is needed)

Points for these will be earned on every flag submitted, and of course one would aim for the root flag.

### Type of boxes

There isn't a fixed category of boxes per se as a wide range of skills can be tested, but I like to categorize them into 2 types:

1. Active Directory
   * Box is connected to a Microsoft directory service for Windows domain networks.&#x20;
   * Exploits used here involve some kind of misconfiguration with the Active Directory, and require a different set of tools to exploit.
   * May or may not involve pivoting, which means to reach a hidden device behind a firewall that is not reachable from our own machine but reachable from the vulnerable target machine.
   * Involves scanning / exploiting a lot of different services and protocols.
   * The goal here is not just to become the administrator of the machine, **but rather to become the domain admin of the entire network.**&#x20;
2. Conventional Machines
   * Machines are independent and not related to other machines.&#x20;
   * Exploits used here are generally localized and the goal is just to become the root user of the machine.

More on Active Directory would be covered in a later section.

## Practice

### [HackTheBox](hacking.md#https-www.hackthebox.eu-hackthebox)

HacktheBox has ton of online machines to hack, and it's the best place by far to practice. It features a ton of paths, and a very cool platform to learn hacking in a more guided method.&#x20;

This website **does not hold your hand**, and you are thrown into the deep end. It really makes you learn a lot about it, thorugh banging your head against the wall and a lot of research.

Suscription to the VIP+ service costs about SG$20-30, if you're considering starting for real.

They also host competitions like UHC, which is basically a root box competition.

### [TryHackMe](hacking.md#https-tryhackme.com-tryhackme)

A good platform similar to HTB that holds your hand more. The machines here are generally easier compared to that of HTB machines. Definitely a good resource fore beginners to start learning how to break stuff.

### [VulnHub](hacking.md#https-www.vulnhub.com-vulnhub)

A website where vulnerable virtual machines can be downloaded and then hacked. It's all free too! The machines themselves take a while to download however, so make sure you have space for them.

### [Proving Grounds](hacking.md#https-portal.offensive-security.com-labs-practiceproving-grounds)

Compared to HTB Machines, which are a bit longer and less realistic, Proving Grounds machines have more real-world vulnerabilities and are a lot shorter. Some of the machines are retired exam boxes, and some are just made by Offensive Security themselves.

The feel of these machines is very similar to that of PWK and OSCP exam machines, and I highly recommend this for preparing for the OSCP. Costs about SG$25 a month.
