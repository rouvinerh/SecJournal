---
description: Not just pressing the 'Hack' button and saying "we're in".
---

# Hacking

## Boot2Root

Boxes on platforms like HackTheBox are technically still CTFs, but instead of having standalone challenges focused on one category, they give machines to hack instead. This is done through connecting to a VPN, and the platform spawning a vulnerable machine for you to enumerate and break into.

All categories in a CTF could be tested here. A box could have a web exploit for initial access and then a binary exploit to become the administrator.

The goal is the same, to get the flag, but the steps are a little different:

* Enumerate the services running on the machine.
* Discover and exploit vulnerabilities within the services running to gain access as a low-privilege user.
* Exploit more vulnerabilities within the machine itself to become the administrator user. This is called **privilege escalation**.
* Laterally move to other machines if needed.

## Boot2Root Websites

### [HackTheBox](../../what-is-security/getting-started/https-www.hackthebox.eu-hackthebox)

A super fun website to hack on, with many high quality machines endless vulnerabilities to exploit. Subscription to the VIP+ service costs US$20 a month.

### [TryHackMe](../../what-is-security/getting-started/https-tryhackme.com-tryhackme)

A more 'hand-holding' platform. The machines here are generally easier.

### [VulnHub](../../what-is-security/getting-started/https-www.vulnhub.com-vulnhub)

A website where vulnerable virtual machines can be downloaded, and run locally to be broken into.

### [Proving Grounds](../../what-is-security/getting-started/https-portal.offensive-security.com-labs-practiceproving-grounds)

Proving Grounds machines have a more real-world feel to them and are a lot shorter as compared to HackTheBox. The main selling point is that OffSec themselves make some of the machines, which is useful when preparing for the OffSec Certified Professional (OSCP) exam.
