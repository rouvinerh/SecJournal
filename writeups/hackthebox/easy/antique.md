---
description: HP JetDirect SNMP exploits followed by some
---

# Antique

## Gaining Access

An Nmap scan reveals that there is only one port open:

<figure><img src="../../../.gitbook/assets/image (2734).png" alt=""><figcaption></figcaption></figure>

When trying to use this Telnet port, we needed some credentials.

<figure><img src="../../../.gitbook/assets/image (347).png" alt=""><figcaption></figcaption></figure>

There's no way that we have to guess credentials, so I started scanning for UDP ports instead.  What I found were some SNMP ports, presumably for the printer.&#x20;

&#x20;

<figure><img src="../../../.gitbook/assets/image (2107).png" alt=""><figcaption></figcaption></figure>

### SNMP Printer Exploit

When googling around for SNMP exploits related to this specific printer, I found one here.

{% embed url="http://www.irongeek.com/i.php?page=security/networkprinterhacking" %}

This page suggested that we can leak the password of a printer just by sending a request via SNMP. This basically dumped the password in a numerical form.

<figure><img src="../../../.gitbook/assets/image (1472).png" alt=""><figcaption></figcaption></figure>

However, some of these characters aren't readable via ASCII. This led me to believe they were in hex form, and converting it back to text revealed the password.

<figure><img src="../../../.gitbook/assets/image (3652).png" alt=""><figcaption></figcaption></figure>

The password is `P@ssw0rd@123!!123`. Now we can access the Telnet port.

### Authenticated Telnet

When accessing the telnet instance, we find out that we have the `exec` command to basically gain RCE over the machine.

<figure><img src="../../../.gitbook/assets/image (3962).png" alt=""><figcaption></figcaption></figure>

With this, a simple reverse shell would do, and also allow us to become the **lp** user to capture the user flag.

<figure><img src="../../../.gitbook/assets/image (109).png" alt=""><figcaption></figcaption></figure>

## Root Flag&#x20;

I ran linpeas to enumerate for me and found port 631 to be active, while remaining undetected from nmap.

<figure><img src="../../../.gitbook/assets/image (609).png" alt=""><figcaption></figcaption></figure>

Using chisel to port forward, we can easily gain access to this instance. We find that this is running CUPS v1.6.1.

<figure><img src="../../../.gitbook/assets/image (2104).png" alt=""><figcaption></figcaption></figure>

This version of CUPS was vulnerable to a root file read exploit. Since this was a port forwarding kind of scenario and I was a bit lazy, I took a loot at the Metasploit exploit code to see what was going on.&#x20;

<figure><img src="../../../.gitbook/assets/image (743).png" alt=""><figcaption></figcaption></figure>

Simple enough, we can just read the root flag directly!

<figure><img src="../../../.gitbook/assets/image (3792).png" alt=""><figcaption></figcaption></figure>
