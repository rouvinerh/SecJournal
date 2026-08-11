---
description: HP JetDirect SNMP exploits followed by some
---

# Antique

## Gaining Access

An Nmap scan reveals that there is only one port open:

![](<../../../.gitbook/assets/image%20(2734).png>)

When trying to use this Telnet port, we needed some credentials.

![](<../../../.gitbook/assets/image%20(347).png>)

There's no way that we have to guess credentials, so I started scanning for UDP ports instead.  What I found were some SNMP ports, presumably for the printer.



![](<../../../.gitbook/assets/image%20(2107).png>)

### SNMP Printer Exploit

When googling around for SNMP exploits related to this specific printer, I found one here.

{% embed url="http://www.irongeek.com/i.php?page=security/networkprinterhacking" %}

This page suggested that we can leak the password of a printer just by sending a request via SNMP. This basically dumped the password in a numerical form.

![](<../../../.gitbook/assets/image%20(1472).png>)

However, some of these characters aren't readable via ASCII. This led me to believe they were in hex form, and converting it back to text revealed the password.

![](<../../../.gitbook/assets/image%20(3652).png>)

The password is `P@ssw0rd@123!!123`. Now we can access the Telnet port.

### Authenticated Telnet

When accessing the telnet instance, we find out that we have the `exec` command to basically gain RCE over the machine.

![](<../../../.gitbook/assets/image%20(3962).png>)

With this, a simple reverse shell would do, and also allow us to become the **lp** user to capture the user flag.

![](<../../../.gitbook/assets/image%20(109).png>)

## Root Flag

I ran linpeas to enumerate for me and found port 631 to be active, while remaining undetected from nmap.

![](<../../../.gitbook/assets/image%20(609).png>)

Using chisel to port forward, we can easily gain access to this instance. We find that this is running CUPS v1.6.1.

![](<../../../.gitbook/assets/image%20(2104).png>)

This version of CUPS was vulnerable to a root file read exploit. Since this was a port forwarding kind of scenario and I was a bit lazy, I took a loot at the Metasploit exploit code to see what was going on.

![](<../../../.gitbook/assets/image%20(743).png>)

Simple enough, we can just read the root flag directly!

![](<../../../.gitbook/assets/image%20(3792).png>)
