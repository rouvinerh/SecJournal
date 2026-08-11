---
description: Instant Root!
---

# Netmon

## Gaining Access

Nmap scan:

![](../../../.gitbook/assets/netmon-4.png)

## FTP Anonymous Login

Seeing port 21 open, we should always test for anonymous logins (low-hanging fruits).

![](../../../.gitbook/assets/netmon-6.png)

This explains why the user flag was captured in exactly 1 minute from the box going live. Easy first blood! Anyways, I realised that from this FTP, we have access to the entire file directory.

## PRTG Network Monitor

Port 80 is running PRTG Network Monitor 18.1.37.13946 (which is outdated):

![](../../../.gitbook/assets/netmon-5.png)

Since we have access to the entire file directory through FTP, we can search for the credentials for this. We can find some backup folders for PRNG Network Monitor within the machine.

![](../../../.gitbook/assets/netmon-7.png)

When we download this file, we can view the content inside, and we are abel to find the `dbpassword` parameter for us.

![](../../../.gitbook/assets/netmon-1.png)

I was able to find a RCE exploit online for this particular version:

{% embed url="https://github.com/chcx/PRTG-Network-Monitor-RCE" %}

In this version of PRTG, there are demo scripts that come downloaded with the software. The demo scripts are vulnerable to RCE (which no one had checked before) and we are allowed to run commands with 'Local System' privileges. This allows us to create new administrator user in the machine (which is what the script does).

![](../../../.gitbook/assets/netmon-2.png)

Afterwards, we can `evil-winrm` in as this new user.

![](../../../.gitbook/assets/netmon-3.png)

This pentest user has administrator privileges over the machine, and thus we can capture all flags present.
