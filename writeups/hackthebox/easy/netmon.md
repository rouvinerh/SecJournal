---
description: Instant Root!
---

# Netmon

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (2258).png" alt=""><figcaption></figcaption></figure>

## FTP Anonymous Login

Seeing port 21 open, we should always test for anonymous logins (low-hanging fruits).

<figure><img src="../../../.gitbook/assets/image (851).png" alt=""><figcaption></figcaption></figure>

This explains why the user flag was captured in exactly 1 minute from the box going live. Easy first blood! Anyways, I realised that from this FTP, we have access to the entire file directory.

## PRTG Network Monitor

Port 80 is running PRTG Network Monitor 18.1.37.13946 (which is outdated):

<figure><img src="../../../.gitbook/assets/image (2264).png" alt=""><figcaption></figcaption></figure>

Since we have access to the entire file directory through FTP, we can search for the credentials for this. We can find some backup folders for PRNG Network Monitor within the machine.&#x20;

<figure><img src="../../../.gitbook/assets/image (982).png" alt=""><figcaption></figcaption></figure>

When we download this file, we can view the content inside, and we are abel to find the `dbpassword` parameter for us.

<figure><img src="../../../.gitbook/assets/image (1228).png" alt=""><figcaption></figcaption></figure>

I was able to find a RCE exploit online for this particular version:

{% embed url="https://github.com/chcx/PRTG-Network-Monitor-RCE" %}

In this version of PRTG, there are demo scripts that come downloaded with the software. The demo scripts are vulnerable to RCE (which no one had checked before) and we are allowed to run commands with 'Local System' privileges. This allows us to create new administrator user in the machine (which is what the script does).&#x20;

<figure><img src="../../../.gitbook/assets/image (1430).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can `evil-winrm` in as this new user.

<figure><img src="../../../.gitbook/assets/image (2097).png" alt=""><figcaption></figcaption></figure>

This pentest user has administrator privileges over the machine, and thus we can capture all flags present.&#x20;
