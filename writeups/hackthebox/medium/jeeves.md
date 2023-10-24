# Jeeves

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (124).png" alt=""><figcaption></figcaption></figure>

Running a detailed scan reveals that Jetty is running on port 50000.

<figure><img src="../../../.gitbook/assets/image (2504).png" alt=""><figcaption></figcaption></figure>

Early enumeration reveals that port 80 has nothing of interest, and SMB does not respond to null credentials so we can't do anything. That just leaves port 50000 for possible exploits.

### Jenkins

Running a `gobuster` on the web application on port 50000 reveals a `/askjeeves` endpoint.

<figure><img src="../../../.gitbook/assets/image (3727).png" alt=""><figcaption></figcaption></figure>

When visiting the endpoint, we see a Jenkins instance running.

<figure><img src="../../../.gitbook/assets/image (731).png" alt=""><figcaption></figcaption></figure>

With Jenkins, we can make use of the script console to run a malicious script. This can be used to give us a reverse shell.

<figure><img src="../../../.gitbook/assets/image (3773).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Keepass Credentials

Within the Documents folder for the user, we can find a kdbx file.

<figure><img src="../../../.gitbook/assets/image (2392).png" alt=""><figcaption></figcaption></figure>

The password for this can be cracked rather easily.

<figure><img src="../../../.gitbook/assets/image (2011).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can use `kp-cli` to view the passwords stored within this database.

<figure><img src="../../../.gitbook/assets/image (1407).png" alt=""><figcaption></figcaption></figure>

Reading the Backup stuff entry, we can find an NTLM hash.

<figure><img src="../../../.gitbook/assets/image (163).png" alt=""><figcaption></figcaption></figure>

There were also other passwords that were found by viewing the DC Recovery PW.

<figure><img src="../../../.gitbook/assets/image (2984).png" alt=""><figcaption></figcaption></figure>

Using the first NTLM hash we found, we can Pass The Hash to gain a shell as the administrator through `pth-winexe`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1453).png" alt=""><figcaption></figcaption></figure>

### Hidden Flag

When trying to capture the root flag, this is what we see:

<figure><img src="../../../.gitbook/assets/image (178).png" alt=""><figcaption></figcaption></figure>

The hint to look deeper indicates that we should look within the Windows Data Stream. In short, Windows Data Stream is an alternate place for us to store bytes of data that aren't otherwise viewable via the conventional methods.&#x20;

{% embed url="https://owasp.org/www-community/attacks/Windows_alternate_data_stream" %}

In short, there are alternate methods of storing data within these alternate data streams which can be used to hide files. We can view the flag by accessing these streams:

<figure><img src="../../../.gitbook/assets/image (2713).png" alt=""><figcaption></figcaption></figure>

We can see that the alternate stream has 34 bytes of data that are hidden within it. We can redirect the file contents to another folder and read the flag.

<figure><img src="../../../.gitbook/assets/image (880).png" alt=""><figcaption></figcaption></figure>
