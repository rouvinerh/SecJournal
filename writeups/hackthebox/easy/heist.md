# Heist

## Gaining Access

As usual, we can start with an Nmap scan:

<figure><img src="../../../.gitbook/assets/image (2036).png" alt=""><figcaption></figcaption></figure>

Take note that port 5985 for `winrm` is available, meaning that we can potentially use `evil-winrm` to gain remote access to the computer if we can find credentials.

### Cisco Hash

Within the web page on port 80, there was a login page:

<figure><img src="../../../.gitbook/assets/image (2436).png" alt=""><figcaption></figcaption></figure>

Weak credentials did not work, so I proceeded to login as a guest. In there, we can see some posts on a forum page of some sort.

<figure><img src="../../../.gitbook/assets/image (1693).png" alt=""><figcaption></figcaption></figure>

Within the attachment were some Cisco Router commands for configurations, and hashes:

<figure><img src="../../../.gitbook/assets/image (2791).png" alt=""><figcaption></figcaption></figure>

There are 2 Level 7 passwords located here, with different usernames. They can be cracked online with this website:

{% embed url="https://www.firewall.cx/cisco-technical-knowledgebase/cisco-routers/358-cisco-type7-password-crack.html" %}

<figure><img src="../../../.gitbook/assets/image (948).png" alt=""><figcaption></figcaption></figure>

The Bcrypt password could also be cracked using `john`.&#x20;

<figure><img src="../../../.gitbook/assets/image (2546).png" alt=""><figcaption></figcaption></figure>

### User Enumeration

With some passwords and potential usernames from the forum, we could begin brute-forcing SMB authentications with different combinations. `hazard` was the user on the forum that also requested for a Windows account for him, so I tried guessing his password first with `crackmapexec`.&#x20;

<figure><img src="../../../.gitbook/assets/image (3323).png" alt=""><figcaption></figcaption></figure>

Worked, but with checking the shares available with `smbmap`, there was nothing of interest:

<figure><img src="../../../.gitbook/assets/image (1479).png" alt=""><figcaption></figcaption></figure>

However, we can use these credentials to enumerate other users that are present on the machine. I used a Metasploit module to do so:

<figure><img src="../../../.gitbook/assets/image (1146).png" alt=""><figcaption></figcaption></figure>

Now we have found more users, we can start brute-forcing again. The password we found earlier works with the `chase` user.&#x20;

<figure><img src="../../../.gitbook/assets/image (3908).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

We can run WinPEAS within this machine to check for easy vectors. This would pickup that some Firefox credentials have been left behind:

<figure><img src="../../../.gitbook/assets/image (1707).png" alt=""><figcaption></figcaption></figure>

There are tools online to dump the hashed passwords for this. But first, I wanted to see if Firefox was running on this machine, then we can use`procdump.exe` to potentially dump the credentials out:

<figure><img src="../../../.gitbook/assets/image (3483).png" alt=""><figcaption></figcaption></figure>

Firefox is indeed running, then we can use `procdump.exe` to dump one of them and analyse the contents on Kali. I used `strings` on the .dmp files and found this password here:

<figure><img src="../../../.gitbook/assets/image (558).png" alt=""><figcaption></figcaption></figure>

With this password, we can `evil-winrm` as the admin:

<figure><img src="../../../.gitbook/assets/image (384).png" alt=""><figcaption></figcaption></figure>
