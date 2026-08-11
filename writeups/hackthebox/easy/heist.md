# Heist

## Gaining Access

As usual, we can start with an Nmap scan:

![](<../../../.gitbook/assets/image%20(2036).png>)

Take note that port 5985 for `winrm` is available, meaning that we can potentially use `evil-winrm` to gain remote access to the computer if we can find credentials.

### Cisco Hash

Within the web page on port 80, there was a login page:

![](<../../../.gitbook/assets/image%20(2436).png>)

Weak credentials did not work, so I proceeded to login as a guest. In there, we can see some posts on a forum page of some sort.

![](<../../../.gitbook/assets/image%20(1693).png>)

Within the attachment were some Cisco Router commands for configurations, and hashes:

![](<../../../.gitbook/assets/image%20(2791).png>)

There are 2 Level 7 passwords located here, with different usernames. They can be cracked online with this website:

{% embed url="https://www.firewall.cx/cisco-technical-knowledgebase/cisco-routers/358-cisco-type7-password-crack.html" %}

![](<../../../.gitbook/assets/image%20(948).png>)

The Bcrypt password could also be cracked using `john`.

![](<../../../.gitbook/assets/image%20(2546).png>)

### User Enumeration

With some passwords and potential usernames from the forum, we could begin brute-forcing SMB authentications with different combinations. `hazard` was the user on the forum that also requested for a Windows account for him, so I tried guessing his password first with `crackmapexec`.

![](<../../../.gitbook/assets/image%20(3323).png>)

Worked, but with checking the shares available with `smbmap`, there was nothing of interest:

![](<../../../.gitbook/assets/image%20(1479).png>)

However, we can use these credentials to enumerate other users that are present on the machine. I used a Metasploit module to do so:

![](<../../../.gitbook/assets/image%20(1146).png>)

Now we have found more users, we can start brute-forcing again. The password we found earlier works with the `chase` user.

![](<../../../.gitbook/assets/image%20(3908).png>)

## Privilege Escalation

We can run WinPEAS within this machine to check for easy vectors. This would pickup that some Firefox credentials have been left behind:

![](<../../../.gitbook/assets/image%20(1707).png>)

There are tools online to dump the hashed passwords for this. But first, I wanted to see if Firefox was running on this machine, then we can use`procdump.exe` to potentially dump the credentials out:

![](<../../../.gitbook/assets/image%20(3483).png>)

Firefox is indeed running, then we can use `procdump.exe` to dump one of them and analyse the contents on Kali. I used `strings` on the .dmp files and found this password here:

![](<../../../.gitbook/assets/image%20(558).png>)

With this password, we can `evil-winrm` as the admin:

![](<../../../.gitbook/assets/image%20(384).png>)
