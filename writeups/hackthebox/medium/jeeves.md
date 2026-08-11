# Jeeves

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(124).png>)

Running a detailed scan reveals that Jetty is running on port 50000.

![](<../../../.gitbook/assets/image%20(2504).png>)

Early enumeration reveals that port 80 has nothing of interest, and SMB does not respond to null credentials so we can't do anything. That just leaves port 50000 for possible exploits.

### Jenkins

Running a `gobuster` on the web application on port 50000 reveals a `/askjeeves` endpoint.

![](<../../../.gitbook/assets/image%20(3727).png>)

When visiting the endpoint, we see a Jenkins instance running.

![](<../../../.gitbook/assets/image%20(731).png>)

With Jenkins, we can make use of the script console to run a malicious script. This can be used to give us a reverse shell.

![](<../../../.gitbook/assets/image%20(3773).png>)

## Privilege Escalation

### Keepass Credentials

Within the Documents folder for the user, we can find a kdbx file.

![](<../../../.gitbook/assets/image%20(2392).png>)

The password for this can be cracked rather easily.

![](<../../../.gitbook/assets/image%20(2011).png>)

Afterwards, we can use `kp-cli` to view the passwords stored within this database.

![](<../../../.gitbook/assets/image%20(1407).png>)

Reading the Backup stuff entry, we can find an NTLM hash.

![](<../../../.gitbook/assets/image%20(163).png>)

There were also other passwords that were found by viewing the DC Recovery PW.

![](<../../../.gitbook/assets/image%20(2984).png>)

Using the first NTLM hash we found, we can Pass The Hash to gain a shell as the administrator through `pth-winexe`.

![](<../../../.gitbook/assets/image%20(1453).png>)

### Hidden Flag

When trying to capture the root flag, this is what we see:

![](<../../../.gitbook/assets/image%20(178).png>)

The hint to look deeper indicates that we should look within the Windows Data Stream. In short, Windows Data Stream is an alternate place for us to store bytes of data that aren't otherwise viewable via the conventional methods.

{% embed url="https://owasp.org/www-community/attacks/Windows_alternate_data_stream" %}

In short, there are alternate methods of storing data within these alternate data streams which can be used to hide files. We can view the flag by accessing these streams:

![](<../../../.gitbook/assets/image%20(2713).png>)

We can see that the alternate stream has 34 bytes of data that are hidden within it. We can redirect the file contents to another folder and read the flag.

![](<../../../.gitbook/assets/image%20(880).png>)
