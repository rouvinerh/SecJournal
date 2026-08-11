---
description: >-
  This is an Easy rated Windows machine. An FTP server with anonymous login has
  some Database files with Telnet credentials. Then, there's a public exploit
  for ZKTeco for PE.
---

# Access

## Gaining Access

As usual, we do an Nmap scan to find the services and ports that are running on the machine.

![](<../../../.gitbook/assets/image%20(2584).png>)

### FTP Anonymous Access

When finding FTP open, we can directly check for anonymous login, which works on this machine.

More notably, there's this Telnet service that is running, which is a bit odd and suspicious.

![](<../../../.gitbook/assets/image%20(3804).png>)

Afterwards, we can proceed to see two types of files that I downloaded back to Kali.

![](<../../../.gitbook/assets/image%20(408).png>)

The .zip file is password protected, so we can move onto the mdb file first.

When analyzing the .mdb file, we can find out that this is a Microsoft Database file, which should contain passwords and other useful details to us.

After some digging around on Kali Linux tools, we can find that there is this command called `mdbtools` that would allow us to analyse the contents of this file. **For this purpose, make sure to transfer the file in binary mode.**

{% embed url="https://www.kali.org/tools/mdbtools/" %}

### Finding Telnet Credentials

When we open this file up in Kali, we can get some interesting results. There are bunch of table names, with one called `auth_user` sticking out.

![](<../../../.gitbook/assets/image%20(1073).png>)

We can dump out the contents of that table using `mdb-export`.

![](<../../../.gitbook/assets/image%20(808).png>)

With these credentials, we can unzip the file to find a .pst file. .pst files can be read using `readpst`. This would generate another .mbox file, which we can read easily.

![](<../../../.gitbook/assets/image%20(2588).png>)

![](<../../../.gitbook/assets/image%20(3815).png>)

Now we have some credentials. Remembering that there was a Telnet server, we can login easily as the 'security' user.

![](<../../../.gitbook/assets/image%20(1855).png>)

We can now grab the user flag from this user.

## Privilege Escalation

### ZKTeco Rabbit Hole

Within the machine, there was a ZKTeco directory in C:\\.

![](<../../../.gitbook/assets/image%20(3759).png>)

A quick searchsploit reveals that there is a public exploits available for this version.

![](<../../../.gitbook/assets/image%20(3284).png>)

This exploit details that privilege escalation is possible as we are allowed to change the executable file with any binary that we choose. However, I was unable to exploit this properly.

### Finding Runas hint

While snooping around on the machine, we can find that in `C:\Users\Public\Desktop`, there is a .lnk file that contains some hints that there are Administrator credentials being cached on this machine.

![](<../../../.gitbook/assets/image%20(1884).png>)

I see lots of runas.exe being used, and when we check the cached passwords using `cmdkey /list`, we can see that we indeed have the Administrator credentials.

![](<../../../.gitbook/assets/image%20(2188).png>)

The administrator credentials being cached basically means that we can execute the `runas /savecred /user:ACCESS\administrator <binary>` command, which is basically a sudo command but on windows.

From here, download a simple reverse shell binary generated from MSFVenom and run the command to gain a reverse shell as the administrator on our listening port.

![](<../../../.gitbook/assets/image%20(1627).png>)

![](<../../../.gitbook/assets/image%20(3049).png>)
