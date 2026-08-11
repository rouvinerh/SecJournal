# Irked

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(1262).png>)

IRC is open on this machine, and it's running UnrealIRCd, which is something that I don't see often.

### IRC Hint

The website shows an image and a hint to use IRC.

![](<../../../.gitbook/assets/image%20(150).png>)

The hint is to check for IRC for this machine. As such, I diverted my attention towards the IRC ports.

### UnrealIRC RCE

When searching for exploits regarding UnrealIRC, I found a few RCE exploits:

![](<../../../.gitbook/assets/image%20(1781).png>)

When trying the RCE exploit, we find that it works.

![](<../../../.gitbook/assets/image%20(3900).png>)

![](<../../../.gitbook/assets/image%20(3123).png>)

## Privilege Escalation

### Steghide

This part took me ages to find out. In the user `djmardov` directory, we find the user flag and some kind of key.

![](<../../../.gitbook/assets/image%20(1468).png>)

Steg was the hint here, and it seems that we have to find an image to retrieve a password from. I spent a long time trying out different images.

Then I realised the website had one image on it as well, and so I tried using extracting the password from that using `steghide`.

![](<../../../.gitbook/assets/image%20(3574).png>)

With this, we can SSH in as `djmardov`.

![](<../../../.gitbook/assets/image%20(2309).png>)

### ViewUser

I ran a LinEnum for this machine, and found `/usr/bin/viewuser` to be an unusual SUID binary.

![](<../../../.gitbook/assets/image%20(3569).png>)

When it was run, it tries to find a `/tmp/listusers` file.

![](<../../../.gitbook/assets/image%20(1445).png>)

Since this file was being run as root due to being an SUID binary, we just need to use the `/tmp/listusers` file to execute some form of Bash script that would give us a root shell.

![](<../../../.gitbook/assets/image%20(1464).png>)
