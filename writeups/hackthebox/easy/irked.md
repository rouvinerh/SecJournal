# Irked

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (1262).png" alt=""><figcaption></figcaption></figure>

IRC is open on this machine, and it's running UnrealIRCd, which is something that I don't see often.

### IRC Hint&#x20;

The website shows an image and a hint to use IRC.

<figure><img src="../../../.gitbook/assets/image (150).png" alt=""><figcaption></figcaption></figure>

The hint is to check for IRC for this machine. As such, I diverted my attention towards the IRC ports.

### UnrealIRC RCE

When searching for exploits regarding UnrealIRC, I found a few RCE exploits:

<figure><img src="../../../.gitbook/assets/image (1781).png" alt=""><figcaption></figcaption></figure>

When trying the RCE exploit, we find that it works.

<figure><img src="../../../.gitbook/assets/image (3900).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3123).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Steghide

This part took me ages to find out. In the user `djmardov` directory, we find the user flag and some kind of key.

<figure><img src="../../../.gitbook/assets/image (1468).png" alt=""><figcaption></figcaption></figure>

Steg was the hint here, and it seems that we have to find an image to retrieve a password from. I spent a long time trying out different images.&#x20;

Then I realised the website had one image on it as well, and so I tried using extracting the password from that using `steghide`.

<figure><img src="../../../.gitbook/assets/image (3574).png" alt=""><figcaption></figcaption></figure>

With this, we can SSH in as `djmardov`.

<figure><img src="../../../.gitbook/assets/image (2309).png" alt=""><figcaption></figcaption></figure>

### ViewUser

I ran a LinEnum for this machine, and found `/usr/bin/viewuser` to be an unusual SUID binary.

<figure><img src="../../../.gitbook/assets/image (3569).png" alt=""><figcaption></figcaption></figure>

When it was run, it tries to find a `/tmp/listusers` file.

<figure><img src="../../../.gitbook/assets/image (1445).png" alt=""><figcaption></figcaption></figure>

Since this file was being run as root due to being an SUID binary, we just need to use the `/tmp/listusers` file to execute some form of Bash script that would give us a root shell.

<figure><img src="../../../.gitbook/assets/image (1464).png" alt=""><figcaption></figcaption></figure>
