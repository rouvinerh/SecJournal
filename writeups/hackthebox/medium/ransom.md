---
description: Mr Robot themed!
---

# Ransom

aining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (1370).png" alt=""><figcaption></figcaption></figure>

Web exploitation time.

### Auth Bypass

The website was some type of Incident Response site, from E Corp.

<figure><img src="../../../.gitbook/assets/image (2115).png" alt=""><figcaption></figcaption></figure>

I tried logging in with some random password, and intercepted the response in Burpsuite to see how the login was handled. Found the `/api` endpoint.&#x20;

<figure><img src="../../../.gitbook/assets/image (2847).png" alt=""><figcaption></figcaption></figure>

I tried playing around with the website by sending JSON objects, and found that setting the `password` parameter to `true` would let us login.

<figure><img src="../../../.gitbook/assets/image (3398).png" alt=""><figcaption></figcaption></figure>

### Home Directory Backup

Once we were in, we could view these files:

<figure><img src="../../../.gitbook/assets/image (3099).png" alt=""><figcaption></figcaption></figure>

We can grab the user flag and also the `homedirectory.zip` file. Upon running an `exiftool` for it, we can see that the file name was `.bash_logout`. All of the files were encrypted with a password, and cracking it was not possible.

<figure><img src="../../../.gitbook/assets/image (1136).png" alt=""><figcaption></figcaption></figure>

When attempting to unzip the file, we can find some SSH keys within it.&#x20;

<figure><img src="../../../.gitbook/assets/image (387).png" alt=""><figcaption></figcaption></figure>

At this point, I began enumerating possible ZIP file exploits that were used. One command we could use was `7z l -slt` which would list out the files and show the technical information for the files:

```bash
7z l -slt uploaded-file-3422.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,32 CPUs AMD Ryzen 9 5900HX with Radeon Graphics         (A50F00),ASM,AES-NI)

Scanning the drive for archives:
1 file, 7735 bytes (8 KiB)

Listing archive: uploaded-file-3422.zip

--
Path = uploaded-file-3422.zip
Type = zip
Physical Size = 7735

----------
Path = .bash_logout
Folder = -
Size = 220
Packed Size = 170
Modified = 2020-02-25 07:03:22
Created = 
Accessed = 
Attributes = _ -rw-r--r--
Encrypted = +
Comment = 
CRC = 6CE3189B
Method = ZipCrypto Deflate
Host OS = Unix
Version = 20
Volume Index = 0
```

This was using ZipCrypto Deflate as the method of zipping.&#x20;

### Decrypting ZIP

Googling a little led me to this repository with instructions on how to recover the password:

{% embed url="https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md" %}

This attack is made possible due to legacy encryption being used, and this form of encryption was vulnerable to the **known plaintext attack**. We would need to have at least 12 bytes of data, with 8 being contiguous to decrypt the password.&#x20;

Because this was simply a home directory with common files like `.bash_logout`, we can easily create another zip file with our machine's `.bash_logout` file and then find the keys using `bkcrack`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1284).png" alt=""><figcaption></figcaption></figure>

We can then retrieve the keys for the ZIP file:

<figure><img src="../../../.gitbook/assets/image (2020).png" alt=""><figcaption></figcaption></figure>

Afterwards, the ZIP file and its contents can be copied to another ZIP file with a known password that we can decrypt.

<figure><img src="../../../.gitbook/assets/image (2537).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3607).png" alt=""><figcaption></figcaption></figure>

Then we can SSH in as the `htb` user.

<figure><img src="../../../.gitbook/assets/image (3891).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

I ran a LinPEAS to find more information, and it enumerated out a potential password for a `mysql` instance:

<figure><img src="../../../.gitbook/assets/image (318).png" alt=""><figcaption></figcaption></figure>

However, the machine does not have any database running. However, the presence of the other APP related environment variables highlighted that the `/srv/prod` directory had the files for the website we exploited earlier.

### Finding Root Password

We would be looking for some type of config files, or a method as to how the authentication mechanisms for the website works.

Within the `/srv/prod/app/Http/Controllers/AuthController.php` file, I found the root password:

<figure><img src="../../../.gitbook/assets/image (591).png" alt=""><figcaption></figcaption></figure>
