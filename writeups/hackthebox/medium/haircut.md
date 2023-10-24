# Haircut

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (980).png" alt=""><figcaption></figcaption></figure>

Website running was rather unique.

### Port 80 RFI

The website only shows this:

<figure><img src="../../../.gitbook/assets/image (475).png" alt=""><figcaption></figcaption></figure>

I ran a directory scan and found an `exposed.php` endpoint. We also find an `/uploads` directory that could potentially be used.

<figure><img src="../../../.gitbook/assets/image (2233).png" alt=""><figcaption></figcaption></figure>

When visiting the PHP site, this is what we see:

<figure><img src="../../../.gitbook/assets/image (3665).png" alt=""><figcaption></figcaption></figure>

There is obviously an RFI exploit here. I tried to upload a PHP reverse shell from PentestMonkey, and then used `curl http://<IP>/uploads/shell.php`, and it worked in getting me a reverse shell.

<figure><img src="../../../.gitbook/assets/image (1485).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Screen 4.5.0

I ran LinPEAS and the SUID binaries were rather interesting:

<figure><img src="../../../.gitbook/assets/image (3550).png" alt=""><figcaption></figcaption></figure>

The last one was `screen-4.5.0`, which was an outdated version vulnerable to a local privilege escalation exploit. We can follow the PoC below to gain a root shell.

{% embed url="https://www.exploit-db.com/exploits/41154" %}

<figure><img src="../../../.gitbook/assets/image (290).png" alt=""><figcaption></figcaption></figure>
