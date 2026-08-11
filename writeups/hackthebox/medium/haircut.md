# Haircut

## Gaining Access

Nmap scan:

![](../../../.gitbook/assets/haircut-7.png)

Website running was rather unique.

### Port 80 RFI

The website only shows this:

![](../../../.gitbook/assets/haircut-6.png)

I ran a directory scan and found an `exposed.php` endpoint. We also find an `/uploads` directory that could potentially be used.

![](../../../.gitbook/assets/haircut-2.png)

When visiting the PHP site, this is what we see:

![](../../../.gitbook/assets/haircut-5.png)

There is obviously an RFI exploit here. I tried to upload a PHP reverse shell from PentestMonkey, and then used `curl http://<IP>/uploads/shell.php`, and it worked in getting me a reverse shell.

![](../../../.gitbook/assets/haircut-1.png)

## Privilege Escalation

### Screen 4.5.0

I ran LinPEAS and the SUID binaries were rather interesting:

![](../../../.gitbook/assets/haircut-4.png)

The last one was `screen-4.5.0`, which was an outdated version vulnerable to a local privilege escalation exploit. We can follow the PoC below to gain a root shell.

{% embed url="https://www.exploit-db.com/exploits/41154" %}

![](../../../.gitbook/assets/haircut-3.png)
