# Haircut

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(980).png>)

Website running was rather unique.

### Port 80 RFI

The website only shows this:

![](<../../../.gitbook/assets/image%20(475).png>)

I ran a directory scan and found an `exposed.php` endpoint. We also find an `/uploads` directory that could potentially be used.

![](<../../../.gitbook/assets/image%20(2233).png>)

When visiting the PHP site, this is what we see:

![](<../../../.gitbook/assets/image%20(3665).png>)

There is obviously an RFI exploit here. I tried to upload a PHP reverse shell from PentestMonkey, and then used `curl http://<IP>/uploads/shell.php`, and it worked in getting me a reverse shell.

![](<../../../.gitbook/assets/image%20(1485).png>)

## Privilege Escalation

### Screen 4.5.0

I ran LinPEAS and the SUID binaries were rather interesting:

![](<../../../.gitbook/assets/image%20(3550).png>)

The last one was `screen-4.5.0`, which was an outdated version vulnerable to a local privilege escalation exploit. We can follow the PoC below to gain a root shell.

{% embed url="https://www.exploit-db.com/exploits/41154" %}

![](<../../../.gitbook/assets/image%20(290).png>)
