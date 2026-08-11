# Knife

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(2480).png>)

### PHP-Dev

I found nothing interesting about the web application hosted on port 80. However, when viewing the traffic proxied through Burpsuite, we see an interesting header:

![](<../../../.gitbook/assets/image%20(2227).png>)

PHP/8.1.0-dev is vulnerable to a publicly available RCE exploit.

{% embed url="https://www.exploit-db.com/exploits/49933" %}

This script can be used to gain a shell as the user.

![](<../../../.gitbook/assets/image%20(3583).png>)

From this, we can get a shell using the `mkfifo` script. After spawning a TTY shell, we find that we are the user `james`.

## Privilege Escalation

### Knife Sudo

When enumerating sudo privileges, we see that we can run `knife`.

![](<../../../.gitbook/assets/image%20(860).png>)

`knife` can be used to spawn a root shell since we can run `sudo` with it.

![](<../../../.gitbook/assets/image%20(709).png>)
