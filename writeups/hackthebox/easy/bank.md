# Bank

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.29.200
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 09:49 EDT
Nmap scan report for 10.129.29.200
Host is up (0.018s latency).
Not shown: 40271 closed tcp ports (conn-refused), 25261 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http
```

DNS being open was the most interesting one.

### Login Credentials

Port 80 reveals a defualt Apache2 Ubuntu page:

![](<../../../.gitbook/assets/image%20(3961).png>)

When we add `bank.htb` to our `/etc/hosts` file and revisit it, it loads a login page:

![](<../../../.gitbook/assets/image%20(432).png>)

There was no SQL Injection or anything on this, and default credentials don't work. I did a `gobuster` scan next to enumerate the possible endpoints.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://bank.htb -t 100      
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://bank.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/06 09:54:37 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 305] [--> http://bank.htb/uploads/]
/assets               (Status: 301) [Size: 304] [--> http://bank.htb/assets/]
/inc                  (Status: 301) [Size: 301] [--> http://bank.htb/inc/]
/server-status        (Status: 403) [Size: 288]
/balance-transfer     (Status: 301) [Size: 314] [--> http://bank.htb/balance-transfer/]
```

The last one was the most interesting. That directory just contained a bunch of `.acc` files.

![](<../../../.gitbook/assets/image%20(1797).png>)

When sorting by size, there was one outlier.

![](<../../../.gitbook/assets/image%20(965).png>)

When viewed, it revealed some credentials.

![](<../../../.gitbook/assets/image%20(3097).png>)

These don't work for SSH, but using this we can login!

### File Upload

Once logged in, we can see a dashboard forbank transfers.

![](<../../../.gitbook/assets/image%20(1081).png>)

The Support section allows us to send messages and upload files:

![](<../../../.gitbook/assets/image%20(4052).png>)

Also, reading the page source reveals another hint.

![](<../../../.gitbook/assets/image%20(2909).png>)

Using this, we can upload a PHP webshell as `cmd.htb`. Then, we can use `curl` to confirm we have RCE.

![](<../../../.gitbook/assets/image%20(2634).png>)

Using a `bash` one-liner, we can get a reverse shell.

![](<../../../.gitbook/assets/image%20(3025).png>)

Grab the user flag.

## Privilege Escalation

### Emergency SUID

I ran a LinPEAS scan to enumerate everything, and found this SUID present on the machine:

```
[+] SUID - Check easy privesc, exploits and write perms                                     
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid 
<TRUMCATED>
-rwsr-xr-x 1 root    root       110K Jun 14  2017 /var/htb/bin/emergency
```

For some reason, when I run this binary, it gives me a `root` shell.

![](<../../../.gitbook/assets/image%20(3561).png>)

Turns out, the source code for the script is here (and it is super unrealistic):

```python
www-data@bank:/tmp$ cat /var/htb/emergency
#!/usr/bin/python
import os, sys

def close():
        print "Bye"
        sys.exit()

def getroot():
        try:
                print "Popping up root shell..";
                os.system("/var/htb/bin/emergency")
                close()
        except:
                sys.exit()

q1 = raw_input("[!] Do you want to get a root shell? (THIS SCRIPT IS FOR EMERGENCY ONLY) [y/n]: ");

if q1 == "y" or q1 == "yes":
        getroot()
else:
        close()
```

Rooted!
