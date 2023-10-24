# Web Services

There are a few things that can be done if we find out certain web services exist on the target. Typically, websites run on port 80 and 443. However, this may not always be the case, and they can run on other ports like 10000 or 8888 depending on the server. Check the port enumeration and determine what's running.

```bash
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  ssl/https
XXX/tcp open  http OR https
```

## Enumeration

Here are some of the commands that I would when I see a web service running on the target. These should generally return some information that is worth while to check.

```bash
# default script enumeration
nmap --script=vuln -sC -sV -O -T4 -p 80,443 <IP>

# Identify server version
whatweb -a 1 <URL> 
webtech -u <URL>
webabalyze -host <URL> -crawl 2

# automatic scanner
nikto -h <URL>

# check what CMS the website is using
cmsmap -F -d <URL>

# wordpress sites only
wpscan --force update -e --url <URL> [--api-token <API>]

# for SSL/TLS websites
sslscan <host:port>
sslyze --regular <ip:port>
```

## Directory Brute Forcing

If we find a web service listening, we can brute force the directories present on the website using tools like `gobuster` or others:

{% code overflow="wrap" %}
```bash
gobuster dir/vhost/dns/s3/version -u <url> -w <wordlist> -t <number of threads>
# -k for TLS scans
# -x to append possible extensions to every try (such as php, html, txt)
# -p to specify pattern

feroxbuster -u <url> -x <extension>
# -H to add header like "Authorization: basic"
# --no-recursion to remove recursive directory finding
# --proxy to proxy packets
# --query to pass auth token or something.
# -w for wordlist
```
{% endcode %}

The difference between gobuster and feroxbuster is that feroxbuster is recursive, meaning if it finds a directory, a separate thread will be allocated to brute forcing the new directory with the wordlist, sort of like re brute forcing the directory to find more hidden directories.

Both of these are really noisy because it is a brute forcing, and will basically be sending web requests to each possible directory and then filtering the requests to see which are alive.&#x20;

## Guessing / Brute Force

When presented with any form of authentication, always try some basic passwords like `admin:admin` or something before brute forcing. We will not know if the website has some kind of Web Application Firewall, or Intrusion Prevention System that would block us if we were to start brute forcing using tools. So make sure to test the presence of security measures and find ways to circumvent it.

{% code overflow="wrap" %}
```bash
hydra -L <wordlist> -P <password list> 192.168.1.101 http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed"

#generate custom wordlist based on website crawler
cewl -d 2 -m 5 -w docswords.txt https://example.com
```
{% endcode %}

## Username Enumeration

From a website, we can find a lot about a company or a domain. This can be in the form of some text somewhere, or perhaps simply contact details of the company staff that we can manipulate.

<figure><img src="../.gitbook/assets/image (2858).png" alt=""><figcaption><p><em>Taken from Search HTB with Hidden Password</em></p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (3361).png" alt=""><figcaption><p><em>Staff Names from Sauna HTB</em></p></figcaption></figure>

From names, we can start to generate possible usernames through using this script to generate permutations from list of names.

<figure><img src="../.gitbook/assets/image (3217).png" alt=""><figcaption></figcaption></figure>



## Vulnerable Software

Most of the time, websites use some sort of framework, engine or some type of service that would make it easier for developers and users. However, when introducing more moving parts to a system, the likelihood of there being exploits and bugs increases.

Sometimes websites are not kept up to date with the current versions of whatever CMS they are using. In order to identify vulnerabilities like this, proper enumeration is key. The key thing to check for in this step is outdated software that has known public exploits.

Things to take note of when enumerating websites:

* What type of framework is this using? React, NodeJS, Flask, Django etc.&#x20;
* How is the information being processed? Are there any fields that users can control?
* If there is a version of the software used on the website, is it vulnerable to any form of attack?

These are but some of the things we can look out for when viewing the websites. This is to be done in conjunction with the other steps.

### Commands

```bash
whatweb -u <url>
cmsmap -F -d <URL>

searchsploit <keyword>
# -m to download the exploit to our machine
searchsploit -m <exploit title>
```

<figure><img src="../.gitbook/assets/image (2571).png" alt=""><figcaption><p><em>Exploit Searching for Matrimonial Engines</em></p></figcaption></figure>

## Vulnerability Testing

This is arguably my favourite part of website enumeration. The thing to look out here for are **parameters and user input that we can abuse.**

In most websites, they would accept some form of user input to be processed by some backend server. Attackers would be interested in seeing how the backend handles data that is supplied by the user. This data can range from random characters to long lines of characters just to see how it reacts.&#x20;

As such, developers of websites need to have **proper user input validation**. When building websites, linking databases, APIs and so on, keep that in mind! Attackers are always able to edit their HTTP requests to some stuff that you would never have imagined. As such, always, always have proper input sanitisation.

The **most important thing** to be familiar with is the **OWASP Top 10**, which are basically the vulnerabilities that website developers and security specialists need to know about. There are definitely more than 10 vulnerabilities however, and the later sections would just cover the vulnerabilities I encountered often when doing machines instead of the Top 10.

{% embed url="https://owasp.org/www-project-top-ten/" %}
