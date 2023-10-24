# Blunder

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (755).png" alt=""><figcaption></figcaption></figure>

Not too sure why FTP was reported. Anyways, we can head to the webpage to enumerate.

### Webpage

Page was just full of placeholder text that didn't mean much.

<figure><img src="../../../.gitbook/assets/image (3879).png" alt=""><figcaption></figcaption></figure>

I ran a directory brute force search to find an `/admin` panel.

<figure><img src="../../../.gitbook/assets/image (3705).png" alt=""><figcaption></figcaption></figure>

The `/admin` panel requires credentials to access. Default weak credentials do not work here.

<figure><img src="../../../.gitbook/assets/image (2236).png" alt=""><figcaption></figcaption></figure>

We also found some other text files that were also of interest.

<figure><img src="../../../.gitbook/assets/image (2706).png" alt=""><figcaption></figcaption></figure>

The `todo.txt` file contained this:

<figure><img src="../../../.gitbook/assets/image (3739).png" alt=""><figcaption></figcaption></figure>

The `install.php` file also contained some other hidden information about the CMS on the administrator panel.

<figure><img src="../../../.gitbook/assets/image (1316).png" alt=""><figcaption></figcaption></figure>

So `fergus` is the administrator of the website, and Bludit is installed on it. Fergus needs to upload some type of image onto the website. We can check the page source for the version of Bludit that is running.

<figure><img src="../../../.gitbook/assets/image (3825).png" alt=""><figcaption></figcaption></figure>

Bludit CMS 3.9.2 is vulnerable to an authenticated RCE exploit. We can use the exploit from this repository on the box

{% embed url="https://github.com/0xkasra/CVE-2019-16113" %}

Now, we need to find some credentials to log in as the administrator.

### Brute Force Login

Initially, I brute forced the login page for the admin panel, but it didn't work out. I tried using `cewl` to create a custom wordlist using the website. Afterwards, using a Auth bruteforce Bypass exploit for Bludit, we can brute force the login and find the correct password.

<figure><img src="../../../.gitbook/assets/image (1648).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (704).png" alt=""><figcaption><p><br></p></figcaption></figure>

We would eventually find the right credentials.

<figure><img src="../../../.gitbook/assets/image (1226).png" alt=""><figcaption></figcaption></figure>

Then, we can use the exploit we found earlier to gain a reverse shell.

<figure><img src="../../../.gitbook/assets/image (2179).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1003).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Hugo Credentials

First thing I look for are databases or configuration files within this Bludit instance. There were other Bludit related files that were of different versions, and each had their own `/bl-content/databases` folders with hashes and other credentials within it.

Within the Bludit-3.10.0a directory, the config files contained credentials for a `hugo` user.

<figure><img src="../../../.gitbook/assets/image (337).png" alt=""><figcaption></figcaption></figure>

This hash can be cracked.

<figure><img src="../../../.gitbook/assets/image (3692).png" alt=""><figcaption></figcaption></figure>

Then we can `su` to Hugo.

<figure><img src="../../../.gitbook/assets/image (635).png" alt=""><figcaption></figcaption></figure>

### Sudo Exploit

When we check `sudo` privileges, we can see that this one is a bit different.

<figure><img src="../../../.gitbook/assets/image (4051).png" alt=""><figcaption></figcaption></figure>

The `!root` bit means that we cannot run `/bin/bash` as root, but we can run it as any other user. Googling for `sudo !root` bypasses led me to this exploit.&#x20;

{% embed url="https://www.exploit-db.com/exploits/47502" %}

We can run it and gain a root shell.

<figure><img src="../../../.gitbook/assets/image (2721).png" alt=""><figcaption></figcaption></figure>
