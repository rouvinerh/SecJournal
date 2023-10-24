# Magic

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (2418).png" alt=""><figcaption></figcaption></figure>

### Login Bypass --> File Upload RCE

The web application shows us some random images as a form of portfolio.

<figure><img src="../../../.gitbook/assets/image (1716).png" alt=""><figcaption></figcaption></figure>

I did a `gobuster` scan and found a few directories of interest:

<figure><img src="../../../.gitbook/assets/image (2064).png" alt=""><figcaption></figcaption></figure>

So there was a `login.php` directory. I didn't have any credentials, so I tried a few low hanging fruits such as `admin:admin` and basic SQL injection. The payload of `' OR 1 --` worked.

Then, I was brought to this page:

<figure><img src="../../../.gitbook/assets/image (3784).png" alt=""><figcaption></figcaption></figure>

This was a PHP site so I tried uploading PHP webshells, but it didn't work. As such, I tried to **embed a webshell witihin a JPG file**.&#x20;

<figure><img src="../../../.gitbook/assets/image (486).png" alt=""><figcaption></figcaption></figure>

Afterwards, we just need to change the extension to `.php.jpeg` and send the file (via Burpsuite). Earlier, a `gobuster` scan found a `/images` directory, so I used `gobuster` on that to find more directories:

<figure><img src="../../../.gitbook/assets/image (695).png" alt=""><figcaption></figcaption></figure>

So the `/uploads` directory is where our files end up. I tried some basic commands, and it worked!

<figure><img src="../../../.gitbook/assets/image (3370).png" alt=""><figcaption></figcaption></figure>

Getting a shell from here is easy.

<figure><img src="../../../.gitbook/assets/image (2090).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SQL Credentials

In the `/var/www/magic` file, I found a set of database credentials.

<figure><img src="../../../.gitbook/assets/image (2160).png" alt=""><figcaption></figcaption></figure>

I used `mysqldump` (which was present on the machine somehow) and dumped out all of the SQL stuff.

<figure><img src="../../../.gitbook/assets/image (2668).png" alt=""><figcaption></figcaption></figure>

I was able to find a set of credentials for the admin user.

<figure><img src="../../../.gitbook/assets/image (781).png" alt=""><figcaption></figcaption></figure>

From reading the `/home` directory, the user on this machine is `theseus`. These credentials work with `su`.

<figure><img src="../../../.gitbook/assets/image (2757).png" alt=""><figcaption></figcaption></figure>

### Fdisk

I checked for SUID binaries, and found one at `/bin/sysinfo`. When trying to execute it, I found that it was executing `fdisk` without the full path.&#x20;

<figure><img src="../../../.gitbook/assets/image (3914).png" alt=""><figcaption></figcaption></figure>

By manipulating the PATH variable and creating a reverse shell script named `fdisk`, I can get a reverse shell as root.

<figure><img src="../../../.gitbook/assets/image (1462).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3568).png" alt=""><figcaption></figcaption></figure>

Port 9999 does not work (presumably due to firewall) so I changed to port 443 and ran `sysinfo` again.

<figure><img src="../../../.gitbook/assets/image (371).png" alt=""><figcaption></figcaption></figure>
