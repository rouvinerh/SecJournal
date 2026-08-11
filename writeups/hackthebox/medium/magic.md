# Magic

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(2418).png>)

### Login Bypass -> File Upload RCE

The web application shows us some random images as a form of portfolio.

![](<../../../.gitbook/assets/image%20(1716).png>)

I did a `gobuster` scan and found a few directories of interest:

![](<../../../.gitbook/assets/image%20(2064).png>)

So there was a `login.php` directory. I didn't have any credentials, so I tried a few low hanging fruits such as `admin:admin` and basic SQL injection. The payload of `' OR 1 --` worked.

Then, I was brought to this page:

![](<../../../.gitbook/assets/image%20(3784).png>)

This was a PHP site so I tried uploading PHP webshells, but it didn't work. As such, I tried to **embed a webshell witihin a JPG file**.

![](<../../../.gitbook/assets/image%20(486).png>)

Afterwards, we just need to change the extension to `.php.jpeg` and send the file (via Burpsuite). Earlier, a `gobuster` scan found a `/images` directory, so I used `gobuster` on that to find more directories:

![](<../../../.gitbook/assets/image%20(695).png>)

So the `/uploads` directory is where our files end up. I tried some basic commands, and it worked!

![](<../../../.gitbook/assets/image%20(3370).png>)

Getting a shell from here is easy.

![](<../../../.gitbook/assets/image%20(2090).png>)

## Privilege Escalation

### SQL Credentials

In the `/var/www/magic` file, I found a set of database credentials.

![](<../../../.gitbook/assets/image%20(2160).png>)

I used `mysqldump` (which was present on the machine somehow) and dumped out all of the SQL stuff.

![](<../../../.gitbook/assets/image%20(2668).png>)

I was able to find a set of credentials for the admin user.

![](<../../../.gitbook/assets/image%20(781).png>)

From reading the `/home` directory, the user on this machine is `theseus`. These credentials work with `su`.

![](<../../../.gitbook/assets/image%20(2757).png>)

### Fdisk

I checked for SUID binaries, and found one at `/bin/sysinfo`. When trying to execute it, I found that it was executing `fdisk` without the full path.

![](<../../../.gitbook/assets/image%20(3914).png>)

By manipulating the PATH variable and creating a reverse shell script named `fdisk`, I can get a reverse shell as root.

![](<../../../.gitbook/assets/image%20(1462).png>)

![](<../../../.gitbook/assets/image%20(3568).png>)

Port 9999 does not work (presumably due to firewall) so I changed to port 443 and ran `sysinfo` again.

![](<../../../.gitbook/assets/image%20(371).png>)
