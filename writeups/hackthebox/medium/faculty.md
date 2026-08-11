# Faculty

## Gaining Access

As usual, we start with a Nmap scan.

![](<../../../.gitbook/assets/image%20(963).png>)

There's the `faculty.htb` domain running on port 80. We can add this to the `/etc/hosts` file.

### SQL Injection

Basic PHP login page for a Faculty Scheduling System is present here:

![](<../../../.gitbook/assets/image%20(1793).png>)

Checking for common directories such as the `/admin` endpoint reveals another login page.

![](<../../../.gitbook/assets/image%20(1439).png>)

Proxying the traffic in Burp, sending a `'` character as a username triggers an SQL error.

![](<../../../.gitbook/assets/image%20(3841).png>)

Now that we have confirmed SQL Injection is present, we can dump out all the tables within the database from this using `sqlmap`.

![](<../../../.gitbook/assets/image%20(689).png>)

The `users` table had an `Administrator` user with a hashed password, however the hash cannot be cracked.

![](<../../../.gitbook/assets/image%20(2724).png>)

In this case, we can dump the `faculty` table and attempt to login via the original login method. There's a PIN number associated with the `Administrator` user and we can use that to login.

![](<../../../.gitbook/assets/image%20(3391).png>)

### PDF Generator LFI

WItin the website, there's a PDF Generator that would display certain courses.

![](<../../../.gitbook/assets/image%20(2268).png>)

We can download this PDF and use `exiftool` to find out more information about it.

![](<../../../.gitbook/assets/image%20(1493).png>)

mPDF 6.0 is vulnerable to an LFI exploit that would allow for us to read the files on the server. With this, we can have to send this payload encoded with Base64:

```
<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
```

This would load a PDF file that contains the `/etc/passwd` file.

![](<../../../.gitbook/assets/image%20(1877).png>)

The `/etc/passwd` file would be attached to the main PDF like this:

![](<../../../.gitbook/assets/image%20(2685).png>)

We can then read it to find out the users that are present on the machine.

![](<../../../.gitbook/assets/image%20(1461).png>)

From here, we can try to find the `admin.php` or `db.php` file within the machine to find some credentials. Doing a quick `gobuster` scan reveals that there is a `db_connect.php` file that we can read to find a password.

![](<../../../.gitbook/assets/image%20(2296).png>)

With this, we can `ssh` in as the `gbyolo` user using the password found.

## Privilege Escalation

### Meta-Git RCE

The other user found on the machine is the `developer` user. When checking the `sudo` privileges of the `gbyolo` user, we find this:

![](<../../../.gitbook/assets/image%20(447).png>)

`meta-git` is a binary that allows us to clone repos as per git. However, this was vulnerable to an RCE exploit, meaning we can execute commands as `developer`.

{% embed url="https://hackerone.com/reports/728040" %}

Using the PoC, we can read the `id_rsa` file from the user's home directory.

![](<../../../.gitbook/assets/image%20(266).png>)

Then, we can SSH in as `developer`.

### GDB Attaching

Doing initial enumeration reveals that the `developer` user is part of the `debug` group.

![](<../../../.gitbook/assets/image%20(3031).png>)

Running LinPEAS also reveals that we can run GDB as we are part of the `debug` group.

![](<../../../.gitbook/assets/image%20(1285).png>)

In this case, `gdb` can be used to attach ourselves to a process **run by root** and spawn more child processes. These child processes would all be running as root and we can basically gain RCE as root in this manner. This would stop the execution process and make the root thread spawn whatever other functions that we want.

First, we would need to find a process running as root, and preferably a Python or Bash one so we can execute commands easily.

![](<../../../.gitbook/assets/image%20(3925).png>)

The PID in this case is `621`, so we can run `gdb -p 621` to attach ourselves there. Afterwards, I called the `system()` function to spawn a reverse shell as root.

![](<../../../.gitbook/assets/image%20(116).png>)

![](<../../../.gitbook/assets/image%20(1125).png>)
