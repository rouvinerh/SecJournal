# Mirai

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (814).png" alt=""><figcaption></figcaption></figure>

### SSH Default Credentials

Checking port 80 reveals a Pi-Hole dashboard:

<figure><img src="../../../.gitbook/assets/image (3803).png" alt=""><figcaption></figcaption></figure>

There's a login function, and I managed to login with default credentials of `pi:raspberry`. I also tried to SSH in as `pi` using these credentials, and it worked for some reason:

<figure><img src="../../../.gitbook/assets/image (2230).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Flag Finding

I was able to run `sudo su` on this machine and search for `root.txt`:

<figure><img src="../../../.gitbook/assets/image (1814).png" alt=""><figcaption></figcaption></figure>

Interesting, because the root flag is where on a USB stick. Now, the backup would probably be some file in a different format and compressed. We know that the flag is a string, so we can use `strings` to get it out. It is stored at `/dev/sdb`.&#x20;

```bash
strings /dev/sdb
```

This would give us the flag once we search the input sufficiently.
