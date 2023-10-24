# SolidState

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (2699).png" alt=""><figcaption></figcaption></figure>

### JAMES Server

SMTP is open, which is rather suspicious. I connected via `nc` and tested some default credentials, and found that `root:root` worked.

<figure><img src="../../../.gitbook/assets/image (2958).png" alt=""><figcaption></figcaption></figure>

Now that we are logged in, we can read some emails:

<figure><img src="../../../.gitbook/assets/image (1056).png" alt=""><figcaption></figcaption></figure>

With this, we can SSH in as `mindy`.

### Shell Escape

When in the user's directory, we find a restricted shell where we cannot execute a lot:

<figure><img src="../../../.gitbook/assets/image (4073).png" alt=""><figcaption></figcaption></figure>

I researched a bit on how to escape this shell, and found that appending `-t "bash --noprofile"` works:

<figure><img src="../../../.gitbook/assets/image (1201).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Cronjob Injection

We can run `pspy32` on this machine to view processes:

<figure><img src="../../../.gitbook/assets/image (2177).png" alt=""><figcaption></figcaption></figure>

I found that we have write access over this file, so we can just append a reverse shell to it:

<figure><img src="../../../.gitbook/assets/image (3126).png" alt=""><figcaption></figcaption></figure>

After waiting for a bit, we would catch a reverse shell:

<figure><img src="../../../.gitbook/assets/image (927).png" alt=""><figcaption></figcaption></figure>
