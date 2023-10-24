# Poison

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (3872).png" alt=""><figcaption></figcaption></figure>

### Base64 Password

We can do a `gobuster` scan on the machine to find all possible files present:

<figure><img src="../../../.gitbook/assets/image (966).png" alt=""><figcaption></figcaption></figure>

On the website itself, it was a simple application to read files:

<figure><img src="../../../.gitbook/assets/image (2395).png" alt=""><figcaption></figcaption></figure>

This was hosted at `http://<IP>/browse.php/?file=<FILENAME>`, which had an obvious LFI. We can use this to read `listfiles.php`, which was present on the machine.

<figure><img src="../../../.gitbook/assets/image (777).png" alt=""><figcaption></figcaption></figure>

There was a `pwdbackup.txt` file, and when read it shows a password that has been encoded 13 times with base64:

<figure><img src="../../../.gitbook/assets/image (622).png" alt=""><figcaption></figcaption></figure>

When decrypted, it gives `Charix!2#4%6&8(0`. We can then use this to SSH in as the user `charix`.

<figure><img src="../../../.gitbook/assets/image (3268).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### VNC

We can check the ports that are open with `netstat -an`.

<figure><img src="../../../.gitbook/assets/image (402).png" alt=""><figcaption></figcaption></figure>

VNC is open on port 5901, and normally, this requires a password file. Conveniently, we can find a `secret.zip` in the user's directory:

<figure><img src="../../../.gitbook/assets/image (521).png" alt=""><figcaption></figcaption></figure>

We can transfer this back to our machine via `base64`, and then use `vncviewer` to login to the VNC service after port forwarding it:

```bash
ssh -L 5901:127.0.0.1:5901 charix@10.10.10.84
vncviewer -passwd secret 127.0.0.1:5901
```

This would spawn a terminal as the `root` user:

<figure><img src="../../../.gitbook/assets/image (1734).png" alt=""><figcaption></figcaption></figure>
