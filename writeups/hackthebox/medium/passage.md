# Passage

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (1509).png" alt=""><figcaption></figcaption></figure>

### Passage News

Port 80 reveals some kind of website archive thing:

<figure><img src="../../../.gitbook/assets/image (221).png" alt=""><figcaption></figcaption></figure>

Checking the page source, we find that this is running CuteNews, which had a few RCE exploits available:

{% embed url="https://www.exploit-db.com/exploits/48800" %}

<figure><img src="../../../.gitbook/assets/image (3821).png" alt=""><figcaption></figcaption></figure>

With this, we can easily gain a reverse shell:

<figure><img src="../../../.gitbook/assets/image (3372).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Paul Credentials

Within the `/var/www/html/CuteNews/cdata/users` directory, we can find some base64 encoded lines:

<figure><img src="../../../.gitbook/assets/image (3060).png" alt=""><figcaption></figcaption></figure>

When one of them was decoded, we find a token of some sorts:

<figure><img src="../../../.gitbook/assets/image (3783).png" alt=""><figcaption></figcaption></figure>

We can crack this hash on crackstation:

<figure><img src="../../../.gitbook/assets/image (835).png" alt=""><figcaption></figcaption></figure>

Then we can `su` to `paul`:

<figure><img src="../../../.gitbook/assets/image (242).png" alt=""><figcaption></figcaption></figure>

Cool

### SSH to Nadav

When I ran LinPEAS on the machine, I found that the public key of `nadav` was the public key of `paul`...?

<figure><img src="../../../.gitbook/assets/image (3932).png" alt=""><figcaption></figcaption></figure>

I tried to `ssh` in as `nadav` from `paul`, and it worked!

<figure><img src="../../../.gitbook/assets/image (2800).png" alt=""><figcaption></figcaption></figure>

### USBCreator

When running another LinPEAS, we find this part here:

<figure><img src="../../../.gitbook/assets/image (2758).png" alt=""><figcaption></figcaption></figure>

{% embed url="https://rioasmara.com/2021/07/16/usbcreator-d-bus-privilege-escalation/" %}

{% code overflow="wrap" %}
```bash
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /tmp/id_rsa true
```
{% endcode %}

Following this PoC would extract the private SSH key of `root` and allow me to SSH in as `root`:

<figure><img src="../../../.gitbook/assets/image (3272).png" alt=""><figcaption></figcaption></figure>
