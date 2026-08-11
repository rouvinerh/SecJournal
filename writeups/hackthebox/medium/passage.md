# Passage

## Gaining Access

Nmap scan:

![](../../../.gitbook/assets/passage-1.png)

### Passage News

Port 80 reveals some kind of website archive thing:

![](../../../.gitbook/assets/passage-2.png)

Checking the page source, we find that this is running CuteNews, which had a few RCE exploits available:

{% embed url="https://www.exploit-db.com/exploits/48800" %}

![](../../../.gitbook/assets/passage-10.png)

With this, we can easily gain a reverse shell:

![](../../../.gitbook/assets/passage-8.png)

## Privilege Escalation

### Paul Credentials

Within the `/var/www/html/CuteNews/cdata/users` directory, we can find some base64 encoded lines:

![](../../../.gitbook/assets/passage-6.png)

When one of them was decoded, we find a token of some sorts:

![](../../../.gitbook/assets/passage-9.png)

We can crack this hash on crackstation:

![](../../../.gitbook/assets/passage-12.png)

Then we can `su` to `paul`:

![](../../../.gitbook/assets/passage-3.png)

Cool

### SSH to Nadav

When I ran LinPEAS on the machine, I found that the public key of `nadav` was the public key of `paul`...?

![](../../../.gitbook/assets/passage-11.png)

I tried to `ssh` in as `nadav` from `paul`, and it worked!

![](../../../.gitbook/assets/passage-5.png)

### USBCreator

When running another LinPEAS, we find this part here:

![](../../../.gitbook/assets/passage-4.png)

{% embed url="https://rioasmara.com/2021/07/16/usbcreator-d-bus-privilege-escalation/" %}

```bash
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /tmp/id_rsa true
```

Following this PoC would extract the private SSH key of `root` and allow me to SSH in as `root`:

![](../../../.gitbook/assets/passage-7.png)
