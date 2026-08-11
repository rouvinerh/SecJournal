# Passage

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(1509).png>)

### Passage News

Port 80 reveals some kind of website archive thing:

![](<../../../.gitbook/assets/image%20(221).png>)

Checking the page source, we find that this is running CuteNews, which had a few RCE exploits available:

{% embed url="https://www.exploit-db.com/exploits/48800" %}

![](<../../../.gitbook/assets/image%20(3821).png>)

With this, we can easily gain a reverse shell:

![](<../../../.gitbook/assets/image%20(3372).png>)

## Privilege Escalation

### Paul Credentials

Within the `/var/www/html/CuteNews/cdata/users` directory, we can find some base64 encoded lines:

![](<../../../.gitbook/assets/image%20(3060).png>)

When one of them was decoded, we find a token of some sorts:

![](<../../../.gitbook/assets/image%20(3783).png>)

We can crack this hash on crackstation:

![](<../../../.gitbook/assets/image%20(835).png>)

Then we can `su` to `paul`:

![](<../../../.gitbook/assets/image%20(242).png>)

Cool

### SSH to Nadav

When I ran LinPEAS on the machine, I found that the public key of `nadav` was the public key of `paul`...?

![](<../../../.gitbook/assets/image%20(3932).png>)

I tried to `ssh` in as `nadav` from `paul`, and it worked!

![](<../../../.gitbook/assets/image%20(2800).png>)

### USBCreator

When running another LinPEAS, we find this part here:

![](<../../../.gitbook/assets/image%20(2758).png>)

{% embed url="https://rioasmara.com/2021/07/16/usbcreator-d-bus-privilege-escalation/" %}

```bash
gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /tmp/id_rsa true
```

Following this PoC would extract the private SSH key of `root` and allow me to SSH in as `root`:

![](<../../../.gitbook/assets/image%20(3272).png>)
