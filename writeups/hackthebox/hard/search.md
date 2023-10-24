# Search

## Gaining Access

Nmap scan revealed standard AD ports, and that port 80 was open.&#x20;

### Hope Sharp

This website was another corporate domain. When scrolling through it, I found this image that was rather interesting.

<figure><img src="../../../.gitbook/assets/image (3604).png" alt=""><figcaption></figcaption></figure>

If you look closely, there was a task with **Send password to Hope Sharp**. Then, **IsolationIsKey?** was the next line.&#x20;

This tells me that there was an interesting password to find. As such, I created a bunch of possible usernames with the name Hope Sharp, and used `crackmapexec` to brute force these credentials. Found that `hope.sharp` was the username:

<figure><img src="../../../.gitbook/assets/image (1828).png" alt=""><figcaption></figcaption></figure>

Additionaly, running `feroxbuster` on the website reveals some directories:

```
301        2l       10w      150c http://10.10.11.129/images
301        2l       10w      146c http://10.10.11.129/js
301        2l       10w      147c http://10.10.11.129/css
301        2l       10w      149c http://10.10.11.129/fonts
403       29l       92w     1233c http://10.10.11.129/staff
```

The `/staff` endpoint was interesting, but it was returning a 403 code.&#x20;

### Bloodhound

After getting these credentials, I wanted to use Bloodhound to map out all objects within the domain. Since I don't have a shell yet, I used `bloodhound-python`.&#x20;

<figure><img src="../../../.gitbook/assets/image (3920).png" alt=""><figcaption></figcaption></figure>

With Bloodhound, I found 2 interesting pieces of information. One was that a user named tristan.davies was a domain admin.

<figure><img src="../../../.gitbook/assets/image (3639).png" alt=""><figcaption></figcaption></figure>

Another was that the `web_svc` user was Kerberoastable. We can then use `GetUserSPNs.py` to gain a hash and crack it.

<figure><img src="../../../.gitbook/assets/image (727).png" alt=""><figcaption></figcaption></figure>

### web\_svc shares

With this user's credentials, I enumerated the shares that were available.

<figure><img src="../../../.gitbook/assets/image (1946).png" alt=""><figcaption></figcaption></figure>

I still don't have access to the **helpdesk** share, so I looked at the rest. Within the RedirectedFolders$ share, I found a ton of usernames.

<figure><img src="../../../.gitbook/assets/image (1853).png" alt=""><figcaption></figcaption></figure>

Then, we can find out if the passwords we have are valid for any other users. I found that `edgar.jacobs` had the same password as the `web_svc` user.

<figure><img src="../../../.gitbook/assets/image (3721).png" alt=""><figcaption></figcaption></figure>

### Helpdesk Share

With this new user, I was finally able to access the helpdesk share.

<figure><img src="../../../.gitbook/assets/image (1239).png" alt=""><figcaption></figcaption></figure>

Within the share, I found a .xlsx file.

<figure><img src="../../../.gitbook/assets/image (3442).png" alt=""><figcaption></figcaption></figure>

Reading this file, I found out some usernames and names of users on the domain.

<figure><img src="../../../.gitbook/assets/image (1597).png" alt=""><figcaption></figcaption></figure>

There was something odd however. Where was column C? The spreadsheet shows A,B and D. Perhaps column C was hidden on purpose because it contained other information. I was unable to expand it or view it, thus confirming it was locked.

### Excel Bypass

This was a good read:

{% embed url="https://yodalearning.com/tutorials/unprotect-excel/" %}

One cool thing about most .xlsx files is that they are actually ZIP files in disguise. We can bypass this content protection by copying the file as a .zip file, and then unzipping it.

<figure><img src="../../../.gitbook/assets/image (2547).png" alt=""><figcaption></figcaption></figure>

Then from every single .xml file, we can remove the `sheetProtection` tag completely. Afterwards, we just need to compress and zip the files back together into another .xlsx file.

We can then view the hidden column C.

<figure><img src="../../../.gitbook/assets/image (3614).png" alt=""><figcaption></figcaption></figure>

We can then brute force all of these passwords with `crackmapexec` and find that one works!

<figure><img src="../../../.gitbook/assets/image (1530).png" alt=""><figcaption></figcaption></figure>

Using the RedirectedFolder$ share, we can sign in as the `sierra.frye` user and retrieve theuser flag.

<figure><img src="../../../.gitbook/assets/image (279).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

Looking around this user's directory, I was able to find a .pfx and .p12 file.

<figure><img src="../../../.gitbook/assets/image (545).png" alt=""><figcaption></figcaption></figure>

### Certificate Loading

Because these are certificates, perhaps they can be loaded into our browser for viewing of hidden websites. However, they are password protected.

<figure><img src="../../../.gitbook/assets/image (3509).png" alt=""><figcaption></figcaption></figure>

We can easily crack this with `pfx2john` and `john`.&#x20;

<figure><img src="../../../.gitbook/assets/image (957).png" alt=""><figcaption></figcaption></figure>

Then we can load this in to our browsers.&#x20;

<figure><img src="../../../.gitbook/assets/image (3297).png" alt=""><figcaption></figcaption></figure>

Now, we can access the /staff page we were rejected from earlier. This would reveal a Powershell Web Access page.

<figure><img src="../../../.gitbook/assets/image (3826).png" alt=""><figcaption></figcaption></figure>

We can login as `sierra.frye` usingthe credentials we found earlier. For Computer Name, I guessed search and research based on the certificates I found, and **research** worked.

### Powershell Web Access&#x20;

Now, we had a CLI as Sierra.frye.

<figure><img src="../../../.gitbook/assets/image (2762).png" alt=""><figcaption><p>'</p></figcaption></figure>

Looking back to Bloodhound, I found that this user was able to ReadGMSAPassword for the `bir-adfs-gmsa` user, in which the latter had GenericAll privileges over the domain admin `tristan.davies`.

<figure><img src="../../../.gitbook/assets/image (3867).png" alt=""><figcaption></figcaption></figure>

We can read the password using the Active Directory Powershell module.

<figure><img src="../../../.gitbook/assets/image (705).png" alt=""><figcaption></figcaption></figure>

Then, we can store the password in a variable (because it's UTF-8 characters and hard to type) and just use Powershell to execute commands remotely.

<figure><img src="../../../.gitbook/assets/image (1735).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (240).png" alt=""><figcaption></figcaption></figure>

Then, because we have `GenericAll` permissions over `tristan.davies`, we can just reset his password.

<figure><img src="../../../.gitbook/assets/image (3514).png" alt=""><figcaption></figcaption></figure>

Lastly, we can use `wmiexec.py` to gain a shell as the domain admin.

<figure><img src="../../../.gitbook/assets/image (3722).png" alt=""><figcaption></figcaption></figure>
