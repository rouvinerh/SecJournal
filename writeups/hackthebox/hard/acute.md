---
description: >-
  Good (and difficult) machine that requires good enumeration to find easily
  exploitable vulnerabilities.
---

# Acute

## Gaining Access

**Nmap Scan:**

<figure><img src="../../../.gitbook/assets/image (328).png" alt=""><figcaption></figcaption></figure>

### Port 443

I ran a nikto scan on the website and found the certificate and domain name. We can add this to the hosts file and try to access it.

<figure><img src="../../../.gitbook/assets/image (3496).png" alt=""><figcaption></figcaption></figure>

The website is as follows:

<figure><img src="../../../.gitbook/assets/image (1715).png" alt=""><figcaption><p>![[21_Acute _image002.png]]</p></figcaption></figure>

While looking at the website, I found that we are able to download a Microsoft word document through clicking the **New Starter Forms** button on the website.

<figure><img src="../../../.gitbook/assets/image (3907).png" alt=""><figcaption></figcaption></figure>

This was pretty odd, and I knew this thing had to be important somehow because why would a box give us a word document?

### Microsoft Word Doc

&#x20;The word doc looks like so, and it contains some useful information.

<figure><img src="../../../.gitbook/assets/image (2797).png" alt=""><figcaption></figcaption></figure>

When looking through the document, we can find more information regarding a user named Lois.

<figure><img src="../../../.gitbook/assets/image (1650).png" alt=""><figcaption></figcaption></figure>

Also, we can find a portal that leads to a Windows PowerShell Web Access portal.

<figure><img src="../../../.gitbook/assets/image (3421).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3044).png" alt=""><figcaption></figcaption></figure>

From here, we just need to find some credentials and the computer name. Looking through the document again, we can find a password of `Password1!`.

<figure><img src="../../../.gitbook/assets/image (3755).png" alt=""><figcaption></figcaption></figure>

### Username and Computer Name

Based on the website, we can find that there are some names listed on it, and these could be the potential usernames that we need.

<figure><img src="../../../.gitbook/assets/image (2135).png" alt=""><figcaption></figcaption></figure>

We can get these names into a file and then use a script to generate out all possible usernames to brute force with the password.

For the computer name, I found it by using `exiftool` on the document downloaded.

<figure><img src="../../../.gitbook/assets/image (1147).png" alt=""><figcaption></figcaption></figure>

Now, we have all the details we need, and all we have left is to brute force the username.

### Powershell Access

The brute forcing of the password took ages. I tried all permutations of usernames based on the names that were available, and found that **edavies** was the right username.

From here, we can get a shell easily.

<figure><img src="../../../.gitbook/assets/image (2108).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (638).png" alt=""><figcaption></figcaption></figure>

There's no user flag yet!

## Privilege Escalation 1

This machine was unique in the sense that the shell we get is very unstable, and seems to be killed every once in a while.

When enumerating using Winpeas.exe, I found nothing of interest until I decided to view the processes that were running on this device. What was interesting was that there was another Powershell instance that was running on the machine.

<figure><img src="../../../.gitbook/assets/image (2118).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3986).png" alt=""><figcaption></figcaption></figure>

### Screengrab

This powershell process was unique because I do not normally see another instance of it running when I'm in machines. As such, our next step would be to investigate this process, and I suspected that it was running on the Desktop of this user.

As such, the next thing to do is get a **meterpreter shell** and use the modules there to grab a screenshot.

We can easily generate one using MSFVenom.

<figure><img src="../../../.gitbook/assets/image (973).png" alt=""><figcaption></figcaption></figure>

Once we get this on the target machine and get a shell, we would need to migrate processes for stability, and then use the **espia** module to get a screenshot.

<figure><img src="../../../.gitbook/assets/image (1100).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3971).png" alt=""><figcaption></figcaption></figure>

When viewing the screenshot, I was surprised to find I was right!

<figure><img src="../../../.gitbook/assets/image (3526).png" alt=""><figcaption></figcaption></figure>

The powershell instance we found earlier was running this command to remotely control another device, which I suspect might be another machine that is not accessible from my machine and required tunneling.

Now we have gotten credentials for another user, imonks.

### RCE as imonks

With this, we can use the same Powershell Web Access portal to gain RCE as this new user.

<figure><img src="../../../.gitbook/assets/image (2972).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can check the directory of his desktop to confirm where the user.txt is.

<figure><img src="../../../.gitbook/assets/image (1348).png" alt=""><figcaption></figcaption></figure>

While I did find the user flag, there was this .ps1 file that was also really interesting. With our RCE capabilities, we can read this file.

<figure><img src="../../../.gitbook/assets/image (2256).png" alt=""><figcaption></figcaption></figure>

This script essentially runs the `Get-Volume` command as the jmorgan user, which is cool. Also, we can note that the imonks user has privileges over this script and we can write to it. What this means is, we can get RCE as jmorgan!

Using the same reverse shell .exe file I generated earlier, we can change the command executed in the ScriptBlock to run that binary instead.

<figure><img src="../../../.gitbook/assets/image (2802).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1483).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (703).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation 2

Now, we can enumerate the machine as this user. First, I checked what privileges we have.

<figure><img src="../../../.gitbook/assets/image (2209).png" alt=""><figcaption></figcaption></figure>

This user basically had full administrative privileges over this machine, and we can proceed to dump the hashes using this user.

However, based on my understanding of this box creator, the root.txt is likely not on this machine but on that hidden machine!

As such, we would need to find a way to gain access to the Administrator account on the hidden machine

### Dumping Hashes

I used mimikatz to dump out the hashes easily. This was done through loading the kiwi module using the earlier meterpreter binary I generated for screengrab.

<figure><img src="../../../.gitbook/assets/image (3139).png" alt=""><figcaption></figcaption></figure>

Then, we can find the Administrator credentials.

<figure><img src="../../../.gitbook/assets/image (1774).png" alt=""><figcaption></figcaption></figure>

The hash can be cracked on crackstation.net.

<figure><img src="../../../.gitbook/assets/image (1389).png" alt=""><figcaption></figcaption></figure>

### RCE as Wallace

When testing the credentials on the other machine, I found that it only worked with a user called wallace, and no one else.

<figure><img src="../../../.gitbook/assets/image (791).png" alt=""><figcaption></figcaption></figure>

As such, we would probably need to enumerate the machine as Wallace. When checking out the C:\Program Files directory, I found this interesting file called keepmeon.

<figure><img src="../../../.gitbook/assets/image (3661).png" alt=""><figcaption></figcaption></figure>

When checking the file, we can see that it just contains a .bat file that runs every 5 minutes or so.

<figure><img src="../../../.gitbook/assets/image (107).png" alt=""><figcaption></figcaption></figure>

Again, we can see how this script is used by Lois. Remember that Lois is the only one who is authorized to change Group Membership of users! So, this script is being run my the user Lois every 5 minutes or so and we have write permissions.

As such, we can easily change the command to add wallace into the Site\_Admin group to allow us to view the files in the hidden machine.

### Gaining Access as Admin

Using the same as earlier to set content of a file, we can change the command that is being run in Lois's script.

<figure><img src="../../../.gitbook/assets/image (3634).png" alt=""><figcaption></figcaption></figure>

After about 5 minutes, we can view the wallace user and see that we are now a Site\_Admin.

<figure><img src="../../../.gitbook/assets/image (2989).png" alt=""><figcaption></figcaption></figure>

With this, we can now access the root.txt file on the other machine.

<figure><img src="../../../.gitbook/assets/image (680).png" alt=""><figcaption></figcaption></figure>

With that, this machine has been pwned!
