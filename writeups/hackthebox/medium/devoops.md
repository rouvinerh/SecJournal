# Devoops

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(3602).png>)

There's only one port open on this machine.

### XXE Injection

On port 5000, this is what we see:

![](<../../../.gitbook/assets/image%20(2388).png>)

We can use `gobuster` on this to find more directories.

![](<../../../.gitbook/assets/image%20(2192).png>)

`/feed` would bring us here:

![](<../../../.gitbook/assets/image%20(2171).png>)

XML Injection is pretty helpful, and i noticed that when we upload a file using this API, a POST request would be sent to the `/upload` directory with HTTP form data.

However, trying to send any XML files that I created results in a Internal Server Error message being returned. Turns out, there are specific elements that we need to use for this endpoint:

![](<../../../.gitbook/assets/image%20(2298).png>)

With these, we can wrap them in another tag and start getting successful uploads through.

![](<../../../.gitbook/assets/image%20(1730).png>)

From this, we identified that we have a user called `roosa`. Then, we can attempt some basic XXE LFI payloads to read the user's private SSH key.

![](<../../../.gitbook/assets/image%20(1662).png>)

Afterwards, we can simply SSH into the machine.

![](<../../../.gitbook/assets/image%20(2385).png>)

## Privilege Escalation

### Git Logs

When checking the `id` of this user, we see that we are part of the `sudo` group.

![](<../../../.gitbook/assets/image%20(2794).png>)

Within the home directory of the user, we also find some Git repository files.

![](<../../../.gitbook/assets/image%20(3636).png>)

Using `find /home -name .git`, we can find the specific location of the Git repository to read its logs.

![](<../../../.gitbook/assets/image%20(1620).png>)

After heading to that directory, we would find an SSH key after using `git log -p -2`:

![](<../../../.gitbook/assets/image%20(93).png>)

![](<../../../.gitbook/assets/image%20(2862).png>)

Surprisingly, this was the root SSH key.

![](<../../../.gitbook/assets/image%20(3045).png>)
