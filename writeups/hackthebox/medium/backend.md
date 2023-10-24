---
description: Taken from UHC.
---

# Backend

## Gaining Access

We start with an Nmap scan as usual:

<figure><img src="../../../.gitbook/assets/image (135).png" alt=""><figcaption></figcaption></figure>

From here, we can view Port 80.&#x20;

### API Enumeration

Here, we can view an API that we need to exploit.

<figure><img src="../../../.gitbook/assets/image (1550).png" alt=""><figcaption></figcaption></figure>

Starting with a Gobuster, we can find out the different endpoints for this:

&#x20;

<figure><img src="../../../.gitbook/assets/image (890).png" alt=""><figcaption></figcaption></figure>

At the `/api/v1` endpoint, we find that that there is a `/user` endpoint that we can fuzz further using `wfuzz`.

<figure><img src="../../../.gitbook/assets/image (2879).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (3817).png" alt=""><figcaption></figcaption></figure>

From here, we can check the `admin` user with an ID of 1.&#x20;

<figure><img src="../../../.gitbook/assets/image (2774).png" alt=""><figcaption></figcaption></figure>

All other numbers do not have directories, so this means there's probably only one user available. I ran further scans on the `/user` endpoint, as there had to be a way to signup or login, and it does exist.

<figure><img src="../../../.gitbook/assets/image (3912).png" alt=""><figcaption></figcaption></figure>

### Creation of User

Within the API, we can try to signup as a user. I wasn't sure what parameters to give, so I just sent a test JSON input with a POST request.

<figure><img src="../../../.gitbook/assets/image (1359).png" alt=""><figcaption></figcaption></figure>

So we need to send them a `body, password and email` parameter within a JSON object to register the user.

<figure><img src="../../../.gitbook/assets/image (1101).png" alt=""><figcaption></figcaption></figure>

Then when using the login function with the username and password, we can grab a JWT token.

<figure><img src="../../../.gitbook/assets/image (397).png" alt=""><figcaption></figcaption></figure>

We can now access the `/docs` endpoint, which was not allowed earlier due to the lack of the Authorization token.

### /docs

<figure><img src="../../../.gitbook/assets/image (523).png" alt=""><figcaption></figcaption></figure>

At first, I thought we were able to load the `/docs` endpoint, but I was wrong.

<figure><img src="../../../.gitbook/assets/image (2050).png" alt=""><figcaption></figcaption></figure>

Checking the traffic proxied, we can see that there was actually a GET request to this `/openapi.json` endpoint, which we can directly access.

<figure><img src="../../../.gitbook/assets/image (1585).png" alt=""><figcaption></figcaption></figure>

Within the documentation, there were 2 very significant endpoints, one to read the user flag, and another to have RCE on the machine.

The user flag can be retrieved by sending a PUT request to this endpoint:

<figure><img src="../../../.gitbook/assets/image (3461).png" alt=""><figcaption></figcaption></figure>

### Getting Admin JWT

Below is the endpont that would allow us to gain a shell on the machine. Notice that we need to have Debug permissions, which is something our user definitely does not have.

<figure><img src="../../../.gitbook/assets/image (3290).png" alt=""><figcaption></figcaption></figure>

Using the API a bit more, we can find an `/updatepass` endpoint as well.

<figure><img src="../../../.gitbook/assets/image (190).png" alt=""><figcaption></figcaption></figure>

This update pass requires the GUID of the user we are trying to reset and a new password. Earlier, we found the GUID of the administrator, so we can easily reset his password and then steal his token.

<figure><img src="../../../.gitbook/assets/image (2207).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1633).png" alt=""><figcaption></figcaption></figure>

However, this still does not work as we do not have the 'debug' permission enabled on our token.

<figure><img src="../../../.gitbook/assets/image (3010).png" alt=""><figcaption></figcaption></figure>

However, because we had administrative permissions, we could access the `/admin/file` endpoint for an easy LFI.

<figure><img src="../../../.gitbook/assets/image (3374).png" alt=""><figcaption></figcaption></figure>

### Finding JWT secret

The first thing to check would be the `env` variables, because we don't know where anything is within this machine. We can do so by reading the `/proc/self/environ` file using our LFI.

<figure><img src="../../../.gitbook/assets/image (1861).png" alt=""><figcaption></figcaption></figure>

Notice the app home is within the `/home/htb/uhc` directory. Combine with the fact that this is running `uvicorn`, which is a Python server, we can look for an `app.py` or `main.py`. Within the `/home/htb/uhc/app/main.py` file, we can read the first part of the code responsible for this server.

<figure><img src="../../../.gitbook/assets/image (2941).png" alt=""><figcaption></figcaption></figure>

We can easily beautify this and read the dependencies it has.

<figure><img src="../../../.gitbook/assets/image (1921).png" alt=""><figcaption></figcaption></figure>

What I did was to check all of these files. For example, for the `app.api.v1.api` portion, it would be located at the `/home/htb/uhc/app/api/v1/api.py` file. When reading these files, I wanted to find out the JWT token Secret so I could create and spoof my own with the Debug permission set.&#x20;

The most interesting one was the `deps.py` file. This file had imported the JWT secret from the `core/config.py` directory.

<figure><img src="../../../.gitbook/assets/image (830).png" alt=""><figcaption></figcaption></figure>

From there, we can read the secret.

<figure><img src="../../../.gitbook/assets/image (424).png" alt=""><figcaption></figcaption></figure>

Once we had the Secret, spoofing another token is easy.

<figure><img src="../../../.gitbook/assets/image (2292).png" alt=""><figcaption></figcaption></figure>

We would then have RCE on the machine at this point.

<figure><img src="../../../.gitbook/assets/image (972).png" alt=""><figcaption></figcaption></figure>

Using a Base64 encoded payload with %20 or $IFS as the space character, we can gain a reverse shell.

<figure><img src="../../../.gitbook/assets/image (1971).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

For root, this was rather simple. Within the `~/uhc` folder, there was an `auth.log` file that had the root credentials within it.

<figure><img src="../../../.gitbook/assets/image (1172).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (827).png" alt=""><figcaption></figcaption></figure>
