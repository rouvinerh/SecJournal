---
description: Builds on the Backend machine with updated security features.
---

# BackendTwo

## Gaining Access

Since this builds on the other Backend machine from UHC, there isn't a lot of enumeration to do.

![](../../../.gitbook/assets/backendtwo-4.png)

Port 80 brings us to an API again, with the admin user still being viewable.

![](../../../.gitbook/assets/backendtwo-11.png)

![](../../../.gitbook/assets/backendtwo-6.png)

### Creating User

We can do the same stuff to create, signin as a user and receive the JWT token for it.

![](../../../.gitbook/assets/backendtwo-13.png)

Afterwards, we can access the `/openapi.json` endpoint to view the functionalities of this API. There was one new functionality, which was to edit the profiles of users.

![](../../../.gitbook/assets/backendtwo-10.png)

This endpoint was rather interesting because it allows us to edit profiles. Checking the JWT token of our current user, we find out that our `id` is 12.

![](../../../.gitbook/assets/backendtwo-20.png)

### Superuser Takeover

With this edit profile stuff, I found out that we can change the attributes related to our account. I changed the profile, email and GUID of the current user to be the same as the administrator's.

![](../../../.gitbook/assets/backendtwo-14.png)

When I found out this worked, I basically also changed the `is_superuser` attribute to `true`.

![](../../../.gitbook/assets/backendtwo-5.png)

After changing all of these, we just need to retrieve the new JWT token we can use for further exploitation.

![](../../../.gitbook/assets/backendtwo-19.png)

### Read and Write Files

The other OpenAPI functionalities included writing files and reading files as the administrator.

![](../../../.gitbook/assets/backendtwo-17.png)

![](../../../.gitbook/assets/backendtwo-7.png)

As usual, I started with reading the code that the application runs on. Since we wcould write files, the only exploit in my mind was to change the some file to include a custom RCE endpoint for us. We can find out all of the locations of the files using the same method as Backend, which involved reading the `/proc/self/environ` file and finding the `/home/htb` directory that had the source code files for the app.

Within the `/home/htb/app/api/v1/endpoints/user.py`  file, this was the original code.

![](../../../.gitbook/assets/backendtwo-2.png)

I changed the code to include a one-liner reverse shell everytime a unique ID was accessed.

![](../../../.gitbook/assets/backendtwo-18.png)

Then we need to convert the file contents using the escape string function on Cyberchef.

![](../../../.gitbook/assets/backendtwo-12.png)

Using this, we can use curl to get the file where we want it. The command would look like this:

```bash
curl http://<IP>/api/v1/admin/file/$(echo -n "/home/htb/app/api/v1/endpoints/user.py" | base64) -H "Content-Type: application/json" -d '{"file": "CODE HERE"}' -H 'Authorization: Bearer <TOKEN>' 
```

Then, we can access the custom endpoint to gain a reverse shell easily.

![](../../../.gitbook/assets/backendtwo-1.png)

![](../../../.gitbook/assets/backendtwo-8.png)

## Privilege Escalation

Once we are in, we can try to read the `auth.log` file and we would find the password for the `htb` user we currently are. This allows us to upgrade our shell via SSH-ing in.

![](../../../.gitbook/assets/backendtwo-9.png)

### Wordle

When I tried to check sudo privileges, I was left with this.

![](../../../.gitbook/assets/backendtwo-15.png)

This was basically wordle, and there are better ways to solve this via checking what directories it uses. I used `strings` to see what libraries it called.

![](../../../.gitbook/assets/backendtwo-16.png)

We can then use `find / -name pam_wordle.so 2> /dev/null` to find this library and run strings on it. It would be located in the `/usr/lib/x86_64-linus-gnu/security` directory and is readable by all. We can then use `strings` on it.

From the output, we find that the wordlist for wordle is from  `/opt/.words`, which would allow us to scope our guesses.

Afterwords, I used `sudo /bin/bash` and just kept guessing based on the words I had.

![](../../../.gitbook/assets/backendtwo-3.png)

Fun enough.
