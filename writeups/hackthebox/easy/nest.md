# Nest

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (3577).png" alt=""><figcaption></figcaption></figure>

Only SMB is open it appears. Port 4386 is for a service called HQK, which I could not do much with at this point.

### SMB Shares

`enum4linux` reveals quite a few shares that are open:

<figure><img src="../../../.gitbook/assets/image (2914).png" alt=""><figcaption></figcaption></figure>

The `Users` one had the most information and was the only one accessible, so I connected and recursively downloaded all possible files:

<figure><img src="../../../.gitbook/assets/image (1356).png" alt=""><figcaption></figcaption></figure>

Within the files downloaded, we can find a `Welcome Email.txt` file.

<figure><img src="../../../.gitbook/assets/image (950).png" alt=""><figcaption></figcaption></figure>

We can then check the permission of shares again with these credentials using `smbmap`.

<figure><img src="../../../.gitbook/assets/image (3077).png" alt=""><figcaption></figcaption></figure>

Now we could read the `Data` share, so I went in and recursively downloaded all files:

<figure><img src="../../../.gitbook/assets/image (1992).png" alt=""><figcaption></figcaption></figure>

Within the files downloaded, the `RU_config.xml` file contained this encrypted password for a user on the machine:

<figure><img src="../../../.gitbook/assets/image (2289).png" alt=""><figcaption></figcaption></figure>

Also, within the contents of that file, was a .NET VB project files.&#x20;

### Password Decryption

What I did was port all the files over to a Windows VM and then compiled it. Afterwards, I opened it up in DnSpy to see how the binary works:

<figure><img src="../../../.gitbook/assets/image (2481).png" alt=""><figcaption></figcaption></figure>

So the binary uses the `RU_config.xml` file and decrypts the password. We can set a breakpoint at that line highlighted and then view the variable contents to see the password after clicking 'Step Over' once. This reveals the password of `xRxRxPANCAK3SxRxRx`.&#x20;

### C.Smith Creds

With these credentials, I can access the directory of the user through SMB, but I did not manage to get a shell. Doesn't really matter because we can still grab the user flag. Within the user's directory there some intresting files I downloaded:

<figure><img src="../../../.gitbook/assets/image (2696).png" alt=""><figcaption></figcaption></figure>

The `Debug Mode Password.txt` was empty for some reason, and I found that weird. As such, I used `allinfo` on SMB to view whether there were alternate data streams present for the file:

<figure><img src="../../../.gitbook/assets/image (1956).png" alt=""><figcaption></figcaption></figure>

This confirms the presence of the alternate data stream, and we can use `cat` to extract the information:

<figure><img src="../../../.gitbook/assets/image (2513).png" alt=""><figcaption></figcaption></figure>

Cool, now we have the HQK password.

### HQK

Now that we have credentials, we can connect to the HQK port via `telnet` and enter DEBUG mode.

<figure><img src="../../../.gitbook/assets/image (2968).png" alt=""><figcaption></figcaption></figure>

With this, I was able to extract the administrator hash.

<figure><img src="../../../.gitbook/assets/image (2016).png" alt=""><figcaption></figcaption></figure>

Within this, we also can find another binary being used:

<figure><img src="../../../.gitbook/assets/image (139).png" alt=""><figcaption></figcaption></figure>

Similar to the previous time, we can load the binary in dnSpy and set a breakpoint to view the password. We would need to use all 3 files, and create an `ldap.conf` file that is passed in as a parameter to the main function. Then, we can view the contents of variables to see the password.

<figure><img src="../../../.gitbook/assets/image (762).png" alt=""><figcaption></figcaption></figure>

Afterwards, we would have full access to the C Drive:

<figure><img src="../../../.gitbook/assets/image (1365).png" alt=""><figcaption></figcaption></figure>
