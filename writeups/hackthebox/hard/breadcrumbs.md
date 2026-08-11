# BreadCrumbs

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(1135).png>)

Port 80 is running a kind of library application.

### Arbitrary File Read

On the webapp, we can search for books using the title and author.

![](<../../../.gitbook/assets/image%20(2010).png>)

![](<../../../.gitbook/assets/image%20(3015).png>)

Doing a quick directory enumeration reveals some interesting directories:

![](<../../../.gitbook/assets/image%20(723).png>)

Testing for SQL Injection within the parameters above reveals nothing of interest. When viewing the Actions that we can do for each book, we would see that we can attempt to borrow it.

![](<../../../.gitbook/assets/image%20(3851).png>)

Clicking yes causes an error to pop up.

![](<../../../.gitbook/assets/image%20(2114).png>)

I wanted to view the requests being made through Burpsuite, and saw this stuff.

![](<../../../.gitbook/assets/image%20(2612).png>)

Attempting to change the `book` parameter in any way causes this error to appear:

![](<../../../.gitbook/assets/image%20(3659).png>)

`file_get_contents()` could be used to read some other files. Earlier, we did a `gobuster` directory enumeration and found a `/db` directory.

![](<../../../.gitbook/assets/image%20(1663).png>)

I attempted to read this file through the potential File Read vulnerability we found earlier, and it worked by changing the `book` paramter to `../../../../../../../../../Users/www-data/Desktop/xampp/htdocs/db/db.php`.

![](<../../../.gitbook/assets/image%20(2076).png>)

We now have some set of credentials that we can use.

### Portal Enumeration

There was nowhere to use this set of credentials, so I carried on with the enumeration. There was this `/portal` directory that brought us to this login page:

![](<../../../.gitbook/assets/image%20(786).png>)

Creating a fake account to login reveals there are 2 cookies being used, one being a JWT token and the other being a PHPSESSID token with our username appended in front.

![](<../../../.gitbook/assets/image%20(3559).png>)

Viewing the page itself reveals several functions we can use.

![](<../../../.gitbook/assets/image%20(586).png>)

I was unable to access the File Management function at `/portal/php/files.php`, hence I took a look at the source code for it using the File Read we found earlier.

![](<../../../.gitbook/assets/image%20(3055).png>)

Seems that `paul` is the administrator of this website.

### Token Spoofing

Knowing that we have an Arbitrary File Read exploit to use, we can leverage on that to read the `authController.php` file of this folder, as this file determines the authentication mechanism and it may have credentials within it.

![](<../../../.gitbook/assets/image%20(1042).png>)

The first thing we notice is the dependencies required, which are the `db.php` file we found earlier, and this `cookie.php` file that is new. We can also find the `$secret_key` variable within the code that it used for a JWT token.

![](<../../../.gitbook/assets/image%20(3119).png>)

We can take a look at the `cookie.php` file.

![](<../../../.gitbook/assets/image%20(1851).png>)

In the last line, we can see that there's a notice to change the second part of the MD5 key every week, meaning that there's something that isn't changed. Also, we notice the `$key` and `$username[$seed]` values here. Then, `$username.md5($key)` is returned as the session cookie.

So first, we can easily spoof the JWT token used because we have found the secret key being used.

![](<../../../.gitbook/assets/image%20(585).png>)

Next, the hint is that the second part of the MD5 key is unchanged, meaning that we can just change the `PHPSESSID` token to have `paul` instead of `hello` in front.

Changing these 2 tokens granted access to the file management page we found earlier. We can upload .zip files here.

![](<../../../.gitbook/assets/image%20(3185).png>)

### Webshell and RCE

This was obviously a PHP site, so I attempted to upload a basic PHP webshell. Since only .zip files were allowed, we can attempt to alter the request to bypass the file extension check.

Viewing the requests shows that there's a `task` variable changing our file to a .zip one.

![](<../../../.gitbook/assets/image%20(4022).png>)

We can change this to .php and it bypasses the file extension check. However, the PHP webshell above does not work, and there may be a WAF in place. I tried different webshells, and `shell_exec()` works.

![](<../../../.gitbook/assets/image%20(3106).png>)

Then, we can access the webshell via checking the `portal/uploads` folder.

![](<../../../.gitbook/assets/image%20(1881).png>)

Then, we can get a reverse shell via whatever method.

![](<../../../.gitbook/assets/image%20(2167).png>)

### SSH as Juliette

When viewing the users present on the machine, we can find a few others:

![](<../../../.gitbook/assets/image%20(2613).png>)

I wanted to enumerate the files for the web application hosted, so I headed there. Within the files for the portal directory, we find a `pizzaDeliveryUserData` folder which is rather suspicious.

![](<../../../.gitbook/assets/image%20(3895).png>)

Within it, we can see one file that stands out.

![](<../../../.gitbook/assets/image%20(3028).png>)

Within it, we can find some credentials for this user.

![](<../../../.gitbook/assets/image%20(3544).png>)

Then, we can SSH in as this user.

## Privilege Escalation

### Sticky Notes

When checking the user directory, we find a `todo.html` file.

![](<../../../.gitbook/assets/image%20(249).png>)

Viewing it reveals a hint to check the Sticky Notes application files for passwords.

![](<../../../.gitbook/assets/image%20(3034).png>)

The files for this are located within the `C:\users\juliette\Appdata\local\pacakages` directory.

![](<../../../.gitbook/assets/image%20(1301).png>)

There we can find some SQLite files.

![](<../../../.gitbook/assets/image%20(3799).png>)

We can transfer this over to our machine and use `sqlite3` to view the contents. Within it, we can find credentials for the `development` user.

![](<../../../.gitbook/assets/image%20(646).png>)

![](<../../../.gitbook/assets/image%20(1425).png>)

### Krypter

These credentials could be used for checking the SMB shares that were open, revealing that we had access to the `Development` share.

![](<../../../.gitbook/assets/image%20(1843).png>)

Within it, we can find a file of interest.

![](<../../../.gitbook/assets/image%20(1402).png>)

This was a ELF binary, and we can run it to see this:

![](<../../../.gitbook/assets/image%20(3073).png>)

So this thing can retrieve a password that is encrypted from somewhere. I opened this file up in IDA to see how it functions.

![](<../../../.gitbook/assets/image%20(2857).png>)

Firstly, we can see that this accesses a service on port 1234 of the machine, which we probably need to use port forwarding to access. Next and more notably, we can see another string that looks a lot like a SQL query.

To check this, I port forwarded the service via SSH using juliette's credentials, then I tried to access the service using `curl`.

![](<../../../.gitbook/assets/image%20(1878).png>)

### SQL Injection in Krypter

This query looked a lot like SQL Injection, and it seems that we can retrieve the key but not the encrypted password itself.

I tried some basic UNION SQL injection, and it worked!

![](<../../../.gitbook/assets/image%20(1900).png>)

Then, we can enumerate the databases present.

![](<../../../.gitbook/assets/image%20(1128).png>)

We can check the `bread` database to view some more stuff.

![](<../../../.gitbook/assets/image%20(2348).png>)

![](<../../../.gitbook/assets/image%20(3280).png>)

Finally, we can just view all of the stuff within this table via `concat()`.

![](<../../../.gitbook/assets/image%20(3494).png>)

Then, we can decrypt the password using the first key we found.

![](<../../../.gitbook/assets/image%20(522).png>)

This password was base64 encoded, and decoding it gives the administrator password, which we can use to SSH in.

![](<../../../.gitbook/assets/image%20(825).png>)
