# Authentication Bypass

Authentication in web applications is a familiar concept. When attacking an authentication mechanism, there are many ways to go about it, and usage of other exploits can supplement or even give way to authentication bypass. This is not really an exploit per se, but rather something attackers look out for.&#x20;

## Exploitation

Generally, we look out for logic vulnerabilities or developers failing to implement some features safely. These include:

* Usage of easy to brute force credentials
* 2FA measures that aren't well secured.
  * For example, a 2FA measure that has a 6 digit PIN but has unlimited tries for it.
* Phishing or Social Engineering Attacks to gain passwords.
* SQL Injection, XSS or other vulnerabilities.
* Lack of account lockout after repeated failed attempts (anti-brute forcing mechanisms)

Personally, when I'm testing for authentication vulnerabilities, I would ask myself the following questions:

* How does the authentication verify the user?&#x20;
* What kind of parameters are being passed into the database?&#x20;
  * POST parameters
  * JSON
* What is being used to **authenticate a user and save their login session?**
  * Are the cookies decryptable like JWT?
  * Can I poison the web cache or smuggle a HTTP request into the backend?
* Is the login sending a request of some form into a backend database? Or is it running purely on Javascript
  * This can be seen if we proxy the requests through Burpsuite&#x20;
* Is there any other information being processed and passed into the web application?
  * For example, are any other parameters, like userID being used?
* Is the website running an outdated version of software that has known exploits for it?
* Are there Web Application Firewalls or Intrusion Detection that would trigger upon entering of special characters into the database?

## Example

Suppose that we have a web application that uses a JWT token to authenticate a session.

<figure><img src="../.gitbook/assets/image (3231).png" alt=""><figcaption></figcaption></figure>

JWT Tokens are basically base64 encoded strings separated into 3 different portions, and they are decryptable or spoofable once we have the private key to encode it properly.

<figure><img src="../.gitbook/assets/image (2325).png" alt=""><figcaption></figcaption></figure>

This particular application runs on Flask, and Flask JWT Tokens are actually decryptable and we can find the secret tokens from this.

<figure><img src="../.gitbook/assets/image (2896).png" alt=""><figcaption></figcaption></figure>

Then, we can create a new cookie with whatever username we like. In this case, the username `blue` was the admin of the page.

<figure><img src="../.gitbook/assets/image (1588).png" alt=""><figcaption></figcaption></figure>

With this new cookie, we can simply swop out the value of the Cookie header we found earlier and be able to login as this new user. This can also be done using Javascript in the browser console with `developer.cookie='cookiehere'`.&#x20;
