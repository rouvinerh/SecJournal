# File Upload Vulnerabilities

## Exploitation

When a website has an insecure file upload feature, it almost always ends up in a high severity attacks resulting in RCE.

An attacker can upload any arbitrary file on a machine and then execute the code within that file. 

Even if there are WAFs to prevent the upload of certain extensions, they can be bypassed if the whitelist / blacklist is not programmed properly.

These include:
* Including double extensions like `.jpg.php`.
* Null byte truncation `%00`.
* Changing the `Content-Type` header.
* Adding file headers to a malicious file (for example, adding the first 4 bytes of a JPEG file to a PHP file).
* Any combination of these techniques!