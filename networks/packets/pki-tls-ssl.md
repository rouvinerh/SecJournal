---
description: Port 443 > 80.
---

# PKI, TLS / SSL

This summarises what's the difference between HTTP and HTTPS, where the S stands for secure. HTTPS runs on port 443, while regular, unencrypted HTTP runs on Port 80.

## Public Key Infrastructure

PKI refers to the set of technologies, frameworks, standards and procedures that supports public key encryption and authentication. PKI for networks revolves around **asymmetric encryption**, which uses a mathematically generated public and private key, both of which are assigned to verify the identites of the endpoints (like Google.com, for example).&#x20;

{% embed url="https://rouvin.gitbook.io/pentesting/pentesting-methodology/terms-and-concepts/passwords-and-encryption#asymmetric-encryption" %}

In essence, PKI allows for end-to-end encryption, which would basically form a 'tunnel' from the host to the endpoint and protect sensitive information, and provide digital identites for users and devices. If we didn't have this, any attacker can simply intercept all the packets being transferred in the air and be able to raed sensitive information in plaintext.

These keys are in the form of **digital certificates.** They can also be called X.509 Certificates, or PKI certificates.&#x20;

## Certificates

There are different types of certificates, each used for various purposes. Here are a few:

### TLS / SSL Certificates

These certificates crypographically link an online entity with a public key. Web browsers use them to authenticate content sent from web servers, ensuring trust in content delivered online.&#x20;

A website owner would need to apply for and **complete the vertification procedure** at the Certificate Authority (CA). This certificate would then be tied to the domain name or IP address of the website, attach a public key to it and then sign it with the CA's own root (or intermediate root) certificate.&#x20;

> Certificate Authorites are entities that are responsible for sotring, signing and issuing digital CAs include tech companies like Google and Microsoft, as well as others like GeoTrust, GoDaddy and Entrust.&#x20;

The process of checking whether these certificates are legit is as follows:

* User tries to access a website, browser then has to verify the PKI certificate authority's signature from its pre-installed root store
  * This is otherwise known as HTTP Strict Transport Security (HSTS)
* Browser then creates a session key and encrypts it using **public key of website.**&#x20;
* Encrypted session key is then sent and decrypted using the website's **pricate key**.&#x20;
* Now, this session key is used for encrypting and decrypting data transmitted between the browser and server for that entire session until termination.

There are a lot of different types of SSL Certs out there, and most domains come with it.&#x20;

In the event that you are accessing a HTTP website that does not have a certificate, browser clients would sometimes alert you like this:

<figure><img src="../../.gitbook/assets/image (1852).png" alt=""><figcaption></figcaption></figure>

This is when the certificate is expired, or not valid. When this happens, we are essentially sending traffic that is not encrypted, making us vulnerable to a **man in the middle attack,** which I'll cover more on in another section.&#x20;

### Code Signing

When software publishers release their products, there would be a digital signature on the executable or binary. The reason this is done is for Intellectual Property protection and to protect users. Unlike an SSL Certificate that merely encrypts the data, a Code Signing Cert would instead **hash the entire code along with the digital certificate.**

This would prevent anyone from actually getting the source code for a closed-source project. When users download this, their system wouuld first check the PKI certificate authority's signature. A hash is generated and it must match with the hash received with the software.&#x20;

Since hashes check integrity, a match would mean the file downloaded has not been edited since the publisher uploaded it, ensuring that the user does not download some malware.&#x20;

### Email Signing

Email Certs, otherwise known as S/MIME certificates, are basically used to secure communications between two email clients. This encrypts data in transit and at rest. The process of this is similar to that of code signing, in which a hash is generated to check for integrity of contents.&#x20;

A subset of this is the PGP signatures used for emails, which are a form of PKI as well.&#x20;
