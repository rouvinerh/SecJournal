# Kerberos

Kerberos is the default authentication service for Microsoft WIndows Domains. This service typically runs on port 88, **and it is key for us to understand how it works before attacking AD.**

## Terms

There are quite a few different services and tickets that make Kerberos work.

1. Ticket Granting Ticket (TGT)
   * Authentication ticket used to request service tickets from the TGs for specific resources from the domain.
2. Key Distribution Center (KDC)
   * Service for issuing TGTs and service tickets that consist of the AS and TGS.
3. Authentication Service (AS)
   * Issues TGTs to be used by the TGS in the domain to request access to other resources.
4. Ticket Granting Service (TGS)
   * Takes the TGT and returns a ticket to a machine on the domain.
5. Service Principal Name (SPN)
   * Identifier given to a service account to associate a service instance with a domain service account.
   * Windows requires that services have a domain service account.
6. KDC Long Term Secret Key
   * Encrypts TT and sign PAC
7. Client Long Term Secret Key
   * Client key is based on the cline's computer or account.
   * Used to check the encrypted timestamp and encrypt the session key.
8. Service Key
   * The service key is based on the service account.
   * Used to encrypt the service portion of the service ticket and sign the PAC.
9. Session Key
   * Issued by the KDC when a TGT is issued, where the user will provide the session key to the KDC along with the TGT when requesting a service ticket.
10. Privilege Attribute Certificate
    * Holds all user's relevant information, sent along with the TGT to the KDC and to be signed by the Target and KDC LT Key to validate the user.

## Process

At the start of the process, we would have this:​

<figure><img src="../../.gitbook/assets/image (3725).png" alt=""><figcaption><p><em>TGT Contents</em></p></figcaption></figure>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FWTUTS177qkR2G18bNEOt%2Fuploads%2Fcht1PGoBtW4TmC5gzMrs%2Fimage.png?alt=media&#x26;token=d2848710-cee5-4b9a-9105-d60753cb8886" alt=""><figcaption><p><em>Service Ticket Contents</em></p></figcaption></figure>

Generally, there are 2 important portions for the Service Tickets as shown above.

* The service portion is encrypted with the **NTLM Hash of the user**.
* The User portion is encrypted with the **TGT Session Key.**

The signing of the key with the Service LT Key and KDC LT Key basically acts like what a signature is in real life, which verifies the ticket is from authorised sources.

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FWTUTS177qkR2G18bNEOt%2Fuploads%2FU3sKhk5AJawTGtqtBZac%2Fimage.png?alt=media&#x26;token=f5944ef7-897e-4bf3-8a1b-a08d8d816246" alt=""><figcaption><p><em>Process for Keberos</em></p></figcaption></figure>

1. AS-REQ
   * The Client requests a TGT
2. AS-REP
   * KDC sends back an encrypted TGT using the Session key
   * The client would then decrypt on their end, and be able to gain the TGT, which can be used to request the service ticket. The name is hence **Ticket Granting Ticket.**
3. TGS-REQ
   * Client sends this encrypted TGT to the TGS with the SPN of the service that the client wants to access.
   * This basically tells the TGS something like "Hi, I'm \<support account name>, and I want to access the MySQL Database".
4. TGS-REP
   * KDC would verify the TGT of the user and that this user has access to the service by checking the privileges of this.
   * Once verified, it sends back a valid session key and service ticket for the service
5. AP-REQ
   * Client takes this session key and ticket and goes to the resource and requests what is wanted.
6. AP-REP
   * If all is well, resource server grants access to the client.

Long story short, there are 2 steps in this process, **one to check whether the client can decrypt the TGT, and another to check if the client can even retrieve a service ticket for the resource.** Hence, this is why it's a 2-way ticket-based mechanism.

The tickets can come in 2 forms, a .kirbi or a .ccache. Mainly .kirbi is used, and it is basically a base64-encoded block of text that can only be decrypted using the client's password. This is because of the fact that it's protected by something we call **asymmetric encryption,** which basically means there are 2 keys involved.
