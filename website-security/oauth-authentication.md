# OAuth Authentication

OAuth 2.0 is a popular authentication framework used for allowing **social media signins**. OAuth provides for information to be shared across applications, and it is quite common to find implementation errors in the framework, leading to stealing of information or bypassing of authentication entirely.

## How OAuth Works

Before exploiting, we need to know how this works. In short, OAuth allows for users to login without exposing their social media login credentials to the application they want to sign in to. Normally, users would have to allow for certain information to be shared with another application before OAuth authentication is allowed to happen. This can be stuff like **your name, email, or other PII**.&#x20;

There are 3 parties in OAuth:

1. Client Application
   * Website that is requesting for user's data on social media
2. Resource Owner
   * The application that has the data being requested
3. OAuth Service Provider
   * The website or application that controls access to the user's data
   * Provides an API to the **authorization server and resource server**.

OAuth allows for multiple ways for its authentication process to be implemented, in the form of 'flows'. How the process for authorization works is:

1. Client application requests for some user's data, specifying exactly what they want and the permissions they have over it (ie. some websites can post on your behalf).
2. User would login to their social media account and give consent for the access.&#x20;
3. Client application would receive **a unique access token** that proves they have permission to access the data. (Method depends on flow type)
4. Client application then uses this token to make API calls to the resource server to retrieve the data needed.

### OAuth flows

Generally, there are 2 different ways for OAuth to grant access. The first being **Authorization Code Grant Type:**

<figure><img src="../.gitbook/assets/image (459).png" alt=""><figcaption></figcaption></figure>

The second is the **Implicit Flow Type:**

<figure><img src="../.gitbook/assets/image (2663).png" alt=""><figcaption></figcaption></figure>

The main difference is that **the implicit flow type is much simpler**. it does not need to obtain an authorization code, thus there's no need to have an access token to exchange for. The client token simply receives an access token immediately and the user can log in.&#x20;

With simplicity comes less security, thus the implicit flow type is much more insecure. If the traffic is intercepted and followed, the user's access token and data are more exposed. Thus, this method is more suited for simpler applications that do not have the infrastructure to store information on the back-end.&#x20;

## Enumeration

When looking out for OAuth vulnerabilities, we would need to read through every single HTTP response that goes on. For example, since there's an API involved, perhaps we can probe that to find useful information about the authentication and resource server. As with most security stuff, I just play around with the requests and change parameters randomly to see if I get any interesting results.&#x20;

Some vulnerabilities include:

* XSS in redirect parameters
* Account takeover / hijacking using /callback&#x20;
* Truncating the authentication flow to be granted access immediately
* Leaking of client secret token or any other information
* SSRF through abusing certain parameters
* Insecure configurations redirect parameters

I haven't had the chance to exploit this in a CTF yet, so as of now I don't have many relevant examples. Hacktricks has loads of bug bounty writeups that are really good reads though.

{% embed url="https://book.hacktricks.xyz/pentesting-web/oauth-to-account-takeover#real-example" %}

