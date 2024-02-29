# OAuth Authentication

OAuth 2.0 is a popular authentication framework used for allowing **signing in via other providers**. For example, 'Sign in with Google/Facebook` uses OAuth. It provides a framework websites to share information and credentials, and sometimes there are implementation errors that lead to possible exploits. 

## OAuth

OAuth allows for users to login without exposing their third party (Google Email, Apple ID, etc.) login credentials to the application they want to sign in to. Normally, users have to allow for certain information to be shared with another application before OAuth authentication is allowed to happen, like an email.

There are 3 parties in OAuth:

1. Client Application
   * Website that is requesting for user's data via third-party method
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

## Flows

Generally, there are 2 different ways for OAuth to grant access. The first being **Authorization Code Grant Type:**

<figure><img src="../../.gitbook/assets/image (459).png" alt=""><figcaption></figcaption></figure>

The second is the **Implicit Flow Type:**

<figure><img src="../../.gitbook/assets/image (2663).png" alt=""><figcaption></figcaption></figure>

Between the two, the implicit flow is easier. It does not need to obtain an authorization code, thus there's no need to have an access token to exchange for. The client token simply receives an access token immediately and the user can log in.

That being said, anything 'implicit' means 'more insecure'. If the traffic is intercepted and followed, the user's access token and data are more exposed. Thus, this method is more suited for simpler applications that do not have the infrastructure to store information on the back-end.&#x20;

## Enumeration

When looking out for OAuth vulnerabilities, one needs to read through every single HTTP response that goes on to understand how information is processed and where it is going. 

Since there's an API involved, one can probe that to find useful information about the authentication and resource server.

Some vulnerabilities include:

* XSS in redirect parameters
* Account takeover / hijacking using /callback&#x20;
* Truncating the authentication flow to be granted access immediately
* Leaking of client secret token or any other information
* SSRF through abusing certain parameters
* Insecure configurations redirect parameters