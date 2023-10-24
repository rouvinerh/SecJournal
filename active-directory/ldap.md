# LDAP

## What is LDAP?

Lightweight Directory Access Protocol (LDAP) is a protocol that enables people to **locate and find** important organisations and resources within a network. The 'lightweight' aspect is that it has lesser code and does not need a ton of resources to run.&#x20;

LDAP is the core protocl behind Active Directory domains. When a user is trying to find an object, such as a printer or another user, LDAP is being used to query the objects and return the correct results.&#x20;

LDAP generally runs on ports 389, and LDAPS (which is LDAP with TLS/SSL) runs on port 636. Generally, there are 3 ways to authenticate via LDAP:

1. Anonymous access with null credentials
2. Name / Password Access
3. Unauthenticated authentication (for logging purposes and developer testing)

### LDAP Query

An LDAP query is the thing that asks the directory service for some information. This is how a standard LDAP query would look like:

```
(&(objectClass=user)(sAMAccountName=yourUserName)
(memberof=CN=YourGroup,OU=Users,DC=YourDomain,DC=com))
```

Few things to take note of here:

* objectClass refers to what type of object we are looking for, whether it's a user, or a file or something
* sAMAccountName is the logon name of the user for the Windows machine.
* Common Name (CN) refers to an attribute of several person-related classes.
* Organizational Unit (OU) tends to refer to the **group** **name** of objects to scope our search
* Domain Component (DC) refers to the domain name of the network we are querying. Generally, they are comprised of 2 components as shown above.

When we do LDAP queries, users use some software with a GUI or a Powershell script to run their queries. Most of the time, there isn't a need to write raw LDAP queries.&#x20;

## Enumeration

With LDAP, there can be vulnerabilities exploited that would allow for an attacker to basically query all about this domain and find out everything about it, such as names of users, groups, and other possible security misconfigurations. `bloodhound` makes use of LDAP to do its querying of the domain, which is represented in a graph format.

`ldapsearch` is the tool I use most when trying to enumerate an LDAP port we have access to. For example, all we need to do is specify using LDAP query terms what type of CN or OU we want to find out more about.

```
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "CN=Users,DC=domain,DC=com"
-x Simple Authentication
-H LDAP Server
-D My User
-w My password
```

Generally, we can scope our search accordingly to find out more. Sometimes, LDAP can reveal loads of interesting information, such as stuff that was left behind in a user's description during development or some file that was left unattended.&#x20;

### Anonymous Login

Similar to SMB, there can be guests allowed to access the domain without credentials (which is obviously bad). We can again use `ldapsearch` for this:

```
ldapsearch -x -H ldap://<IP> -D '' -w '' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
```

## Resources

Hacktricks basically has all the commands one needs to run LDAP enumeration. Just make sure to actually look through the output, which can be quite long at times.&#x20;

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap" %}
