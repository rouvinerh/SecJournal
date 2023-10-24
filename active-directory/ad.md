# Active Directory

Active Directory is a system that allows administrators to create and manage domains, users and objects within a network. For example, an admin can create a group of users, such as local administrators, and give them control over specific directories and areas on the server. AD is used for organizing large groups of users into logical groups and smaller groups, providing different levels of access control at each level.

Active Directory is becoming more common in engagements nowadays and the focus has shifted. Microsoft's domain services are extremely convenient for managing an entire domain, whether it be for school or work. However, with convenience, comes great security risks.

## AD Simplified

To think about AD, I tend to think about it like a tree, with leaves and branches representing every single 'thing' in the domain.

Let's suppose this:

* One leaf represents one user
* One small branch represents a group of leaves
* One big branch represents a group of small branches
* One trunk represents a group of big branches.

One user can access every single part of the leaf, because it's his and he has permissions. A user is part of a local group of other leaves, connected together by one small branch. So, a user can traverse within the small branch he is in. **The user cannot go and see other small branches, or go anywhere apart from his small branch.**

Each small branch can represent groups of users in a company, like the Sales, IT, or HR Department. Obviously, you cannot have a Sales employee go and view HR documents because it's in a separate branch.

Now, groups of small branches are part of one big branch. The rules are similar, and one big branch cannot go and see other big branches. Big branches could represent different parts of an international company, with the Asia HQ not being able to view the European HQ data.

The trunk of the tree can see everything, and basically controls everything within all big branches. Permissions are **transitive** here, meaning a trunk user can control the leaves and view what they are doing. The users that live here and have these permissions are the administrators of everything, and they can be called **domain admins.**

Within each branch, small and big, there would be administrators there to make sure everything is running smoothly. This could be your boss, or the IT guy who administers the entire section of the company.

<figure><img src="../.gitbook/assets/image (2720).png" alt=""><figcaption></figcaption></figure>

I like to think of AD as a company having multiple computers and users all under a domain like `company.com`.&#x20;

## AD Terms

The AD structure includes 5 main things:

1. Directories
   * Contains all the information about the objects of the Active Directory
2. Objects
   * Every single 'thing' inside the network, whether it be a database, user, computer, shared folder etc.
   * Think of these like nodes that are interconnected with each other.
3. Domains
   * Objects are contained here. Inside a forest of devices, there can be more than one domain, and each domain has their own set of objects and privileges.
4. Trees
   * Collections of domains with the same ending.
   * For instance, _dev.domain.com, domain.com, mail.domain.com etc._
5. Forests
   * Generally the highest level of the organization hierarchy, and a group of trees make this up.

Active Directory relies on a number of protocols for nodes within the forest to "talk to each other" or share files. There are a couple of different protocols that run on Active Directory, in order to make it function normally. These can also be called AD Domain Services, or AD DS.

1. Domain Services
   * Centralized data and manages communication between users and domains.
   * This includes all forms of login authentication and search functionality
2. Certificate Services
   * Certificates are used for verifying that the user is legit (kind of)
   * AD DS would create, distribute and manage all of these secure certificates
3. Lightweight Directory Services (LDAP)
   * Directory-enabled applications using the LDAP protocol
4. Single Sign-on (SSO)
   * Used to authenticate a user in multiple applications or services just by logging into one session once.
5. Access Control controls
   * Protects information in the domain by preventing users from taking content out of the system and unauthorized access to content through the use of Access Control Lists (ACL).
6. DNS Service
   * Resolving of domain name to the correct IP address within the domain.

Windows machines have the Administrator user as the superuser, while in Active Directory environments these are called **domain admins**. Generally, being a domain admin means you have access to every part of the network and can make whatever changes you want.

Additionally, AD networks also have something called a **Domain Controller** which as the name implies, is basically a server that centrally manages users, enables for resource sharing. This one thing basically controls the entire domain. DCs are typically the target of cyber attacks, as controlling the DC would mean we have control over the entire network.

## Authentication <a href="#authentication" id="authentication"></a>

Windows in general makes use of something called NTLM hashes. What NTLM hashes are is basically a hash format, of which the password is taken through a **one-way function that produces a string of text** where there is no way to reverse the function**.**

The traditional method of authentication on Windows is using NTLM hashes, which are considered more insecure due to their own set of vulnerabilities. Since the hash cannot be reversed, what an attacker can do is instead make use of dictionary attacks, which would basically use common passwords in a wordlist (typically from data leaks of any kind and found online), hash them and compare it one by one. Many tools, websites and even services provide allow for dictionary attacks, and **hashes of common passwords are cracked almost instantly.**&#x20;

So to cirumvent this, AD uses something called Kerberos, which is more 'secure' than NTLM due to using a two-way function, including a third party authorisation, as well as stronger encryption.
