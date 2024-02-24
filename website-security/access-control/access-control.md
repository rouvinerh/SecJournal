# Access Control

## Explanation

This vulnerability is all about **privilege escalation** within a web application. Access control are the constraints on users who can perform authorized actions (like delete users).

This is dependent on authentication and session management. Broken access controls means that the application fails to verify whether a user is allowed to perform certain actions. 

There are 2 types of vertical access controls. 
* Vertical access controls prevent regular users from carrying out actions that an administrator (or user with higher privileges) can carry out.
* Horizontal access controls prevent users from accessing information or carrying out actions that users of the **same privilege level** can carry out (For example, changing the password of another regular user).

Broken access controls can be exploited in various ways. In some applications, the `/admin` directory is not protected and one can still send requests. In others, IDOR can be exploited.

In general, never rely on obfuscation alone for access control, follow the 'Least privilege' principle by denying access to resources by default. 