# Jerry

## Gaining Access

Nmap scan:

![](<../../../.gitbook/assets/image%20(3165).png>)

There is a vulnerable version of Tomcat running on this machine

### Tomcat RCE

The Tomcat instance here is vulnerable to RCE. To exploit this, we would need access to the `/manager` endpoint to upload WAR reverse shells.

For this, we can attempt to access it to see the default credentials.

![](<../../../.gitbook/assets/image%20(464).png>)

Was a bit lazy, hence used `msf` to solve this box and gain a root shell instantly.

![](<../../../.gitbook/assets/image%20(368).png>)
