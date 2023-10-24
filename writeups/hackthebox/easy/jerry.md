# Jerry

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (3165).png" alt=""><figcaption></figcaption></figure>

There is a vulnerable version of Tomcat running on this machine

### Tomcat RCE

The Tomcat instance here is vulnerable to RCE. To exploit this, we would need access to the `/manager` endpoint to upload WAR reverse shells.

For this, we can attempt to access it to see the default credentials.

<figure><img src="../../../.gitbook/assets/image (464).png" alt=""><figcaption></figcaption></figure>

Was a bit lazy, hence used `msf` to solve this box and gain a root shell instantly.

<figure><img src="../../../.gitbook/assets/image (368).png" alt=""><figcaption></figcaption></figure>
