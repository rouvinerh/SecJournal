---
description: ''' OR ''1= ''1'' -- -'
---

# SQL Injection

Structured Query Language (SQL) is a language used to communicate and interact with relational databases. SQL Databases, such as PostGreSQL, MySQL, MSSQL and Oracle.&#x20;

SQL Injection on the other hand, is the injection of SQL queries to manipulate the database into executing queries to extract data or even achieve command execution.

<figure><img src="../.gitbook/assets/image (2254).png" alt=""><figcaption><p><em>Taken from PortSwigger Web Security Academy</em></p></figcaption></figure>

## Basic Injection

It occurs when user input is not sanitised, queries don't use parameterised variables and input is passed into queries. SQL syntax is kind of like English, so suppose have a query like this:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
# * means wildcard
```

It uses the `SELECT` verb to retrieve data, and the other variables are as follows:

1. `products` is the table name.
2. `category` and `released` are the column names within `products`
3. `WHERE` and `AND` used to specify extra conditions to filter data.

Easy right? Now, suppose that a website has a login page that takes in a username and password from the user. It then authenticates users based on this query:

```sql
SELECT 'password@12345' FROM password WHERE username = 'tim'
# on true, it grants access
# if false, deny access
```

Now, what were to happen if a user keys in `' OR 1=1 -- -`? The resultant query (in a poorly designed application) would look like:

```sql
SELECT '' OR 1=1-- - FROM password WHERE username = 'tim'
# SELECT '' OR 1=1 is a true statement!
# this would grant us access!
```

The first quote 'escapes' the string, and the `-- -` comments the rest of the query. OR is used to create a fake logical expression, followed by `1=1` which is a true statement.

> For logical OR, `statement1 OR statement2` returns true if **either statement 1 or 2 is true**. For logical AND, it requires **both statements to be true** to return true.

This is a basic SQL Injection technique, using `' OR 1=1--` to bypass a simple login that does not validate user input.

## UNION Injection

UNION is a command in SQL that allows for an additional SELECT query to be processed, and appends the results to the original query.

```sql
UNION SELECT username, password FROM users
# select two fields from users and append together in one command
```

There are a few requirements for this to work:

* Individual queries (on the LEFT and RIGHT of UNION) must return the **same number of columns.**
* Data types in each column **must be compatible between individual queries.**
  * In other words, make sure that username and password are both strings, not integers.

To use UNION injection, one has to determine:

* How many columns are present within that table?
* Which columns returned from the original query are of suitable data types?

One method for determining how many columns there are is brute forcing the possible number of columns:

```sql
' UNION SELECT NULL --
' UNION SELECT NULL,NULL -- 
' UNION SELECT NULL,NULL,NULL -- 
# etc...
```

A query with the correct number of columns would be processed without errors. This can be indicated by the response HTTP code. For example, if a 404 is returned, then the wrong number of columns has been entered.

The reason for using `NULL` is because it is **convertible to every commonly used data type**. This means it's kind of compatible with all of them.

<figure><img src="../.gitbook/assets/image (2955).png" alt=""><figcaption><p><em>Usage of SQL Injection in URL to retrieve all user information</em></p></figcaption></figure>

## Blind Injection

All the earlier vulnerabilities return the query's result. But what if it doesn't? The backend database could simply process the request without printing it out on the screen via exception handling. This is where Blind SQLI is used to play 'hangman' with the database.

There are 2 types of Blind SQL Injection, **time-based and boolean-based.**

### Boolean-Based&#x20;

Boolean-based SQL Injection relies on the website returning different results when a `true` and `false` query is processed. For example, a `false` condition can return a different error message or a 404.

I normally test this using one guaranteed false and true query, and then checking if the response is different:

```sql
' OR 1=2 -- -
' OR 1=1 -- -
```

From here, one can retrieve data character by character:

{% code overflow="wrap" %}
```sql
# start to guess possible usernames from a table
AND SUBSTRING((SELECT password from users where username = 'Administrator'), 1, <num>) =/>a/<' s
```
{% endcode %}

The SUBSTRING command, which would each character position indicated by `<num>` until a 'true' condition is returned.

### Time-Based

Now, suppose that the website does not have a visual difference on true or false queries, thus preventing us from guessing characters.

The `sleep` function within SQL Databases can be used. A `true` condition would call `sleep()`, and one can measure the amount of time taken for the response to be returned:

{% code overflow="wrap" %}
```sql
SELECT CASE WHEN (SUBSTRING(password,1,1)='1') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE (username='administrator')--
# if true, sleep 10 seconds, otherwise none.
```
{% endcode %}