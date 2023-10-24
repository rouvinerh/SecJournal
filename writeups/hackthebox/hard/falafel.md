# Falafel

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (3828).png" alt=""><figcaption></figcaption></figure>

### FalafeLovers

Port 80 reveals a kind of social network website.

<figure><img src="../../../.gitbook/assets/image (1310).png" alt=""><figcaption></figcaption></figure>

I ran a `gobuster` scan on the website, and it revealed tons of interesting directories.

<figure><img src="../../../.gitbook/assets/image (3523).png" alt=""><figcaption></figcaption></figure>

On the `cyberlaw.txt` file, we can find some hints on what to do next.

<figure><img src="../../../.gitbook/assets/image (2062).png" alt=""><figcaption></figcaption></figure>

Interesting. So there's a `chris` user and he hacked the website first.&#x20;

### SQL Injection

There was a login page on the website we could access.

<figure><img src="../../../.gitbook/assets/image (2166).png" alt=""><figcaption></figcaption></figure>

When trying to enter credentials for the `admin` user, this was the error received.

<figure><img src="../../../.gitbook/assets/image (1275).png" alt=""><figcaption></figcaption></figure>

When a random input as the user, we get a different error.

<figure><img src="../../../.gitbook/assets/image (3042).png" alt=""><figcaption></figcaption></figure>

It seems that there's a boolean condition present on the website. I proceeded to test this with `sqlmap` using `--level=5 --risk=3` flags. I also included the `--string` flag to signify which was the boolean condition to use.

<figure><img src="../../../.gitbook/assets/image (4026).png" alt=""><figcaption></figcaption></figure>

We can then dump out the database.

<figure><img src="../../../.gitbook/assets/image (2567).png" alt=""><figcaption></figcaption></figure>

Now we can login as `chris`.

### Type Juggling

Viewing the profile of chris reveals a hint to use PHP Type Juggling.

<figure><img src="../../../.gitbook/assets/image (323).png" alt=""><figcaption></figcaption></figure>

PHP Type juggling was a type of vulnerability that can be used to **force the returning of true** through using specific hashes.

{% embed url="https://medium.com/swlh/php-type-juggling-vulnerabilities-3e28c4ed5c09" %}

There are repositories of hashes that we can use easily.

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/README.md" %}

When using these hashes as the password in the login page, we can login as the `admin` user.

### Word Limits

Viewing the profile of the `admin` user shows a hint to bypass some kind of limit.

<figure><img src="../../../.gitbook/assets/image (3092).png" alt=""><figcaption></figcaption></figure>

Didn't know how to abuse this yet, so I tried to exploit the image upload function that we now had access to.

<figure><img src="../../../.gitbook/assets/image (592).png" alt=""><figcaption></figcaption></figure>

I attempted to upload some PHP webshells, but it did not work.

<figure><img src="../../../.gitbook/assets/image (3596).png" alt=""><figcaption></figcaption></figure>

When uploading a jpg file, this is the output we get.

<figure><img src="../../../.gitbook/assets/image (272).png" alt=""><figcaption></figcaption></figure>

Attempting to access our webshell does not work. However, we can see how the name of our file can be manipulated to fit the CMD being executed. Seeing the hint earlier on the `admin` profile about the limits of the file name.

So, I tested this via changing the file name to something absurdly long.

<figure><img src="../../../.gitbook/assets/image (1748).png" alt=""><figcaption></figcaption></figure>

There was this `Trying to shorten...` bit that was rather suspicious. Perhaps we could use this to **remove the .jpg extension and leave a .php extension**. So what I did was attempt to upload a `cmd.php.jpg` file, and have the name of the file be such that it would shorten to `cmd.php`. This truncation of the name would allow me to upload my webshell.

This would mean having a file name of 236 characters (which was the max when counted), and this works in uploading the file.

<figure><img src="../../../.gitbook/assets/image (1355).png" alt=""><figcaption></figcaption></figure>

We can then test our RCE.

<figure><img src="../../../.gitbook/assets/image (1945).png" alt=""><figcaption></figcaption></figure>

Then we can get a reverse shell easily.

<figure><img src="../../../.gitbook/assets/image (844).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Moshe Credentials

First, we can view the users present on this machine by reading the `/etc/passwd` file, and see that `moshe` and `yossi` are present.

<figure><img src="../../../.gitbook/assets/image (2985).png" alt=""><figcaption></figcaption></figure>

Then, we can view the files for the webroot. In there, we can find some SQL credentials.

<figure><img src="../../../.gitbook/assets/image (2538).png" alt=""><figcaption></figcaption></figure>

We can then `su` to moshe.

<figure><img src="../../../.gitbook/assets/image (1635).png" alt=""><figcaption></figcaption></figure>

### Video Group

When running LinPEAS, we see that `moshe` is part of the `video` group.

<figure><img src="../../../.gitbook/assets/image (2964).png" alt=""><figcaption></figcaption></figure>

Users part of the `video` group have access to a video device or the screen output. I first checked if there were other users logged in via `w`, and `yossi` is logged in.

<figure><img src="../../../.gitbook/assets/image (3837).png" alt=""><figcaption></figcaption></figure>

This means we can take a screenshot of his session and see if we can find any credentials. This blog was useful in exploiting it.

{% embed url="https://steflan-security.com/linux-privilege-escalation-exploiting-user-groups/" %}

```bash
cp /dev/fb0 /tmp/fb0.raw
width=$(cat /sys/class/graphics/fb0/virtual_size | cut -d, -f1)
height=$(cat /sys/class/graphics/fb0/virtual_size | cut -d, -f2)
```

Then, we can run this perl script to convert the raw data into a screenshot.

```perl
#!/usr/bin/perl -w

$w = shift || 240;
$h = shift || 320;
$pixels = $w * $h;

open OUT, "|pnmtopng" or die "Can't pipe pnmtopng: $!\n";

printf OUT "P6%d %d\n255\n", $w, $h;

while ((read STDIN, $raw, 2) and $pixels--) {
   $short = unpack('S', $raw);
   print OUT pack("C3",
      ($short & 0xf800) >> 8,
      ($short & 0x7e0) >> 3,
      ($short & 0x1f) << 3);
}

close OUT;
```

Afterwards, we can transfer this back to our machine and find that it is an image file.

<figure><img src="../../../.gitbook/assets/image (1321).png" alt=""><figcaption></figcaption></figure>

Initially, the picture looked like some kind of rubbish.

<figure><img src="../../../.gitbook/assets/image (2044).png" alt=""><figcaption></figcaption></figure>

Then I realised it was probably because I messed up the dimensions of the image, so I changed to to these values using `gimp` as per the script to reveal some credentials:

<figure><img src="../../../.gitbook/assets/image (99).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1492).png" alt=""><figcaption></figcaption></figure>

Then, we can `su` as `yossi`.

### Disk Group

Earlier, we found that `yossi` was part of the `disk` and `cdrom` group. Perhaps there was something mounted on the machine that we can access.

<figure><img src="../../../.gitbook/assets/image (3453).png" alt=""><figcaption></figcaption></figure>

Using `debugfs` on the `/dev/sda1` filesystem (which just looked off), we find out that we can access the `/root` directory.

<figure><img src="../../../.gitbook/assets/image (1300).png" alt=""><figcaption></figcaption></figure>

&#x20;We can also find the private SSH key for `root`.

<figure><img src="../../../.gitbook/assets/image (3093).png" alt=""><figcaption></figcaption></figure>

Then, we can SSH in as `root`.

<figure><img src="../../../.gitbook/assets/image (372).png" alt=""><figcaption></figcaption></figure>
