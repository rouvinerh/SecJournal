# Packing Green

## Whatsapp Scams

Recently, I've been receiving messages like this:

<figure><img src="../../../.gitbook/assets/image (208).png" alt=""><figcaption></figcaption></figure>

## Invoice?

The link is not malicious and is a real service that brings me here:

<figure><img src="../../../.gitbook/assets/image (2558).png" alt=""><figcaption></figcaption></figure>

Firstly, I didn't order no flowers or orchids. There are a few things that we can extract from this 'Tax Invoice'. We can find this scammer's email here:

<figure><img src="../../../.gitbook/assets/image (1846).png" alt=""><figcaption></figcaption></figure>

This domain doesn't have a website of any sort. I used the Whois service to identify this domain:

{% embed url="https://www.whois.com/whois/kaisencapital.com" %}

Within the invoice, we can also find some other interesting information:

<figure><img src="../../../.gitbook/assets/image (214).png" alt=""><figcaption></figcaption></figure>

I ran a check on these UEN numbers, and they are legit and from the Fu Luxe company. I just found it odd that they would bill me through XERO instead of doing an email to the company's finance team, or calling me directly.&#x20;

`exiftool` doesn't reveal anything interesting about this PDF:

```
$ exiftool Invoice\ INV-9716.pdf 
ExifTool Version Number         : 12.57
File Name                       : Invoice INV-9716.pdf
Directory                       : .
File Size                       : 97 kB
File Modification Date/Time     : 2023:07:15 13:39:07+08:00
File Access Date/Time           : 2023:07:15 13:39:07+08:00
File Inode Change Date/Time     : 2023:07:15 13:39:07+08:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
Linearized                      : No
Warning                         : Objects in xref table (42) exceed trailer dictionary Size (41)
PDF Version                     : 1.7
Page Count                      : 4
Modify Date                     : 2023:07:15 05:39:02+00:00
Author                          : 
Create Date                     : 2023:07:15 05:39:02+00:00
Title                           : 
Creator                         : Aspose Ltd.
Subject                         : 
Producer                        : Aspose.Pdf for .NET 6.6
```

Take note of the date, because although the charges are '3 months overdue', this file was created on the same day that I receved the message.

We can also take a look at the 'items' that I 'ordered':

<figure><img src="../../../.gitbook/assets/image (1441).png" alt=""><figcaption></figcaption></figure>

I found it quite hilarious that their mathematics was correct.&#x20;

## Conclusion

I honestly cannot tell if this was an honest mistake, or if this was a scam. It's certainly shady, and being paranoid is a result of seeing all the scams around.&#x20;

## Update

Turns out this might've been a legit person. Asked me if I was working at \<LEGIT COMPANY NAME> and I said no, they said sorry.&#x20;

Whoops. May or may not have replied with funny things.&#x20;
