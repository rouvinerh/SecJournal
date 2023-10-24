# May Chong

## Scam or not?

Recently, I received this email.

<figure><img src="../../../.gitbook/assets/image (2338).png" alt=""><figcaption></figcaption></figure>

This looks like a poorly constructed email, one because I don't use OneDrive, and second, who is May Chong? Take note that I configured Microsoft Outlook to **never download images no matter what by default**. This would potentially block any form of scripting that may download viruses just from opening the mail.&#x20;

Let's take a look at the website using Curl.

<figure><img src="../../../.gitbook/assets/image (3781).png" alt=""><figcaption></figcaption></figure>

So the link uses an index.php and takes some ?id= as the parameter. Interesting because I don't think I've ever seen such a link from NUS. Normally, NUS links come with a .nus.edu.sg domain or something to verfify it.&#x20;

When checking the rest of the HTML returned, we can see loads of JS.

<figure><img src="../../../.gitbook/assets/image (3439).png" alt=""><figcaption></figcaption></figure>

Quite shabby for an 'NUS' website.&#x20;

## The Website

This is what the website looks like:

<figure><img src="../../../.gitbook/assets/image (1785).png" alt=""><figcaption><p><em>May Chong's</em></p></figcaption></figure>

Interesting. We can play spot the difference between the image above, and the login from edurec!

<figure><img src="../../../.gitbook/assets/image (974).png" alt=""><figcaption><p><em>Edurec</em></p></figcaption></figure>

Notice a key few differences. There is a property part missing. Also, on Edurec, it says **Register 2FA** and on the other website, it says **Help On 2FA.** Also, earlier I used curl to analyse the website to see loads of hidden JS being executed. However, the main page only reveals this in their page source.

<figure><img src="../../../.gitbook/assets/image (1850).png" alt=""><figcaption></figcaption></figure>

We can test the login as follows:

<figure><img src="../../../.gitbook/assets/image (4087).png" alt=""><figcaption></figcaption></figure>

After logging in, it looks like this was just a phishing campaign from NUS.&#x20;

<figure><img src="../../../.gitbook/assets/image (2717).png" alt=""><figcaption></figcaption></figure>

Quite cool that NUS would do a campaign for this.&#x20;
