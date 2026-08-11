# May Chong

## Scam or not?

Recently, I received this email.

![](../../../.gitbook/assets/may-chong-3.png)

This looks like a poorly constructed email, one because I don't use OneDrive, and second, who is May Chong? Take note that I configured Microsoft Outlook to **never download images no matter what by default**. This would potentially block any form of scripting that may download viruses just from opening the mail.

Let's take a look at the website using Curl.

![](../../../.gitbook/assets/may-chong-6.png)

So the link uses an index.php and takes some ?id= as the parameter. Interesting because I don't think I've ever seen such a link from NUS. Normally, NUS links come with a .nus.edu.sg domain or something to verfify it.

When checking the rest of the HTML returned, we can see loads of JS.

![](../../../.gitbook/assets/may-chong-5.png)

Quite shabby for an 'NUS' website.

## The Website

This is what the website looks like:

![May Chong's](../../../.gitbook/assets/may-chong-1.png)

Interesting. We can play spot the difference between the image above, and the login from edurec!

![Edurec](../../../.gitbook/assets/may-chong-8.png)

Notice a key few differences. There is a property part missing. Also, on Edurec, it says **Register 2FA** and on the other website, it says **Help On 2FA.** Also, earlier I used curl to analyse the website to see loads of hidden JS being executed. However, the main page only reveals this in their page source.

![](../../../.gitbook/assets/may-chong-2.png)

We can test the login as follows:

![](../../../.gitbook/assets/may-chong-7.png)

After logging in, it looks like this was just a phishing campaign from NUS.

![](../../../.gitbook/assets/may-chong-4.png)

Quite cool that NUS would do a campaign for this.
