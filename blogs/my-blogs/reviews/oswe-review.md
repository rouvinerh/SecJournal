# OSWE Review

## TL;DR

I enjoyed the course and found that learning source code review was genuinely useful — it made me more confident when conducting internal web application testing. The exam itself was straightforward and fair, based on the material covered. PortSwigger's Web Security Academy complemented the course extremely well, allowing me to practice exploiting specific vulnerabilities. I personally feel the course is both useful and worth the price for anyone interested in application security. I took it to clear the OSCE3 certification before I graduate from university.

## Introduction

The OffSec Web Expert (OSWE) course is a white-box penetration testing certification. The Advanced Web Attacks and Exploitation (AWAE) course focuses on manual source code analysis, understanding logic flaws, and crafting custom exploits rather than relying on automated tools. Instead of black-box guessing at vulnerabilities, you're expected to audit real source code to identify flaws.

You can expect to read a lot of code, and the course dives into how vulnerabilities are discovered and exploited at a fundamental level.

The course syllabus is as follows:

![Taken from OffSec's Website](../../../../.gitbook/assets/oswe-review-image.png)

## Pre-Requisites

Technically, you could take the course without preparation — but I prepared ahead of time to ensure I could clear it quickly. Below are the resources I used and recommend.

I also suggest being comfortable with penetration testing concepts before starting, meaning one should ideally complete courses like OSCP or CPTS (whichever suits your preference).

### Scripting

For scripting, being familiar with Python’s `requests` module and basic HTML parsing using `BeautifulSoup` or regex is enough. I prepared by scripting a large portion of the labs from PortSwigger's Web Academy. This included automated CSRF token extraction, file uploads, sending different request types, and using BurpSuite as a proxy to debug scripts.

Some of the scripting I have done can be found here:

{% embed url="https://rouvin.gitbook.io/ibreakstuff/website-security/sql-injection/sql-injection-portswigger-writeup" %}

I also solved some Insane machines on HTB, such as CrossFit and Fulcrum. The exam required no-click exploits to be created, so learning to write JavaScript for XSS, and even setting up Python HTTP Servers to handle callbacks. I also got familiar with using the `socket` module in case the course required it. The writeups and scripts for these machines can be found here:

{% embed url="https://rouvin.gitbook.io/ibreakstuff/writeups/hackthebox/insane/htb-fulcrum"}

{% embed url="https://rouvin.gitbook.io/ibreakstuff/writeups/hackthebox/insane/htb-crossfit" %}

By the end of the practicing, I had script templates almost every scenario ready to go, making the actual scripting for the exam easy.

### Source Code Review + MVC

Learning to read code comfortably is a must, as the course assumes familiarity with Java, C#, PHP and JavaScript audits. To prepare for this course, I did create a basic MVC Pet Shop, which can be found here:

{% embed url="https://github.com/rouvinerh/Simple-MVC-PetShop" %}

The purpose was to get familiar with the MVC framework and practice writing C#. I followed Microsoft’s documentation while building and customising the site:

{% embed url="https://learn.microsoft.com/en-us/aspnet/mvc/overview/older-versions-1/getting-started-with-mvc/getting-started-with-mvc-part1" %}

Additionally, I interned in a web application security role prior to taking the OSWE, where I audited Ruby and Typescript codebases. While I found most of my bugs through black-box testing (mainly due to my inexperience at the time), the exposure helped me get used to scanning large codebases quickly for potential issues.

### Web Vulnerabilities

There were 2 resources I used to get familiar with all the web application vulnerabilities required. The first was PortSwigger Web Academy, which I used for scripting as well. This is hands down the **best possible web application exploitation training**. The labs cover just about every common vulnerability and it is **free**. As mentioned above, I also used the labs for practicing Python scripting.

{% embed url="https://portswigger.net/web-security" %}

`websec.fr` was another website I practiced on. This resource contains a collection of vulnerable PHP applications, and provides the source code for each application for the user. I mainly used this to learn to **identify vulnerabilities from source code** instead of just attacking blindly.

{% embed url="https://websec.fr/" %}

I find these two resources complement each other perfectly. PortSwigger teaches exploitation through black-box labs, while `websec.fr` helps you practice basic source code analysis to find vulnerabilities.

## The Course

The course itself was a pleasure to go through, and the most fun and useful OffSec course I have done so far.

The course itself goes through various 'case studies', where vulnerabilities for various softwares written in different languages were analysed. More importantly, it showcased **how** the vulnerabilities were caused by reviewing source code, and how different vulnerabilities can be changed together to achieve RCE.

For example, in one module focusing on ManageEngine, the course walks you through how an SQL Injection was discovered, and then explores different exploitation methods to turn the vulnerability into Remote Code Execution. It even dives into filter bypass techniques, which I found especially interesting.

One key takeaway was learning **why certain inputs cause vulnerabilities**. I found myself learning more about how Deserialization, Server-Side Template Injection (SSTI) and Prototype Pollution came about. It covered the underlying application logic and explained how and where the vulnerable sink was, and the impacts it caused.

Since I had prior internship experience with code review, the course felt relatively straightforward to me. That said, developing an effective methodology for code review is something that only comes with experience, and the course does not enforce a specific approach.

I believe that going through the course material is sufficient to develop some form of methodology.

## Pricing

OffSec courses are currently priced at US$1749, and I believe OSWE was worth the price. The course saves you a lot of setup time by providing pre-built vulnerable software environments, which allows you to focus on learning rather than wasting time on deployment and debugging unrelated issues.

Again, having done an application security role prior to the course, I can definitely see why the skills learned in this course are useful.

## Exam

For the exam you are given **48 hours to get at least 85 out of 100 points** by compromising the target applications. Another **24 hours is given to write the report**.

The exam also requires users to create scripts that automate the exploit chain in any language. As with all OffSec exams, no automated exploit tools like `sqlmap` or generative AI tools can be used. For this exam I used a Chrome extension that blocked the Google AI overview that is automatically included during searches.

{% embed url="https://chromewebstore.google.com/detail/bye-bye-google-ai-turn-of/imllolhfajlbkpheaapjocclpppchggc?pli=1" %}

I found that the time limit given was rather generous, and there was more than enough time to clear the objectives. My only advice is to allocate sufficient time to write and test the exploit scripts used, and to always test the scripts created. **Ensure to include the scripts within the exam report!**

I had quite a lot of fun during the exam, and got the passing score on the first day. The rest of the time was for scripting and writing my report. Everything you need is in the course, and I did not need to do extensive external research. Perhaps it was my preparation and experience before taking the course.

I submitted the report and got my result back in 2 days:

![Passed!](../../../../.gitbook/assets/oswe-review-image-1.png)

## Conclusion

Overall, I found the course great training and I highly recommend it to anyone looking to get into application security. It provides great hands-on practice and builds the foundation for source code review methodologies, which has made me more confident when it comes to auditing large codebases.

Also, it helped me in getting my next internship focusing on AppSec. c: