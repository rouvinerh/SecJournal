# OSCP Review

## TL;DR

I chose not to focus much on the course material and went straight into the labs. This was due to the way I prepared for my OSCP, where I went from having no knowledge of coding to eventually earning the certification. I wrote about that journey, including my failures and exam attempts, in detail here:

{% embed url="https://medium.com/@rouvin/how-i-tried-harder-6eb22fb6cf48" %}

It took me two attempts to pass — I finally cleared it on my second try with 80 points. The exam has changed since then, and a new "OSCP+" is available. If I take that in the future, I’ll update this review.

## Introduction

The Offensive Security Certified Professional (OSCP) is one of the most recognized and respected certifications for penetration testers. Unlike most certifications that rely on multiple-choice questions or heavy theoretical content, OSCP is completely hands-on. It requires candidates to apply practical skills in a controlled hacking environment. I took the course in 2022, during the period when OffSec was starting to introduce Active Directory (AD) labs and slowly phasing out Buffer Overflow content.

The syllabus is as follows:

![Taken from OffSec's Website](../../../../.gitbook/assets/oscp-review-image-1.png)

## Pre-Requisites

There are no pre-requisites per se, as anyone can technically buy the course and take the exam. However, I strongly recommend having the following knowledge before starting:

- A basic understanding of C and Python to modify exploits as needed.

- A solid grasp of fundamental networking concepts.

- Confidence using the command line interface on both Linux and Windows systems.

- Basic Bash scripting knowledge.

- Some familiarity with Windows Active Directory environments.

I would also recommend practicing on platforms such as HackTheBox (HTB) and OffSec's Proving Grounds Practice. I think if you can understand the methodologies and tools used in writeups from `0xdf` or `ippsec`, it is good enough.

HackTheBox machines tend to focus more on exploitation and are often more challenging in that aspect, whereas Proving Grounds machines are usually more focused on enumeration and tend to follow the 'OSCP style' closely. Both platforms are valuable in different ways.

## The Course

I enjoyed working through the lab environment and completed a full report for all the machines I solved. In my view, the real strength of the OSCP course lies not in the technical content, but in the emphasis on developing a sound methodology. Over time, every tester will develop their own style, but proper enumeration will always remain the foundation of a successful penetration test.

Prior to starting the OSCP, I spent most of my time on HTB and Proving Grounds Practice, which helped me develop a structured approach. Because of this, the OSCP course did not introduce any new concepts for me apart from Buffer Overflows. That being said, I did refer heavily to external resources like HackTricks, `exploitdb` and various OSCP cheatsheets for payloads and commands.

What really stuck with me was the 'Try Harder' mindset. I appreciated being thrown into the deep end, as it taught me how to push forward even when it felt impossible. The persistence and resilience gained have benefitted me greatly in my cyber pursuits.

## Pricing

At a price of US$1,749, the OSCP is quite expensive. Whether or not it is worth the cost depends on your goals.

Is OSCP worth it purely based on the knowledge one gains from it? **No.** 

The skills covered in the OSCP can be learned through other platforms at lower costs. Personally, I learned much more from practicing on HTB. Since I completed the OSCP, new alternatives like the Certified Penetration Testing Specialist (CPTS) certification have come about. These newer certifications often provide more advanced material at a lower price. Some online reviews I have read mention that the CPTS is 'better in OSCP in every way', with a 'more difficult exam environment'. I cannot comment on such statements as I have never taken the CPTS, but naturally I trust the words of authors who are both OSCP and CPTS certified more.

Is it worth it if you want to get past resume screening? **Yes.** 

The OSCP helped me secure roles and opportunities that might have been out of reach otherwise. Despite being around for many years, the OSCP still carries weight in the industry and is often treated as a baseline requirement for offensive security roles. 

## Exam

The exam gives you **24 hours to score at least 70 out of 100 points**, which you can earn by exploiting standalone machines and Active Directory sets. After the exam session, you have another 24 hours to submit a professional report documenting your work. Automated tools like sqlmap and AI-based tools such as ChatGPT are not allowed. The various ways to achieve these points are outlined here:

![Taken from OffSec's Website](../../../../.gitbook/assets/oscp-review-image-2.png)

I took the exam twice in 2022. I failed on my first attempt because I lacked a clear methodology, panicked when things went wrong, and felt uncomfortable being watched by the proctor. I also struggled with nerves and could not sleep the night before.

For my second attempt, I was much more prepared. I spent time practicing mock exams, learning to write reports as I worked, and improving my ability to stay calm under pressure. This preparation paid off, and I managed to pass within the first eight hours.

Writing the report was straightforward for me, as I had plenty of experience writing machine writeups for my GitBook. 2 days after submitting the report, I received the results:

![Passed!](../../../../.gitbook/assets/oscp-review-image.png)

## Conclusion

There has been a lot of debate about whether the OSCP is outdated or overpriced, especially with the rise of alternatives like CPTS. I have not taken the CPTS, so I cannot make a fair comparison.

What I can say is that the OSCP was never the real source of growth for me. The actual value was in the journey leading up to the exam. The hours spent solving machines, the countless writeups, and the self-study. The certification itself was simply the milestone that marked my progress. 

The OSCP did help me open doors in the industry, and it led to internship opportunities where I continued learning far beyond what the course could offer. It even sparked interest in certain areas of information security and future projects. In fact, the GitBook you are reading was created as a direct result of the countless writeups I wrote while practicing OSCP report writing. Eventually, I decided to make it public and use it as an online portfolio to document my progress and growth.

In the end, the OSCP is still useful if you are looking for **recognition and career opportunities**, just do not expect it to teach the latest exploits or advanced techniques.