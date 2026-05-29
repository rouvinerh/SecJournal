# Bug Bounties

## My First Year!

As mentioned in May 2025, I spent a year doing bug bounties to learn about findings bugs in websites during my final year in university. I mainly focused on VDPs, occasionally earning some bounties here and there.

My first year can be summed up with one question: **_How do I stop gambling with targets and become efficient?_**

Overall, it was a good learning experience, but a frustrating one. Some days I could find 4 to 5 separate bugs, while other days (or even weeks) returned nothing. I relate this to training for a canoe sprint race, from my former athletic years. In that sport, time trials and competition results provide concrete metrics to track progress. However, I felt that when your results are driven more by luck and how you feel on the day, with huge variances in between, it is no different from gambling. I knew my approach had to change if I wanted consistency.

So I took a step back from hunting for a week and thought about my workflow, asking myself what can I do better. Going back and forth with Claude, along with reading a lot of Medium articles, helped answer these questions. I ended up spending a fair bit of time working to build a script that automated parts of my recon process, along with incorporating Google Dorks to do targeted recon on a subdomain. Before that, I used to click into each and every subdomain hoping to come across a bug. **This is gambling, not hunting!**

Next, I needed to change **what** I actually did once I landed on those subdomains. Minified JavaScript used to intimidate me as it looked like an unreadable wall of text, so I avoided it entirely. Forcing myself to work through it turned out to be one of the better decisions I made, uncovering hidden endpoints, resources, and other interesting things that led to real bugs. It is the same as sport. The perfect technique is comprised of specific, unintuitive and exhausting actions that are incredibly difficult to master. However, it will eventually become second nature with enough practice.

Having these mindset changes allowed me to perform better. For my first year, I found a total of **82** bugs that were triaged. Not bad, considering I spent about 4 months overseas with limited hunting. Some notable achievements:

- Ranked **#1** on Sony’s VDP program in 2026

- Ranked **#1** Treasury Board of Canada VDP program

- Ranked **#2** on Bose's VDP program (lots of reports in Pending Program Review for now)

- Ranked **#5** on U.S. DoD VDP in 2026

- Ranked **#22** for City of Vienna's Bug Bounty Program (a private turned public BB program that was around for a while)

Several of these programs launched in 2026, and being able to find bugs quickly ahead of the field is a good sign that my automation and methodology are working.

Moving forward, the goal shifts from fixing my own process to getting inside the minds of the companies I target. Having worked as a bug triager at PayPal, I know how these companies operate and what kind of issues are triaged. I roughly understand how enterprise software is put together, how engineering teams think, and most importantly where mistakes slip through. In racing, even with perfect technique, worrying too much about your opponents can cause you to lose focus your own race. The key is not to fear them, but to understand their weaknesses, where they fall short, and using that knowledge to your advantage.

Let's see what the second year brings

## Writeups

My impact assessment is based on my experience as a bug triager for PayPal. If I would have accepted / awarded it there, it might be posted here.

I mainly use HackerOne and BugCrowd. Sometimes I come across bugs outside of these platforms, through programs not publicly listed.

## Profiles

My profiles can be found below (and yes, I'm lucky to have my last name as my username):

{% embed url="http://hackerone.com/erh/" %}

{% embed url="https://bugcrowd.com/h/erh" %}
