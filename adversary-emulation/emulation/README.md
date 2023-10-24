---
description: >-
  Just my notes, all of these are public information / Googable / ChatGPT-able
  anyway.
---

# Red Teaming

## Threat-Informed Defence

This is a strategy used to advance global understanding of adversary tradecraft, measure evolving adversary behaviour via playbooks or software, enable continuous assessment of defence and to continuously idenfiy and catalyse development and/or research new ways to thwart ATT\&CK techniques.

> Threat-Informed Defence applies a deep understanding of adversary tradecraft and technology to protect against, detect and mitigate cyber-attacks. It's a community-based approach to a worldwide challenge.
>
> _MITRE_

In layman terms, we are using existing adversary tactics, techniques and procedures (TTPs) from the MITRE ATT\&CK Framework to **emulate** attacks on corporate (or simulated) infrastructure. The definition of **emulation** in this case is to replicate the effects or behaviour of a given technique by executing the actual process which produces them.&#x20;

### APTs

Advanced Persistent Threats (APTs) is a term used to describe a stealthy threat actor, which is typically a nation state or state-sponsored groups, which gains unauthorised access to a computer network and remains undetected for an extended period.&#x20;

Their goals can include:

* Stealing secrets or other sensitive information (Politically motivated)
* Financial Gain (Ransomware, FIN groups)
* Hacktivisim (Anonymous)
* Destruction of Stuff

Essentially, they are elite hackers (which may or may not be state-sponsored) that are always present as a threat to organisations (hence the persistent threat part). There are many groups with differing motivations, and they can be found on the MITRE database.

{% embed url="https://attack.mitre.org/groups/" %}

One rather infamous example is the Carbanak group, which is a group that targets financial institutions with the goal being to steal money from banks. At the time of writing, they have stolen about $900m from banks worldwide.

It has been reported that their mastermind was caught, but their campaigns still continue:

{% embed url="https://www.europol.europa.eu/media-press/newsroom/news/mastermind-behind-eur-1-billion-cyber-bank-robbery-arrested-in-spain" %}

This is but one example of a FIN APT group. There are other groups, like Oilrig, which mainly use supply chain attacks on infrastructure like OT or ICS systems.&#x20;

### TTPs

Adversary Tactics, Techniques and Procedures (TTPs) are the techniques and stuff used by threat actors to carry out their operations. These are documented in the MITRE ATT\&CK Framework, which is a knowledge base describing these techniques.

They record all the techniques used by the different APTs worldwide, so that cybersecurity experts can better test their systems to prepare for any attacks. This is where the **emulation** part comes in.

For example, if I was part of the red team in a bank and tasked to prepare an adversary emulation plan for a certain FIN group, the MITRE ATT\&CK Framework has the TTPs and techniques that this particular group uses. I can then craft my adversary emulation plan in accordance to the TTPs that they use and test my systems.

This would allow me to get a better understanding of the current flaws in my defence systems, better preparing our organisation against real attacks.&#x20;

DFIR Report is a website that provides really comprehensive reports of how APTs infiltrate systems and what they do there. Their illustrations of the timeline is top-notch and really helpful in learning what an APT does after getting in.

{% embed url="https://thedfirreport.com/" %}

## Red Team vs Pentesting

The red team is meant to **emulate adversary attacks.** They provide an adversarial perspective by challenging the assumptions made by an organisation and defenders. By challenging these assumptions, a red team can identify vulnerabilities in an organisation's OPSEC.&#x20;

There is some degree of overlap with penetration testing, but they have fundamentally different objectives. A typical pentest would focus on one technology stack within a company's entire infrastructure, such as their website or backend database. The goal is to **identify as many vulnerabilities as possible, demonstrate how those may be exploited, and provide some risk ratings**.&#x20;

The output is a report detailing each vulnerability and needed remediation actions, such as installing a patch or configuring software. In a pentest, **there is no focus on detection or response**, and the only goal is to hack the system to find vulnerabilities.&#x20;

On the other hand, the red team has a clear objective laid out, which is to gain access to a particular system (such as a particular server) instead of finding all the bugs within the infrastructure. They also have to emulate a **real-life threat** to the organistaion (For example, banks may be attacked by FIN APT groups). So for this case, we need to use specific TTPs based on the adversary we are trying to emulate.&#x20;

A penetration test is not focused on stealth, evasion or the ability for the blue team to detect and respond. Rather, the blue team might be aware that the penetration test is even happening, and let it happen because they are here to find out all the vulnerabilities and weak endpoints, so very noisy scans such as `autorecon` and `nmap` can be used for this depending on the client.&#x20;

On the other hand, a red team operation is **very focused on stealth and evasion**. As the goal is to emulate a real-life threat, OPSEC and not getting caught are the most important aspects of a red team operation. The blue team is actively trying to detect the red team operations and block them instead of letting it happen.&#x20;

The tools used are different as well. Penetration testers might have more scanners and other tools which focus more on testing individual systems within the scope. A red team would use tools such as Cobalt Strike to again, simulate a real APT.&#x20;

<figure><img src="../../.gitbook/assets/image (3248).png" alt=""><figcaption></figcaption></figure>

I should note that the point of adversary emulation is to, well, **emulate the adversary correctly**. Sometimes, a red team might incorporate super advanced tactics that involve a lot of complicated pieces of code working together to get a beacon. However, APTs might just do it the easy way and still not get caught, defeating the 'adversary emulation' for better defence intention.&#x20;

<figure><img src="../../.gitbook/assets/image (70).png" alt=""><figcaption></figcaption></figure>

That's why proper threat intelligence is important!&#x20;

## Purple Teaming

Purple teaming is a relatively new concept that came about to better prepare organisations against attacks. It is the optimisation of a relationship between adversary and defender capabilities. A purple team exercise would involve both the red and blue teams, where the red team would execute operations emulating a chosen adversary, and the blue team would actively try to detect and block such operations from working.

I personally feel that a Attack/Defend CTF is somewhat similar to a purple team exercise. This involves a blue team that is actively reviewing logs and detecting when an intruder is in the system and trying to capture the flag, while the red team is actively trying to not get caught.

Another example is in military planning. When we plan for a mission in the military, we tend to have two groups as well, an Intelligence team (Red) and an Operations team (Blue).&#x20;

{% hint style="info" %}
All of these are public information that I found on the Internet.&#x20;
{% endhint %}

{% embed url="https://irp.fas.org/doddir/army/fm34-8/ch3.htm" %}

{% embed url="https://irp.fas.org/doddir/army/miobc/msnanllp.htm" %}

The Purple Team Framework is developed by SCYTHE, and more information can be found here:

{% embed url="https://github.com/scythe-io/purple-team-exercise-framework" %}

Also, AttackIQ has a free course teaching the Foundations of Purple Teaming. I highly recommend it if you want to learn more about it. The instructor, Ben Opel, teaches the concepts well and is super knowledgeable thanks to his years in the military helping hone this skill set.&#x20;

Most importantly, it's absolutely free!

{% embed url="https://www.academy.attackiq.com/courses/foundations-of-purple-teaming" %}
