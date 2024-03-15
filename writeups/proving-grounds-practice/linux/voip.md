# VoIP

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 4000 192.168.152.156
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-06 15:06 +08
Nmap scan report for 192.168.152.156
Host is up (0.17s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8000/tcp open  http-alt
```

### Initial Enumeration -> Digest Leak

Port 80 had a login page:

<figure><img src="../../../.gitbook/assets/image (4088).png" alt=""><figcaption></figcaption></figure>

We didn't have any credentials, and weak credentials don't work, so we can move on first.

Port 8000 had another login page:

<figure><img src="../../../.gitbook/assets/image (3782).png" alt=""><figcaption></figcaption></figure>

`admin:admin` worked for this one, and we were brought to a IP Phone instance, which matches the name of the box being Voice over IP:

<figure><img src="../../../.gitbook/assets/image (3589).png" alt=""><figcaption></figcaption></figure>

Within the logs tab, we can see that there were some calls being logged:

<figure><img src="../../../.gitbook/assets/image (3447).png" alt=""><figcaption></figcaption></figure>

Within the Configuration tab, there was some XML looking output. Here's it below:

```markup
<scenario name="VOIP responder">
  <recv request="INVITE" crlf="true">
  </recv>
  <send>
  <![CDATA[
     SIP/2.0 100 Trying
     [last_Via:]
     [last_From:]
     [last_To:];tag=[pid]SIPpTag01[call_number]
     [last_Call-ID:]
     [last_CSeq:]
     Contact: <sip:[local_ip]:[local_port];transport=[transport]>
     Content-Length: 0
     ]]>
  </send>

  <send>
  <![CDATA[
     SIP/2.0 180 Ringing
     [last_Via:]
     [last_From:]
     [last_To:];tag=[pid]SIPpTag01[call_number]
     [last_Call-ID:]
     [last_CSeq:]
     Contact: <sip:[local_ip]:[local_port];transport=[transport]>
     Content-Length: 0
     ]]>
  </send>
 <timewait milliseconds="4000"/>
  <send retrans="500">
  <![CDATA[
     SIP/2.0 200 OK
     [last_Via:]
     [last_From:]
     [last_To:];tag=[pid]SIPpTag01[call_number]
     [last_Call-ID:]
     [last_CSeq:]
     Contact: <sip:[local_ip]:[local_port];transport=[transport]>
     Content-Type: application/sdp
     Content-Length: [len]
     v=0
     o=user1 53655765 2353687637 IN IP[local_ip_type] [local_ip]
     s=-
     c=IN IP[media_ip_type] [media_ip]
     t=0 0
     m=audio [media_port] RTP/AVP 0
     a=rtpmap:0 PCMU/8000
     ]]>
  </send>

  <connection>$connect</connection>

  <recv request="ACK">
  </recv>
  <send>
  <![CDATA[
     BYE sip:[service]@[remote_ip]:[remote_port] SIP/2.0
     Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
     From: sipp <sip:sipp@[local_ip]:[local_port]>;tag=[pid]SIPpTag09[call_number]
     To: [service] <sip:[service]@[remote_ip]:[remote_port]>[peer_tag_param]
     Call-ID: [call_id]
     CSeq: 2 BYE
     Contact: sip:sipp@[local_ip]:[local_port]
     Max-Forwards: 70
     Subject: Performance Test
     Content-Length: 0
     ]]>

  </send>

<!-- Dynamnic response generator -->

  <recv response="*">
   <action>
     <ereg regexp=“^[A-Za-z0-9_.]+$" search_in="response" assign_to="status"/>
     <strcmp assign_to="result" variable="1" value=“status" />
     <test assign_to="status" variable="result" compare="equal" value="0.0"/>
   </action>
  </recv>
  <send>
  <![CDATA[
     $result
  ]]>
  </send>


<timewait milliseconds="4000"/>

<ResponseTimeRepartition value="10, 20, 30, 40, 50, 100, 150, 200"/>

<CallLengthRepartition value="10, 50, 100, 500, 1000, 5000, 10000"/>

</scenario> 
```

The only thing notable about this was teh protocl used, which was SIP/2.0. Since we know that SIP is being used, we can test for stuff on Hacktricks like SIPDigestLeak from the `sippts` repo:

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-voip" %}

{% embed url="https://github.com/Pepelux/sippts/wiki/SIPDigestLeak" %}

Using this worked and we managed to get a hashed password:

```
$ python3 sipdigestleak.py -i 192.168.152.156
```

<figure><img src="../../../.gitbook/assets/image (261).png" alt=""><figcaption></figcaption></figure>

This hash cracks easily:

<figure><img src="../../../.gitbook/assets/image (1905).png" alt=""><figcaption></figcaption></figure>

With this, we can login to port 80 as `adm_sip`.&#x20;

<figure><img src="../../../.gitbook/assets/image (3780).png" alt=""><figcaption></figcaption></figure>

### Audio File -> SSH Creds

We can view the CDR (Call Data Records) and find that one of them is raw, which allows us to download it:

<figure><img src="../../../.gitbook/assets/image (493).png" alt=""><figcaption></figcaption></figure>

This is a raw audio file, and we need to convert it using `sox`. We can find the exact configurations required in the Stream Rates tab on the left:

<figure><img src="../../../.gitbook/assets/image (2039).png" alt=""><figcaption></figcaption></figure>

Then, we can convert this to a `wav` file:

```
$ sox -t raw -r 8000 -v 4 -c 1 -e mu-law 2138.raw out.wav
sox WARN sox: `out.wav' output clipped 6377 samples; decrease volume?
sox WARN sox: `2138.raw' balancing clipped 13425 samples; decrease volume?
```

Afterwards, we can listen to the audio file and it just plays this one line.

{% hint style="info" %}
Your password has been changed to Password1234 where the P is capital.
{% endhint %}

Interesting. We have a username, but not a password. This was the part I got stuck at for a long time. I tried some usernames like `voip`, `zoiper`, and `voiper` because those were popular softwares used with VoIP, and `voiper` worked:

<figure><img src="../../../.gitbook/assets/image (1991).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

This was simple:

```
voiper@VOIP:~$ sudo -l                                                                       
[sudo] password for voiper:                                                                  
Matching Defaults entries for voiper on VOIP:                                                
    env_reset, mail_badpass,                                                                 
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin 

User voiper may run the following commands on VOIP:
    (ALL : ALL) ALL
```

<figure><img src="../../../.gitbook/assets/image (4085).png" alt=""><figcaption></figcaption></figure>

Rooted!
