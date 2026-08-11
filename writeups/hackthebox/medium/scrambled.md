---
description: Linux Method here.
---

# Scrambled

## Gaining Access

Nmap Scan:

![](../../../.gitbook/assets/scrambled-5.png)

### ScrambleCorp

The website was another corporate webpage.

![](../../../.gitbook/assets/scrambled-29.png)

In the IT Services tab, we can view this warning:

![](../../../.gitbook/assets/scrambled-12.png)

So this machine presented the challenge of not using NTLM at all, but **only Kerberos tickets.** Enumerating further, we can find more resources in the page source:

![](../../../.gitbook/assets/scrambled-6.png)

Heading to the Support Request page shows this:

![](../../../.gitbook/assets/scrambled-17.png)

One interesting thign we get from this is that there is a `ksimpson` user within the domain. the image there seems intentionally left there.

Additionally, the Sales Order page reveals more information which could be useful:

![](../../../.gitbook/assets/scrambled-15.png)

There's some binary that would conenct to `dc1.scrm.local` on port 4411, which we can note down. Might be BOF exploit later on.

### getTGT + SMB Shares

Armed with one user, I attmepted to request for a TGT using his username as the password:

![](../../../.gitbook/assets/scrambled-23.png)

Now we have one ticket, we can attempt to access some SMB shares using `smbclient.py`.

![](../../../.gitbook/assets/scrambled-22.png)

Ton of shares here, but we can only access the `Public` share. We can find one interesting file here.

![](../../../.gitbook/assets/scrambled-25.png)

![](../../../.gitbook/assets/scrambled-19.png)

### Kerberoasting

Within this PDF, we can find some useful hints on where to head to next:

![](../../../.gitbook/assets/scrambled-13.png)

So an attacker was able to retrieve stuff from an SQL database used by HR. Furthermore, the Kerberos authentication bit made me realise that we should be attempting to resolve User SPNs to Kerberoast whatever SQL users there were.

We can use `getUserSPNs.py` to do so.

![](../../../.gitbook/assets/scrambled-28.png)

Afterwards, we can retrieve the tickets using the `-request` flag. Thsi would give us a hash that we can crack using `john`.

![](../../../.gitbook/assets/scrambled-26.png)

### Converting to Ticket + RCE

NTLM authentication was totally shut down, so we have to take this password and convert it to a valid ticket. I used `impacket-secretsdump` to get the Domain SIDs of the users present:

![](../../../.gitbook/assets/scrambled-20.png)

Then, we can use `impacket-ticketer` to create a ticket, export it and also run `impacket-mssqlclient` to connect to the MSSQL instance using Kerberos:

![](../../../.gitbook/assets/scrambled-2.png)

Then, we can enable `xp_cmdshell` to gain RCE on the machine.

![](../../../.gitbook/assets/scrambled-8.png)

Using this, we can gain a reverse shell using whatever method. I always prefer to download a copy of `nc.exe` onto the machine and run it (not the stealthiest).

![](../../../.gitbook/assets/scrambled-11.png)

![](../../../.gitbook/assets/scrambled-3.png)

## Privilege Escalation

I was unable to do much as this user. So instead, I went to enumerate the SQL database a bit more to hopefully find some credentials within it (as hinted by the PDF earlier).

### Miscsvc

Was able to find this:

![](../../../.gitbook/assets/scrambled-27.png)

Then, we can take a look at the ScrambleHR database.

![](../../../.gitbook/assets/scrambled-24.png)

I took a look at the UserImport table and found some new credentials.

![](../../../.gitbook/assets/scrambled-14.png)

With these credentials, we can attempt to `evil-winrm` in. However this does not work as the user is not part of the Remote Management Group.

Instead, I used some remote Powershell to gain RCE via ScriptBlocks.

![](../../../.gitbook/assets/scrambled-10.png)

We can gain another reverse shell easily and capture the user flag.

![](../../../.gitbook/assets/scrambled-4.png)

### Scramble Client

Taking a look around the machine, we can go ahead and view all the other Shares that we could not access just now by reading the `C:\Shares` directory. There, I was able to find the ScrambleClient.exe file that was running on port 4411.

![](../../../.gitbook/assets/scrambled-7.png)

Transferred this back to my machine via nc.exe, and then took a look at it using `strings`.

![](../../../.gitbook/assets/scrambled-16.png)

I see DeserializeFromBase64, which is a huge security flaw as user input should never be deserialized. I transferred this binary to another Windows VM (Commando VM in this case) and then opened it up in dnSpy.

As usual, it first asks for creds (as per the image we found earlier). We can find this snippet in code for the login authentication:

```csharp
public bool Logon(string Username, string Password)
{
    bool result;
    try
    {
        if (string.Compare(Username, "scrmdev", true) == 0)
        {
            Log.Write("Developer logon bypass used");
            result = true;
        }
```

There was a custom backdoor using the `scrmdev` user! We can easily login then. Afterwards, I took a look back at port 4411 on the machine, which was running this binary as I found out the binary accepts some commands based on reading the dnSpy code.

We can send LIST\_ORDERS to the port, and it would return some base64 stuff:

![](../../../.gitbook/assets/scrambled-21.png)

This was interesting, and reading the code also allowed us to send an UPLOAD\_ORDER; command, followed by base64 encoded stuff. I knew the payload was being deserialized, just had to find out what was the function used as it might be vulnerable to RCE.

Took a look at the base64 functions and found this:

```csharp
public string SerializeToBase64()
{
    BinaryFormatter binaryFormatter = new BinaryFormatter();
    Log.Write("Binary formatter init successful");
    string result;
    using (MemoryStream memoryStream = new MemoryStream())
    {
        binaryFormatter.Serialize(memoryStream, this);
        result = Convert.ToBase64String(memoryStream.ToArray());
    }
    return result;
}
```

This program was using `BinaryFormatter()`, which an insecure function that could be exploited via `ysoserial`.

### Constructing Payload

I had to download `ysoserial.exe` on my Windows VM to build my payload. We can then use it to create this payload:

![](../../../.gitbook/assets/scrambled-9.png)

Afterwards, we just need to prepend a UPLOAD\_ORDER; string, and send this to port 4411. On our listener port, we would catch a SYSTEM shell.

![](../../../.gitbook/assets/scrambled-18.png)

![](../../../.gitbook/assets/scrambled-1.png)
