---
description: Mainly using open-source tools.
---

# Adversary Emulation

## Environment Creation

In most exercises, there should be some kind of 'range' of which we can run our attacks without affecting the main production environment. This is where the development of a simulated testbed is required.&#x20;

### Vagrant

Vagrant is an open-source software project developed by Hashicorp that enables the building and maintaining of portable virtual software development environments.

In layman terms, it allows for us to script the spinning up of Virtual Machines using providers like VirutalBox or VMWare automatically and quickly using a `Vagrantfile` script.&#x20;

{% embed url="https://developer.hashicorp.com/vagrant/docs/vagrantfile" %}

{% hint style="warning" %}
Recently, Hashicorp has basically made their software closed source. In the meantime, we can use the OpenTF Foundation's implementation of Infrastructure as Code, which is an (always) open source alternative :D
{% endhint %}

{% embed url="https://github.com/opentffoundation/opentf" %}

The VMs can then be provisioned with startup scripts to download the necessary packages and files from our host machine or the Internet. The syntax of this software is super easy to understand, and it's relatively stable (although sometimes prone to bugs and resetting is required).

To install this, we can use the `choco` package manager to do so on Windows:

```powershell
# In an administrator powershell.exe instance
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
choco install vagrant
```

Here's a quick example of a setting up a Linux machine with some tools:

<pre><code>Vagrant.configure("2") do |config|
    config.vm.define "linux" do |linux|
        linux.vm.box = "hashicorp/bionic64"
<strong>        linux.vm.hostname = "my_linux_machine"
</strong>            
        # network
<strong>        linux.vm.network "private_network", ip: "192.168.1.5"
</strong>        linux.vm.network "public_network",bridge: "enp0s3", ip: "123.111.0.5"
            
<strong>        # scripts
</strong>        linux.vm.provision "file", source: "software.deb", destination: "/home/vagrant/software.deb"
        linux.vm.provision "shell", path: "setup.sh", privileged: true 
            
        # virtualize
        linux.vm.provider "virtualbox" do |v, override|
            v.name = "my_linux_machine"
            v.customize ["modifyvm", :id, "--clipboard", "bidirectional"]
            v.customize ['modifyvm', :id, '--draganddrop', 'bidirectional']
            v.memory = 4096
            v.cpus = 1
            v.gui = true
        end
    end
end
</code></pre>

The `vm.box` option can be changed to whatever we want based on the available boxes from Hashicorp's Vagrant Cloud library:

{% embed url="https://app.vagrantup.com/boxes/search" %}

The provisioning is done through putting files from our host machine to the VM, and we can also run scripts like `setup.sh` from our machine. If we want to create and run our VM, just head to the directory with the `Vagrantfile` and relevant files, and then run:

```powershell
vagrant up
```

This would download the image from the Vagrant Cloud and set up the VM for us. If we want to stop or destroy the VM, we can do so accordingly:

```powershell
vagrant halt linux
OR 
vagrant destroy linux [--force] ## does not prompt if --force specified
```

The above `Vagrantfile` sets up the machines on one host machine, so it is ideal if we do not have or want to use Cloud providers to host our machines. However, take note that setting up multiple VMs is hardware intensive and requires lots of space and RAM, so change the `v.memory` and `v.cpus` according to your needs.

The fast provisioning and destruction of VMs using Vagrant makes it great for setting up environments quickly for adversary emulation, malware analysis or just general testing without affecting our host machine. There are loads of Github repositories out there for stuff like Windows Reverse Engineering or Malware Analysis ready to go.&#x20;

### Terraform

Terraform is another open-source software tool created by Hashicorp. The main difference between this and Vagrant is that Terraform is able to deploy infrastructure using services like AWS a bit easier, and do all the same stuff that Vagrant can do.&#x20;

{% embed url="https://developer.hashicorp.com/terraform/docs" %}

I won't delve into Terraform scripts too much, since the documentation by Hashicorp is pretty comprehensive and easy to use.&#x20;

## Automated Adversary

Now that we have provisioned our simulated enterprise environment, we need a way to simulate our adversary based on our threat model (ie. if you are a financial institution, emulate FIN groups instead of groups that target OT / ICS sectors).&#x20;

One tool I have used is called Caldera, which a free software developed by MITRE that allows for automated threat emulation:

{% embed url="https://github.com/mitre/caldera" %}

Alternatively, red teams can do this manually if desired (but automated just saves loads of time).&#x20;

Caldera is a software that contains a C2 server with a REST API and web interface, as well as various plugins that include agents, reporting, collection of existing TTPs and much more. For example, Sandcat is one of the plugins, which provides a Golang based beacon to create agents on hosts:

{% embed url="https://github.com/mitre/sandcat" %}

Will include:

* Creating adversary profiles based on threat intel
* Deploying agents and running operations
* Scythe2Caldera script that I made! For automating creation of adversary profiles based of the Community Threats Repository maintainted by SCYTHE for Purple Teaming.

## Documentation

Open-Source Vectr (how to please upper management with clear documentation lol).&#x20;
