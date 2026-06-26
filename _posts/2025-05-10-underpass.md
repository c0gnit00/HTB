---
title: "Underpass"
date: 2025-05-10 00:00:00 +0500
categories: [HackTheBox, Linux]
tags: [Default-Credentials, MD5-Hash-Cracking, SNMP-Enumeration, Sudo-Misconfiguration, sudo-mosh-server, daloRADIUS, mosh-server]
description: Writeup for HackTheBox Underpass machine
image:
  path: assets/img/underpass/underpass.png
  alt: HTB Underpass
---
## Executive Summary

This report documents the security assessment and penetration testing walkthrough of the HackTheBox machine **Underpass**, an easy-difficulty Linux server. The compromise highlights the risks of exposing active Simple Network Management Protocol (SNMP) services with guessable community strings, utilizing default application credentials, and configuring permissive `sudo` policies on administrative binaries that support arbitrary wrapper shell invocation.

**Attack Chain Summary:**

1. **UDP Port Scan & SNMP Enumeration → Information Disclosure:** Active UDP port scanning identified an open SNMP service on port 161. Enumerating SNMP using common community strings (like `public`) revealed sensitive system configuration details, including references to a local daloRADIUS instance.

2. **Default Application Credentials & Hash Harvesting → User Foothold:** Accessing the daloRADIUS web application page and logging in with default credentials (`administrator` / `radius`) granted access to the administrator dashboard. Reviewing user settings exposed the MD5 password hash for the system service user `svcMosh`. Cracking the hash offline yielded the plaintext password `underwaterfriends`, enabling interactive SSH access.

3. **Mosh Server Sudo Misconfiguration → Root:** Sudo policy enumeration on the `svcMosh` account showed that the user was permitted to run the `/usr/bin/mosh-server` binary as root without a password. By invoking `mosh-server` with root privileges and establishing a local client connection, a shell session was spawned in the root context.

**Impact:** Complete system compromise. An unauthenticated remote attacker can enumerate system services, gain user-level access, and elevate privileges to root.

---

## Reconnaissance & Initial Port Scanning

### Nmap TCP Scan

An initial TCP scan was executed to locate active services.

```shell
┌──(kali㉿kali)-[~/HTB-machine/underpass]
└─$ sudo nmap -sC -sV -Pn 10.10.11.48
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (0.05s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Underpass Pentesting Services
```

The TCP scan reveals standard ports: SSH on port 22 and Apache HTTP on port 80.

### Nmap UDP Scan

Because standard TCP services do not present immediate vulnerabilities, we conduct a UDP scan targeting the top 100 UDP ports to identify overlooked services. UDP scans are slower than TCP because the protocol is connectionless — the scanner sends probes and waits for ICMP port-unreachable responses or application-layer replies, rather than relying on a SYN/ACK handshake.

```shell
┌──(kali㉿kali)-[~/HTB-machine/underpass]
└─$ sudo nmap -sU --top-ports 100 10.10.11.48
```

<img src="Images/image2.jpg" alt="Nmap UDP Scan Output">

The UDP scan identifies that the **SNMP (Simple Network Management Protocol)** service is active on port 161/udp.

---

## SNMP Enumeration & Directory Discovery

### SNMP Walk

SNMP uses a hierarchical OID (Object Identifier) tree to organize manageable device parameters. Agents expose variables organized under standardized MIBs (Management Information Bases) like `1.3.6.1.2.1` (mib-2/system) for OS-level data. Access is controlled by community strings — effectively plaintext passwords embedded in every packet. SNMPv2c transmits community strings and data in cleartext, making it trivially interceptable.

We perform SNMP enumeration using the default community string `public` to query system details:

```shell
┌──(kali㉿kali)-[~/HTB-machine/underpass]
└─$ snmpwalk -v 2c -c public 10.10.11.48
```

<img src="Images/image3.jpg" alt="SNMP Enumeration Output">

The SNMP output reveals system details and variables, exposing a local reference to **daloRADIUS**, an advanced web management application for RADIUS database structures.

### Web Directory Brute-Forcing

Navigating to the root directory `http://underpass.htb/` displays a default landing page. To find the daloRADIUS endpoint, we execute `dirsearch` to scan for hidden directories:

```shell
┌──(kali㉿kali)-[~/HTB-machine/underpass]
└─$ dirsearch -u http://underpass.htb/ -t 50 -e php,txt,html
```

<img src="Images/image4.jpg" alt="Dirsearch Scan Results">

The directory search uncovers the `/daloradius/` path, confirming the directory is active on the server.

---

## Web Application Exploitation & Hash Cracking

### daloRADIUS Panel Access

We navigate to the daloRADIUS login panel at `http://underpass.htb/daloradius/`:

<img src="Images/image5.jpg" alt="daloRADIUS Panel Default Login">

daloRADIUS is a web-based management interface for FreeRADIUS, a popular RADIUS authentication server. It stores user credentials including password hashes in a MySQL/MariaDB database.

We attempt to authenticate using default daloRADIUS administrative credentials:
- **Username:** `administrator`
- **Password:** `radius`

The login succeeds, granting access to the daloRADIUS management dashboard.

<img src="Images/image8.jpg" alt="daloRADIUS Operator Dashboard">

### Credential Harvesting

Within the operator panel, we navigate to the user accounts or operator settings to list system users:

<img src="Images/image9.jpg" alt="daloRADIUS User List">

The listing exposes a user profile configured for `svcMosh`. The user details reveal the password hash associated with this user:

<img src="Images/image10.jpg" alt="Password Hash Output">

daloRADIUS by default stores user passwords as unsalted MD5 hashes (`$P$` or raw MD5 depending on configuration). The extracted hash is a standard MD5 hash (hashcat mode 0, john format `raw-md5`).

- **MD5 Hash:** `55260195ec4a02db16dbbbf690e8ef3e`
- **Cracked Password:** `underwaterfriends`

The hash is cracked offline using Hashcat:

```shell
┌──(kali㉿kali)-[~/HTB-machine/underpass]
└─$ hashcat -m 0 -a 0 55260195ec4a02db16dbbbf690e8ef3e /usr/share/wordlists/rockyou.txt
55260195ec4a02db16dbbbf690e8ef3e:underwaterfriends
```

---

## SSH Initial Access

### User Foothold

Using the cracked credentials, we authenticate via SSH as the user `svcMosh`:

```shell
┌──(kali㉿kali)-[~/HTB-machine/underpass]
└─$ ssh svcMosh@10.10.11.48
```

<img src="Images/image11.jpg" alt="SSH Foothold Session">

The SSH login is successful, establishing a low-privilege foothold. We can now retrieve the user flag (`user.txt`).

---

## Privilege Escalation

### Sudo Rules Analysis

We perform local enumeration to locate privilege escalation vectors. We inspect allowed `sudo` configurations using:

```shell
svcMosh@underpass:~$ sudo -l
```

<img src="Images/image12.jpg" alt="Sudo Configuration Output">

The output indicates that the user `svcMosh` is permitted to run `/usr/bin/mosh-server` as root without supplying a password:

```
(root) NOPASSWD: /usr/bin/mosh-server
```

### Exploit Mechanics

Mosh (Mobile Shell) is a UDP-based remote terminal protocol designed as a replacement for SSH that handles IP roaming and intermittent connectivity. It uses two components: `mosh-client` (the local terminal UI) and `mosh-server` (the remote session process). 

The `mosh-server` binary accepts a `--server` option that specifies the wrapper command used to spawn the remote session environment. By default this is `login` or `sshd`, but it can be set to any executable. When `mosh-server` starts, it forks the specified command as the session process — and that process inherits the privilege level of the `mosh-server` invocation.

Because we can run `/usr/bin/mosh-server` as root via `sudo`, we abuse this by setting `--server` to a shell:

```shell
svcMosh@underpass:~$ mosh --server="sudo /usr/bin/mosh-server" localhost
```

This command tells the local `mosh` client to connect to `localhost` and invoke `sudo /usr/bin/mosh-server` as the server-side command. The `sudo` invocation spawns `mosh-server` as root. Since no `--server` override is passed at the mosh-server level, it defaults to the user's login shell — but the mere fact that the server process runs as root means any command executed through the mosh session inherits root privileges.

The mosh client connects to the localhost instance, initializing a session. The connection returns an interactive shell running as `root`:

<img src="Images/image13.jpg" alt="Root Shell Spawning">

We can now retrieve the root flag (`root.txt`).

---

## Mitigations & Security Recommendations

To secure the environment and prevent similar compromise vectors, the following hardening steps are recommended:

1. **Secure SNMP Configuration:**
   - Deprecate SNMP version 2c which transmits data in cleartext and relies on weak community strings. Upgrade to SNMPv3 to enforce message encryption, integrity checks, and user authentication.
   - Change default community strings (e.g., `public`, `private`) to cryptographically strong, randomly generated strings.
   - Implement firewall rules or bind configurations to restrict SNMP access to authorized management IPs.

2. **Remediate Default Web Application Credentials:**
   - Enforce password rotation policies requiring default admin credentials (`administrator:radius` in daloRADIUS) to be changed immediately upon application deployment.

3. **Restrict Sudo Privileges:**
   - Avoid granting wildcard or NOPASSWD sudo access to system binaries that permit command execution, shell escapes, or arbitrary command execution hooks (such as `mosh`).
   - If `mosh` support is required, configure strict alias rules or limit execution rights.
