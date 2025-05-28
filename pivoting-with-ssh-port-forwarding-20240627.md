---
tags:
  - hack
  - linux
---

# Pivoting with SSH Port Forwarding

Simple port forwarding with `nmap` uses the `-L` or `-R` flags:

For local,

```text
-L local_socket:remote_socket

Specifies that connections to the given TCP port or Unix socket on the local (client) host are to be forwarded to the  given host  and port, or Unix socket, on the remote side. This works by allocating a socket to listen to either a TCP port on the local side, optionally bound to the specified bind_address, or to a Unix socket. Whenever a connection is made to the local port or socket, the connection is forwarded over the secure channel, and a connection is made to either host port  hostport, or the Unix socket remote_socket, from the remote machine.
```

For example, to connect your Kali machine's local port 8080 to the target's port 80 that's listening only on `localhost`, use:

  `nmap -L8080:localhost:80 user@target -N`

For remote,

```text
-R [bind_address:]port:host:hostport
-R remote_socket:host:hostport
-R [bind_address:]port
Specifies that connections to the given TCP port or Unix socket on the remote (server) host are to be forwarded to the local side. This works by allocating a socket to listen to either a TCP port or to a Unix socket on the remote side. Whenever a connection is made to this port or Unix socket, the connection is forwarded over the secure channel, and a connection is made from the  local  machine  to  either an explicit destination specified by host port hostport, or local_socket, or, if no explicit destination was specified, ssh will act as a SOCKS 4/5 proxy and forward connections to the destinations  requested  by  the remote SOCKS client.

```

For example, I have `python3 -m http.server` running on my Kali machine on port 80. I want port 8080 on the target to expose that server to all its network segments.

```console
$ ssh -R0.0.0.0:8080:0.0.0.0:80 ubuntu@t
Warning: Permanently added 't' (ED25519) to the list of known hosts.
ubuntu@t's password:
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
...
ubuntu@WEB01:~$ netstat -lnpt | grep 8080
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      -
tcp6       0      0 :::8080                 :::*                    LISTEN      -
...

ubuntu@WEB01:~$ curl -I localhost:8080
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.9
Date: Thu, 27 Jun 2024 22:01:57 GMT
Content-type: text/html
Content-Length: 0
Last-Modified: Mon, 06 May 2024 18:31:42 GMT
```
