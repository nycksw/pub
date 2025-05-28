---
tags:
  - hack
  - linux
---

# Pivoting with Socat

Socat can be used to forward traffic. In the example below, 10.10.1.1 is the attacking machine running a web server, and the `socat` command will expose that server to all its network segments on port 8080:

```console
socat TCP4-LISTEN:8080,fork,reuseaddr TCP4:10.10.1.1:80
```

Or, to expose a machine on the far side of our pivot host, `socat` can listen on port 8080 and forward connections to the otherwise inaccessible machine 172.16.1.1:

```console
socat TCP4-LISTEN:8080,fork,reuseaddr TCP4:172.16.1.1:80
```

From the man page:

```text
TCP-LISTEN:<port>

Listens on <port> [TCP service] and accepts a TCP/IP connection. The IP version is 4 or the one specified with address option pf,  socat  option  (-4, -6), or environment variable SOCAT_DEFAULT_LISTEN_IP.  Note that opening this address usually blocks until a client connects. Option groups: FD,SOCKET,LISTEN,CHILD,RANGE,IP4,IP6,TCP,RETRY Useful options: crnl, fork, bind, range, tcpwrap, pf, max-children,  backlog,  accept-timeout,  mss,  su,  reuseaddr,  retry, cool-write See also: TCP4-LISTEN, TCP6-LISTEN, UDP-LISTEN, SCTP-LISTEN, UNIX-LISTEN, OPENSSL-LISTEN, TCP-CONNECT

TCP4-LISTEN:<port>

Like TCP-LISTEN, but only supports IPv4 protocol (example). Option groups: FD,SOCKET,LISTEN,CHILD,RANGE,IP4,TCP,RETRY
```
