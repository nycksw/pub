---
tags:
  - hack
  - linux
---

# Pivoting with `sshuttle`

From the man page:

> sshuttle allows you to create a VPN connection from your machine to any remote server that you can connect to via ssh, as long as that server has a sufficiently new Python installation. To work, you must have root access on the local machine, but you can have a normal account on the server. It’s valid to run sshuttle more than once simultaneously on a single client machine, connecting to a different server every time, so you can be on more than one VPN at once.

This is a quick and easy technique that feels more natural than using `proxychains` but the network traffic is still a bit limited, e.g. you can't do half-open scans, similar to how `proxychains` works.

```console
$ sudo sshuttle -r ubuntu@t 172.16.5.0/23 -v
Starting sshuttle proxy (version 1.1.2).
c : Starting firewall manager with command: ['/usr/bin/python3', '/usr/bin/sshuttle', '-v', '--method', 'auto', '--firewall']
fw: Starting firewall with Python version 3.11.9
fw: ready method name nat.
c : IPv6 enabled: Using default IPv6 listen address ::1
c : Method: nat
c : IPv4: on
c : IPv6: on
c : UDP : off (not available with nat method)
c : DNS : off (available)
c : User: off (available)
c : Subnets to forward through remote host (type, IP, cidr mask width, startPort, endPort):
c :   (<AddressFamily.AF_INET: 2>, '172.16.5.0', 23, 0, 0)
c : Subnets to exclude from forwarding:
c :   (<AddressFamily.AF_INET: 2>, '127.0.0.1', 32, 0, 0)
c :   (<AddressFamily.AF_INET6: 10>, '::1', 128, 0, 0)
c : TCP redirector listening on ('::1', 12300, 0, 0).
c : TCP redirector listening on ('127.0.0.1', 12300).
c : Starting client with Python version 3.11.9
c : Connecting to server...
ubuntu@t's password:
 s: Running server on remote host with /usr/bin/python3 (version 3.8.10)
 s: latency control setting = True
 s: auto-nets:False
c : Connected to server.
fw: setting up.
fw: ip6tables -w -t nat -N sshuttle-12300
fw: ip6tables -w -t nat -F sshuttle-12300
fw: ip6tables -w -t nat -I OUTPUT 1 -j sshuttle-12300
fw: ip6tables -w -t nat -I PREROUTING 1 -j sshuttle-12300
fw: ip6tables -w -t nat -A sshuttle-12300 -j RETURN --dest ::1/128 -p tcp
fw: ip6tables -w -t nat -A sshuttle-12300 -j RETURN -m addrtype --dst-type LOCAL
fw: iptables -w -t nat -N sshuttle-12300
fw: iptables -w -t nat -F sshuttle-12300
fw: iptables -w -t nat -I OUTPUT 1 -j sshuttle-12300
fw: iptables -w -t nat -I PREROUTING 1 -j sshuttle-12300
fw: iptables -w -t nat -A sshuttle-12300 -j RETURN --dest 127.0.0.1/32 -p tcp
fw: iptables -w -t nat -A sshuttle-12300 -j REDIRECT --dest 172.16.5.0/23 -p tcp --to-ports 12300
fw: iptables -w -t nat -A sshuttle-12300 -j RETURN -m addrtype --dst-type LOCAL
```

Now the web server on the internal segment is reachable:

```console
$ curl -I 172.16.5.19
HTTP/1.1 200 OK
Content-Length: 703
Content-Type: text/html
Last-Modified: Mon, 28 Mar 2022 15:33:29 GMT
Accept-Ranges: bytes
ETag: "8e6cf72cb942d81:0"
Server: Microsoft-IIS/10.0
Date: Thu, 27 Jun 2024 22:34:39 GMT
```
