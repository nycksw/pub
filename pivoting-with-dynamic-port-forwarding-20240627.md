---
tags:
  - hack
  - linux
---

# Pivoting with Dynamic Port Forwarding

The OpenSSH client has a built-in SOCKS proxy for "dynamic port forwarding".

I'll use the `-D` flag from `ssh` for the dynamic port forwarding (SOCKS server):

```text
-D [bind_address:]port
               Specifies a local “dynamic” application-level port forwarding.  This works by allocating a socket to listen to port  on  the
               local  side,  optionally bound to the specified bind_address.  Whenever a connection is made to this port, the connection is
               forwarded over the secure channel, and the application protocol is then used to determine where to connect to from  the  re‐
               mote  machine.   Currently the SOCKS4 and SOCKS5 protocols are supported, and ssh will act as a SOCKS server.  Only root can
               forward privileged ports.  Dynamic port forwardings can also be specified in the configuration file.
               IPv6 addresses can be specified by enclosing the address in square brackets.  Only  the  superuser  can  forward  privileged
               ports.   By default, the local port is bound in accordance with the GatewayPorts setting.  However, an explicit bind_address
               may be used to bind the connection to a specific address.  The bind_address of “localhost” indicates that the listening port
               be bound for local use only, while an empty address or ‘*’ indicates that the port should be available from all interfaces.
```

And `-N`:

```text
       -N      Do not execute a remote command.  This is useful for just forwarding ports.  Refer to  the  description  of  SessionType  in
               ssh_config(5) for details.
```

Start the SOCKS server:

```console
$ ssh -D 9050 ubuntu@t -N
Warning: Permanently added 't' (ED25519) to the list of known hosts.
ubuntu@t's password:
```

I can verify the port is listening on `localhost`:

```console
# netstat -lnpt4 |grep 9050
tcp        0      0 127.0.0.1:9050          0.0.0.0:*               LISTEN      55268/ssh
```

Here's the appropriate configuration for `proxychains`:

```console
$ tail -n1 /etc/proxychains4.conf
socks5 127.0.0.1 9050
```

Now I can scan a host on the far network segment:

```console
$ proxychains nmap -sT -p80 -sCV 172.16.5.19
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-27 15:34 CST
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  172.16.5.19:80  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  172.16.5.19:80  ...  OK
...
proxychains] Strict chain  ...  127.0.0.1:9050  ...  172.16.5.19:80  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:9050  ...  172.16.5.19:80  ...  OK
Nmap scan report for 172.16.5.19
Host is up (0.24s latency).
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.34 seconds
```

Using `proxychains` is slow, and limits what you can do. For example, only connect-scans (`nmap -sT`) will work because incomplete connections (like half-connect scans) aren't possible.

Something similar to the above can be done on Windows using [Plink](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html) and [Proxifier](https://www.proxifier.com/).