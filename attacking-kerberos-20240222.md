---
tags:
  - hack
---
# Attacking Kerberos

## Overview of Kerberos

The handshake happens in three phases, with each phase containing two steps, a request and a reply.

### 1. Authentication Server (AS)

The purpose of this phase is for the client and the network to mutually **authenticate** each other as demonstrated by mutual possession of the client's password hash.

The client completes this phase possessing two important things:

- Ticket Granting Ticket (TGT)
- A symmetric session key for talking to the next service in the process, the Ticket Granting Service (TGS).

### 2. Ticket Granting Service (TGS)

The purpose of this phase is for the client to obtain proof of **authorization** for the desired application.

The client completes this phase possessing two important things:

- A symmetric session key for talking to the desired application.
- A _service ticket_, unreadable by the client, to be passed to the application for the final phase.

### 3. Application (AP)

The purpose of the final phase is for the client and the application server to mutually authenticate each other, and for the application server to verify the client is authorized. After this, the application may be used so long as the service ticket remains valid.

## Attack Vectors

- [`kerbrute`](using-kerbrute-20240722.md)
- [Impacket](https://github.com/fortra/impacket) `GetNPUsers.py`: Find users with preauthentication disabled.
- [Impacket](https://github.com/fortra/impacket) `GetUserSPNs.py`: Get potentially crackable hashes for users with service principal names set.
