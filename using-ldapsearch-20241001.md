# Using `ldapsearch`

## Getting the `DN`

```console
$ ldapsearch -H ldap://10.10.10.161 -x -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts
#

#
dn:
namingContexts: DC=htb,DC=local
namingContexts: CN=Configuration,DC=htb,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=htb,DC=local
namingContexts: DC=DomainDnsZones,DC=htb,DC=local
namingContexts: DC=ForestDnsZones,DC=htb,DC=local
...
```

## Querying without Auth

```console
$ ldapsearch -H ldap://10.10.10.161 -x -b "DC=htb,DC=local" | wc -l
10760
```
