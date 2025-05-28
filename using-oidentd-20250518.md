---
tags: [linux]
---
# Using `oidentd` For IRC

I've never used `ident` for anything besides connecting to EFnet.

`/etc/oident.conf`

```json
default {
     default {
          deny spoof
          deny spoof_all
          deny spoof_privport
          allow random
          allow random_numeric
          allow numeric
          allow hide
          force reply "eater"
     }
}
```