---
tags:
  - linux
---
# Using the Argos Extension with Gnome

Here's how to use the [Argos](https://github.com/p-e-w/argos) extension on Gnome 46 to show an IP address in the title bar of the Gnome Shell.

- `git clone https://github.com/p-e-w/argos`
- `mkdir -p ~/.local/share/gnome-shell/extensions`
- `mv argos/argos@pew.worldwidemann.com ~/.local/share/gnome-shell/extensions/`
- Restart the Gnome Shell with `Alt-F2` and `r`.
* Put the following in `/.config/argos/show_ip.15s.sh`:

```bash
#!/bin/bash

# Show IP addresss for $iface.

iface="tun0"
ip=$(/sbin/ifconfig $iface | grep 'inet ' | awk '{print $2}')
if [[ -n "$ip" ]]; then
  echo $iface: $ip
else
  echo "$iface down"
fi
```

- `chmod +x ~/.config/argos/show_ip..15s.sh`
