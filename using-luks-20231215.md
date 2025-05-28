---
tags:
  - linux
---
# Using LUKS

Configuring an external USB backup drive as a [LUKS](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup)-encrypted volume that auto-mounts after boot or when reconnected.

## Preparing the Encrypted Volume

Here are the commands I used to prepare the disk:

- `cryptsetup luksFormat /dev/sda`
- `cryptsetup open /dev/sda bak`
- `mkfs.ext4 /dev/mapper/bak`

I created a keyfile in order to automount the encrypted volume without requiring an interactive passphrase entry.

- `dd if=/dev/urandom of=/root/keyfiles/bak bs=1024 count=4`
- `chmod 400 /root/keyfiles/bak`
- `cryptsetup luksAddKey /dev/sda /root/keyfiles/bak`

## Auto-mounting After Boot

Then, I grabbed two UUIDs, one for the logical encrypted volume and one for the physical drive:

```text
# blkid
[...]
/dev/mapper/bak: UUID="922cdc15-0868-4225-81f2-a95f6fefeaec" BLOCK_SIZE="4096" TYPE="ext4"
/dev/sda: UUID="2d7357c6-c6dc-4989-b5a8-9af366a60064" TYPE="crypto_LUKS"
```

The physical drive UUID goes into `/etc/crypttab`, and the logical volume UUID goes into `/etc/fstab`:

```text
# tail -n1 /etc/fstab /etc/crypttab 
==> /etc/fstab <==
UUID=922cdc15-0868-4225-81f2-a95f6fefeaec /bak ext4 defaults 0 2

==> /etc/crypttab <==
bak UUID=2d7357c6-c6dc-4989-b5a8-9af366a60064 /root/keyfiles/bak luks
```

## Auto-mounting After Reconnecting

To get this working correctly when the device is unplugged is…complicated. I used a combination of `udev`, `systemd` and a script that can wait for device actions to complete.

`/etc/udev/rules.d/90-automount-bak.rules`:

```sh
ACTION=="add", KERNEL=="sd?", ENV{ID_FS_UUID}=="2d7357c6-c6dc-4989-b5a8-9af366a60064", TAG+="systemd", ENV{SYSTEMD_WANTS}+="mount-bak.service"
```

For the next step I had to use `systemd` because `udev` lacks permissions to mount volumes.

`/etc/systemd/system/mount-bak.service`:

```text
[Unit]
Description=Mount LUKS device on /bak

[Service]
Type=oneshot
ExecStart=/root/mount-bak.sh
```

Reload the new bits:

```text
systemctl daemon-reload
udevadm control --reload-rules && udevadm trigger
```

`/root/mount.sh`:

```sh
#!/bin/bash

UUID="2d7357c6-c6dc-4989-b5a8-9af366a60064"
DEV="/dev/disk/by-uuid/${UUID}"
MAPPED_DEV="/dev/mapper/bak"
MOUNT_POINT="/bak"
LOG_FILE="/tmp/mount-bak.log"

{
  # Check if already mounted
  if findmnt -rn "$MOUNT_POINT" | grep -q " $MAPPED_DEV "; then
    echo "Device $MAPPED_DEV is already mounted on $MOUNT_POINT"
    exit 0
  fi

  for i in {1..30}; do
    if [ -e "$DEV" ]; then
      echo "Device found: $DEV"
      if cryptsetup status bak | grep -q "is active"; then
        echo "LUKS volume 'bak' is already active. Closing it first..."
        cryptsetup close bak
      fi
      echo "Opening LUKS volume..."
      cryptsetup open "$DEV" bak --key-file=/root/keyfiles/bak
      echo "Mounting LUKS volume on $MOUNT_POINT..."
      mount "$MAPPED_DEV" "$MOUNT_POINT" && break
    fi
    echo "Waiting for device $DEV to become available..."
    sleep 1
  done

  if ! mountpoint -q "$MOUNT_POINT"; then
    echo "Failed to mount $MAPPED_DEV on $MOUNT_POINT"
    exit 1
  fi

  echo "Device $MAPPED_DEV mounted successfully on $MOUNT_POINT"

} 2>&1 | tee "$LOG_FILE"
```
