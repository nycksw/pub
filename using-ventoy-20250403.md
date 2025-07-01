# Using Ventoy for Windows Installers

For making a bootable USB drive to install Windows, I use [Ventoy](https://www.ventoy.net/), a shim that allows loading arbitrary ISOs. This sidesteps some of the quirks and repetition when creating Windows installation media.

- Follow the [installation media](https://support.microsoft.com/en-us/windows/create-installation-media-for-windows-99a58364-8c02-206f-aa6f-40c3b507420d) links and grab a "Disk Image (ISO)" for your target version of Windows.
- Download [Ventoy](https://www.ventoy.net/en/download.html) and untar it, e.g.:
    - `tar xzvf ventoy-1.1.05-linux.tar.gz && cd ventoy-1.1.05`
- Prepare the USB drive and put Ventoy on it, e.g.:
  - `sudo wipefs --all /dev/sdx`
  - `sudo sh Ventoy2Disk.sh -i /dev/sdx`
- Put the Windows ISO on the USB drive:
    - `sudo mkdir /mnt/ventoy`
    - `sudo mount /dev/sdx1 /mnt/ventoy`
    - `cp Win11_24H2_English_x64.iso /mnt/ventoy/ && sync`
- Boot the target system using the USB drive, select the ISO, and choose "Normal" mode.