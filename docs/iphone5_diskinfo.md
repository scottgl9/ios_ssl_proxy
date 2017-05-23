Disk info from iPhone 5 using gptfdisk:

Disk /dev/disk0: 3906250 sectors, 14.9 GiB
Logical sector size: 4096 bytes
Disk identifier (GUID): F44D244A-C82E-4691-98AC-5B6069E38C2A
Partition table holds up to 128 entries
First usable sector is 6, last usable sector is 3906244
Partitions will be aligned on 256-sector boundaries
Total free space is 3906239 sectors (14.9 GiB)

Number  Start (sector)    End (sector)  Size       Code  Name

cott-Glovers-iPhone:~ root# ./gptfdisk /dev/disk0s1  
GPT fdisk (gdisk) version 1.0.0

Warning: Devices opened with shared lock will not have their
partition table automatically reloaded!
Partition table scan:
  MBR: protective
  BSD: not present
  APM: not present
  GPT: present

Found valid GPT with protective MBR; using GPT.

Command (? for help): p
Disk /dev/disk0s1: 3870731 sectors, 14.8 GiB
Logical sector size: 4096 bytes
Disk identifier (GUID): 26287AF5-1068-4CD6-A41B-0E34BE9221FF
Partition table holds up to 2 entries
First usable sector is 6, last usable sector is 3870725
Partitions will be aligned on 2-sector boundaries
Total free space is 0 sectors (0 bytes)

Number  Start (sector)    End (sector)  Size       Code  Name
   1               6          575087   2.2 GiB     AF00  System
   2          575088         3870725   12.6 GiB    AF00  Data

Partition number (1-2): 1
Partition GUID code: 48465300-0000-11AA-AA11-00306543ECAC (Apple HFS/HFS+)
Partition unique GUID: 12ACD143-86EC-499C-8CB7-815B7516A81F
First sector: 6 (at 24.0 KiB)
Last sector: 575087 (at 2.2 GiB)
Partition size: 575082 sectors (2.2 GiB)
Attribute flags: 0000000000000000
Partition name: 'System'

Recovery/transformation command (? for help): i
Partition number (1-2): 2
Partition GUID code: 48465300-0000-11AA-AA11-00306543ECAC (Apple HFS/HFS+)
Partition unique GUID: FBE81AF8-EA22-AD41-B8E9-71D210E873CE
First sector: 575088 (at 2.2 GiB)
Last sector: 3870725 (at 14.8 GiB)
Partition size: 3295638 sectors (12.6 GiB)
Attribute flags: 0003000000000000
Partition name: 'Data'

