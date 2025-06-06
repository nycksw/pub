---
tags:
  - hack
  - linux
---
# Using `hashcat` with GPUs


## NVIDIA GeForce RTX 4070 Laptop (AD106M, 8 GiB)

Using CUDA gave me a performance boost of 6x for the SHA256 hash-rate.

```console
$ hashcat -I
hashcat (v6.2.6) starting in backend information mode

OpenCL Info:
============

OpenCL Platform ID #1
  Vendor..: The pocl project
  Name....: Portable Computing Language
  Version.: OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG

  Backend Device ID #1
    Type...........: CPU
    Vendor.ID......: 128
    Vendor.........: GenuineIntel
    Name...........: cpu-haswell-Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
    Version........: OpenCL 3.0 PoCL HSTR: cpu-x86_64-pc-linux-gnu-haswell
    Processor(s)...: 12
    Clock..........: 4100
    Memory.Total...: 13559 MB (limited to 2048 MB allocatable in one block)
    Memory.Free....: 6747 MB
    Local.Memory...: 256 KB
    OpenCL.Version.: OpenCL C 1.2 PoCL
    Driver.Version.: 5.0+debian
    
$ hashcat -b
hashcat (v6.2.6) starting in benchmark mode
...
OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz, 6747/13559 MB (2048 MB allocatable), 12MCU

Benchmark relevant options:
===========================
* --optimized-kernel-enable

-------------------
* Hash-Mode 0 (MD5)
-------------------

Speed.#1.........:   906.3 MH/s (13.52ms) @ Accel:1024 Loops:1024 Thr:1 Vec:8

----------------------
* Hash-Mode 100 (SHA1)
----------------------

Speed.#1.........:   371.4 MH/s (32.72ms) @ Accel:1024 Loops:1024 Thr:1 Vec:8

---------------------------
* Hash-Mode 1400 (SHA2-256)
---------------------------

Speed.#1.........:   146.3 MH/s (42.84ms) @ Accel:1024 Loops:512 Thr:1 Vec:8
...
```

Installing Nvidia CUDA Compiler:

```text
$ nvcc
Command 'nvcc' not found, but can be installed with:
sudo apt install nvidia-cuda-toolkit
Do you want to install it? (N/y)y
sudo apt install nvidia-cuda-toolkit
...
0 upgraded, 63 newly installed, 0 to remove and 3 not upgraded.
Need to get 2,141 MB of archives.
After this operation, 6,768 MB of additional disk space will be used.
Do you want to continue? [Y/n] y
...
```

Retesting:

```text
$ hashcat -I
hashcat (v6.2.6) starting in backend information mode

CUDA Info:
==========

CUDA.Version.: 12.0

Backend Device ID #1 (Alias: #2)
  Name...........: NVIDIA GeForce GTX 1050 Ti with Max-Q Design
  Processor(s)...: 6
  Clock..........: 1417
  Memory.Total...: 4040 MB
  Memory.Free....: 3990 MB
  Local.Memory...: 48 KB
  PCI.Addr.BDFe..: 0000:01:00.0

OpenCL Info:
============

OpenCL Platform ID #1
  Vendor..: NVIDIA Corporation
  Name....: NVIDIA CUDA
  Version.: OpenCL 3.0 CUDA 12.0.151

  Backend Device ID #2 (Alias: #1)
    Type...........: GPU
    Vendor.ID......: 32
    Vendor.........: NVIDIA Corporation
    Name...........: NVIDIA GeForce GTX 1050 Ti with Max-Q Design
    Version........: OpenCL 3.0 CUDA
    Processor(s)...: 6
    Clock..........: 1417
    Memory.Total...: 4040 MB (limited to 1010 MB allocatable in one block)
    Memory.Free....: 3968 MB
    Local.Memory...: 48 KB
    OpenCL.Version.: OpenCL C 1.2
    Driver.Version.: 525.147.05
    PCI.Addr.BDF...: 01:00.0

OpenCL Platform ID #2
  Vendor..: The pocl project
  Name....: Portable Computing Language
  Version.: OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG

  Backend Device ID #3
    Type...........: CPU
    Vendor.ID......: 128
    Vendor.........: GenuineIntel
    Name...........: cpu-haswell-Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
    Version........: OpenCL 3.0 PoCL HSTR: cpu-x86_64-pc-linux-gnu-haswell
    Processor(s)...: 12
    Clock..........: 4100
    Memory.Total...: 13559 MB (limited to 2048 MB allocatable in one block)
    Memory.Free....: 6747 MB
    Local.Memory...: 256 KB
    OpenCL.Version.: OpenCL C 1.2 PoCL
    Driver.Version.: 5.0+debian

$ hashcat -b
hashcat (v6.2.6) starting in benchmark mode
...
CUDA API (CUDA 12.0)
====================
* Device #1: NVIDIA GeForce GTX 1050 Ti with Max-Q Design, 3990/4040 MB, 6MCU

OpenCL API (OpenCL 3.0 CUDA 12.0.151) - Platform #1 [NVIDIA Corporation]
========================================================================
* Device #2: NVIDIA GeForce GTX 1050 Ti with Max-Q Design, skipped

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #2 [The pocl project]
==================================================================================================================================================
* Device #3: cpu-haswell-Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz, skipped

Benchmark relevant options:
===========================
* --optimized-kernel-enable

-------------------
* Hash-Mode 0 (MD5)
-------------------

Speed.#1.........:  6829.5 MH/s (57.53ms) @ Accel:512 Loops:256 Thr:512 Vec:8

----------------------
* Hash-Mode 100 (SHA1)
----------------------

Speed.#1.........:  2338.9 MH/s (85.04ms) @ Accel:64 Loops:1024 Thr:512 Vec:1

---------------------------
* Hash-Mode 1400 (SHA2-256)
---------------------------

Speed.#1.........:   875.7 MH/s (56.38ms) @ Accel:8 Loops:1024 Thr:1024 Vec:1

---------------------------
* Hash-Mode 1700 (SHA2-512)
---------------------------

Speed.#1.........:   284.9 MH/s (43.36ms) @ Accel:128 Loops:64 Thr:256 Vec:1

-------------------------------------------------------------
* Hash-Mode 22000 (WPA-PBKDF2-PMKID+EAPOL) [Iterations: 4095]
-------------------------------------------------------------

Speed.#1.........:   117.5 kH/s (95.44ms) @ Accel:16 Loops:1024 Thr:512 Vec:1

-----------------------
* Hash-Mode 1000 (NTLM)
-----------------------
...
```

## AMD RX 6800

Raw notes:

- `sudo add-apt-repository multiverse && sudo apt update`
- `wget https://repo.radeon.com/amdgpu-install/6.2.0/ubuntu/jammy/amdgpu-install_6.2.60102-1_all.deb`
- `apt install ./amdgpu-install_6.4.60400-1_all.deb`
- `amdgpu-install --usecase=rocm,opencl --no-dkms --accept-eula`
- `sudo apt install rocm-opencl-runtime rocm-opencl rocm-opencl-dev`
- `sudo apt purge mesa-opencl-icd`

Much, much faster:

```text
$ hashcat -b
hashcat (v6.2.6) starting in benchmark mode

Benchmarking uses hand-optimized kernel code by default.
You can use it in your cracking session by setting the -O option.
Note: Using optimized kernel code limits the maximum supported password length.
To disable the optimized kernel code in benchmark mode, use the -w option.

OpenCL API (OpenCL 2.1 AMD-APP (3649.0)) - Platform #1 [Advanced Micro Devices, Inc.]
=====================================================================================
* Device #1: AMD Radeon RX 6800 XT, 16256/16368 MB (13912 MB allocatable), 36MCU

Benchmark relevant options:
===========================
* --optimized-kernel-enable

-------------------
* Hash-Mode 0 (MD5)
-------------------

Speed.#1.........: 52014.6 MH/s (22.69ms) @ Accel:128 Loops:1024 Thr:256 Vec:1

----------------------
* Hash-Mode 100 (SHA1)
----------------------

Speed.#1.........: 20129.8 MH/s (59.16ms) @ Accel:512 Loops:1024 Thr:64 Vec:1

---------------------------
* Hash-Mode 1400 (SHA2-256)
---------------------------

Speed.#1.........:  8509.5 MH/s (70.15ms) @ Accel:512 Loops:1024 Thr:32 Vec:1

---------------------------
* Hash-Mode 1700 (SHA2-512)
---------------------------

Speed.#1.........:  1997.5 MH/s (74.68ms) @ Accel:128 Loops:256 Thr:128 Vec:1

-------------------------------------------------------------
* Hash-Mode 22000 (WPA-PBKDF2-PMKID+EAPOL) [Iterations: 4095]
-------------------------------------------------------------

Speed.#1.........:  1028.6 kH/s (70.37ms) @ Accel:128 Loops:256 Thr:256 Vec:1

-----------------------
* Hash-Mode 1000 (NTLM)
-----------------------

Speed.#1.........: 95172.7 MH/s (12.38ms) @ Accel:128 Loops:1024 Thr:256 Vec:1
...
```