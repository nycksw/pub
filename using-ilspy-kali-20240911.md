---
tags:
  - hack
  - linux
---
# Using ILSpy on Kali

[ILSpy](https://github.com/icsharpcode/ILSpy) is a .NET decompiler.

This worked on Kali 2024.3.

```console
# lsb_release -a
No LSB modules are available.
Distributor ID: Kali
Description:    Kali GNU/Linux Rolling
Release:        2024.3
Codename:       kali-rolling
```

That version of Kali ships with SDK version 6.0.400, which won't work for ILSpy:

```console
$ dotnet --list-sdks
6.0.400 [/usr/share/dotnet/sdk]
```

So, to install the updated SDK I'll add the Microsoft repository:

```console
$ wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
--2024-09-11 09:35:15--  https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb
Resolving packages.microsoft.com (packages.microsoft.com)... 13.107.246.41, 2620:1ec:bdf::41
Connecting to packages.microsoft.com (packages.microsoft.com)|13.107.246.41|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4304 (4.2K) [application/octet-stream]
Saving to: ‘packages-microsoft-prod.deb’

packages-microsoft-prod.deb                  100%[=============================================================================================>]   4.20K  --.-KB/s    in 0s

2024-09-11 09:35:16 (173 MB/s) - ‘packages-microsoft-prod.deb’ saved [4304/4304]

$ sudo dpkg -i packages-microsoft-prod.deb

Selecting previously unselected package packages-microsoft-prod.
(Reading database ... 498060 files and directories currently installed.)
Preparing to unpack packages-microsoft-prod.deb ...
Unpacking packages-microsoft-prod (1.1-debian12) ...
Setting up packages-microsoft-prod (1.1-debian12) ...

$ sudo apt update
...
```

And then install `dotnet-sdk-8.0`:

```text
$ sudo apt install dotnet-sdk-8.0
Upgrading:
  dotnet-host

Installing:
  dotnet-sdk-8.0

Installing dependencies:
  aspnetcore-runtime-8.0  aspnetcore-targeting-pack-8.0  dotnet-apphost-pack-8.0  dotnet-hostfxr-8.0  dotnet-runtime-8.0  dotnet-runtime-deps-8.0  dotnet-targeting-pack-8.0

Summary:
  Upgrading: 1, Installing: 8, Removing: 0, Not Upgrading: 312
  Download size: 138 MB
  Space needed: 557 MB / 169 GB available
```

Verifying that the new SDK is available:

```console
$ dotnet --list-sdks
6.0.400 [/usr/share/dotnet/sdk]
8.0.401 [/usr/share/dotnet/sdk]
```

Now I'll grab the repository for ILSpy:

```console
$ git clone https://github.com/icsharpcode/ILSpy.git && cd ILSpy
Cloning into 'ILSpy'...
remote: Enumerating objects: 78805, done.
remote: Counting objects: 100% (1744/1744), done.
remote: Compressing objects: 100% (740/740), done.
remote: Total 78805 (delta 1170), reused 1414 (delta 1002), pack-reused 77061 (from 1)
Receiving objects: 100% (78805/78805), 41.71 MiB | 233.00 KiB/s, done.
Resolving deltas: 100% (63001/63001), done.
```

Here is the commit I used for this:

```text
$ git rev-parse --short HEAD
533a77379
```

PowerShell is a requirement for ILSpy, so I'll check that it's installed:

```text
$ pwsh --version
PowerShell 7.2.6
```

Now I'll grab the submodules:

```console
$ git submodule update --init --recursive
Submodule 'ILSpy-tests' (https://github.com/icsharpcode/ILSpy-tests) registered for path 'ILSpy-tests'
Cloning into '/home/e/src/ILSpy/ILSpy-tests'...
Submodule path 'ILSpy-tests': checked out '6f8860e420b54bdfd726ec3c58a4d178416f9156'
```

And then I can build the non-Windows version of ILSpy:

```console
$ dotnet build ILSpy.XPlat.slnf

Welcome to .NET 8.0!
---------------------
SDK Version: 8.0.401

----------------
Installed an ASP.NET Core HTTPS development certificate.
To trust the certificate, view the instructions: https://aka.ms/dotnet-https-linux

----------------
Write your first app: https://aka.ms/dotnet-hello-world
Find out what's new: https://aka.ms/dotnet-whats-new
Explore documentation: https://aka.ms/dotnet-docs
Report issues and find source on GitHub: https://github.com/dotnet/core
Use 'dotnet --help' to see available commands or visit: https://aka.ms/dotnet-cli
--------------------------------------------------------------------------------------
An issue was encountered verifying workloads. For more information, run "dotnet workload update".
  Determining projects to restore...
  Restored /home/e/src/ILSpy/ICSharpCode.Decompiler.TestRunner/ICSharpCode.Decompiler.TestRunner.csproj (in 2.94 sec).
  Restored /home/e/src/ILSpy/ICSharpCode.ILSpyX/ICSharpCode.ILSpyX.csproj (in 9.8 sec).
  Restored /home/e/src/ILSpy/ICSharpCode.Decompiler.PowerShell/ICSharpCode.Decompiler.PowerShell.csproj (in 16.17 sec).
  Restored /home/e/src/ILSpy/ICSharpCode.Decompiler/ICSharpCode.Decompiler.csproj (in 47.6 sec).
  Restored /home/e/src/ILSpy/ICSharpCode.ILSpyCmd/ICSharpCode.ILSpyCmd.csproj (in 48.98 sec).
  Restored /home/e/src/ILSpy/ICSharpCode.Decompiler.Tests/ICSharpCode.Decompiler.Tests.csproj (in 1.93 min).
  533a773791f9186f624244ed9d0ebbfbaaf996ad
  ILSpyUpdateAssemblyInfo2089394407
  ICSharpCode.Decompiler.TestRunner -> /home/e/src/ILSpy/ICSharpCode.Decompiler.TestRunner/bin/Debug/net8.0/ICSharpCode.Decompiler.TestRunner.dll
  ICSharpCode.Decompiler -> /home/e/src/ILSpy/ICSharpCode.Decompiler/bin/Debug/netstandard2.0/ICSharpCode.Decompiler.dll
  ICSharpCode.Decompiler.PowerShell -> /home/e/src/ILSpy/ICSharpCode.Decompiler.PowerShell/bin/Debug/netstandard2.0/ICSharpCode.Decompiler.PowerShell.dll
  Successfully created package '/home/e/src/ILSpy/ICSharpCode.Decompiler/bin/Debug/ICSharpCode.Decompiler.9.0.0.7755-preview2.nupkg'.
  ICSharpCode.ILSpyX -> /home/e/src/ILSpy/ICSharpCode.ILSpyX/bin/Debug/net8.0/ICSharpCode.ILSpyX.dll
  533a773791f9186f624244ed9d0ebbfbaaf996ad
  Successfully created package '/home/e/src/ILSpy/ICSharpCode.ILSpyX/bin/Debug/ICSharpCode.ILSpyX.9.0.0.7755-preview2.nupkg'.
  ICSharpCode.ILSpyCmd -> /home/e/src/ILSpy/ICSharpCode.ILSpyCmd/bin/Debug/net8.0/ilspycmd.dll
  Successfully created package '/home/e/src/ILSpy/ICSharpCode.ILSpyCmd/bin/Debug/ilspycmd.9.0.0.7755-preview2.nupkg'.
  ICSharpCode.Decompiler.Tests -> /home/e/src/ILSpy/ICSharpCode.Decompiler.Tests/bin/Debug/net8.0-windows/ICSharpCode.Decompiler.Tests.dll

Build succeeded.
    0 Warning(s)
    0 Error(s)

Time Elapsed 00:02:12.18
```

Finally, I'm able to decompile an assembly to stdout, like so:

```console
$ ./ICSharpCode.ILSpyCmd/bin/Debug/net8.0/ilspycmd ~/htb-cascade/CascAudit.exe
using System;
using System.CodeDom.Compiler;
using System.ComponentModel;
using System.ComponentModel.Design;
using System.Configuration;
...
```
