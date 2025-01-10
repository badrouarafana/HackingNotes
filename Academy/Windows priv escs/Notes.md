## Starting

Check network information
```powershell
ipconfig /all 
arp -a
route print
```

Check windows defender status
```powershell-session
Get-MpComputerStatus
```

List AppLocker rules 
```powershell-session
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

Test AppLocker policy to check if cmd is denied by the policy
```powershell-session
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
```

To check for other thing we can modify the command for example:
```
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -Path C:\*\*\*\*\*.exe -User Everyone
```

## Initial Enumeration
Get running tasks:

```powershell
tasklist /svc
```

Get env variable and system info

```
set
systeminfo
```

If `systeminfo` doesn't display hotfixes, they may be queriable with [WMI](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)
```cmd-session
wmic qfe
```

We can do this with PowerShell as well using the [Get-Hotfix](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix?view=powershell-7.1) cmdlet.

```powershell-session
PS C:\htb> Get-HotFix | ft -AutoSize
```

Check installed softwares and versions.
```powershell-session
Get-WmiObject -Class Win32_Product |  select Name, Version
```

Then comes favorite part, checking for open services 
```cmd-session
netstat -ano
```

Current  user's info
```powershell
query user
echo %USERNAME%
whoami /priv
whoami /groups
```

Knowing what other users are on the system is important as well. If we gained RDP access to a host using credentials we captured for a user `bob`, and see a `bob_adm` user in the local administrators group, it is worth checking for credential re-use
using net commands 

```cmd-session
net user
```

Knowing what non-standard groups are present on the host can help us determine what the host is used for, how heavily accessed it is, or may even lead to discovering a misconfiguration such as all Domain Users in the Remote Desktop or local administrators groups.
```cmd-session
net localgroup
```

and to have further info about a specific group and its users 
```cmd-session
net localgroup administrators
```