# SMB
already done previously.

In windows example with DIR

    C:\htb> dir \\192.168.220.129\Finance\

In windows example with net use

    net use n: \\192.168.220.129\Finance

We can add the password in it as well.

    net use n: \\192.168.220.129\Finance /user:plaintext Password123

Using Powershell

    Get-ChildItem \\192.168.220.129\Finance\
using new-PSDrive instead of net use 

    New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"

With password, it's getting quite complicated 

    PS C:\htb> $username = 'plaintext'
    PS C:\htb> $password = 'Password123'
    PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
    PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
    PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

Using Linux we can use the mount command.
We create a mount directory and mount the samba share.

    MysterPedro@htb[/htb]$ sudo mkdir /mnt/Finance
    MysterPedro@htb[/htb]$ sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance

# Databases:
## MSSQL


Best use dbeaver, I think it's great to have a database GUI.
or in command line linux use : 

    sqsh -S 10.129.20.13 -U username -P Password123

Windows:

    sqlcmd -S 10.129.20.13 -U username -P Password123