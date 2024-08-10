# FTP
file transfer protocol runs on layer 7 of TCP/IP stack on port 21 and used to upload files.

The most used ftp in linux servers is vsFTPd, and default conf is located in ``
The most used ftp in linux servers is vsFTPd, and default conf is located in `/etc/vsftpd.conf`

a command to see common configurations : `cat /etc/vsftpd.conf | grep -v "#"` 

| Option                       | Description                                                                  |
|------------------------------|------------------------------------------------------------------------------|
| listen=NO                    | Run from inetd or as a standalone daemon?                                     |
| listen_ipv6=YES              | Listen on IPv6 ?                                                             |
| anonymous_enable=NO          | Enable Anonymous access?                                                     |
| local_enable=YES             | Allow local users to login?                                                  |
| dirmessage_enable=YES        | Display active directory messages when users go into certain directories?    |
| use_localtime=YES            | Use local time?                                                              |
| xferlog_enable=YES           | Activate logging of uploads/downloads?                                       |
| connect_from_port_20=YES     | Connect from port 20?                                                        |
| secure_chroot_dir=/var/run/vsftpd/empty | Name of an empty directory                                        |
| pam_service_name=vsftpd      | This string is the name of the PAM service vsftpd will use.                  |
| rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem | The last three options specify the location of the RSA certificate to use for SSL encrypted connections. |
| rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key |                                              |
| ssl_enable=NO                |                                                                              |
## Dangerouse setting  

| Option                         | Description                                                                  |
|--------------------------------|------------------------------------------------------------------------------|
| anonymous_enable=YES           | Allowing anonymous login?                                                    |
| anon_upload_enable=YES         | Allowing anonymous to upload files?                                          |
| anon_mkdir_write_enable=YES    | Allowing anonymous to create new directories?                                |
| no_anon_password=YES           | Do not ask anonymous for password?                                           |
| anon_root=/home/username/ftp   | Directory for anonymous.                                                     |
| write_enable=YES               | Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE? |


this file `/etc/ftpusers` specify the blacklist users.

Download all available files with wget 

    wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136

if ftp is using ssl this is the command to connect 

    openssl s_client -connect 10.129.14.136:21 -starttls ftp

# SMB
Server Message Block (SMB) is a client-server protocol that regulates access to files and entire directories and other network resources such as printers, routers, or interfaces released for the network
in linux version it runs on 137,138,139 over TCP

    or with smb client 
interesting command `rpcclient`

    rpcclient -U "" 10.129.14.128

| Option                  | Description                                                   |
|-------------------------|---------------------------------------------------------------|
| srvinfo                 | Server information.                                           |
| enumdomains             | Enumerate all domains that are deployed in the network.       |
| querydominfo            | Provides domain, server, and user information of deployed domains. |
| netshareenumall         | Enumerates all available shares.                              |
| netsharegetinfo <share> | Provides information about a specific share.                  |
| enumdomusers            | Enumerates all domain users.                                  |
| queryuser <RID>         | Provides information about a specific user.                   |

Example 

    SMB
    rpcclient $> enumdomusers

    user:[mrb3n] rid:[0x3e8]
    user:[cry0l1t3] rid:[0x3e9]

    rpcclient $> queryuser 0x3e9
    rpcclient $> queryuser 0x3e8

    querygroup 0x201

a way to brute force user's RIDs 

    MysterPedro@htb[/htb]$ for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

or using a script 

    crackmapexec smb 10.129.14.128 --shares -u '' -p ''


# NSF
NFS runs on tcp 1111 and 2049 by default, to run the scan with nmap use this script 

    sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049

## Settings

Setting in `/etc/export`, and it's easy to set up

| Option               | Description                                                                                           |
|----------------------|-------------------------------------------------------------------------------------------------------|
| rw                   | Read and write permissions.                                                                           |
| ro                   | Read only permissions.                                                                                |
| sync                 | Synchronous data transfer. (A bit slower)                                                             |
| async                | Asynchronous data transfer. (A bit faster)                                                            |
| secure               | Ports above 1024 will not be used.                                                                    |
| insecure             | Ports above 1024 will be used.                                                                        |
| no_subtree_check     | This option disables the checking of subdirectory trees.                                              |
| root_squash          | Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents root from accessing files on an NFS mount. |

## Dangerous setting 

| Option            | Description                                                                                           |
|-------------------|-------------------------------------------------------------------------------------------------------|
| rw                | Read and write permissions.                                                                           |
| insecure          | Ports above 1024 will be used.                                                                        |
| nohide            | If another file system was mounted below an exported directory, this directory is exported by its own exports entry. |
| no_root_squash    | All files created by root are kept with the UID/GID 0.                                                |

    root@nfs:~# echo '/mnt/nfs  10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports
    root@nfs:~# systemctl restart nfs-kernel-server 
    root@nfs:~# exportfs

    /mnt/nfs      	10.129.14.0/24

To show available shares 

    showmount -e 10.129.14.128

Mounting NFS Share

    MysterPedro@htb[/htb]$ mkdir target-NFS
    MysterPedro@htb[/htb]$ sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
    MysterPedro@htb[/htb]$ cd target-NFS
    MysterPedro@htb[/htb]$ tree .

# DNS

| DNS Record | Description                                                                                                                                                                                                                      |
|------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| A          | Returns an IPv4 address of the requested domain as a result.                                                                                                                                                                     |
| AAAA       | Returns an IPv6 address of the requested domain.                                                                                                                                                                                 |
| MX         | Returns the responsible mail servers as a result.                                                                                                                                                                                |
| NS         | Returns the DNS servers (nameservers) of the domain.                                                                                                                                                                             |
| TXT        | This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam. |
| CNAME      | This record serves as an alias for another domain name. If you want the domain www.hackthebox.eu to point to the same IP as hackthebox.eu, you would create an A record for hackthebox.eu and a CNAME record for www.hackthebox.eu.  |
| PTR        | The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.                                                                                                                   |
| SOA        | Provides information about the corresponding DNS zone and email address of the administrative contact.                                                                                                               |

bruteforcing a subdomain

    MysterPedro@htb[/htb]$ for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done
or with DNSenum

dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb

# MSSQL

use metasploit module `scanner/mssql/mssql_ping`

or this command `python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth`

# WINRM

    MysterPedro@htb[/htb]$ evil-winrm -i 10.129.201.248 -u Cry0l1t3 -p P455w0rD!
    
    /usr/share/doc/python3-impacket/examples/wmiexec.py Cry0l1t3:"P455w0rD!"@10.129.201.248 "hostname"