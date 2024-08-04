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