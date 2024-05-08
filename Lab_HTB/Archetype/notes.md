* Run an nmap 

* Figured a smb share is open for anonymous auth 

* Connect to the SMB with the command `smbclient -N -L //10.129.136.136/` and saw a backup repo with a MSSQL credentials

* use impacket python script to connect to the mssql database with the command : `python3 ~/impacket/examples/mssqlclient.py  sql_svc:M3g4c0rp123@10.129.136.136 -p 1433 -windows-auth` 

* see the help with the help command 