# Introduction to Linux Privilege Escalation


when we audit a linux system we have to look for the OS version, the Kernel version, and running services

to have root processes

```sh
ps aux | grep root
```

also Installed Packages and Versions, Logged in users

try to ls home ...etc

look for ssh keys 

```sh
ls -l ~/.ssh
```

bash history 
try `sudo -l`

try to read /etc/passwd maybe we can find a hash 
See cron JOBs that's what i need to see.

```sh
ls -la /etc/cron.daily/
```
File Systems & Additional Drives wirh `lsblk`

Set uid and getgid and writable permission files 
```bash
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
```
for files 
```sh
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```
## OS info 

```bash
cat /cat /etc/os-release
echo $PATH
env
uname -a
lscpu  # cpu version
cat /etc/shells
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student # hidden files
find / -type d -name ".*" -ls 2>/dev/null # hidden directories
ls -l /tmp /var/tmp /dev/shm
```
## Linux Services & Internals Enumeration

check ip a and ip route 

cat /etc/hosts

check lastlogs

check this command w and history
check if there is any history file

```bash
find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null
```

check the crontab

    ls -la /etc/cron.daily/


good command t check for gtobin and installed packets 

```bash
for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done
```

look for configuration files 

```bash
find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null
```

find scripts 
```bash
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"
```