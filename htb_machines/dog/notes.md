# DOG machine easy

First enumeration with nmap found port 80 and 22.


enumeration with gobuster, found .git directory 

use git_dumper to dump everything, found a password in settings.php

searched for potential users, found tiffany admin.

this CMS is vulnerable to a CVE (added module to get backdoor)

found users in /etc/passwd and tried the same password found for one user to shh and it worked.

with sudo-l , i found it uses a php script with eval function init and i used this payload


```
sudo /usr/local/bin/bee --root=/var/www/html eval "echo shell_exec('su root -');"
```