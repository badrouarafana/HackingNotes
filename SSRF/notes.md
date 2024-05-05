## Server side forgery request (SSRF)

Server-side request forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location.

In a case, we might have a website that requests an API for information, we might change the API link into localhost, and try to perform privileged operations.

example : 

    http://localhost/admin/delete?username=carlos

small bash script to realize that :

    for i in {1..255}; do
        curl  -X POST https://0a0100d603a48ce5814f89b400f0003b.web-security-academy.net/product/stock -d "stockApi=http%3a%2f%2f192.168.0.$i%3a8080%2fadmin%2fdelete%3fusername%3dcarlos" -o /dev/null -w "%{http_code}\n" -s
    done

## SSRF with blacklist-based input filters
Some applications block input containing hostnames like 127.0.0.1 and localhost, or sensitive URLs like /admin. In this situation, you can often circumvent the filter using the following techniques:

* Use an alternative IP representation of 127.0.0.1, such as 2130706433, 017700000001, or 127.1.
* Register your own domain name that resolves to 127.0.0.1. You can use spoofed.burpcollaborator.net for this purpose.
* Obfuscate blocked strings using URL encoding or case variation.
* Provide a URL that you control, which redirects to the target URL. Try using different redirect codes, as well as different protocols for the target URL. For example, switching from an http: to https: URL during the redirect has been shown to bypass some anti-SSRF filters.

Sometime, if it's still not working we might need to use some obfuscation example a =  %2561 // didn't know how nor why it work, need to see some obfuscation modules

some times we might add the evil url : example

    <url>&path=http://192.168.0.68/admin


## Blind SSRF vulnerabilities
Blind SSRF vulnerabilities occur if you can cause an application to issue a back-end HTTP request to a supplied URL, but the response from the back-end request is not returned in the application's front-end response.

Blind SSRF is harder to exploit but sometimes leads to full remote code execution on the server or other back-end components.

// for the lab, need to see in in HTB since burp collaborator is not for free :(

    