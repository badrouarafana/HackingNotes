# XSS

Cross-site scripting (also known as XSS) is a web security vulnerability that allows an attacker to compromise the interactions that users have with a vulnerable application.

# XSS payloads

for decades the most common payload to doscover the xss vulns was `alert()`, but since 2021 and if chrome is used, the new payload used is `print()`

# Types of XSS

 Reflected XSS, where the malicious script comes from the current HTTP request.

    
    https://insecure-website.com/status?message=All+is+well.
    <p>Status: All is well.</p>
The application doesn't perform any other processing of the data, so an attacker can easily construct an attack like this:

    https://insecure-website.com/status?message=<script>/*+Bad+stuff+here...+*/</script>
    <p>Status: <script>/* Bad stuff here... */</script></p>


Stored XSS, where the malicious script comes from the website's database.

 DOM (document object model)-based XSS, where the vulnerability exists in client-side code rather than server-side code.

 In the following example, an application uses some JavaScript to read the value from an input field and write that value to an element within the HTML:

    var search = document.getElementById('search').value;
    var results = document.getElementById('results');
    results.innerHTML = 'You searched for: ' + search;

If the attacker can control the value of the input field, they can easily construct a malicious value that causes their own script to execute:

    You searched for: <img src=1 onerror='/* Bad stuff here... */'>
    
In a typical case, the input field would be populated from part of the HTTP request, such as a URL query string parameter, allowing the attacker to deliver an attack using a malicious URL, in the same manner as reflected XSS.