# API

## Discovering 
When discovering API, take a look into documentation , if it's not available, check well-known endpoints 

    /api
    /swagger/index.html
    /openapi.json

if an endpoint is identified try to investigate the base path, for instance :

    /api/swagger/v1
    /api/swagger
    /api

## API error

When pentesting api, check error for hints, for example : 

    GET or PATCH API/products/1/price
the error we get : 

    {"type":"ClientError","code":400,"error":"Only 'application/json' Content-Type is supported"}

So here we know that we have to `Content-type: application/json` and the body as the payload.

## Preventing vulnerabilities in APIs
When designing APIs, make sure that security is a consideration from the beginning. In particular, make sure that you:

Secure your documentation if you don't intend your API to be publicly accessible.

Ensure your documentation is kept up to date so that legitimate testers have full visibility of the API's attack surface.
Apply an allowlist of permitted HTTP methods.

Validate that the content type is expected for each request or response.

Use generic error messages to avoid giving away information that may be useful for an attacker.

Use protective measures on all versions of your API, not just the current production version.

To prevent mass assignment vulnerabilities, allowlist the properties that can be updated by the user, and blocklist sensitive properties that shouldn't be updated by the user.

# Pollution in the query string
CTF chall

1. get the reset_toekn from the API `username=administrator%26field=reset_token`
2. use it to change admin password 
# Parameter pollution
Consider a similar example, but where the client-side user input is in JSON data. When you edit your name, your browser makes the following request:

    POST /myaccount
    {"name": "peter"}
This results in the following server-side request:

    PATCH /users/7312/update
    {"name":"peter"}
You can attempt to add the access_level parameter to the request as follows:

    POST /myaccount
    {"name": "peter\",\"access_level\":\"administrator"}
If the user input is decoded, then added to the server-side JSON data without adequate encoding, this results in the following server-side request:

    PATCH /users/7312/update
    {"name":"peter","access_level":"administrator"}
Again, this may result in the user peter being given administrator access.

Structured format injection can also occur in responses. For example, this can occur if user input is stored securely in a database, then embedded into a JSON response from a back-end API without adequate encoding. You can usually detect and exploit structured format injection in responses in the same way you can in requests.