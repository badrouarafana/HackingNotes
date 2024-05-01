# API

## Discovering 
When discovering API, take a look into documenation , if it's not available, check well-known endpoints 

    /api
    /swagger/index.html
    /openapi.json

if an endpoint is identified try to investigate the base path, for instance :

    /api/swagger/v1
    /api/swagger
    /api

## API error

When pentensting api, check error for hints, for example : 

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
