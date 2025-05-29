# API

## Discovering APIs
When discovering APIs, check the documentation first. If it's not available, investigate well-known endpoints such as:

    /api
    /swagger/index.html
    /openapi.json

If an endpoint is identified, try to investigate the base path. Examples include:

    /api/swagger/v1
    /api/swagger
    /api

## API Errors
When pentesting APIs, analyze error messages for hints. For example:

    GET or PATCH API/products/1/price

If the error returned is:

    {"type":"ClientError","code":400,"error":"Only 'application/json' Content-Type is supported"}

This indicates that the `Content-Type` header must be set to `application/json`, and the body should contain the payload.

## Preventing Vulnerabilities in APIs
When designing APIs, ensure security is a priority from the start. Key considerations include:

- **Secure Documentation**: Protect your documentation if the API is not intended to be publicly accessible.
- **Keep Documentation Updated**: Ensure legitimate testers have full visibility of the API's attack surface.
- **Restrict HTTP Methods**: Apply an allowlist of permitted HTTP methods.
- **Validate Content Types**: Ensure the content type is as expected for each request or response.
- **Use Generic Error Messages**: Avoid revealing information that could aid attackers.
- **Protect All API Versions**: Apply security measures to all versions, not just the current production version.
- **Prevent Mass Assignment**: Allowlist properties that can be updated by users and blocklist sensitive properties.

## Query String Pollution (CTF Challenge)
1. Retrieve the `reset_token` from the API using a polluted query string:
    ```
    username=administrator%26field=reset_token
    ```
2. Use the token to reset the administrator's password.

## Parameter Pollution
Consider an example where user input is sent in JSON data. For instance:

    POST /myaccount
    {"name": "peter"}

This results in the following server-side request:

    PATCH /users/7312/update
    {"name":"peter"}

You can attempt to inject additional parameters, such as `access_level`, as follows:

    POST /myaccount
    {"name": "peter\",\"access_level\":\"administrator"}

If the input is improperly sanitized, the server-side request may look like this:

    PATCH /users/7312/update
    {"name":"peter","access_level":"administrator"}

This could result in the user `peter` being granted administrator access.

### Structured Format Injection in Responses
Structured format injection can also occur in API responses. For example, if user input is securely stored in a database but embedded into a JSON response without proper encoding, it can lead to vulnerabilities. Detect and exploit these issues in responses similarly to how you would in requests.