# cognito-guacamole-extension
Integration between cognito and Apache Guacamole

This extension enforces a default connection for a known user for a Guacamole instance.
The authentication of the user is done against Cognito via a JWT token.

Since its expected that the container will have no internet access, the Cognito JKS can be
passed in as a base64 encoded string.

# Container environment variables

| Variable | Description |
|----------|-------------|
KEYSTORE_URL    | The Cognito keystore URL.
KEYSTORE_DATA   | The base64 encoding of the above URL's contents if there is no internet access.
VALIDATE_ISSUER | true/false. Whether to validate the issuer of the token (should be true for production).
ISSUER          | The issuer name to validate against.
CLIENT_PARAMS   | The connection parameters and VNC options.
CLIENT_USERNAME | The username this Guacamole instance is reserved for.

The github action builds and pushes the image to dockerhub dwpdigital/cognito-guacamole-extension
