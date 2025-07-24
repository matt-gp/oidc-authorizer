# oidc-authorizer

oidc-authorizer is a golang application which is run as an Api Gateway lambda authorizer. It is able to dynamically work with v1/v2/webhook payloads without the need for confiugration.

## Env Vars
 * `ACCEPTED_ISSUERS` - The Accepted Issuers.
 * `JWKS_URI` - The URI of the Java Web KeyStore.
 * `PRINCIPAL_ID_CLAIMS` - The principal id claims, default `sub`.
 * `LOG_LEVEL` - log level to use, default `info`.
