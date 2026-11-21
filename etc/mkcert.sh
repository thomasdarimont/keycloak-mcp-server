#!/usr/bin/env bash
# Local HTTPS for the management UI with mkcert (https://github.com/FiloSottile/mkcert, `brew install mkcert`):
# installs mkcert's CA in the local trust stores once and writes a certificate for localhost into .certs/ (git-ignored).
# host.docker.internal is in it too: Keycloak in a container reaching the server on the host over HTTPS (JWKS).
#
#   etc/mkcert.sh [more host names]
#
# The server picks the files up with
#   QUARKUS_TLS_KEY_STORE_PEM_UI_CERT=.certs/localhost.pem QUARKUS_TLS_KEY_STORE_PEM_UI_KEY=.certs/localhost-key.pem
# (used by quarkus:dev with the management UI on HTTPS).
set -euo pipefail
cd "$(dirname "$0")/.."
command -v mkcert >/dev/null || { echo "mkcert not found: brew install mkcert (and nss for Firefox)"; exit 1; }
mkdir -p .certs
mkcert -install
mkcert -cert-file .certs/localhost.pem -key-file .certs/localhost-key.pem localhost 127.0.0.1 ::1 host.docker.internal "$@"
# the CA certificate, for containers that have to trust the certificate (a Keycloak fetching the server's JWKS over
# HTTPS, the server calling Keycloak): public, but git-ignored with the rest
cp "$(mkcert -CAROOT)/rootCA.pem" .certs/rootCA.pem
echo "wrote .certs/localhost.pem, .certs/localhost-key.pem and .certs/rootCA.pem (CA: $(mkcert -CAROOT))"
