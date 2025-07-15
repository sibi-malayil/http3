#!/bin/bash

# Generate self-signed certificates for HTTP/3 testing

echo "Generating self-signed certificates for localhost..."

# Generate private key
openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048

# Generate certificate signing request
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=Test/L=Test/O=HTTP3 Test/CN=localhost"

# Generate self-signed certificate (valid for 365 days)
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

# Convert to PKCS#8 format (which rustls prefers)
openssl pkcs8 -topk8 -nocrypt -in server.key -out server_pkcs8.key

# Create a certificate chain file (for self-signed, it's just the certificate)
cp server.crt server_chain.pem

# Clean up CSR
rm server.csr

echo "Certificates generated:"
echo "  - server.crt: Server certificate"
echo "  - server.key: Server private key (PKCS#1)"
echo "  - server_pkcs8.key: Server private key (PKCS#8)"
echo "  - server_chain.pem: Certificate chain"

# Generate client certificates (optional, for mutual TLS)
echo -e "\nGenerating client certificates..."

openssl genpkey -algorithm RSA -out client.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key client.key -out client.csr -subj "/C=US/ST=Test/L=Test/O=HTTP3 Test Client/CN=client"
openssl x509 -req -days 365 -in client.csr -signkey client.key -out client.crt
openssl pkcs8 -topk8 -nocrypt -in client.key -out client_pkcs8.key
rm client.csr

echo "  - client.crt: Client certificate"
echo "  - client.key: Client private key (PKCS#1)"
echo "  - client_pkcs8.key: Client private key (PKCS#8)"

echo -e "\nDone!"