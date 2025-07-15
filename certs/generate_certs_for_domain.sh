#!/bin/bash

# Generate self-signed certificates for cloud-computing.co

DOMAIN="cloud-computing.co"

echo "Generating self-signed certificates for $DOMAIN..."

# Create a config file for the certificate with SANs
cat > cert.conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Test
L = Test
O = Cloud Computing
CN = $DOMAIN

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = www.$DOMAIN
DNS.3 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate private key
openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048

# Generate certificate with the config
openssl req -new -x509 -key server.key -out server.crt -days 365 -config cert.conf -extensions v3_req

# Convert to PKCS#8 format
openssl pkcs8 -topk8 -nocrypt -in server.key -out server_pkcs8.key

# Create certificate chain
cp server.crt server_chain.pem

# Clean up
rm cert.conf

echo "Certificates generated:"
echo "  - server.crt: Server certificate for $DOMAIN"
echo "  - server.key: Server private key (PKCS#1)"
echo "  - server_pkcs8.key: Server private key (PKCS#8)"
echo "  - server_chain.pem: Certificate chain"
echo ""
echo "Note: These are self-signed certificates. For production, use Let's Encrypt."