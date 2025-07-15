#!/bin/bash

# Script to get Let's Encrypt certificates for cloud-computing.co

DOMAIN="cloud-computing.co"
EMAIL="your-email@example.com"  # Replace with your email

echo "Getting Let's Encrypt certificates for $DOMAIN..."
echo "Note: This requires:"
echo "  1. The domain $DOMAIN must point to this server"
echo "  2. Port 80 must be accessible from the internet"
echo "  3. Certbot must be installed (sudo apt install certbot)"
echo ""

# Check if certbot is installed
if ! command -v certbot &> /dev/null; then
    echo "certbot is not installed. Install it with:"
    echo "  sudo apt update && sudo apt install certbot"
    exit 1
fi

# Option 1: Standalone mode (requires port 80 to be free)
echo "Using standalone mode (requires port 80 to be free)..."
sudo certbot certonly --standalone -d $DOMAIN --non-interactive --agree-tos --email $EMAIL

if [ $? -eq 0 ]; then
    echo "Success! Certificates are in /etc/letsencrypt/live/$DOMAIN/"
    
    # Copy certificates to our certs directory
    echo "Copying certificates to local certs directory..."
    sudo cp /etc/letsencrypt/live/$DOMAIN/fullchain.pem ./server_chain.pem
    sudo cp /etc/letsencrypt/live/$DOMAIN/privkey.pem ./server.key
    sudo cp /etc/letsencrypt/live/$DOMAIN/cert.pem ./server.crt
    
    # Convert private key to PKCS#8 format
    sudo openssl pkcs8 -topk8 -nocrypt -in ./server.key -out ./server_pkcs8.key
    
    # Fix permissions
    sudo chown $USER:$USER server*.pem server*.key server*.crt
    chmod 600 server*.key
    
    echo "Certificates copied to certs directory!"
else
    echo "Failed to get certificates. Common issues:"
    echo "  - Port 80 is not accessible"
    echo "  - Domain doesn't point to this server"
    echo "  - Rate limits (try again later)"
fi