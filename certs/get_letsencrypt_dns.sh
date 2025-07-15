#!/bin/bash

# Alternative: Get Let's Encrypt certificates using DNS challenge
# This doesn't require port 80 to be open

DOMAIN="cloud-computing.co"
EMAIL="your-email@example.com"  # Replace with your email

echo "Getting Let's Encrypt certificates for $DOMAIN using DNS challenge..."
echo "This method requires you to add TXT records to your DNS."
echo ""

# Check if certbot is installed
if ! command -v certbot &> /dev/null; then
    echo "certbot is not installed. Install it with:"
    echo "  sudo apt update && sudo apt install certbot"
    exit 1
fi

# Use manual DNS challenge
echo "Running certbot with DNS challenge..."
sudo certbot certonly --manual --preferred-challenges dns -d $DOMAIN --non-interactive --agree-tos --email $EMAIL

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
fi