#!/bin/bash
# สร้าง self-signed certificate สำหรับ development
# สำหรับ production ให้ใช้ Let's Encrypt แทน

set -e
CERTS_DIR="$(dirname "$0")/../nginx/certs"
mkdir -p "$CERTS_DIR"

if [ -f "$CERTS_DIR/cert.pem" ] && [ -f "$CERTS_DIR/key.pem" ]; then
  echo "Certificates already exist in $CERTS_DIR — skipping."
  echo "Delete them manually to regenerate."
  exit 0
fi

DOMAIN="${DOMAIN:-localhost}"
echo "Generating self-signed certificate for: $DOMAIN"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$CERTS_DIR/key.pem" \
  -out    "$CERTS_DIR/cert.pem" \
  -subj   "/C=TH/ST=KhonKaen/L=KhonKaen/O=KKU Research/CN=$DOMAIN" \
  -addext "subjectAltName=DNS:$DOMAIN,DNS:localhost,IP:127.0.0.1"

chmod 600 "$CERTS_DIR/key.pem"
echo "Done: $CERTS_DIR/cert.pem + key.pem"
echo ""
echo "For production, replace with real certificates from Let's Encrypt:"
echo "  certbot certonly --standalone -d your-domain.com"
echo "  cp /etc/letsencrypt/live/your-domain.com/fullchain.pem nginx/certs/cert.pem"
echo "  cp /etc/letsencrypt/live/your-domain.com/privkey.pem  nginx/certs/key.pem"
