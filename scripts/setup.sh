#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!!]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; exit 1; }

echo "========================================"
echo "  eBPF QoS Research — First-time Setup"
echo "========================================"
echo ""

# ── 1. .env ─────────────────────────────────────────────────────────────────
if [ ! -f .env ]; then
  warn ".env not found — generating from .env.example"
  cp .env.example .env

  # สร้าง password แบบ random 24 ตัวอักษร
  if command -v openssl &>/dev/null; then
    PASS=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 24)
  else
    PASS=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 24)
  fi

  sed -i "s/change_me_strong_password_here/${PASS}/" .env
  ok ".env created with random DB_PASSWORD"
  warn "Password stored in .env (keep this file safe, it's not in git)"
else
  ok ".env already exists — skipping"
fi

# ตรวจว่า DB_PASSWORD ไม่ว่าง
DB_PASS=$(grep '^DB_PASSWORD=' .env | cut -d= -f2-)
if [ -z "$DB_PASS" ]; then
  err "DB_PASSWORD is empty in .env — please set a password and re-run"
fi

# ── 2. Directories ────────────────────────────────────────────────────────────
mkdir -p nginx/certs nginx/logs
ok "nginx/certs and nginx/logs directories ready"

# ── 3. SSL Certificate ────────────────────────────────────────────────────────
if [ ! -f nginx/certs/cert.pem ] || [ ! -f nginx/certs/key.pem ]; then
  warn "SSL certs not found — generating self-signed cert"

  # ดึง DOMAIN จาก .env ถ้ามี ถ้าไม่มีใช้ hostname
  DOMAIN=$(grep '^DOMAIN=' .env | cut -d= -f2- | tr -d '"')
  DOMAIN=${DOMAIN:-$(hostname -f 2>/dev/null || echo "localhost")}

  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout nginx/certs/key.pem \
    -out    nginx/certs/cert.pem \
    -subj   "/CN=${DOMAIN}" \
    -addext "subjectAltName=DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1" \
    2>/dev/null

  ok "Self-signed cert generated for: ${DOMAIN}"
  warn "To use a real cert: replace nginx/certs/cert.pem and nginx/certs/key.pem"
else
  ok "SSL certs already exist — skipping"
fi

# ── 4. Build & Start ──────────────────────────────────────────────────────────
echo ""
echo "Building and starting containers..."
sudo docker compose up -d --build

echo ""
ok "Done! App running at https://$(grep '^DOMAIN=' .env | cut -d= -f2- | tr -d '"' || echo 'localhost')"
warn "Browser will show SSL warning for self-signed cert — click Advanced → Proceed"
