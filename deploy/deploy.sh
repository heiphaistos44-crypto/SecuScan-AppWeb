#!/bin/bash
# deploy.sh — Déploiement SecuScan Web sur VPS Debian 13
# Usage : exécuter SUR le VPS depuis /opt/secuscan
set -euo pipefail

APP_DIR="/opt/secuscan"
LOG() { echo "[$(date -Iseconds)] [INFO] $*"; }

cd "$APP_DIR"

# ── 1. Rust toolchain ──────────────────────────────────────────────
if ! command -v cargo >/dev/null 2>&1; then
    source "$HOME/.cargo/env" 2>/dev/null || {
        LOG "Installation rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    }
fi

# ── 2. Build serveur (yara-x : compile longue au 1er build) ────────
LOG "cargo build --release..."
cd "$APP_DIR/server"
cargo build --release
LOG "Binaire : $APP_DIR/server/target/release/secuscan-server"

# ── 3. Build frontend ──────────────────────────────────────────────
LOG "Build frontend Vue..."
cd "$APP_DIR/web"
npm ci --prefer-offline
npm run build
LOG "Frontend buildé dans $APP_DIR/web/dist"

# ── 4. PM2 ─────────────────────────────────────────────────────────
cd "$APP_DIR"
if pm2 describe secuscan >/dev/null 2>&1; then
    LOG "Restart PM2 secuscan..."
    pm2 restart secuscan --update-env
else
    LOG "Création process PM2 secuscan (port 3005)..."
    STATIC_DIR="$APP_DIR/web/dist" \
    PORT=3005 \
    pm2 start "$APP_DIR/server/target/release/secuscan-server" --name secuscan
    pm2 save
fi

# ── 5. Vérification ────────────────────────────────────────────────
sleep 2
curl -fsS http://127.0.0.1:3005/api/health && echo "" && LOG "Déploiement OK ✅"
