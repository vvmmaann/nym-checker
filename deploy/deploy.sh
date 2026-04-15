#!/bin/bash
# Pulls latest from git origin/main and restarts the service.
# Invoked by systemd path unit, cron, or webhook.
set -euo pipefail
cd /opt/nym-checker
echo "[$(date -u +%FT%TZ)] pulling..."
git fetch --quiet origin main
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)
if [ "$LOCAL" = "$REMOTE" ]; then
  echo "already up to date ($LOCAL)"
  exit 0
fi
git reset --hard origin/main
echo "updated: $LOCAL -> $REMOTE"
systemctl restart nym-checker
echo "service restarted"
