# Deploy

## Initial setup on a fresh server

```bash
apt install -y python3 python3-pip git
pip install fastapi uvicorn httpx

cd /opt
git clone https://github.com/vvmmaann/nym-checker.git
cd nym-checker

# Main service
cp deploy/nym-checker.service /etc/systemd/system/
# Edit env vars in the unit (NYM_CHECKER_TOKEN etc), then:
systemctl daemon-reload
systemctl enable --now nym-checker
```

## Auto-deploy via GitHub webhook

1. Generate a random secret:

```bash
WEBHOOK_SECRET=$(openssl rand -hex 32)
echo "$WEBHOOK_SECRET"
```

2. Add to `nym-checker-webhook.service`, install:

```bash
cp deploy/nym-checker-webhook.service /etc/systemd/system/
nano /etc/systemd/system/nym-checker-webhook.service  # paste WEBHOOK_SECRET
systemctl daemon-reload
systemctl enable --now nym-checker-webhook
```

3. Open port 9999 on firewall (or reverse-proxy through your existing web server).

4. In GitHub: repo → Settings → Webhooks → Add webhook:
   - Payload URL: http://your-server:9999/webhook
   - Content type: application/json
   - Secret: (paste the same WEBHOOK_SECRET)
   - Events: Just the push event
   - Active: yes

After that every push to main auto-deploys within seconds.

## Manual deploy

```bash
bash /opt/nym-checker/deploy/deploy.sh
```
