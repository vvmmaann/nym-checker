# Tiny HMAC-verified GitHub webhook receiver.
# Run under systemd on port 9999 and add a reverse-proxy /webhook -> 127.0.0.1:9999,
# or put it on its own public port behind a firewall rule that only allows GitHub IPs.
# Env: WEBHOOK_SECRET (HMAC shared secret), DEPLOY_SCRIPT (absolute path).

import hashlib, hmac, json, os, subprocess, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

SECRET = os.environ.get('WEBHOOK_SECRET', '').encode()
DEPLOY_SCRIPT = os.environ.get('DEPLOY_SCRIPT', '/opt/nym-checker/deploy/deploy.sh')
PORT = int(os.environ.get('WEBHOOK_PORT', '9999'))

if not SECRET:
    print('ERROR: set WEBHOOK_SECRET env var', file=sys.stderr)
    sys.exit(1)

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != '/webhook':
            self.send_response(404); self.end_headers(); return
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length)
        sig_header = self.headers.get('X-Hub-Signature-256', '')
        if not sig_header.startswith('sha256='):
            self.send_response(400); self.end_headers(); self.wfile.write(b'no sig'); return
        sent_sig = sig_header.split('=',1)[1]
        expected = hmac.new(SECRET, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sent_sig, expected):
            self.send_response(403); self.end_headers(); self.wfile.write(b'bad sig'); return
        event = self.headers.get('X-GitHub-Event', '')
        try:
            payload = json.loads(body)
        except Exception:
            payload = {}
        if event == 'ping':
            self.send_response(200); self.end_headers(); self.wfile.write(b'pong'); return
        if event == 'push' and payload.get('ref') == 'refs/heads/main':
            Thread(target=lambda: subprocess.run([DEPLOY_SCRIPT], check=False), daemon=True).start()
            self.send_response(202); self.end_headers(); self.wfile.write(b'deploying')
            return
        self.send_response(204); self.end_headers()

    def log_message(self, fmt, *args):
        print(f'[webhook] {self.address_string()} - {fmt%args}')

if __name__ == '__main__':
    print(f'[webhook] listening on 0.0.0.0:{PORT} -> {DEPLOY_SCRIPT}')
    HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
