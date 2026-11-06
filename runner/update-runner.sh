#!/usr/bin/env bash
# Update only the runner program on the executor VM. Keeps the runner token, the private-IP bind
# and the image digests pinned by push-images.sh. Run as root:
#   curl -fsSL https://raw.githubusercontent.com/Aashir01/receipts-agents/main/runner/update-runner.sh | bash
set -euo pipefail
SRC="${1:-https://raw.githubusercontent.com/Aashir01/receipts-agents/main}"
DIR=/opt/agentrush-runner
echo "==> Downloading the latest runner"
curl -fsSL "$SRC/runner/app.py" -o "$DIR/app.py.new"
python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$DIR/app.py.new"
cp "$DIR/app.py" "$DIR/app.py.bak" 2>/dev/null || true
mv "$DIR/app.py.new" "$DIR/app.py"
echo "==> Installing the signing library"
"$DIR/venv/bin/pip" install -q cryptography
echo "==> Restarting the runner"
systemctl restart agentrush-runner
sleep 3
BIND=$(grep '^RUNNER_BIND=' /etc/agentrush/runner.env | cut -d= -f2-)
curl -fsS "http://${BIND:-127.0.0.1}:8080/health" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("runner ok:", d.get("ok"), "| signs results:", d.get("signing"))
for k, v in (d.get("images") or {}).items():
    print(f"  {k}: {v.get(\"digest\", \"?\")[:90]}")'
echo "Done. Previous version kept at $DIR/app.py.bak"
