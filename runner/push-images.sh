#!/usr/bin/env bash
# Push the sandbox, browser and egress images to a Vultr Container Registry and pin the runner to
# their exact digests. Run on the executor VM after `docker login <registry host>`.
# The script logs out again at the end, so the executor keeps holding no secrets.
# Usage: bash /opt/agentrush-runner/push-images.sh atl.vultrcr.com/countersign
set -euo pipefail
REG="${1:?usage: push-images.sh <registry, for example atl.vultrcr.com/countersign>}"
HOST="${REG%%/*}"
TAG="$(date -u +%Y%m%d-%H%M)"
ENVF=/etc/agentrush/runner.env
declare -A VAR=([agentrush-sandbox]=SANDBOX_IMAGE [agentrush-browser]=BROWSER_IMAGE [agentrush-egress]=EGRESS_IMAGE)
for img in agentrush-sandbox agentrush-browser agentrush-egress; do
  echo "==> $img"
  docker tag "$img:latest" "$REG/$img:$TAG"
  docker push -q "$REG/$img:$TAG" >/dev/null
  DIGEST="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$REG/$img:$TAG" | grep "^$REG/$img@sha256:" | head -1)"
  if [ -z "$DIGEST" ]; then echo "ERROR: no digest for $img" >&2; exit 1; fi
  if grep -q "^${VAR[$img]}=" "$ENVF"; then
    sed -i "s#^${VAR[$img]}=.*#${VAR[$img]}=$DIGEST#" "$ENVF"
  else
    echo "${VAR[$img]}=$DIGEST" >> "$ENVF"
  fi
  echo "    pinned $DIGEST"
done
docker logout "$HOST" >/dev/null 2>&1 || true
rm -f /root/.docker/config.json
systemctl restart agentrush-runner
sleep 3
echo
echo "Runner now uses images pinned by digest. Registry credentials removed from this VM."
grep -E '^(SANDBOX|BROWSER|EGRESS)_IMAGE=' "$ENVF"
