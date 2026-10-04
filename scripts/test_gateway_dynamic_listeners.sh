#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/xshield-gateway-listeners.XXXXXX")
origin_pid=""
gateway_pid=""

cleanup() {
    status=$?
    if [[ "$status" != "0" ]]; then
        sed -n '1,160p' "$test_dir/gateway.log" 2>/dev/null || true
        sed -n '1,80p' "$test_dir/origin.log" 2>/dev/null || true
    fi
    [[ -z "$gateway_pid" ]] || kill -KILL "$gateway_pid" 2>/dev/null || true
    [[ -z "$origin_pid" ]] || kill "$origin_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
    wait "$origin_pid" 2>/dev/null || true
    rm -rf -- "$test_dir"
}
trap cleanup EXIT INT TERM

free_port() {
    python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

origin_port=$(free_port)
bootstrap_port=$(free_port)
dynamic_port=$(free_port)
apply_port=$(free_port)
key_hex=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
snapshot_path="$test_dir/edge.snapshot.json"

python3 - "$origin_port" <<'PY' >"$test_dir/origin.log" 2>&1 &
import http.server
import sys

port = int(sys.argv[1])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"origin:{self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
PY
origin_pid=$!

cat >"$test_dir/config.json" <<JSON
{
  "listen":"127.0.0.1:$bootstrap_port",
  "origin":{"address":"127.0.0.1:$origin_port","server_name":"origin.local","tls":false},
  "tenant_id":"tenant_dynamic",
  "site_id":"site_a",
  "policy_revision":"policy-r1",
  "audit":{"directory":"$test_dir/audit","key_id":"journal-key-r1","producer_id":"edge-test","max_bytes":1048576,"high_watermark_bytes":786432,"segment_max_bytes":262144},
  "operations":[{"operation_id":"entry","method":"GET","path":"/","admission":"PUBLIC"}]
}
JSON

cargo build --quiet --manifest-path "$repo_root/Cargo.toml" -p xshield-gateway --bin xshield-gateway
XSHIELD_CONFIG="$test_dir/config.json" \
XSHIELD_JOURNAL_KEY_HEX="8888888888888888888888888888888888888888888888888888888888888888" \
XSHIELD_PUBLIC_HOSTS="origin.local" \
XSHIELD_EDGE_APPLY_KEY_HEX="$key_hex" \
XSHIELD_EDGE_APPLY_LISTEN="127.0.0.1:$apply_port" \
XSHIELD_EDGE_SNAPSHOT_PATH="$snapshot_path" \
    "$repo_root/target/debug/xshield-gateway" >"$test_dir/gateway.log" 2>&1 &
gateway_pid=$!

for _ in {1..80}; do
    status=$(curl -sS -o "$test_dir/bootstrap.body" -w '%{http_code}' \
        -H 'Host: origin.local' "http://127.0.0.1:$bootstrap_port/" 2>/dev/null || true)
    [[ "$status" == "200" ]] && break
    sleep 0.1
done
[[ "$(<"$test_dir/bootstrap.body")" == "origin:/" ]]

python3 - "$test_dir/apply.json" "$origin_port" "$bootstrap_port" "$dynamic_port" <<'PY'
import json
import sys

path, origin_port, bootstrap_port, dynamic_port = sys.argv[1:]

def config(site, port):
    return {
        "listen": f"127.0.0.1:{port}",
        "origin": {"address": f"127.0.0.1:{origin_port}", "server_name": "origin.local", "tls": False},
        "tenant_id": "tenant_dynamic",
        "site_id": site,
        "policy_revision": "policy-r1",
        "audit": {"directory": "target/xshield-dynamic-audit", "key_id": "journal-key-r1", "producer_id": "edge-test", "max_bytes": 16777216, "high_watermark_bytes": 12582912, "segment_max_bytes": 4194304},
        "operations": [{"operation_id": "entry", "method": "GET", "path": "/", "admission": "PUBLIC"}],
    }

request = {
    "protocol_version": 1,
    "tenant_id": "tenant_dynamic",
    "apply_id": "apply_0190c8f4-5b8a-7e8a-8e8a-1f6c0a5d1a01",
    "snapshot_revision": 2,
    "sites": [
        {"site_id": "site_a", "listen_port": int(bootstrap_port), "public_origin": "https://site-a.example", "gateway_config": config("site_a", bootstrap_port), "revision": 1},
        {"site_id": "site_b", "listen_port": int(dynamic_port), "public_origin": "https://site-b.example", "gateway_config": config("site_b", dynamic_port), "revision": 1},
    ],
}
with open(path, "w", encoding="utf-8") as output:
    json.dump(request, output, separators=(",", ":"))
PY

signature=$(python3 - "$test_dir/apply.json" "$key_hex" <<'PY'
import hashlib
import hmac
import sys
with open(sys.argv[1], "rb") as body:
    print(hmac.new(bytes.fromhex(sys.argv[2]), body.read(), hashlib.sha256).hexdigest())
PY
)
apply_status=$(curl -sS -o "$test_dir/apply.response" -w '%{http_code}' \
    -H "x-xshield-apply-signature: $signature" \
    --data-binary "@$test_dir/apply.json" \
    "http://127.0.0.1:$apply_port/internal/v1/apply")
[[ "$apply_status" == "200" ]]
grep -q '"active_revision":2' "$test_dir/apply.response"

status=$(curl -sS -o "$test_dir/dynamic.body" -w '%{http_code}' \
    -H 'Host: site-b.example' "http://127.0.0.1:$dynamic_port/" 2>/dev/null)
[[ "$status" == "200" ]]
[[ "$(<"$test_dir/dynamic.body")" == "origin:/" ]]
status=$(curl -sS -o "$test_dir/static.body" -w '%{http_code}' \
    -H 'Host: site-a.example' "http://127.0.0.1:$bootstrap_port/" 2>/dev/null)
[[ "$status" == "200" ]]
[[ "$(<"$test_dir/static.body")" == "origin:/" ]]

[[ -s "$snapshot_path" ]]
kill -KILL "$gateway_pid"
wait "$gateway_pid" 2>/dev/null || true
gateway_pid=""
sed -i.bak "s|$test_dir/audit|$test_dir/restart-audit|" "$test_dir/config.json"
XSHIELD_CONFIG="$test_dir/config.json" \
XSHIELD_JOURNAL_KEY_HEX="8888888888888888888888888888888888888888888888888888888888888888" \
XSHIELD_PUBLIC_HOSTS="origin.local" \
XSHIELD_EDGE_APPLY_KEY_HEX="$key_hex" \
XSHIELD_EDGE_APPLY_LISTEN="127.0.0.1:$apply_port" \
XSHIELD_EDGE_SNAPSHOT_PATH="$snapshot_path" \
    "$repo_root/target/debug/xshield-gateway" >"$test_dir/gateway.log" 2>&1 &
gateway_pid=$!
for _ in {1..80}; do
    status=$(curl -sS -o "$test_dir/restarted.body" -w '%{http_code}' \
        -H 'Host: site-b.example' "http://127.0.0.1:$dynamic_port/" 2>/dev/null || true)
    [[ "$status" == "200" ]] && break
    sleep 0.1
done
if [[ "$status" != "200" || ! -s "$test_dir/restarted.body" ]]; then
    echo "gateway did not restore the persisted dynamic listener (status=$status)" >&2
    exit 1
fi
if [[ "$(<"$test_dir/restarted.body")" != "origin:/" ]]; then
    echo "gateway restored listener returned an unexpected body" >&2
    exit 1
fi

echo "gateway dynamic listener integration passed"
