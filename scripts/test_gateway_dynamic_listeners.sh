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

write_apply_request() {
python3 - "$1" "$origin_port" "$bootstrap_port" "$dynamic_port" "$2" <<'PY'
import json
import sys

path, origin_port, bootstrap_port, dynamic_port, revision = sys.argv[1:]

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
    "snapshot_revision": int(revision),
    "sites": [
        {"site_id": "site_a", "listen_port": int(bootstrap_port), "public_origin": "https://site-a.example", "gateway_config": config("site_a", bootstrap_port), "revision": 1},
        {"site_id": "site_b", "listen_port": int(dynamic_port), "public_origin": "https://site-b.example", "gateway_config": config("site_b", dynamic_port), "revision": 1},
    ],
}
with open(path, "w", encoding="utf-8") as output:
    json.dump(request, output, separators=(",", ":"))
PY
}
write_apply_request "$test_dir/apply.json" 1
write_apply_request "$test_dir/apply2.json" 2

request_signature() {
    python3 - "$1" "$key_hex" <<'PY'
import hashlib
import hmac
import sys
with open(sys.argv[1], "rb") as body:
    print(hmac.new(bytes.fromhex(sys.argv[2]), body.read(), hashlib.sha256).hexdigest())
PY
}

# Posts one apply request. Leaves the request signature in $signature, the
# status in $apply_status, the response headers in apply.headers and the body
# in apply.response.
post_apply() {
    signature=$(request_signature "$1")
    apply_status=$(curl -sS -D "$test_dir/apply.headers" -o "$test_dir/apply.response" \
        -w '%{http_code}' \
        -H "x-xshield-apply-signature: $signature" \
        --data-binary "@$1" \
        "http://127.0.0.1:$apply_port/internal/v1/apply")
}

# The edge signs its acknowledgement over the signature of the request it
# answers; recompute that independently of the Rust implementation.
verify_ack_signature() {
    python3 - "$test_dir/apply.headers" "$test_dir/apply.response" "$key_hex" "$signature" <<'PY'
import hashlib
import hmac
import sys

headers_path, body_path, key_hex, request_signature = sys.argv[1:]
with open(headers_path, encoding="ascii") as handle:
    values = [
        line.split(":", 1)[1].strip()
        for line in handle
        if line.lower().startswith("x-xshield-apply-ack-signature:")
    ]
assert len(values) == 1, values
with open(body_path, "rb") as handle:
    body = handle.read()
message = b"xshield-edge-apply-ack-v1\n" + request_signature.encode() + b"\n" + body
expected = hmac.new(bytes.fromhex(key_hex), message, hashlib.sha256).hexdigest()
assert hmac.compare_digest(values[0], expected), (values[0], expected)
PY
}

# The control plane's first snapshot is revision 1, the same number as the
# static bootstrap snapshot this edge started with. That used to answer 409
# EDGE_APPLY_IDEMPOTENCY_CONFLICT, so the first apply could never succeed.
post_apply "$test_dir/apply.json"
[[ "$apply_status" == "200" ]]
grep -q '"active_revision":1' "$test_dir/apply.response"
verify_ack_signature

# A newer revision replaces it, an identical retry is idempotent and an older
# revision is refused.
post_apply "$test_dir/apply2.json"
[[ "$apply_status" == "200" ]]
grep -q '"active_revision":2' "$test_dir/apply.response"
verify_ack_signature
post_apply "$test_dir/apply2.json"
[[ "$apply_status" == "200" ]]
post_apply "$test_dir/apply.json"
[[ "$apply_status" == "409" ]]
grep -q 'EDGE_APPLY_STALE_REVISION' "$test_dir/apply.response"

# The persisted snapshot holds the whole tenant routing and policy set.
python3 - "$snapshot_path" <<'PY'
import os
import stat
import sys

mode = stat.S_IMODE(os.stat(sys.argv[1]).st_mode)
assert mode == 0o600, oct(mode)
PY

# Health requests are signed over a timestamp and a nonce: a captured request
# cannot be replayed, a stale one expires, and the old constant signature no
# longer authenticates.
python3 - "$apply_port" "$key_hex" <<'PY'
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request

port, key_hex = sys.argv[1:]
key = bytes.fromhex(key_hex)
url = f"http://127.0.0.1:{port}/internal/v1/health"


def sign(message):
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def call(headers):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def signed(timestamp):
    nonce = os.urandom(16).hex()
    return {
        "x-xshield-apply-signature": sign(f"xshield-edge-health-v2\n{timestamp}\n{nonce}".encode()),
        "x-xshield-health-timestamp": str(timestamp),
        "x-xshield-health-nonce": nonce,
    }


now = int(time.time())
request = signed(now)
status, body = call(request)
assert status == 200 and body["edge_state"] == "healthy", (status, body)
status, body = call(request)
assert (status, body["reason_code"]) == (401, "EDGE_HEALTH_REQUEST_REPLAYED"), (status, body)
status, body = call(signed(now - 120))
assert (status, body["reason_code"]) == (401, "EDGE_HEALTH_REQUEST_EXPIRED"), (status, body)
status, body = call({"x-xshield-apply-signature": sign(b"health-v1")})
assert (status, body["reason_code"]) == (401, "EDGE_APPLY_SIGNATURE_INVALID"), (status, body)
PY

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
