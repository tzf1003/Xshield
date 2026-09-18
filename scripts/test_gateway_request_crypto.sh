#!/usr/bin/env bash
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/xshield-gateway-crypto.XXXXXX")
origin_pid=""
gateway_pid=""
test_database="xshield_crypto_${PPID}_${RANDOM}"

cleanup() {
    status=$?
    if [[ "$status" != "0" ]]; then
        sed -n '1,160p' "$test_dir/gateway.log" 2>/dev/null || true
        sed -n '1,160p' "$test_dir/origin.log" 2>/dev/null || true
    fi
    if [[ -n "$gateway_pid" ]]; then kill -KILL "$gateway_pid" 2>/dev/null || true; fi
    if [[ -n "$origin_pid" ]]; then kill "$origin_pid" 2>/dev/null || true; fi
    wait "$gateway_pid" 2>/dev/null || true
    wait "$origin_pid" 2>/dev/null || true
    dropdb --if-exists "$test_database" >/dev/null 2>&1 || true
    rm -r -- "$test_dir"
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
gateway_port=$(free_port)
capture="$test_dir/origin-bodies"
request_key="7777777777777777777777777777777777777777777777777777777777777777"
response_key="9999999999999999999999999999999999999999999999999999999999999999"
fingerprint_key="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
database_base_url=${XSHIELD_TEST_DATABASE_BASE_URL:-"postgresql://${PGUSER:-$(id -un)}@${PGHOST:-localhost}:${PGPORT:-5432}"}
database_url="$database_base_url/$test_database"

createdb "$test_database"
for migration in "$repo_root"/migrations/*.sql; do
    psql -X -v ON_ERROR_STOP=1 -d "$test_database" -f "$migration" >/dev/null
done

python3 - "$origin_port" "$capture" <<'PY' >"$test_dir/origin.log" 2>&1 &
import http.server
import pathlib
import sys

port = int(sys.argv[1])
capture = pathlib.Path(sys.argv[2])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = (
            b'<!doctype html><html><head><meta charset="utf-8"></head><body>v2</body></html>'
            if self.path == "/home?build=2"
            else b"<!doctype html><html><head></head><body>ok</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("ETag", '"origin-home-r1"')
        if self.path == "/home-csp":
            self.send_header("Content-Security-Policy", "default-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        with capture.open("ab") as output:
            output.write(body + b"\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
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
  "listen":"127.0.0.1:$gateway_port",
  "origin":{"address":"127.0.0.1:$origin_port","server_name":"origin.local","tls":false},
  "tenant_id":"tenant_crypto",
  "site_id":"site_crypto",
  "policy_revision":"policy-r1",
  "audit":{"directory":"$test_dir/audit","key_id":"journal-key-r1","producer_id":"edge-test","max_bytes":1048576,"high_watermark_bytes":786432,"segment_max_bytes":262144},
  "identity_store":{"max_connections":2,"acquire_timeout_ms":2000},
  "sensor":{"origin":"http://127.0.0.1:$gateway_port","build_ref":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","heartbeat_seconds":15},
  "operations":[{
    "operation_id":"orders.create",
    "method":"POST",
    "path":"/orders",
    "admission":"PUBLIC",
    "source_action":null,
    "resource_type":null,
    "view_profile":null,
    "request_crypto":{"mode":"DIRECT_DECRYPT","adapter_revision":"orders-json-r1","key_id":"request-key-r1","key_not_before":1,"key_expires_at":4102444800,"max_envelope_bytes":4096,"max_plaintext_bytes":1024,"max_message_age_seconds":60,"max_future_skew_seconds":5,"max_active_messages":1000},
    "response":{"mode":"BUFFERED_JSON","max_bytes":1024,"crypto":{"mode":"DIRECT_ENCRYPT","adapter_revision":"orders-response-r1","key_id":"response-key-r1","key_not_before":1,"key_expires_at":4102444800,"message_ttl_seconds":60,"max_envelope_bytes":3072}}
  },{
    "operation_id":"orders.observe",
    "method":"POST",
    "path":"/orders-observe",
    "admission":"PUBLIC",
    "source_action":null,
    "resource_type":null,
    "view_profile":null,
    "request_crypto":{"mode":"OBSERVE","adapter_revision":"orders-candidate-r2"}
  },{
    "operation_id":"home.read",
    "method":"GET",
    "path":"/home",
    "admission":"PUBLIC",
    "source_action":null,
    "resource_type":null,
    "view_profile":null,
    "response":{"mode":"SENSOR_HTML","max_bytes":128,"adapter_revision":"home-r1","origin_sha256":"8afe2e0204ebb1d838fdd6ce33cfb526ad18ca0d3877cc1a3768a778332c054a","injection_offset":27,"additional_adapters":[{"adapter_revision":"home-r2","origin_sha256":"6b4a57c5b8f040a713e1692702de199600126a862b020f36b33bfe6616e8afd6","injection_offset":49}]}
  },{
    "operation_id":"home-csp.read",
    "method":"GET",
    "path":"/home-csp",
    "admission":"PUBLIC",
    "source_action":null,
    "resource_type":null,
    "view_profile":null,
    "response":{"mode":"SENSOR_HTML","max_bytes":128,"adapter_revision":"home-r1","origin_sha256":"8afe2e0204ebb1d838fdd6ce33cfb526ad18ca0d3877cc1a3768a778332c054a","injection_offset":27}
  }]
}
JSON

cargo build --quiet --manifest-path "$repo_root/Cargo.toml" -p xshield-gateway --bin xshield-gateway
XSHIELD_CONFIG="$test_dir/config.json" \
XSHIELD_JOURNAL_KEY_HEX="8888888888888888888888888888888888888888888888888888888888888888" \
XSHIELD_REQUEST_DECRYPTION_KEY_HEX="$request_key" \
XSHIELD_RESPONSE_ENCRYPTION_KEY_HEX="$response_key" \
XSHIELD_FINGERPRINT_KEY_HEX="$fingerprint_key" \
XSHIELD_DATABASE_URL="$database_url" \
    "$repo_root/target/debug/xshield-gateway" >"$test_dir/gateway.log" 2>&1 &
gateway_pid=$!

for _ in $(seq 1 100); do
    if curl --silent --output /dev/null "http://127.0.0.1:$gateway_port/not-configured"; then
        break
    fi
    sleep 0.05
done
kill -0 "$gateway_pid"

curl --fail --silent --show-error -D "$test_dir/sensor-headers" \
    -o "$test_dir/sensor.js" \
    "http://127.0.0.1:$gateway_port/__xshield/v1/sensor/1.0.0.js"
cmp "$repo_root/sensor/src/sensor.ts" "$test_dir/sensor.js"
grep -qi '^content-type: text/javascript; charset=utf-8' "$test_dir/sensor-headers"
grep -qi '^cache-control: public, max-age=31536000, immutable' "$test_dir/sensor-headers"
grep -qi '^cross-origin-resource-policy: same-origin' "$test_dir/sensor-headers"
grep -qi '^x-content-type-options: nosniff' "$test_dir/sensor-headers"
grep -qi '^x-xshield-sensor-version: 1.0.0' "$test_dir/sensor-headers"
grep -qi '^x-xshield-request-id: req_' "$test_dir/sensor-headers"

curl --fail --silent --show-error -D "$test_dir/loader-headers" \
    -o "$test_dir/loader.js" \
    "http://127.0.0.1:$gateway_port/__xshield/v1/sensor/1.0.0-loader.js"
cmp "$repo_root/sensor/src/loader.ts" "$test_dir/loader.js"
grep -qi '^cache-control: public, max-age=31536000, immutable' "$test_dir/loader-headers"

curl --fail --silent --show-error -D "$test_dir/home-headers" \
    -o "$test_dir/home.html" "http://127.0.0.1:$gateway_port/home"
grep -q '<script defer src="/__xshield/v1/sensor/1.0.0.js"></script><script defer src="/__xshield/v1/sensor/1.0.0-loader.js"></script></head>' "$test_dir/home.html"
grep -qi '^cache-control: private, no-store' "$test_dir/home-headers"
! grep -qi '^etag:' "$test_dir/home-headers"
curl --fail --silent --show-error -o "$test_dir/home-v2.html" \
    "http://127.0.0.1:$gateway_port/home?build=2"
grep -q '<meta charset="utf-8"><script defer src="/__xshield/v1/sensor/1.0.0.js"></script><script defer src="/__xshield/v1/sensor/1.0.0-loader.js"></script></head>' "$test_dir/home-v2.html"
home_csp_status=$(curl --silent --show-error -o "$test_dir/home-csp.body" \
    -w '%{http_code}' "http://127.0.0.1:$gateway_port/home-csp")
[[ "$home_csp_status" == "502" ]]

curl --fail --silent --show-error -D "$test_dir/bootstrap-headers" \
    -o "$test_dir/bootstrap.json" \
    "http://127.0.0.1:$gateway_port/__xshield/v1/bootstrap"
grep -qi '^content-type: application/json' "$test_dir/bootstrap-headers"
grep -qi '^cache-control: private, no-store' "$test_dir/bootstrap-headers"
grep -qi '^pragma: no-cache' "$test_dir/bootstrap-headers"
grep -qi '^cross-origin-resource-policy: same-origin' "$test_dir/bootstrap-headers"
grep -qi '^x-content-type-options: nosniff' "$test_dir/bootstrap-headers"
grep -qi '^x-xshield-request-id: req_' "$test_dir/bootstrap-headers"
python3 - "$test_dir/bootstrap.json" <<'PY'
import json
import pathlib
import sys

bootstrap = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert bootstrap["sensor_version"] == "1.0.0"
assert bootstrap["build_ref"] == "a" * 64
assert bootstrap["heartbeat_seconds"] == 15
assert bootstrap["prepare_url"] == "/__xshield/v1/events/prepare"
assert bootstrap["page_handle"].startswith("pgh_")
assert bootstrap["navigation_id"].startswith("nav_")
assert bootstrap["request_id"].startswith("req_")
PY

plaintext='{"sku":"A-1","quantity":2}'
now=$(date +%s)

make_envelope() {
python3 - "$request_key" "$plaintext" "$1" "$2" "$3" "$4" <<'PY'
import json
import struct
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = bytes.fromhex(sys.argv[1])
plaintext = sys.argv[2].encode()
nonce = bytes.fromhex(sys.argv[3])
message_id = sys.argv[4]
issued_at = int(sys.argv[5])
expires_at = int(sys.argv[6])
values = [
    "xshield.request.direct-decrypt.v1",
    "tenant_crypto",
    "site_crypto",
    "orders.create",
    "POST",
    "/orders",
    "orders-json-r1",
    "request-key-r1",
    message_id,
    str(issued_at),
    str(expires_at),
    "application/json",
]
aad = b"".join(struct.pack(">I", len(value.encode())) + value.encode() for value in values)
sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
print(json.dumps({
    "schema_version": 1,
    "adapter_revision": "orders-json-r1",
    "key_id": "request-key-r1",
    "message_id": message_id,
    "issued_at": issued_at,
    "expires_at": expires_at,
    "nonce": nonce.hex(),
    "ciphertext": sealed[:-16].hex(),
    "tag": sealed[-16:].hex(),
}, separators=(",", ":")))
PY
}

message_id="msg_018f2a3b-4c5d-7000-8000-000000000901"
nonce="030303030303030303030303"
envelope=$(make_envelope "$nonce" "$message_id" "$((now - 1))" "$((now + 30))")

curl --fail --silent --show-error -D "$test_dir/valid-headers" -o "$test_dir/valid-response" \
    -H 'Content-Type: application/vnd.xshield.encrypted+json' \
    --data-binary "$envelope" "http://127.0.0.1:$gateway_port/orders"
grep -qi '^content-type: application/vnd.xshield.encrypted+json' "$test_dir/valid-headers"
response_request_id=$(awk 'tolower($1) == "x-xshield-request-id:" {gsub("\r", ""); print $2}' \
    "$test_dir/valid-headers")
python3 - "$response_key" "$response_request_id" "$plaintext" "$test_dir/valid-response" <<'PY'
import json
import pathlib
import struct
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = bytes.fromhex(sys.argv[1])
request_id = sys.argv[2]
expected = sys.argv[3].encode()
envelope = json.loads(pathlib.Path(sys.argv[4]).read_text())
values = [
    "xshield.response.direct-encrypt.v1",
    "tenant_crypto",
    "site_crypto",
    "orders.create",
    request_id,
    "POST",
    "/orders",
    "200",
    "orders-response-r1",
    "response-key-r1",
    envelope["message_id"],
    str(envelope["issued_at"]),
    str(envelope["expires_at"]),
    "application/json",
    "application/vnd.xshield.encrypted+json",
]
aad = b"".join(struct.pack(">I", len(value.encode())) + value.encode() for value in values)
sealed = bytes.fromhex(envelope["ciphertext"] + envelope["tag"])
assert AESGCM(key).decrypt(bytes.fromhex(envelope["nonce"]), sealed, aad) == expected
assert envelope["message_id"].startswith("msg_")
assert envelope["expires_at"] > envelope["issued_at"]
PY
[[ "$(cat "$capture")" == "$plaintext" ]]

status=$(curl --silent --output "$test_dir/replay-response" --write-out '%{http_code}' \
    -H 'Content-Type: application/vnd.xshield.encrypted+json' \
    --data-binary "$envelope" "http://127.0.0.1:$gateway_port/orders")
[[ "$status" == "409" ]]
grep -q 'REQUEST_CRYPTO_REPLAY_DETECTED' "$test_dir/replay-response"

different_message=$(make_envelope "$nonce" \
    "msg_018f2a3b-4c5d-7000-8000-000000000902" "$((now - 1))" "$((now + 30))")
status=$(curl --silent --output "$test_dir/nonce-reuse-response" --write-out '%{http_code}' \
    -H 'Content-Type: application/vnd.xshield.encrypted+json' \
    --data-binary "$different_message" "http://127.0.0.1:$gateway_port/orders")
[[ "$status" == "409" ]]
grep -q 'REQUEST_CRYPTO_REPLAY_DETECTED' "$test_dir/nonce-reuse-response"

different_nonce=$(make_envelope "060606060606060606060606" \
    "$message_id" "$((now - 1))" "$((now + 30))")
status=$(curl --silent --output "$test_dir/message-reuse-response" --write-out '%{http_code}' \
    -H 'Content-Type: application/vnd.xshield.encrypted+json' \
    --data-binary "$different_nonce" "http://127.0.0.1:$gateway_port/orders")
[[ "$status" == "409" ]]
grep -q 'REQUEST_CRYPTO_REPLAY_DETECTED' "$test_dir/message-reuse-response"

expired=$(make_envelope "040404040404040404040404" \
    "msg_018f2a3b-4c5d-7000-8000-000000000903" "$((now - 40))" "$((now - 10))")
status=$(curl --silent --output "$test_dir/expired-response" --write-out '%{http_code}' \
    -H 'Content-Type: application/vnd.xshield.encrypted+json' \
    --data-binary "$expired" "http://127.0.0.1:$gateway_port/orders")
[[ "$status" == "400" ]]
grep -q 'REQUEST_CRYPTO_MESSAGE_EXPIRED' "$test_dir/expired-response"

future=$(make_envelope "050505050505050505050505" \
    "msg_018f2a3b-4c5d-7000-8000-000000000904" "$((now + 10))" "$((now + 40))")
status=$(curl --silent --output "$test_dir/future-response" --write-out '%{http_code}' \
    -H 'Content-Type: application/vnd.xshield.encrypted+json' \
    --data-binary "$future" "http://127.0.0.1:$gateway_port/orders")
[[ "$status" == "400" ]]
grep -q 'REQUEST_CRYPTO_MESSAGE_FROM_FUTURE' "$test_dir/future-response"

tampered=$(python3 - "$envelope" <<'PY'
import json
import sys
value = json.loads(sys.argv[1])
value["tag"] = "00" * 16
print(json.dumps(value, separators=(",", ":")))
PY
)
status=$(curl --silent --output "$test_dir/tampered-response" --write-out '%{http_code}' \
    -H 'Content-Type: application/vnd.xshield.encrypted+json' \
    --data-binary "$tampered" "http://127.0.0.1:$gateway_port/orders")
[[ "$status" == "400" ]]
grep -q 'REQUEST_CRYPTO_AUTHENTICATION_FAILED' "$test_dir/tampered-response"

status=$(curl --silent --output "$test_dir/plaintext-response" --write-out '%{http_code}' \
    -H 'Content-Type: application/vnd.xshield.encrypted+json' \
    --data-binary "$plaintext" "http://127.0.0.1:$gateway_port/orders")
[[ "$status" == "400" ]]
grep -q 'REQUEST_ENVELOPE_INVALID' "$test_dir/plaintext-response"

status=$(curl --silent --output "$test_dir/query-response" --write-out '%{http_code}' \
    -H 'Content-Type: application/vnd.xshield.encrypted+json' \
    --data-binary "$envelope" "http://127.0.0.1:$gateway_port/orders?mode=changed")
[[ "$status" == "400" ]]
grep -q 'REQUEST_ENVELOPE_INVALID' "$test_dir/query-response"
[[ "$(wc -l < "$capture" | tr -d ' ')" == "1" ]]

opaque='legacy-protocol-body'
curl --fail --silent --show-error --output "$test_dir/observe-response" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "$opaque" "http://127.0.0.1:$gateway_port/orders-observe"
[[ "$(tail -n 1 "$capture")" == "$opaque" ]]

echo "gateway request crypto E2E passed"
