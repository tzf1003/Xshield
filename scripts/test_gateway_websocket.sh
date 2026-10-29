#!/usr/bin/env bash
# End-to-end proof that a declared `business_websocket` route really proxies
# a protected site's own WebSocket traffic through the edge (docs/22 M2, the
# "无 WSS" gap) rather than being refused like any other HTTP Upgrade request.
# Starts the real gateway binary in front of a minimal Python WS-echo origin,
# drives the handshake and a few data frames with a minimal Python WS client,
# and checks the connection's audit journal for the per-message records the
# gateway's passive frame scanner (business_ws::FrameScanner) is supposed to
# produce. Needs only python3 (stdlib). Set CARGO_TARGET_DIR to build outside
# the repo.
# macOS ships bash 3.2, where `set -e` ignores a failing `[[ ]]`, so an assertion
# written that way passes silently. Refuse to run rather than check less than CI.
if ((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 1))); then
    echo "error: $0 needs bash >= 4.1 (found $BASH_VERSION); on macOS install a newer bash and put it first in PATH" >&2
    exit 2
fi
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/xshield-gateway-websocket.XXXXXX")
gateway_bin="${CARGO_TARGET_DIR:-$repo_root/target}/debug/xshield-gateway"
dump_audit_bin="${CARGO_TARGET_DIR:-$repo_root/target}/debug/examples/dump_access_audit"
origin_pid=""
gateway_pid=""

cleanup() {
    status=$?
    if [[ "$status" != "0" ]]; then
        echo "--- gateway.log ---" >&2
        sed -n '1,160p' "$test_dir/gateway.log" 2>/dev/null >&2 || true
        echo "--- origin.log ---" >&2
        sed -n '1,160p' "$test_dir/origin.log" 2>/dev/null >&2 || true
    fi
    [[ -z "$gateway_pid" ]] || kill -KILL "$gateway_pid" 2>/dev/null || true
    [[ -z "$origin_pid" ]] || kill "$origin_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
    wait "$origin_pid" 2>/dev/null || true
    rm -rf -- "$test_dir"
}
trap cleanup EXIT INT TERM

if [[ ! -x "$gateway_bin" ]]; then
    echo "building xshield-gateway..."
    (cd "$repo_root" && cargo build -p xshield-gateway --bin xshield-gateway)
fi
if [[ ! -x "$dump_audit_bin" ]]; then
    echo "building dump_access_audit (to read back the encrypted audit journal)..."
    (cd "$repo_root" && cargo build -p xshield-control --example dump_access_audit)
fi

free_port() {
    python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

origin_port=$(free_port)
edge_port=$(free_port)
journal_key=8888888888888888888888888888888888888888888888888888888888888888

# Shared RFC 6455 frame codec (stdlib only), used by both the origin and the
# client scripts below.
cat >"$test_dir/ws_codec.py" <<'PY'
import struct


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed mid-frame")
        buf += chunk
    return buf


def recv_handshake(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("peer closed during handshake")
        buf += chunk
    return buf.decode("latin1")


def recv_frame(sock):
    first = recv_exact(sock, 2)
    opcode = first[0] & 0x0F
    masked = (first[1] & 0x80) != 0
    length = first[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", recv_exact(sock, 8))[0]
    mask = recv_exact(sock, 4) if masked else None
    payload = recv_exact(sock, length)
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def send_frame(sock, opcode, payload, mask):
    length = len(payload)
    first = 0x80 | opcode
    if length <= 125:
        header = bytes([first, (0x80 if mask else 0) | length])
    elif length <= 0xFFFF:
        header = bytes([first, (0x80 if mask else 0) | 126]) + struct.pack(">H", length)
    else:
        header = bytes([first, (0x80 if mask else 0) | 127]) + struct.pack(">Q", length)
    if mask:
        import os

        key = os.urandom(4)
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
        sock.sendall(header + key + payload)
    else:
        sock.sendall(header + payload)
PY

# The protected site's own WebSocket backend: accepts one handshake, echoes
# every data frame it receives (text or binary) with the same opcode, and
# answers a close frame in kind. Standard WS server behavior: frames it
# receives are masked (any real browser client masks), frames it sends are
# not (RFC 6455 forbids a server from masking its own frames).
cat >"$test_dir/origin.py" <<'PY'
import hashlib
import base64
import socket
import sys

sys.path.insert(0, sys.argv[2])
from ws_codec import recv_handshake, recv_frame, send_frame

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def accept_key(sec_key):
    digest = hashlib.sha1((sec_key + GUID).encode()).digest()
    return base64.b64encode(digest).decode()


def handle(conn):
    head = recv_handshake(conn)
    lines = head.split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
    if "sec-websocket-key" not in headers:
        # An ordinary, non-upgrade request: answer it like any plain HTTP
        # route, so the edge's regression check (same origin process, no
        # Upgrade header) sees normal behavior rather than a WS handshake.
        body = b"ok"
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("latin1") + body
        conn.sendall(response)
        return
    key = headers["sec-websocket-key"]
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept_key(key)}\r\n"
        "\r\n"
    )
    conn.sendall(response.encode("latin1"))
    while True:
        opcode, payload = recv_frame(conn)
        if opcode == 0x8:
            send_frame(conn, 0x8, payload, mask=False)
            return
        if opcode in (0x1, 0x2):
            send_frame(conn, opcode, payload, mask=False)
        elif opcode == 0x9:
            send_frame(conn, 0xA, payload, mask=False)


port = int(sys.argv[1])
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", port))
listener.listen(8)
while True:
    conn, _ = listener.accept()
    try:
        handle(conn)
    except Exception as error:
        print(f"origin connection ended: {error}", file=sys.stderr)
    finally:
        conn.close()
PY

python3 "$test_dir/origin.py" "$origin_port" "$test_dir" >"$test_dir/origin.log" 2>&1 &
origin_pid=$!

cat >"$test_dir/config.json" <<JSON
{
  "listen":"127.0.0.1:$edge_port",
  "origin":{"address":"127.0.0.1:$origin_port","server_name":"origin.local","tls":false},
  "tenant_id":"tenant_ws",
  "site_id":"site_ws",
  "policy_revision":"policy-r1",
  "audit":{"directory":"$test_dir/audit","key_id":"journal-key-r1","producer_id":"edge-ws-test","max_bytes":1048576,"high_watermark_bytes":786432,"segment_max_bytes":262144},
  "operations":[
    {"operation_id":"entry","method":"GET","path":"/","admission":"PUBLIC"},
    {"operation_id":"chat.ws","method":"GET","path":"/ws/chat","admission":"PUBLIC","business_websocket":{"adapter_revision":"chat-ws-r1","max_observed_frame_bytes":65536}}
  ]
}
JSON

unset XSHIELD_EDGE_TLS_CERT_PATH XSHIELD_EDGE_TLS_KEY_PATH XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED
env \
    XSHIELD_CONFIG="$test_dir/config.json" \
    XSHIELD_JOURNAL_KEY_HEX="$journal_key" \
    XSHIELD_PUBLIC_HOSTS="127.0.0.1" \
    "$gateway_bin" >"$test_dir/gateway.log" 2>&1 &
gateway_pid=$!

echo "waiting for the edge to accept connections on $edge_port..."
for _ in $(seq 1 100); do
    if python3 -c "
import socket, sys
try:
    socket.create_connection(('127.0.0.1', $edge_port), timeout=0.2).close()
except OSError:
    sys.exit(1)
" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$gateway_pid" 2>/dev/null; then
        echo "error: gateway exited during startup" >&2
        exit 1
    fi
    sleep 0.1
done

# A plain request to an ordinary (non-websocket) route must still behave
# exactly as before: this is the regression this feature must not cause.
echo "checking an ordinary route is unaffected..."
plain_status=$(python3 -c "
import http.client
conn = http.client.HTTPConnection('127.0.0.1', $edge_port, timeout=5)
conn.request('GET', '/', headers={'Host': '127.0.0.1'})
print(conn.getresponse().status)
")
[[ "$plain_status" == "200" ]] || {
    echo "error: plain route returned $plain_status, expected 200" >&2
    exit 1
}

cat >"$test_dir/client.py" <<'PY'
import base64
import os
import socket
import sys

sys.path.insert(0, sys.argv[2])
from ws_codec import recv_exact, recv_frame, send_frame

port = int(sys.argv[1])
key = base64.b64encode(os.urandom(16)).decode()
sock = socket.create_connection(("127.0.0.1", port), timeout=5)
request = (
    "GET /ws/chat HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
sock.sendall(request.encode("latin1"))

head = b""
while b"\r\n\r\n" not in head:
    chunk = sock.recv(4096)
    assert chunk, "edge closed before completing the handshake"
    head += chunk
head_text = head.decode("latin1")
assert head_text.startswith("HTTP/1.1 101"), f"edge did not relay the 101 upgrade: {head_text!r}"
assert "sec-websocket-accept" in head_text.lower(), "no Sec-WebSocket-Accept in the relayed response"

# One ordinary text frame.
send_frame(sock, 0x1, b"hello through the edge", mask=True)
opcode, payload = recv_frame(sock)
assert opcode == 0x1, f"expected a text echo, got opcode {opcode}"
assert payload == b"hello through the edge", f"echo mismatch: {payload!r}"

# A larger frame, to exercise the 16-bit extended length path end to end.
big = b"x" * 5000
send_frame(sock, 0x2, big, mask=True)
opcode, payload = recv_frame(sock)
assert opcode == 0x2, f"expected a binary echo, got opcode {opcode}"
assert payload == big, "large frame echo mismatch"

# A clean close, both ways.
send_frame(sock, 0x8, b"", mask=True)
opcode, _ = recv_frame(sock)
assert opcode == 0x8, f"expected a close echo, got opcode {opcode}"
sock.close()
print("websocket round-trip through the edge: OK")
PY
echo "driving a real WebSocket handshake and echo round-trip through the edge..."
python3 "$test_dir/client.py" "$edge_port" "$test_dir"

# Give the gateway's logging() hook and the durable audit writer a moment to
# flush the connection's closing record after the client's socket closed.
sleep 0.3

echo "checking the audit journal for per-connection and per-message records..."
# The journal is AES-256-GCM encrypted (xshield-audit), so the records can't
# be found by grepping the segment files directly; decrypt with the same key
# the gateway was given and read back the plaintext JSON lines instead.
events=$(XSHIELD_CONTROL_AUDIT_KEY_ID="journal-key-r1" \
    XSHIELD_CONTROL_AUDIT_KEY_HEX="$journal_key" \
    "$dump_audit_bin" "$test_dir/audit")

if ! grep -q '"business_ws.closed"' <<<"$events"; then
    echo "error: no business_ws.closed record found in the audit journal" >&2
    echo "--- decrypted events ---" >&2
    echo "$events" >&2
    exit 1
fi
if ! grep -q '"business_ws.message"' <<<"$events"; then
    echo "error: no business_ws.message record found in the audit journal" >&2
    echo "--- decrypted events ---" >&2
    echo "$events" >&2
    exit 1
fi
message_count=$(grep -c '"business_ws.message"' <<<"$events")
[[ "$message_count" -ge 4 ]] || {
    echo "error: expected at least 4 audited messages (2 data + 2 close), found $message_count" >&2
    echo "--- decrypted events ---" >&2
    echo "$events" >&2
    exit 1
}

echo "OK: business websocket route proxied, echoed, and audited end to end ($message_count messages)."
