#!/usr/bin/env bash
# End-to-end proof of the edge transport against the real gateway binary:
# native TLS (versions, ALPN h2/http1.1, refusals) and routing over it, PROXY
# protocol v1/v2 from trusted and untrusted peers, and fail-closed startup.
# Everything lives in a temporary directory: a throwaway CA and edge
# certificate, a Python origin, gateway journals. Needs python3, curl with
# HTTP/2 support and openssl. Set CARGO_TARGET_DIR to build outside the repo.
set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# Each phase sets exactly the transport variables it tests.
unset XSHIELD_EDGE_TLS_CERT_PATH XSHIELD_EDGE_TLS_KEY_PATH XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/xshield-gateway-transport.XXXXXX")
gateway_bin="${CARGO_TARGET_DIR:-$repo_root/target}/debug/xshield-gateway"
origin_pid=""
gateway_pid=""
run=0

stop_gateway() {
    if [[ -n "$gateway_pid" ]]; then
        kill -KILL "$gateway_pid" 2>/dev/null || true
        wait "$gateway_pid" 2>/dev/null || true
        gateway_pid=""
    fi
}

cleanup() {
    status=$?
    if [[ "$status" != "0" ]]; then
        sed -n '1,120p' "$test_dir/gateway.log" 2>/dev/null || true
    fi
    stop_gateway
    [[ -z "$origin_pid" ]] || kill "$origin_pid" 2>/dev/null || true
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
edge_port=$(free_port)
apply_port=$(free_port)
apply_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
journal_key=8888888888888888888888888888888888888888888888888888888888888888

# The origin echoes the target and Host it received, so the checks below see
# exactly what the edge forwarded.
python3 - "$origin_port" <<'PY' >"$test_dir/origin.log" 2>&1 &
import http.server
import sys

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = f"origin:{self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Origin-Host", self.headers.get("Host", ""))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY
origin_pid=$!

# Throwaway CA and an edge certificate for site-a.example and unknown.example
# (the second name lets a wrong-Host request pass certificate checks, so its
# refusal is the router's).
pki="$test_dir/pki"
mkdir -m 0700 "$pki"
cat >"$pki/openssl.cnf" <<'CNF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = placeholder
[ca_ext]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[edge_ext]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:site-a.example,DNS:unknown.example
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
CNF
openssl req -x509 -config "$pki/openssl.cnf" -extensions ca_ext -subj "/CN=xshield transport test CA" \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$pki/ca.key" -out "$pki/ca.pem" \
    -days 2 2>/dev/null
openssl req -new -config "$pki/openssl.cnf" -subj "/CN=site-a.example" \
    -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$pki/edge.key" -out "$pki/edge.csr" 2>/dev/null
openssl x509 -req -in "$pki/edge.csr" -CA "$pki/ca.pem" -CAkey "$pki/ca.key" -CAcreateserial \
    -days 2 -sha256 -extfile "$pki/openssl.cnf" -extensions edge_ext -out "$pki/edge.pem" 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$pki/other.key" 2>/dev/null
chmod 600 "$pki/edge.key" "$pki/other.key"
cp "$pki/edge.key" "$pki/open.key"
chmod 644 "$pki/open.key"

# Writes a bootstrap config; a second argument "limited" adds a per-source
# budget of one request (1 rps, burst 1) so the limiter key is observable.
write_config() {
    local path=$1 limits=${2:-}
    local policy=""
    if [[ "$limits" == "limited" ]]; then
        policy=',"site_policy":{"limits":{"requests_per_second":1,"burst":1}}'
    fi
    cat >"$path" <<JSON
{
  "listen":"127.0.0.1:$edge_port",
  "origin":{"address":"127.0.0.1:$origin_port","server_name":"origin.local","tls":false},
  "tenant_id":"tenant_transport",
  "site_id":"site_a",
  "policy_revision":"policy-r1",
  "audit":{"directory":"$test_dir/audit-$run","key_id":"journal-key-r1","producer_id":"edge-transport-test","max_bytes":1048576,"high_watermark_bytes":786432,"segment_max_bytes":262144},
  "operations":[{"operation_id":"entry","method":"GET","path":"/","admission":"PUBLIC"},{"operation_id":"probe","method":"GET","path":"/h2","admission":"PUBLIC"},{"operation_id":"absolute","method":"GET","path":"/abs","admission":"PUBLIC"}]$policy
}
JSON
}

start_gateway() {
    local limits=$1
    shift
    stop_gateway
    run=$((run + 1))
    write_config "$test_dir/config-$run.json" "$limits"
    env "$@" \
        XSHIELD_CONFIG="$test_dir/config-$run.json" \
        XSHIELD_JOURNAL_KEY_HEX="$journal_key" \
        XSHIELD_PUBLIC_HOSTS="site-a.example" \
        XSHIELD_EDGE_APPLY_KEY_HEX="$apply_key" \
        XSHIELD_EDGE_APPLY_LISTEN="127.0.0.1:$apply_port" \
        "$gateway_bin" >"$test_dir/gateway.log" 2>&1 &
    gateway_pid=$!
    python3 "$test_dir/edge_probe.py" wait
}

# Probe helpers shared by the phases (stdlib only).
cat >"$test_dir/edge_probe.py" <<'PY'
import hashlib
import hmac
import json
import os
import socket
import ssl
import sys
import time
import urllib.request

EDGE_PORT = int(os.environ["EDGE_PORT"])
APPLY_PORT = int(os.environ["APPLY_PORT"])
APPLY_KEY = bytes.fromhex(os.environ["APPLY_KEY_HEX"])
CA = os.environ["EDGE_CA"]
SIGNATURE_V2 = b"\r\n\r\n\x00\r\nQUIT\n"


def health():
    timestamp = int(time.time())
    nonce = os.urandom(16).hex()
    message = f"xshield-edge-health-v2\n{timestamp}\n{nonce}".encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{APPLY_PORT}/internal/v1/health",
        headers={
            "x-xshield-apply-signature": hmac.new(APPLY_KEY, message, hashlib.sha256).hexdigest(),
            "x-xshield-health-timestamp": str(timestamp),
            "x-xshield-health-nonce": nonce,
        },
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def wait():
    # Data-plane sockets are bound before the apply listener, so a health
    # answer means the edge is accepting connections.
    for _ in range(100):
        try:
            return health()
        except OSError:
            time.sleep(0.1)
    raise SystemExit("gateway did not become healthy")


def proxy_v1(source, port=51234):
    family = "TCP6" if ":" in source else "TCP4"
    destination = "::1" if family == "TCP6" else "127.0.0.1"
    return f"PROXY {family} {source} {destination} {port} {EDGE_PORT}\r\n".encode()


def proxy_v2(source=None, port=40000):
    if source is None:  # LOCAL: the balancer's own health check
        return SIGNATURE_V2 + bytes([0x20, 0x00, 0x00, 0x00])
    block = (
        socket.inet_aton(source)
        + socket.inet_aton("127.0.0.1")
        + port.to_bytes(2, "big")
        + EDGE_PORT.to_bytes(2, "big")
    )
    return SIGNATURE_V2 + bytes([0x21, 0x11]) + len(block).to_bytes(2, "big") + block


def connect(prefix=b"", tls=True, version=None, alpn=("http/1.1",), sni="site-a.example"):
    sock = socket.create_connection(("127.0.0.1", EDGE_PORT), timeout=5)
    if prefix:
        sock.sendall(prefix)
    if not tls:
        return sock
    context = ssl.create_default_context(cafile=CA)
    if version is not None:
        context.minimum_version = version
        context.maximum_version = version
    if alpn:
        context.set_alpn_protocols(list(alpn))
    return context.wrap_socket(sock, server_hostname=sni)


def read_all(sock):
    data = b""
    while True:
        try:
            chunk = sock.recv(65536)
        except (ConnectionResetError, ssl.SSLError, TimeoutError):
            break
        if not chunk:
            break
        data += chunk
    sock.close()
    return data


def exchange(sock, request):
    sock.sendall(request)
    head, _, body = read_all(sock).partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1]) if head.startswith(b"HTTP/1.") else None
    return status, head.decode("latin-1").lower(), body.decode("latin-1")


def get(prefix=b"", host="site-a.example", target="/", **connection):
    request = f"GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    return exchange(connect(prefix, **connection), request)


def tls11_client_hello():
    # Built by hand so the refusal is the edge's, not the local TLS policy.
    body = b"\x03\x02" + b"\x5a" * 32 + b"\x00" + b"\x00\x04\xc0\x13\x00\x2f" + b"\x01\x00"
    handshake = b"\x01\x00\x00" + bytes([len(body)]) + body
    return b"\x16\x03\x01\x00" + bytes([len(handshake)]) + handshake


def raw(payload):
    sock = socket.create_connection(("127.0.0.1", EDGE_PORT), timeout=5)
    sock.sendall(payload)
    return read_all(sock)


def handshake_refused(prefix=b""):
    try:
        connect(prefix).close()
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError, TimeoutError):
        return True
    return False


if __name__ == "__main__" and sys.argv[1:] == ["wait"]:
    wait()
PY

export EDGE_PORT="$edge_port" APPLY_PORT="$apply_port" APPLY_KEY_HEX="$apply_key" EDGE_CA="$pki/ca.pem"
probe() {
    python3 - "$@" <<<"import sys; sys.path.insert(0, '$test_dir')
$(cat)"
}

cargo build --quiet --manifest-path "$repo_root/Cargo.toml" -p xshield-gateway --bin xshield-gateway

tls_env=(XSHIELD_EDGE_TLS_CERT_PATH="$pki/edge.pem" XSHIELD_EDGE_TLS_KEY_PATH="$pki/edge.key")

# Phase A: plaintext, no PROXY protocol: today's behaviour, and the baseline a
# wrong Host over TLS is compared with.
start_gateway plain
probe <<'PY'
from edge_probe import get, health
status, head, body = get(tls=False)
assert (status, body) == (200, "origin:/"), (status, head, body)
status, _, body = get(tls=False, host="unknown.example")
assert status == 503 and "SITE_CONFIG_UNAVAILABLE" in body, (status, body)
state = health()
assert state["tls_enabled"] is False and state["proxy_protocol_enabled"] is False, state
assert state["tls_handshake_failures"] == 0 and state["proxy_header_rejections"] == 0, state
PY

# Phase B: native TLS on the same listener.
start_gateway plain "${tls_env[@]}"
probe <<'PY'
import ssl
from edge_probe import connect, get, health, raw, tls11_client_hello

# (a) TLS 1.3 and 1.2 complete with ALPN; TLS 1.1 gets a protocol_version alert.
for version, name in [(ssl.TLSVersion.TLSv1_3, "TLSv1.3"), (ssl.TLSVersion.TLSv1_2, "TLSv1.2")]:
    sock = connect(version=version, alpn=("h2", "http/1.1"))
    assert (sock.version(), sock.selected_alpn_protocol()) == (name, "h2"), (sock.version(), sock.selected_alpn_protocol())
    sock.close()
    status, _, body = get(version=version)
    assert (status, body) == (200, "origin:/"), (name, status, body)
reply = raw(tls11_client_hello())
assert reply[:1] == b"\x15" and reply[5:7] == b"\x02\x46", reply
# Plaintext HTTP on a TLS port never gets an HTTP answer.
reply = raw(b"GET / HTTP/1.1\r\nHost: site-a.example\r\nConnection: close\r\n\r\n")
assert not reply.startswith(b"HTTP/"), reply

# (c) A Host no site owns is refused exactly as in plaintext, whatever the SNI.
for sni in ["unknown.example", "site-a.example"]:
    status, _, body = get(host="unknown.example", sni=sni)
    assert status == 503 and "SITE_CONFIG_UNAVAILABLE" in body, (sni, status, body)

# An absolute-form target is routed by its authority and reaches the origin
# as origin-form with the origin's own Host; a Host that disagrees with it is
# refused before routing.
port = __import__("os").environ["EDGE_PORT"]
status, head, body = get(host=f"site-a.example:{port}", target=f"https://site-a.example:{port}/abs")
assert (status, body) == (200, "origin:/abs") and "x-origin-host: origin.local" in head, (status, head, body)
status, _, _ = get(host="site-a.example", target="https://unknown.example/abs")
assert status == 400, status

state = health()
assert state["tls_enabled"] is True and state["proxy_protocol_enabled"] is False, state
assert state["tls_handshake_failures"] == 2, state
PY

# (b) curl negotiates HTTP/2 (bridged to the HTTP/1.1 origin) and HTTP/1.1.
curl_tls=(curl -sS --cacert "$pki/ca.pem" --resolve "site-a.example:$edge_port:127.0.0.1")
version=$("${curl_tls[@]}" --http2 -D "$test_dir/h2.headers" -o "$test_dir/h2.body" \
    -w '%{http_version} %{http_code}' "https://site-a.example:$edge_port/h2")
[[ "$version" == "2 200" ]] || { echo "expected HTTP/2 200, got $version" >&2; exit 1; }
[[ "$(<"$test_dir/h2.body")" == "origin:/h2" ]]
grep -qi '^x-origin-host: origin.local' "$test_dir/h2.headers"
version=$("${curl_tls[@]}" --http1.1 -o "$test_dir/h1.body" -w '%{http_version} %{http_code}' \
    "https://site-a.example:$edge_port/")
[[ "$version" == "1.1 200" ]] || { echo "expected HTTP/1.1 200, got $version" >&2; exit 1; }
[[ "$(<"$test_dir/h1.body")" == "origin:/" ]]

# Phase C: TLS plus PROXY protocol from a trusted balancer (this loopback
# peer). Each source address may make one request (1 rps, burst 1), so the
# second request reveals which address the rate limiter keyed it under.
start_gateway limited "${tls_env[@]}" XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED="127.0.0.1/32"
probe <<'PY'
from edge_probe import connect, exchange, get, handshake_refused, health, proxy_v1, proxy_v2

def statuses(prefix):
    return [get(prefix)[0], get(prefix)[0]]

# LOCAL (balancer health check) keeps the balancer's own address.
assert statuses(proxy_v2()) == [200, 429]
# (d) v1 and v2 sources each get their own bucket: the header, not the TCP
# peer, is the client.
assert statuses(proxy_v1("198.51.100.7")) == [200, 429]
assert statuses(proxy_v2("203.0.113.9")) == [200, 429]
status, _, body = get(proxy_v1("198.51.100.7"))
assert status == 429 and "SITE_RATE_LIMIT_EXCEEDED" in body, (status, body)
# A client's own PROXY header inside the TLS stream is HTTP garbage.
sock = connect(proxy_v1("198.51.100.30"))
status, _, _ = exchange(sock, proxy_v1("192.0.2.66") + b"GET / HTTP/1.1\r\nHost: site-a.example\r\n\r\n")
assert status == 400, status
assert get(proxy_v1("192.0.2.66"))[0] == 200, "the inner header charged 192.0.2.66"
# A trusted peer that skips the header is closed before any TLS handshake.
assert handshake_refused()
state = health()
assert state["proxy_protocol_enabled"] is True and state["tls_enabled"] is True, state
assert state["proxy_header_rejections"] == 1 and state["tls_handshake_failures"] == 0, state
PY

# Phase D: PROXY protocol on, but this peer is not a trusted balancer: its
# header is never honoured and is just bytes that fail HTTP parsing.
start_gateway limited XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED="10.0.0.0/8,fd00::/8"
probe <<'PY'
from edge_probe import get, health, proxy_v1, proxy_v2
assert get(proxy_v1("198.51.100.7"), tls=False)[0] == 400
assert get(proxy_v2("203.0.113.9"), tls=False)[0] in (400, None)
# Its own address is the client: one request, then the limit.
assert [get(tls=False)[0], get(tls=False)[0]] == [200, 429]
state = health()
assert state["proxy_protocol_enabled"] is True and state["proxy_header_rejections"] == 0, state
PY
stop_gateway

# Phase E: invalid transport configuration stops startup; TLS never falls
# back to plaintext and key material never reaches the log.
expect_startup_failure() {
    local expected=$1
    shift
    run=$((run + 1))
    write_config "$test_dir/config-$run.json" plain
    env "$@" XSHIELD_CONFIG="$test_dir/config-$run.json" XSHIELD_JOURNAL_KEY_HEX="$journal_key" \
        "$gateway_bin" >"$test_dir/startup.log" 2>&1 &
    local pid=$!
    for _ in {1..100}; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        echo "gateway started despite: $expected" >&2
        exit 1
    fi
    local status=0
    wait "$pid" || status=$?
    if [[ "$status" == "0" ]] || ! grep -qF -- "$expected" "$test_dir/startup.log"; then
        echo "expected startup failure '$expected' (status $status):" >&2
        cat "$test_dir/startup.log" >&2
        exit 1
    fi
    if grep -q "PRIVATE KEY\|BEGIN" "$test_dir/startup.log"; then
        echo "startup error echoed PEM material" >&2
        exit 1
    fi
}
# (e) A key readable by group/other aborts startup.
expect_startup_failure "chmod 600" \
    XSHIELD_EDGE_TLS_CERT_PATH="$pki/edge.pem" XSHIELD_EDGE_TLS_KEY_PATH="$pki/open.key"
expect_startup_failure "must be set together" XSHIELD_EDGE_TLS_CERT_PATH="$pki/edge.pem"
expect_startup_failure "must be set together" XSHIELD_EDGE_TLS_KEY_PATH="$pki/edge.key"
expect_startup_failure "is set but empty" \
    XSHIELD_EDGE_TLS_CERT_PATH="$pki/edge.pem" XSHIELD_EDGE_TLS_KEY_PATH=
expect_startup_failure "does not match" \
    XSHIELD_EDGE_TLS_CERT_PATH="$pki/edge.pem" XSHIELD_EDGE_TLS_KEY_PATH="$pki/other.key"
expect_startup_failure "holds no PEM certificate chain" \
    XSHIELD_EDGE_TLS_CERT_PATH="$pki/openssl.cnf" XSHIELD_EDGE_TLS_KEY_PATH="$pki/edge.key"
expect_startup_failure "cannot read" \
    XSHIELD_EDGE_TLS_CERT_PATH="$pki/missing.pem" XSHIELD_EDGE_TLS_KEY_PATH="$pki/edge.key"
expect_startup_failure "XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED" XSHIELD_EDGE_PROXY_PROTOCOL_TRUSTED="0.0.0.0/0"

echo "gateway transport integration passed"
