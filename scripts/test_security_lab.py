#!/usr/bin/env python3
"""Run bounded real-edge checks against the local Docker security lab."""

import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
# Honour CARGO_TARGET_DIR so builds can live outside the repository (large disk).
TARGET = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
EDGE = TARGET / "debug/xshield-gateway"
JUICE = "http://127.0.0.1:53000"
IDOR = "http://127.0.0.1:53001"


def request(url, headers=None):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=5) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read(), dict(error.headers)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_target(url):
    for _ in range(100):
        try:
            if request(url)[0] == 200:
                return
        except (OSError, TimeoutError):
            pass
        time.sleep(0.1)
    raise RuntimeError(f"lab target did not become ready: {url}")


def main():
    if not EDGE.is_file():
        raise SystemExit("build edge first: cargo build -p xshield-gateway --bin xshield-gateway")
    wait_for_target(JUICE + "/rest/products/search?q=apple")
    wait_for_target(IDOR + "/health")
    assert request(IDOR + "/orders/order-b", {"Authorization": "Bearer lab-token-alice"})[0] == 200, "IDOR fixture changed"

    with tempfile.TemporaryDirectory(prefix="xshield-security-lab-") as directory:
        work = Path(directory)
        port = free_port()
        config = {
            "listen": f"127.0.0.1:{port}",
            "origin": {"address": "127.0.0.1:53000", "server_name": "juice.lab", "tls": False},
            "tenant_id": "tenant_security_lab",
            "site_id": "site_juice",
            "policy_revision": "lab-r1",
            "audit": {
                "directory": str(work / "audit"), "key_id": "journal-lab-r1", "producer_id": "edge-lab",
                "max_bytes": 1048576, "high_watermark_bytes": 786432, "segment_max_bytes": 262144,
            },
            "site_policy": {
                "waf": {"enabled": True, "blocked_headers": ["X-Lab-Block"],
                        "blocked_query_fragments": ["' or 1=1--", "<script"], "max_cookie_bytes": 128},
                "limits": {"max_request_body_bytes": 1024, "max_response_body_bytes": 16777216,
                           "requests_per_second": 1000, "burst": 2000},
            },
            "operations": [
                {"operation_id": "products.search", "method": "GET", "path": "/rest/products/search",
                 "admission": "PUBLIC"},
            ],
        }
        config_path = work / "gateway.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        env = os.environ.copy()
        env.update({
            "XSHIELD_CONFIG": str(config_path),
            "XSHIELD_PUBLIC_HOSTS": "juice.lab",
            "XSHIELD_JOURNAL_KEY_HEX": "8" * 64,
        })
        with (work / "gateway.log").open("wb") as log:
            gateway = subprocess.Popen([str(EDGE)], env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                base = f"http://127.0.0.1:{port}"
                headers = {"Host": "juice.lab"}
                for _ in range(100):
                    if gateway.poll() is not None:
                        raise RuntimeError((work / "gateway.log").read_text(errors="replace"))
                    try:
                        if request(base + "/rest/products/search?q=apple", headers)[0] == 200:
                            break
                    except (OSError, TimeoutError):
                        pass
                    time.sleep(0.1)
                else:
                    raise RuntimeError("edge did not become ready")

                cases = {}
                for label, path, extra in [
                    ("allowed_search", "/rest/products/search?q=apple", {}),
                    ("unlisted_route", "/api/Products", {}),
                    ("blocked_header", "/rest/products/search?q=apple", {"X-Lab-Block": "1"}),
                    ("oversize_cookie", "/rest/products/search?q=apple", {"Cookie": "a=" + "x" * 256}),
                    ("sqli_candidate", "/rest/products/search?q=" + urllib.parse.quote("' OR 1=1--"), {}),
                    ("sqli_plus_candidate", "/rest/products/search?q=%27+OR+1%3D1--", {}),
                    ("xss_candidate", "/rest/products/search?q=" + urllib.parse.quote("<script>alert(1)</script>"), {}),
                    ("malformed_query", "/rest/products/search?q=%GG", {}),
                ]:
                    status, body, response_headers = request(base + path, headers | extra)
                    try:
                        reason = json.loads(body).get("reason_code")
                    except (ValueError, TypeError):
                        reason = None
                    cases[label] = {"status": status, "reason_code": reason,
                                    "request_id": response_headers.get("X-Xshield-Request-Id")}
                assert cases["allowed_search"]["status"] == 200, cases
                assert cases["unlisted_route"]["status"] == 403, cases
                assert cases["blocked_header"]["reason_code"] == "WAF_HEADER_BLOCKED", cases
                assert cases["oversize_cookie"]["reason_code"] == "WAF_COOKIE_TOO_LARGE", cases
                assert cases["sqli_candidate"]["reason_code"] == "WAF_QUERY_BLOCKED", cases
                assert cases["sqli_plus_candidate"]["reason_code"] == "WAF_QUERY_BLOCKED", cases
                assert cases["xss_candidate"]["reason_code"] == "WAF_QUERY_BLOCKED", cases
                assert cases["malformed_query"]["reason_code"] == "WAF_QUERY_INVALID", cases
                assert cases["malformed_query"]["status"] == 400, cases
                assert cases["sqli_candidate"]["status"] == 403, cases
                assert all(case["request_id"] for case in cases.values()), cases
                assert any((work / "audit").glob("segment-*.xja")), "durable audit missing"
                direct_status = request(JUICE + "/rest/products/search?q=" + urllib.parse.quote("' OR 1=1--"))[0]
                cases["sqli_candidate"]["direct_status"] = direct_status
                print(json.dumps(cases, ensure_ascii=False, indent=2))
            finally:
                gateway.terminate()
                try:
                    gateway.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    gateway.kill()
                    gateway.wait()


if __name__ == "__main__":
    main()
