#!/usr/bin/env python3
"""Register the local Juice Shop through the control API using an Agent key."""

import json
import os
import sys
import urllib.request


def main() -> int:
    key = os.environ.get("XSHIELD_AGENT_API_KEY")
    if not key or not key.startswith("xsk_"):
        raise SystemExit("set XSHIELD_AGENT_API_KEY to the one-time displayed key")
    base = os.environ.get("XSHIELD_CONTROL_URL", "http://127.0.0.1:9443")
    payload = {
        "site_id": "site_juice",
        "display_name": "OWASP Juice Shop",
        "public_origin": "https://juice.local",
        "upstream_address": "127.0.0.1:53000",
        "upstream_server_name": "juice.lab",
        "upstream_tls": False,
        "listen_port": 56188,
        "entry_path": "/rest/products/search",
        "security_entry": "public",
        "sensor_enabled": False,
        "policy_revision": "juice-lab-r1",
        "status": "active",
        "policy": {
            "routes": [
                {"operation_id": "juice.home", "method": "GET", "path": "/", "security_entry": "public"},
                {"operation_id": "products.search", "method": "GET", "path": "/rest/products/search", "security_entry": "public"},
                {"operation_id": "juice.static.styles_css", "method": "GET", "path": "/styles.css", "security_entry": "public"},
                {"operation_id": "juice.static.polyfills_js", "method": "GET", "path": "/polyfills.js", "security_entry": "public"},
                {"operation_id": "juice.static.scripts_js", "method": "GET", "path": "/scripts.js", "security_entry": "public"},
                {"operation_id": "juice.static.main_js", "method": "GET", "path": "/main.js", "security_entry": "public"},
                *[
                    {"operation_id": f"juice.static.{name.replace('.', '_').replace('-', '_')}", "method": "GET", "path": f"/{name}", "security_entry": "public"}
                    for name in (
                        "rolldown-runtime-BoHGiXSq.js", "chunk-DBPdFzgj.js", "chunk-eYAgyLdn.js",
                        "chunk-DAJ4olp_.js", "t.js", "hacking-instructor-BXwB7EFQ.js",
                        "confetti-DoPrSMNP.js", "about.component-CZcG2819.js",
                        "coding-challenge-page.component-VgIt3B-z.js", "faucet.module-60SLa5Cr.js",
                        "recycle.component-BMXcwerA.js", "wallet-web3.module-s802s5aS.js",
                        "web3-sandbox.module-C8MIIA8b.js",
                    )
                ],
                {"operation_id": "juice.application_version", "method": "GET", "path": "/rest/application-version", "security_entry": "public"},
                {"operation_id": "juice.application_configuration", "method": "GET", "path": "/rest/application-configuration", "security_entry": "public"},
                {"operation_id": "juice.challenges", "method": "GET", "path": "/rest/Challenges/", "security_entry": "public"},
                {"operation_id": "juice.languages", "method": "GET", "path": "/rest/languages", "security_entry": "public"},
                {"operation_id": "juice.quantities", "method": "GET", "path": "/rest/Quantities/", "security_entry": "public"},
                {"operation_id": "juice.search", "method": "GET", "path": "/rest/search", "security_entry": "public"},
                {"operation_id": "juice.socket_poll", "method": "GET", "path": "/socket.io/", "security_entry": "public"},
                {"operation_id": "juice.socket_send", "method": "POST", "path": "/socket.io/", "security_entry": "public"},
            ],
            "waf": {
                "enabled": True,
                "blocked_headers": ["X-Lab-Block"],
                "blocked_query_fragments": ["' or 1=1--", "<script"],
                "max_cookie_bytes": 128,
            },
            "static_asset_max_path_depth": 5,
        },
    }
    body = json.dumps(payload).encode()
    request = urllib.request.Request(
        f"{base.rstrip('/')}/control/v1/sites",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Xshield-API-Key": key,
            "X-Xshield-Agent-Run-Id": "agt_00000000-0000-7000-8000-000000000001",
            "Idempotency-Key": "juice-shop-register-r1",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        print(response.read().decode())

    apply_request = urllib.request.Request(
        f"{base.rstrip('/')}/control/v1/sites/site_juice/apply",
        method="POST",
        headers={
            "X-Xshield-API-Key": key,
            "X-Xshield-Agent-Run-Id": "agt_00000000-0000-7000-8000-000000000001",
            "Idempotency-Key": "juice-shop-apply-r1",
        },
    )
    with urllib.request.urlopen(apply_request, timeout=15) as response:
        print(response.read().decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
