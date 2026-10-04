#!/usr/bin/env python3
"""Isolated PostgreSQL + real gateway regression for an intentionally IDOR-prone origin."""

import json
import argparse
import hashlib
import hmac
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EDGE = ROOT / "target/debug/xshield-gateway"
MODEL_EVAL = ROOT / "target/debug/xshield-model-eval"
FINGERPRINT_KEY = "7" * 64
LABELS = ROOT / "tests/security-lab/independent_labels.json"
SCENARIOS = {
    "orders": {"origin": "http://127.0.0.1:53001", "host": "idor.lab",
               "site_id": "site_idor", "login": "/login", "list": "/orders",
               "detail": "/orders/", "collection": "orders", "resource_key": "id",
               "own": "order-a", "other": "order-b", "bearer": "lab-token-alice",
               "action": "orders.open", "read_operation": "orders.read",
               "list_operation": "orders.list", "resource_type": "order",
               "path_parameter": "order_id", "view_profile": "customer_detail",
               "seed": "idor_seed.sql", "cases": ("own_order", "cross_order")},
    "invoices": {"origin": "http://127.0.0.1:53002", "host": "invoice.lab",
                 "site_id": "site_invoice", "login": "/session", "list": "/invoices",
                 "detail": "/invoices/", "collection": "invoices", "resource_key": "ref",
                 "own": "invoice-100", "other": "invoice-200",
                 "bearer": "invoice-token-alice", "action": "invoices.open",
                 "read_operation": "invoices.read", "list_operation": "invoices.list",
                 "resource_type": "invoice", "path_parameter": "invoice_id",
                 "view_profile": "billing_detail", "seed": "invoice_seed.sql",
                 "cases": ("own_invoice", "cross_invoice")},
}


def load_independent_labels():
    raw = LABELS.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    frozen = os.environ.get("XSHIELD_LAB_LABEL_SHA256")
    if frozen is not None and frozen != digest:
        raise RuntimeError("cross-site label file changed during evaluation")
    return json.loads(raw), digest


def source_history(db_name, db_env, source_request_id, spec):
    if not re.fullmatch(r"req_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                        source_request_id or ""):
        raise AssertionError("source request ID missing or malformed")
    query = f"""
        SELECT json_build_object(
          'source_request_id', e.source_request_id,
          'source_evidence_ref', e.response_evidence_id,
          'action_id', a.source_action_ref,
          'mapping_revision', a.mapping_revision,
          'subject_ref', b.principal_ref,
          'grant_count', (SELECT count(*) FROM xshield.resource_grants g
             WHERE g.tenant_id=a.tenant_id AND g.site_id=a.site_id
               AND g.action_ref=a.action_ref AND g.status='active'
               AND g.expires_at > clock_timestamp())
        )
        FROM xshield.ui_actions a
        JOIN xshield.response_evidence e ON e.tenant_id=a.tenant_id
          AND e.site_id=a.site_id AND e.response_evidence_id=a.response_evidence_id
        JOIN xshield.auth_bindings b ON b.tenant_id=a.tenant_id
          AND b.site_id=a.site_id AND b.binding_id=a.binding_id
        WHERE a.tenant_id='tenant_lab' AND a.site_id='{spec["site_id"]}'
          AND e.source_request_id='{source_request_id}'
          AND a.status='active' AND a.expires_at > clock_timestamp()
          AND e.status='verified' AND e.expires_at > clock_timestamp()
          AND b.status='active' AND b.absolute_expires_at > clock_timestamp();
    """
    lines = subprocess.check_output(["psql", "-X", "-At", "-d", db_name, "-c", query],
                                    env=db_env, text=True).strip().splitlines()
    if len(lines) != 1:
        raise AssertionError(f"expected one source-chain row, found {len(lines)}")
    facts = json.loads(lines[0])
    assert facts["subject_ref"] == "principal_alice"
    assert facts["action_id"] == spec["action"] and facts["mapping_revision"] == "mapping-r1"
    assert facts["grant_count"] == 1
    return facts


def write_private_json(path, payload):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(payload, output, ensure_ascii=False, separators=(",", ":"))
        output.write("\n")


def active_grant_count(db_name, db_env, facts, resource, spec):
    canonical = b"\0".join((b"xshield-resource-v1", b"tenant_lab",
                            spec["site_id"].encode(), spec["resource_type"].encode(),
                            resource.encode())) + b"\0"
    digest = hmac.new(bytes.fromhex(FINGERPRINT_KEY), canonical, hashlib.sha256).hexdigest()
    query = f"""
        SELECT count(*) FROM xshield.resource_grants g
        JOIN xshield.ui_actions a ON a.tenant_id=g.tenant_id AND a.site_id=g.site_id
          AND a.action_ref=g.action_ref AND a.binding_id=g.binding_id
          AND a.auth_epoch=g.auth_epoch
        JOIN xshield.auth_bindings b ON b.tenant_id=a.tenant_id AND b.site_id=a.site_id
          AND b.binding_id=a.binding_id
        WHERE g.tenant_id='tenant_lab' AND g.site_id='{spec["site_id"]}'
          AND a.source_request_id='{facts["source_request_id"]}'
          AND a.source_action_ref='{spec["action"]}'
          AND b.principal_ref='principal_alice' AND b.status='active'
          AND g.resource_type='{spec["resource_type"]}'
          AND g.operation_id='{spec["read_operation"]}'
          AND g.view_id='{spec["view_profile"]}'
          AND encode(g.resource_key_hmac,'hex')='{digest}'
          AND g.status='active' AND g.expires_at > clock_timestamp()
          AND a.status='active' AND a.expires_at > clock_timestamp();
    """
    return int(subprocess.check_output(["psql", "-X", "-At", "-d", db_name, "-c", query],
                                       env=db_env, text=True).strip())


def write_jev_fixtures(directory, facts, action_resource, attempts, spec, db_name, db_env, independent):
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    source = {
        "provenance": "operator_supplied_offline",
        "source_kind": "response_evidence",
        "source_evidence_ref": facts["source_evidence_ref"],
        "source_request_id": facts["source_request_id"],
        "action_id": facts["action_id"],
        "action_subject_ref": facts["subject_ref"],
        "action_resource_ref": action_resource,
        "mapping_revision": facts["mapping_revision"],
    }
    site_labels = independent["sites"][spec["name"]]
    assert site_labels["site_id"] == spec["site_id"]
    assert tuple(label["case"] for label in site_labels["labels"]) == spec["cases"]
    assert [label["requested_resource_ref"] for label in site_labels["labels"]] == [spec["own"], spec["other"]]
    assert [label["expected_choice"] for label in site_labels["labels"]] == ["ALLOW", "DENY"]
    for label_row in site_labels["labels"]:
        label = label_row["case"]
        resource = label_row["requested_resource_ref"]
        count = active_grant_count(db_name, db_env, facts, resource, spec)
        if count != (1 if resource == action_resource else 0):
            raise RuntimeError(f"unexpected active grant count for {label}: {count}")
        grant = "active" if count == 1 else "missing"
        payload = {
            "schema_version": 1, "approval_ref": "lab-review-required-r1",
            "model_revision": "jev-1.13.0", "policy_revision": "lab-r1",
            "prompt_revision": "lab-idor-r1",
            "untrusted_content": f"GET {spec['detail']}{resource}",
            "auth_facts": {"provenance": "operator_supplied_offline",
                           "subject_ref": facts["subject_ref"],
                           "requested_resource_ref": resource,
                           "current_grant": grant,
                           "source_request_id": facts["source_request_id"],
                           "attempt_request_id": attempts[label]},
            "page_evidence": source,
            "question": {"type": "choice",
                         "instructions": "Assess whether the requested resource matches the observed action and current grant. Choose UNKNOWN if evidence is insufficient.",
                         "criteria": {"ALLOW": "The provided action and current grant support this resource.",
                                      "DENY": "The resource lacks the required grant or action match.",
                                      "NONE": "No applicable order request.",
                                      "UNKNOWN": "Evidence does not establish a decision."}},
        }
        path = directory / f"{label}_review_required.json"
        write_private_json(path, payload)
        print(json.dumps({"fixture": str(path), "label_case": label,
                          "source_evidence_ref": facts["source_evidence_ref"]}))
    write_private_json(directory / "labels.json",
                       {"source_request_id": facts["source_request_id"],
                        "dataset_id": independent["dataset_id"],
                        "site_id": spec["site_id"],
                        "labels": [{**row, "attempt_request_id": attempts[row["case"]]}
                                   for row in site_labels["labels"]]})


def evaluate_jev_lab(work, db_name, db_env, database_url, fixture_dir, spec):
    if not MODEL_EVAL.is_file():
        raise RuntimeError("build xshield-model-eval before running Jev lab")
    route = os.environ.get("XSHIELD_JEV_ROUTE", "gateway")
    secret_name = "XSHIELD_JEV_API_KEY" if route == "direct" else "AI_GATEWAY_API_KEY"
    if not os.environ.get(secret_name):
        raise RuntimeError(f"{secret_name} is required for the Jev lab")
    db_command(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", db_name, "-c",
                "INSERT INTO xshield.model_evaluation_admission_scopes "
                "(tenant_id,site_id,policy_revision,max_active_calls,lease_seconds,configured_at) "
                f"VALUES ('tenant_lab','{spec['site_id']}','lab-r1',1,45,"
                "date_trunc('milliseconds',clock_timestamp()))"], db_env)
    evidence_root = work / "jev-evidence"
    journal_root = work / "jev-journal"
    evidence_root.mkdir(mode=0o700)
    journal_root.mkdir(mode=0o700)
    model_env = db_env.copy()
    model_env[secret_name] = os.environ[secret_name]
    model_env.update({
        "XSHIELD_DATABASE_URL": database_url,
        "XSHIELD_JEV_ROUTE": route,
        "XSHIELD_TENANT_ID": "tenant_lab",
        "XSHIELD_SITE_ID": spec["site_id"],
        "XSHIELD_EVIDENCE_ROOT": str(evidence_root),
        "XSHIELD_EVIDENCE_KEY_ID": "jev-lab-evidence-r1",
        "XSHIELD_EVIDENCE_KEY_HEX": secrets.token_hex(32),
        "XSHIELD_EVIDENCE_MAX_TOTAL_BYTES": str(32 * 1024 * 1024),
        "XSHIELD_MODEL_JOURNAL_DIRECTORY": str(journal_root),
        "XSHIELD_JOURNAL_KEY_ID": "jev-lab-journal-r1",
        "XSHIELD_JOURNAL_KEY_HEX": secrets.token_hex(32),
        "XSHIELD_AUDIT_MAX_BYTES": str(16 * 1024 * 1024),
    })
    reports = []
    for label in spec["cases"]:
        input_path = fixture_dir / f"{label}_review_required.json"
        valid = subprocess.run([str(MODEL_EVAL), "--validate-input", str(input_path)],
                               capture_output=True, text=True, env=model_env, timeout=10)
        if valid.returncode or valid.stdout.strip() != "MODEL_INPUT_VALID":
            raise RuntimeError(f"Jev lab input validation failed for {label}")
        invocation = subprocess.run([str(MODEL_EVAL), "--approved-input", str(input_path)],
                                    capture_output=True, text=True, env=model_env, timeout=30)
        try:
            report = json.loads(invocation.stdout)
        except ValueError as error:
            raise RuntimeError(f"Jev lab produced no receipt for {label}") from error
        print(json.dumps({"case": label, "status": report.get("status"),
                          "reason_code": report.get("reason_code"),
                          "model_call_id": report.get("model_call_id")}))
        if invocation.returncode or report.get("status") != "success":
            raise RuntimeError(f"Jev evaluation failed for {label}: {report.get('reason_code')}")
        reports.append({"case": label, "report": report})
        request_id = report.get("request_id", "")
        if not re.fullmatch(r"req_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                            request_id):
            raise RuntimeError(f"Jev receipt has invalid request ID for {label}")
        catalog_sql = (
            "SELECT count(*), count(*) FILTER (WHERE classification='RESTRICTED' "
            "AND status='active') FROM xshield.artifact_catalog "
            f"WHERE tenant_id='tenant_lab' AND site_id='{spec['site_id']}' "
            f"AND request_id='{request_id}'"
        )
        counts = subprocess.check_output(["psql", "-X", "-At", "-F", "|", "-d", db_name,
                                          "-c", catalog_sql], env=db_env, text=True).strip()
        if counts != "4|4":
            raise RuntimeError(f"Jev catalog barrier failed for {label}: {counts}")
    lease_counts = subprocess.check_output(
        ["psql", "-X", "-At", "-F", "|", "-d", db_name, "-c",
         "SELECT count(*) FILTER (WHERE status='released'), "
         "count(*) FILTER (WHERE status='active') "
         "FROM xshield.model_evaluation_admission_leases "
         f"WHERE tenant_id='tenant_lab' AND site_id='{spec['site_id']}'"],
        env=db_env, text=True).strip()
    if lease_counts != "2|0" or not any(journal_root.glob("segment-*.xja")):
        raise RuntimeError("Jev admission release or terminal journal unavailable")
    reports_path = work / "jev-reports.json"
    write_private_json(reports_path, reports)
    score_env = model_env.copy()
    score_env["XSHIELD_LAB_REPORTS_FILE"] = str(reports_path)
    score_env["XSHIELD_LAB_LABELS_FILE"] = str(fixture_dir / "labels.json")
    score_env["XSHIELD_LAB_SITE_ID"] = spec["site_id"]
    score_env.pop("XSHIELD_JEV_API_KEY", None)
    score = subprocess.run(["cargo", "test", "-p", "xshield-worker",
                            "--test", "jev_idor_lab", "--", "--ignored", "--nocapture"],
                           cwd=ROOT, capture_output=True, text=True, env=score_env, timeout=120)
    print(score.stdout[-4000:])
    if score.returncode:
        raise RuntimeError("Jev lab scoring failed; inspect test diagnostics")
    decisions = []
    for line in score.stdout.splitlines():
        if line.startswith("JEV_LAB_SCORE "):
            decisions.append(json.loads(line.removeprefix("JEV_LAB_SCORE ")))
    if len(decisions) != len(spec["cases"]):
        raise RuntimeError("Jev lab scoring output incomplete")
    return decisions


def request(url, method="GET", headers=None):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=b"" if method == "POST" else None,
                                                          method=method, headers=headers or {}), timeout=5) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read(), dict(error.headers)


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def db_command(args, env):
    subprocess.run(args, check=True, env=env, stdout=subprocess.DEVNULL)


def credentials(user, base, spec):
    status, body, headers = request(base + spec["login"], "POST", {"Host": spec["host"], "X-Lab-User": user})
    assert status == 200, (status, body)
    payload = json.loads(body)
    cookie = headers.get("Set-Cookie", "").split(";", 1)[0]
    assert cookie.startswith("__Host-xshield_sid="), headers
    return {"Host": spec["host"], "Cookie": cookie,
            "Authorization": "Bearer " + payload["access_token"]}


def outcome(base, path, headers):
    status, body, response_headers = request(base + path, headers=headers)
    try:
        decoded = json.loads(body)
    except ValueError:
        decoded = {}
    return status, decoded, response_headers.get("X-Xshield-Request-Id")


def summarize_observations(reports, evaluated):
    observations = [row for report in reports for row in report["observations"]]
    if len({row["edge_request_id"] for row in observations}) != len(observations):
        raise RuntimeError("live edge request identities are not unique")
    if len({report["site_id"] for report in reports}) != len(reports):
        raise RuntimeError("cross-site evaluation repeated one scope")
    edge_scores = {"benign_allowed": 0, "benign_denied": 0,
                   "malicious_denied": 0, "malicious_allowed": 0,
                   "edge_error": 0}
    for row in observations:
        if row["origin_status"] != 200:
            raise RuntimeError("origin baseline did not expose the fixed object")
        if row["truth_class"] not in ("benign", "malicious"):
            raise RuntimeError("independent label class is invalid")
        category = row["truth_class"]
        if row["expected_choice"] != ("ALLOW" if category == "benign" else "DENY"):
            raise RuntimeError("independent label decision conflicts with fixture truth")
        if row["edge_status"] == 200:
            outcome_name = "allowed"
        elif 400 <= row["edge_status"] < 500:
            outcome_name = "denied"
        else:
            edge_scores["edge_error"] += 1
            continue
        edge_scores[f"{category}_{outcome_name}"] += 1
    scores = {"false_allow": 0, "false_deny": 0, "abstain": 0, "unavailable": 0,
              "correct_allow": 0, "correct_deny": 0}
    if evaluated:
        for row in observations:
            actual = row["model_choice"]
            expected = row["expected_choice"]
            if actual is None:
                scores["unavailable"] += 1
            elif actual in ("UNKNOWN", "NONE"):
                scores["abstain"] += 1
            elif actual not in ("ALLOW", "DENY") or expected not in ("ALLOW", "DENY"):
                raise RuntimeError("model choice or label is invalid")
            elif actual == expected:
                scores["correct_allow" if actual == "ALLOW" else "correct_deny"] += 1
            else:
                scores["false_allow" if actual == "ALLOW" else "false_deny"] += 1
    model_edge_consistent = None
    if evaluated:
        model_edge_consistent = all(
            (row["model_choice"] == "ALLOW" and row["edge_status"] == 200)
            or (row["model_choice"] == "DENY" and row["edge_status"] >= 400)
            for row in observations
        )
    return {"dataset_id": "xshield_lab_cross_site_r1",
                      "mode": "live_jev_verified_against_edge" if evaluated else "edge_only",
                      "site_count": len(reports), "sample_count": len(observations),
                      "edge_scores": edge_scores,
                      "jev_scores": scores if evaluated else None,
                      "model_edge_consistent": model_edge_consistent,
                      "model_influenced_edge": False,
                      "observations": observations}


def run_all(args, label_digest):
    if args.jev_fixtures_dir is not None:
        raise RuntimeError("--jev-fixtures-dir requires one --scenario")
    reports = []
    for name in SCENARIOS:
        command = [sys.executable, __file__, "--scenario", name]
        if args.evaluate_jev:
            command.append("--evaluate-jev")
        child_env = os.environ.copy()
        child_env["XSHIELD_LAB_LABEL_SHA256"] = label_digest
        child = subprocess.run(command, capture_output=True, text=True, timeout=240, env=child_env)
        if child.returncode:
            print(child.stdout[-3000:])
            raise RuntimeError(f"{name} lab failed: {child.stderr[-1000:]}")
        lines = [line.removeprefix("LAB_RESULT ") for line in child.stdout.splitlines()
                 if line.startswith("LAB_RESULT ")]
        if len(lines) != 1:
            raise RuntimeError(f"{name} lab result unavailable")
        reports.append(json.loads(lines[0]))
        _, observed_digest = load_independent_labels()
        if observed_digest != label_digest:
            raise RuntimeError("cross-site label file changed during evaluation")
    summary = summarize_observations(reports, args.evaluate_jev)
    summary["label_sha256"] = label_digest
    if args.evaluate_jev:
        report_dir = ROOT / "target/xshield-security-lab"
        report_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        report_path = report_dir / f"live-jev-{uuid.uuid4().hex}.json"
        summary["report_path"] = str(report_path)
        write_private_json(report_path, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jev-fixtures-dir", type=Path,
                        help="Create private, review-required Jev inputs from the lab ledger")
    parser.add_argument("--evaluate-jev", action="store_true",
                        help="Run real TypeSafe Jev shadow calls and score encrypted records")
    parser.add_argument("--scenario", choices=(*SCENARIOS, "all"), default="orders")
    args = parser.parse_args()
    independent, label_digest = load_independent_labels()
    if args.scenario == "all":
        run_all(args, label_digest)
        return
    spec = {"name": args.scenario, **SCENARIOS[args.scenario]}
    origin = spec["origin"]
    if not EDGE.is_file():
        raise SystemExit("build edge first: cargo build -p xshield-gateway --bin xshield-gateway")
    for _ in range(100):
        try:
            if request(origin + "/health")[0] == 200:
                break
        except (OSError, TimeoutError):
            pass
        time.sleep(0.1)
    else:
        raise RuntimeError(f"{args.scenario} origin did not become ready")
    own_direct_status, own_direct_body, _ = request(
        origin + spec["detail"] + spec["own"],
        headers={"Authorization": "Bearer " + spec["bearer"]})
    assert own_direct_status == 200 and json.loads(own_direct_body)["owner"] == "alice"
    status, direct, _ = request(origin + spec["detail"] + spec["other"],
                                headers={"Authorization": "Bearer " + spec["bearer"]})
    assert status == 200 and json.loads(direct)["owner"] == "bob", "fixture must exhibit IDOR"
    db_name = "xshield_lab_" + uuid.uuid4().hex[:16]
    db_env = os.environ.copy()
    db_env.pop("XSHIELD_JEV_API_KEY", None)
    db_env.update({"PGHOST": "127.0.0.1", "PGPORT": "55432", "PGUSER": "xshield_dev",
                   "PGPASSWORD": os.getenv("XSHIELD_LAB_PGPASSWORD", "xshield_dev")})
    db_command(["createdb", db_name], db_env)
    try:
        for migration in sorted((ROOT / "migrations").glob("*.sql")):
            db_command(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", db_name, "-f", str(migration)], db_env)
        db_command(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", db_name,
                    "-f", str(ROOT / "tests/security-lab" / spec["seed"])], db_env)
        with tempfile.TemporaryDirectory(prefix=f"xshield-{args.scenario}-lab-") as directory:
            work = Path(directory)
            listen = port()
            config = {
                "listen": f"127.0.0.1:{listen}",
                "origin": {"address": origin.removeprefix("http://"),
                           "server_name": spec["host"], "tls": False},
                "tenant_id": "tenant_lab", "site_id": spec["site_id"], "policy_revision": "lab-r1",
                "audit": {"directory": str(work / "audit"), "key_id": "journal-lab-r1",
                          "producer_id": "edge-lab", "max_bytes": 1048576,
                          "high_watermark_bytes": 786432, "segment_max_bytes": 262144},
                "identity_store": {"max_connections": 2, "acquire_timeout_ms": 2000},
                "site_policy": {"waf": {"enabled": True, "blocked_query_fragments": ["' or 1=1--"],
                                        "max_cookie_bytes": 8192}},
                "operations": [
                    {"operation_id": "auth.login", "method": "POST", "path": spec["login"],
                     "admission": "AUTH_ENTRY", "response": {"mode": "BUFFERED_JSON", "max_bytes": 512,
                     "auth_binding": {"success_status": 200, "principal_pointer": "/identity/id",
                                      "authorization_context_pointer": "/identity/authorization_context",
                                      "bearer_pointer": "/access_token", "credential_ttl_seconds": 1800,
                                      "session_ttl_seconds": 3600}}},
                    {"operation_id": spec["list_operation"], "method": "GET", "path": spec["list"],
                     "admission": "AUTHENTICATED_ROOT", "response": {"mode": "BUFFERED_JSON", "max_bytes": 1024,
                     "resource_grant": {"success_status": 200, "items_pointer": spec["list"],
                                        "resource_pointer": "/" + spec["resource_key"],
                                        "action_ref_field": "_xshield_action_ref",
                                        "target_operation_id": spec["read_operation"], "target_mapping_revision": "mapping-r1",
                                        "ttl_seconds": 900, "max_items": 10, "max_active_grants": 100}}},
                    {"operation_id": spec["read_operation"], "method": "GET",
                     "path": spec["detail"] + "{" + spec["path_parameter"] + "}",
                     "admission": "UI_ACTION_REQUIRED", "source_action": spec["action"],
                     "resource_type": spec["resource_type"], "view_profile": spec["view_profile"],
                     "resource_path_parameter": spec["path_parameter"]},
                ],
            }
            config_path = work / "gateway.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            edge_env = db_env.copy()
            edge_env.update({
                "XSHIELD_CONFIG": str(config_path), "XSHIELD_PUBLIC_HOSTS": spec["host"],
                "XSHIELD_EDGE_LISTEN_PORTS": f"127.0.0.1:{listen}",
                "XSHIELD_JOURNAL_KEY_HEX": "8" * 64, "XSHIELD_FINGERPRINT_KEY_HEX": FINGERPRINT_KEY,
                "XSHIELD_DATABASE_URL": f"postgresql://xshield_dev:{db_env['PGPASSWORD']}@127.0.0.1:55432/{db_name}",
            })
            edge_env.pop("XSHIELD_EDGE_APPLY_KEY_HEX", None)
            edge_env.pop("XSHIELD_EDGE_SNAPSHOT_PATH", None)
            with (work / "gateway.log").open("wb") as log:
                edge = subprocess.Popen([str(EDGE)], env=edge_env, stdout=log, stderr=subprocess.STDOUT)
                try:
                    base = f"http://127.0.0.1:{listen}"
                    for _ in range(100):
                        if edge.poll() is not None:
                            raise RuntimeError((work / "gateway.log").read_text(errors="replace"))
                        try:
                            if request(base + spec["list"], headers={"Host": spec["host"]})[0] in (401, 429):
                                break
                        except (OSError, TimeoutError):
                            pass
                        time.sleep(0.1)
                    else:
                        raise RuntimeError("edge did not become ready")
                    alice = credentials("alice", base, spec)
                    bob = credentials("bob", base, spec)
                    list_status, list_body, list_request_id = outcome(base, spec["list"], alice)
                    assert list_status == 200, (list_status, list_body)
                    items = list_body[spec["collection"]]
                    assert len(items) == 1 and items[0][spec["resource_key"]] == spec["own"]
                    matching_items = items
                    action = items[0]["_xshield_action_ref"]
                    before = json.loads(request(origin + "/__lab/metrics")[1])
                    query_denial = outcome(base, spec["list"] + "?q=%27+OR+1%3D1--", alice)
                    assert query_denial[0] == 403 and query_denial[1].get("reason_code") == "WAF_QUERY_BLOCKED"
                    own = outcome(base, spec["detail"] + spec["own"], alice | {"X-Xshield-Action-Ref": action})
                    other = outcome(base, spec["detail"] + spec["other"], alice | {"X-Xshield-Action-Ref": action})
                    missing = outcome(base, spec["detail"] + spec["own"], alice)
                    cross = outcome(base, spec["detail"] + spec["own"], bob | {"X-Xshield-Action-Ref": action})
                    assert own[0] == 200 and own[1]["owner"] == "alice", own
                    assert all(result[0] == 403 for result in (other, missing, cross)), (other, missing, cross)
                    assert all(result[2] for result in (own, other, missing, cross))
                    after = json.loads(request(origin + "/__lab/metrics")[1])
                    assert after.get("GET " + spec["list"], 0) == before.get("GET " + spec["list"], 0)
                    assert after.get("GET " + spec["detail"] + spec["own"], 0) == before.get("GET " + spec["detail"] + spec["own"], 0) + 1
                    assert after.get("GET " + spec["detail"] + spec["other"], 0) == before.get("GET " + spec["detail"] + spec["other"], 0)
                    grant_count = int(subprocess.check_output(
                        ["psql", "-X", "-At", "-d", db_name, "-c",
                         f"SELECT count(*) FROM xshield.resource_grants WHERE tenant_id='tenant_lab' AND site_id='{spec['site_id']}' AND status='active'"],
                        env=db_env, text=True).strip())
                    assert grant_count >= 1, grant_count
                    decisions = []
                    if args.jev_fixtures_dir is not None or args.evaluate_jev:
                        facts = source_history(db_name, db_env, list_request_id, spec)
                        fixture_dir = args.jev_fixtures_dir or work / "jev-inputs"
                        write_jev_fixtures(fixture_dir, facts, items[0][spec["resource_key"]],
                                           {spec["cases"][0]: own[2], spec["cases"][1]: other[2]},
                                           spec, db_name, db_env, independent)
                        if args.evaluate_jev:
                            decisions = evaluate_jev_lab(work, db_name, db_env, edge_env["XSHIELD_DATABASE_URL"],
                                                         fixture_dir, spec)
                    db_command(["psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", db_name, "-c",
                                f"UPDATE xshield.resource_grants SET status='revoked' WHERE tenant_id='tenant_lab' AND site_id='{spec['site_id']}'"], db_env)
                    revoked = outcome(base, spec["detail"] + spec["own"], alice | {"X-Xshield-Action-Ref": action})
                    assert revoked[0] == 403, revoked
                    after_revocation = json.loads(request(origin + "/__lab/metrics")[1])
                    assert after_revocation.get("GET " + spec["detail"] + spec["own"], 0) == after.get("GET " + spec["detail"] + spec["own"], 0)
                    assert any((work / "audit").glob("segment-*.xja")), "durable audit missing"
                    site_labels = independent["sites"][args.scenario]["labels"]
                    choices = {entry["case"]: entry["actual"] for entry in decisions}
                    shadow_records = {entry["case"]: entry for entry in decisions}
                    observations = []
                    if not (len(site_labels) == len((own, other)) == len((own_direct_status, status))):
                        raise RuntimeError("Jev observation cardinality mismatch")
                    for label, edge_outcome, baseline in zip(site_labels, (own, other),
                                                              (own_direct_status, status)):
                        observations.append({"site_id": spec["site_id"], "case": label["case"],
                                             "truth_class": label["truth_class"],
                                             "expected_choice": label["expected_choice"],
                                             "origin_status": baseline, "edge_status": edge_outcome[0],
                                             "edge_reason": edge_outcome[1].get("reason_code"),
                                             "edge_request_id": edge_outcome[2],
                                             "source_request_id": list_request_id,
                                             "model_choice": choices.get(label["case"]),
                                             "model_call_id": shadow_records.get(label["case"], {}).get("model_call_id"),
                                             "model_duration_ms": shadow_records.get(label["case"], {}).get("duration_ms"),
                                             "model_usage": shadow_records.get(label["case"], {}).get("usage"),
                                             "model_cost_usd": None})
                    print("LAB_RESULT " + json.dumps({"site_id": spec["site_id"],
                                                        "observations": observations}, separators=(",", ":")))
                finally:
                    edge.terminate()
                    try:
                        edge.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        edge.kill()
                        edge.wait()
    finally:
        db_command(["dropdb", "--if-exists", db_name], db_env)


if __name__ == "__main__":
    main()
