"""Asks the real Jev how it answers the layer 2 / layer 3 states of the function-level design.

The key comes from XSHIELD_JEV_API_KEY only. Nothing here writes it anywhere.
Usage: python3 jev_probe.py <path to state.rs> <variant: current|draft> [out.json]
"""
import json
import os
import re
import ssl
import sys
import time
import urllib.request

ENDPOINT = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-1.13.0"

FUNCTION_PARAGRAPH = (
    " state.request.function is present only on a site that keeps a table of its functions; a "
    "function is the method and the path with ids replaced. function.known false means that no "
    "ordinary session of this site has used this method and path, so the request did not come "
    "from a page or a call the application offers its users. Judge that apart from the values: "
    "answer DENY when the path or interface name points at administration, operations, debugging, "
    "monitoring, configuration, internal or developer tooling, a backup, a directory or file "
    "listing, a bulk export or a bulk delete; answer ALLOW when it is plainly an ordinary page or "
    "API of the same application as state.recent and the values pass the checks above. "
    "function.attempt over_privilege means an administrator confirmed this function as "
    "administrators-only and this session is not an administrator session: answer DENY."
)
PARAGRAPHS = {
    "draft2": (
        " state.request.function is present only on a site that keeps a table of its functions; a "
        "function is the method and the path with ids replaced. function.known false only means "
        "that this method and path are not in that table yet, which is true of every new page and "
        "API, so by itself it is never a reason to deny. It matters for one kind of path only: "
        "answer DENY when the path or interface name points at administration, operations, "
        "debugging, monitoring, server configuration, internal or developer tooling, a backup, a "
        "directory or file listing, a bulk export or a bulk delete. For every other path judge the "
        "request by its values exactly as if function were absent. function.attempt over_privilege "
        "means an administrator confirmed this function as administrators-only and this session is "
        "not an administrator session: answer DENY."
    ),
    "draft3": (
        " state.request.function is present only on a site that keeps a table of its functions; a "
        "function is the method and the path with ids replaced. function.known false means the "
        "table does not list this method and path. Most such requests are ordinary: a new page, a "
        "new API, a static file. Answer DENY for function.known false only when the path or "
        "interface name itself shows a privileged or operational function that an application "
        "page for ordinary users would not call: administration (admin, manage, staff roles, "
        "audit), operations and monitoring (metrics, actuator, server-status, health internals), "
        "debugging and developer tooling (debug, swagger, console, phpinfo), internal or "
        "configuration endpoints, backups, directory or file listings (ftp), bulk export or bulk "
        "delete of a whole collection. Otherwise function.known false changes nothing: judge the "
        "values as above. function.attempt over_privilege means an administrator confirmed this "
        "function as administrators-only and this session is not an administrator session: "
        "answer DENY."
    ),
}
DENY_MEANINGS = {
    "draft2": "Some object the request selects was never shown to this session as that kind of object, or the request reaches an administration, operations or internal function.",
    "draft3": "Some object the request selects was never shown to this session as that kind of object, or the request reaches a privileged or operational function.",
}
DENY_MEANING_DRAFT = (
    "Some object the request selects was never shown to this session as that kind of object, "
    "or the request uses a function this session has no normal path to."
)


def constants(state_rs: str) -> dict:
    text = open(state_rs, encoding="utf-8").read()
    out = {}
    for name in ("ACCESS_INSTRUCTIONS", "ATTACK_INSTRUCTIONS"):
        match = re.search(rf'const {name}: &str = "((?:[^"\\]|\\.)*)";', text)
        out[name] = json.loads('"' + match.group(1) + '"')
    return out


def questions(consts: dict, variant: str) -> dict:
    access = consts["ACCESS_INSTRUCTIONS"]
    deny = "Some object the request selects was never shown to this session as that kind of object."
    if variant != "current":
        marker = " Answer DENY if any object-selecting value was never shown"
        assert marker in access
        access = access.replace(marker, PARAGRAPHS.get(variant, FUNCTION_PARAGRAPH) + marker)
        deny = DENY_MEANINGS.get(variant, DENY_MEANING_DRAFT)
    return {
        "access": {
            "type": "choice",
            "instructions": access,
            "criteria": {
                "ALLOW": "Every object the request selects was shown to this session, or this is an entry request with only its own input.",
                "DENY": deny,
                "UNKNOWN": "Insufficient evidence.",
            },
        },
        "attack": {
            "type": "choice",
            "instructions": consts["ATTACK_INSTRUCTIONS"],
            "criteria": {
                "BENIGN": "No attack content.",
                "ATTACK": "Attack content present.",
                "UNKNOWN": "Insufficient evidence.",
            },
        },
    }


RECENT = [
    {"method": "GET", "path": "/api/home", "status": 200},
    {"method": "GET", "path": "/api/patients", "status": 200},
    {"method": "GET", "path": "/api/patients/7005", "status": 200},
    {"method": "GET", "path": "/api/patients/7005/notes", "status": 200},
]
SEEN_7005 = {
    "at": "path[2]",
    "kind": "reference",
    "value": "7005",
    "seen_as": ["id @ GET /api/patients [patient]"],
    "verified": True,
    "object": "patient",
}


def state(method, path, values=None, function=None, entry=False, recent=RECENT, entries=None):
    request = {"method": method, "path": path, "values": values or [], "truncated": False}
    if function is not None:
        request["function"] = function
    return {
        "entry": {"matched": entry},
        "session": {
            "age_seconds": 640,
            "entries_passed": entries if entries is not None else ["/login", "/api/home", "/api/patients"],
        },
        "recent": recent,
        "request": request,
    }


UNKNOWN = {"known": False}
ADMIN_ATTEMPT = {"tier": "admin", "attempt": "over_privilege"}


def inp(at, value):
    return {"at": at, "kind": "input", "value": value, "seen_as": []}


# (group, name, expected access, state)
CASES = [
    # Layer 3: functions outside the site's table that must not be reached.
    ("L3-deny", "GET /metrics", "DENY", state("GET", "/metrics", function=UNKNOWN)),
    ("L3-deny", "GET /actuator/env", "DENY", state("GET", "/actuator/env", function=UNKNOWN)),
    ("L3-deny", "GET /api/admin/export", "DENY", state("GET", "/api/admin/export", function=UNKNOWN)),
    ("L3-deny", "GET /admin/users", "DENY", state("GET", "/admin/users", function=UNKNOWN)),
    ("L3-deny", "GET /ftp/", "DENY", state("GET", "/ftp/", function=UNKNOWN)),
    ("L3-deny", "GET /debug/vars", "DENY", state("GET", "/debug/vars", function=UNKNOWN)),
    ("L3-deny", "GET /api/internal/config", "DENY", state("GET", "/api/internal/config", function=UNKNOWN)),
    ("L3-deny", "GET /swagger-ui/index.html", "DENY", state("GET", "/swagger-ui/index.html", function=UNKNOWN)),
    ("L3-deny", "GET /server-status", "DENY", state("GET", "/server-status", function=UNKNOWN)),
    ("L3-deny", "GET /api/patients/export-all", "DENY", state("GET", "/api/patients/export-all", function=UNKNOWN)),
    ("L3-deny", "DELETE /api/patients (bulk)", "DENY", state("DELETE", "/api/patients", function=UNKNOWN)),
    ("L3-deny", "PUT /api/staff/{id}/role, own verified id", "DENY",
     state("PUT", "/api/staff/7005/role", values=[SEEN_7005, inp("body.role", "admin")], function=UNKNOWN)),
    ("L3-deny", "GET /infrastructure/backup", "DENY", state("GET", "/infrastructure/backup", function=UNKNOWN)),
    # Layer 3: ordinary functions that are new to the table and must pass.
    ("L3-allow", "GET /api/v2/coupons", "ALLOW", state("GET", "/api/v2/coupons", function=UNKNOWN)),
    ("L3-allow", "GET /api/notifications/unread", "ALLOW", state("GET", "/api/notifications/unread", function=UNKNOWN)),
    ("L3-allow", "GET /api/appointments/today", "ALLOW", state("GET", "/api/appointments/today", function=UNKNOWN)),
    ("L3-allow", "GET /api/profile/settings", "ALLOW", state("GET", "/api/profile/settings", function=UNKNOWN)),
    ("L3-allow", "GET /help/faq", "ALLOW", state("GET", "/help/faq", function=UNKNOWN)),
    ("L3-allow", "GET /api/dashboard/summary", "ALLOW", state("GET", "/api/dashboard/summary", function=UNKNOWN)),
    ("L3-allow", "GET /api/departments", "ALLOW", state("GET", "/api/departments", function=UNKNOWN)),
    ("L3-allow", "GET /api/patients/{id}/timeline, verified id", "ALLOW",
     state("GET", "/api/patients/7005/timeline", values=[SEEN_7005], function=UNKNOWN)),
    ("L3-allow", "POST /api/feedback with text", "ALLOW",
     state("POST", "/api/feedback", values=[inp("body.message", "预约页面加载有点慢")], function=UNKNOWN)),
    ("L3-allow", "GET /api/reports/monthly", "ALLOW", state("GET", "/api/reports/monthly", function=UNKNOWN)),
    ("L3-allow", "POST /api/patients/{id}/prescriptions, verified id", "ALLOW",
     state("POST", "/api/patients/7005/prescriptions",
           values=[SEEN_7005, inp("body.drug", "amoxicillin"), inp("body.dose", "500mg")], function=UNKNOWN)),
    ("L3-allow", "GET /chunk-5f3a9c.js", "ALLOW", state("GET", "/chunk-5f3a9c.js", function=UNKNOWN)),
    # Layer 2: a confirmed administrators-only function, session is not an administrator.
    ("L2-deny", "POST /api/admin/export", "DENY", state("POST", "/api/admin/export", function=ADMIN_ATTEMPT)),
    ("L2-deny", "GET /api/audit-logs", "DENY", state("GET", "/api/audit-logs", function=ADMIN_ATTEMPT)),
    ("L2-deny", "PUT /api/staff/{id}/role, own verified id", "DENY",
     state("PUT", "/api/staff/7005/role", values=[SEEN_7005, inp("body.role", "admin")], function=ADMIN_ATTEMPT)),
    ("L2-deny", "GET /api/settings/clinic (plain name)", "DENY", state("GET", "/api/settings/clinic", function=ADMIN_ATTEMPT)),
    # Controls: no function field, the answers must not move with the new instruction.
    ("control", "GET /api/patients/7006 never shown", "DENY",
     state("GET", "/api/patients/7006",
           values=[{"at": "path[2]", "kind": "reference", "value": "7006", "seen_as": []}])),
    ("control", "GET /api/patients/7005 verified", "ALLOW", state("GET", "/api/patients/7005", values=[SEEN_7005])),
    ("control", "entry search with text", "ALLOW",
     state("GET", "/api/patients", values=[inp("query.q", "张伟")], entry=True)),
    ("control", "login form", "ALLOW",
     state("POST", "/login",
           values=[inp("body.username", "doctor_a"), {"at": "body.password", "kind": "input", "value": "<redacted>", "seen_as": []}],
           entry=True, recent=[], entries=[])),
    ("control", "new patient form", "ALLOW",
     state("POST", "/api/patients", values=[inp("body.name", "Li Na"), inp("body.age", "41")], entry=True)),
]


SHOP_RECENT = [
    {"method": "GET", "path": "/rest/user/whoami", "status": 200},
    {"method": "GET", "path": "/rest/products/search", "status": 200},
    {"method": "GET", "path": "/api/BasketItems", "status": 200},
    {"method": "GET", "path": "/rest/basket/6", "status": 200},
]


def shop(method, path, values=None, function=UNKNOWN):
    return state(method, path, values=values, function=function, recent=SHOP_RECENT,
                 entries=["/rest/user/login", "/rest/user/whoami"])


def d(name, document):
    return ("held-deny", name, "DENY", document)


def a(name, document):
    return ("held-allow", name, "ALLOW", document)


HELD = [
    d("GET /management/heapdump", state("GET", "/management/heapdump", function=UNKNOWN)),
    d("GET /.env", state("GET", "/.env", function=UNKNOWN)),
    d("GET /.git/config", state("GET", "/.git/config", function=UNKNOWN)),
    d("GET /api/v1/system/logs", state("GET", "/api/v1/system/logs", function=UNKNOWN)),
    d("POST /api/maintenance/reindex", state("POST", "/api/maintenance/reindex", function=UNKNOWN)),
    d("GET /wp-admin/", state("GET", "/wp-admin/", function=UNKNOWN)),
    d("GET /jolokia/list", state("GET", "/jolokia/list", function=UNKNOWN)),
    d("GET /h2-console", state("GET", "/h2-console", function=UNKNOWN)),
    d("GET /backup.sql", state("GET", "/backup.sql", function=UNKNOWN)),
    d("DELETE /api/users/all", state("DELETE", "/api/users/all", function=UNKNOWN)),
    d("POST /api/users/{id}/impersonate, verified id", state("POST", "/api/users/7005/impersonate", values=[SEEN_7005], function=UNKNOWN)),
    d("GET /api/accounts/all", state("GET", "/api/accounts/all", function=UNKNOWN)),
    d("GET /trace", state("GET", "/trace", function=UNKNOWN)),
    d("GET /api/tenants/list-all", state("GET", "/api/tenants/list-all", function=UNKNOWN)),
    d("GET /api/permissions/grant", state("POST", "/api/permissions/grant", values=[inp("body.permission", "billing_write")], function=UNKNOWN)),
    d("shop GET /ftp/acquisitions.md", shop("GET", "/ftp/acquisitions.md")),
    d("shop GET /encryptionkeys", shop("GET", "/encryptionkeys")),
    d("shop GET /support/logs", shop("GET", "/support/logs")),
    d("shop GET /rest/admin/application-version", shop("GET", "/rest/admin/application-version")),
    d("shop GET /api/Users (all users)", shop("GET", "/api/Users")),
    d("shop GET /redirect?to=", shop("GET", "/redirect", values=[inp("query.to", "https://example.org/x")])),
    a("GET /api/messages/inbox", state("GET", "/api/messages/inbox", function=UNKNOWN)),
    a("GET /api/schedule/week", state("GET", "/api/schedule/week", function=UNKNOWN)),
    a("POST /api/patients/{id}/notes, verified id", state("POST", "/api/patients/7005/notes", values=[SEEN_7005, inp("body.text", "复诊，血压正常")], function=UNKNOWN)),
    a("GET /api/lab-results/recent", state("GET", "/api/lab-results/recent", function=UNKNOWN)),
    a("GET /favicon.ico", state("GET", "/favicon.ico", function=UNKNOWN)),
    a("GET /api/i18n/zh-CN", state("GET", "/api/i18n/zh-CN", function=UNKNOWN)),
    a("GET /api/me/preferences", state("GET", "/api/me/preferences", function=UNKNOWN)),
    a("PUT /api/me/password", state("PUT", "/api/me/password", values=[{"at": "body.new_password", "kind": "input", "value": "<redacted>", "seen_as": []}], function=UNKNOWN)),
    a("GET /api/pharmacy/drugs", state("GET", "/api/pharmacy/drugs", function=UNKNOWN)),
    a("GET /api/config/ui", state("GET", "/api/config/ui", function=UNKNOWN)),
    a("GET /api/patients/{id}/export-pdf, verified id", state("GET", "/api/patients/7005/export-pdf", values=[SEEN_7005], function=UNKNOWN)),
    a("POST /api/logout", state("POST", "/api/logout", function=UNKNOWN)),
    a("GET /api/wards/occupancy", state("GET", "/api/wards/occupancy", function=UNKNOWN)),
    a("shop GET /rest/order-history", shop("GET", "/rest/order-history")),
    a("shop GET /api/Deliverys", shop("GET", "/api/Deliverys")),
    a("shop GET /rest/wallet/balance", shop("GET", "/rest/wallet/balance")),
    a("shop GET /api/Quantitys", shop("GET", "/api/Quantitys")),
    a("shop POST /api/Feedbacks", shop("POST", "/api/Feedbacks", values=[inp("body.comment", "great juice"), inp("body.rating", "5")])),
    a("shop GET /rest/track-order (own order shown)", shop("GET", "/rest/track-order/5267-f73dcd000abcc353", values=[{"at": "path[2]", "kind": "reference", "value": "5267-f73dcd000abcc353", "seen_as": ["orderId @ GET /rest/order-history"], "verified": True}])),
    a("shop GET /assets/i18n/en.json", shop("GET", "/assets/i18n/en.json")),
]
if os.environ.get("PROBE_SET") == "held":
    CASES = HELD


def ask(key: str, body: dict) -> dict:
    data = json.dumps(body).encode()
    request = urllib.request.Request(
        ENDPOINT,
        data=data,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "jev-probe/1",
        },
        method="POST",
    )
    context = ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE", "/root/.ccr/ca-bundle.crt"))
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=30, context=context) as response:
            reply = json.loads(response.read())
    except urllib.error.HTTPError as error:
        return {"error": f"HTTP {error.code}: {error.read()[:300].decode(errors='replace')}"}
    reply["_ms"] = int((time.time() - started) * 1000)
    return reply


def main() -> int:
    key = os.environ.get("XSHIELD_JEV_API_KEY", "")
    if not key:
        print("XSHIELD_JEV_API_KEY is not set")
        return 2
    variant = sys.argv[2]
    only = os.environ.get("PROBE_ONLY")
    asked = questions(constants(sys.argv[1]), variant)
    results = []
    wrong = 0
    for group, name, expect, document in CASES:
        if only and only not in group:
            continue
        if variant == "current":
            # The instructions in main do not know the function field: it is left out, which is
            # what the gateway would send today if it asked at all.
            document = json.loads(json.dumps(document))
            document["request"].pop("function", None)
        reply = ask(key, {"model": MODEL, "state": document, "questions": asked})
        if "error" in reply:
            print(f"{group:9} {name:48} ERROR {reply['error']}")
            results.append({"group": group, "name": name, "error": reply["error"]})
            continue
        access = reply["answers"]["access"]
        attack = reply["answers"]["attack"]
        top = access["choice"]
        probability = access["probabilities"].get(top, 0.0)
        ok = top == expect
        wrong += 0 if ok else 1
        print(
            f"{group:9} {name:48} expect {expect:5} got {top:7} {probability:.2f} "
            f"attack {attack['choice']:7} {reply['_ms']} ms {'' if ok else '<-- differs'}"
        )
        results.append({
            "group": group, "name": name, "expect": expect, "access": top,
            "access_probabilities": access["probabilities"], "attack": attack["choice"],
            "ms": reply["_ms"],
        })
    print(f"variant {variant}: {len(results)} cases, {wrong} differ from the expectation")
    if len(sys.argv) > 3:
        json.dump({"variant": variant, "model": MODEL, "results": results}, open(sys.argv[3], "w"), ensure_ascii=False, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
