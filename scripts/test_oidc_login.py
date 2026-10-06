#!/usr/bin/env python3
"""Drives the control plane's OIDC login against a real Keycloak, without a browser.

Purpose: the authorization-code + PKCE login, callback validation, session
establishment, CSRF binding, step-up re-authentication and logout of
`xshield-control` had only been exercised against mocks. This script plays the
browser (it keeps its own cookie jars and follows redirects by hand) against a
running control process and a running Keycloak, and asserts the outcome on the
wire, in PostgreSQL and in the management audit journal.

It is stdlib only. It does not start anything: `scripts/test_oidc_login.sh`
starts the throwaway database, Keycloak and the control process and then calls
this script with their addresses (see `--help`).

Assumptions that are NOT hidden by this script:
  * The browser's TLS requirement is not reproduced. The control plane marks its
    cookies `Secure` and `__Host-`-prefixed; a browser only accepts those over
    HTTPS or on a loopback origin. Here the "browser" is this script, which
    records and replays them literally, so it proves the attributes the server
    sends and that the server accepts them back, not browser enforcement.
  * The console origin (`http://127.0.0.1:55173`, the redirect URI registered in
    the dev realm) is only a name: no console runs. Redirects to it are rewritten
    to the control listener, as the console's same-origin proxy would.
  * The dev realm's `acr` is a hardcoded claim, so this proves the control
    plane's ACR check against what Keycloak sends, not that Keycloak performed
    multi-factor authentication.

Exit status 0 only when every check passed.
"""

from __future__ import annotations

import argparse
import hashlib
import base64
import http.client
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.parse
from html.parser import HTMLParser

RESULTS: list[tuple[bool, str, str]] = []


def expect(condition: bool, name: str, detail: str = "") -> bool:
    RESULTS.append((bool(condition), name, detail))
    marker = "ok  " if condition else "FAIL"
    suffix = f"  [{detail}]" if detail and not condition else ""
    print(f"{marker} {name}{suffix}", flush=True)
    return bool(condition)


def section(title: str) -> None:
    print(f"\n== {title}", flush=True)


class Response:
    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    def header(self, name: str) -> str | None:
        values = [v for k, v in self.headers if k.lower() == name.lower()]
        return values[0] if values else None

    def set_cookies(self) -> list[str]:
        return [v for k, v in self.headers if k.lower() == "set-cookie"]

    def json(self) -> dict:
        return json.loads(self.body.decode("utf-8"))

    def error_code(self) -> str | None:
        try:
            return self.json().get("error_code")
        except (ValueError, UnicodeDecodeError):
            return None


class Jar:
    """A minimal cookie jar: name -> value, honouring Max-Age=0 deletion."""

    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def absorb(self, response: Response) -> None:
        for raw in response.set_cookies():
            name, value, attributes = parse_set_cookie(raw)
            if attributes.get("max-age") == "0" or value == "":
                self.values.pop(name, None)
            else:
                self.values[name] = value

    def header(self) -> str | None:
        if not self.values:
            return None
        return "; ".join(f"{k}={v}" for k, v in self.values.items())


def parse_set_cookie(raw: str) -> tuple[str, str, dict[str, str]]:
    parts = [part.strip() for part in raw.split(";")]
    name, _, value = parts[0].partition("=")
    attributes: dict[str, str] = {}
    for part in parts[1:]:
        key, _, attribute_value = part.partition("=")
        attributes[key.lower()] = attribute_value
    return name, value, attributes


def request(
    base: str,
    method: str,
    path_or_url: str,
    jar: Jar | None = None,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> Response:
    parsed = urllib.parse.urlsplit(path_or_url if "://" in path_or_url else base + path_or_url)
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=20)
    target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    send = dict(headers or {})
    if jar is not None and jar.header() is not None:
        send["Cookie"] = jar.header()  # type: ignore[assignment]
    try:
        connection.request(method, target, body=body, headers=send)
        try:
            raw = connection.getresponse()
        except http.client.RemoteDisconnected as error:
            # A server that drops the connection without an answer (for example a
            # panicking handler) is a failure of its own, not a transport quirk.
            raise RuntimeError(f"{method} {target.split('?')[0]}: connection closed without a response") from error
        response = Response(raw.status, raw.getheaders(), raw.read())
    finally:
        connection.close()
    if jar is not None:
        jar.absorb(response)
    return response


class LoginFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.action: str | None = None
        self.fields: dict[str, str] = {}
        self._in_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form" and values.get("id") == "kc-form-login":
            self.action = values.get("action")
            self._in_form = True
        elif tag == "input" and self._in_form and values.get("name"):
            self.fields[values["name"]] = values.get("value") or ""  # type: ignore[index]

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._in_form = False


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class Harness:
    def __init__(self, args: argparse.Namespace) -> None:
        self.control = args.control_url.rstrip("/")
        self.keycloak = args.keycloak_url.rstrip("/")
        self.console_origin = args.console_origin.rstrip("/")
        self.database_url = args.database_url
        self.audit_dir = args.audit_dir
        self.dump_bin = args.dump_bin
        self.skip_stale_wait = args.skip_stale_wait
        realm = json.load(open(args.realm_file, encoding="utf-8"))
        self.users = {
            user["username"]: (user["id"], user["credentials"][0]["value"]) for user in realm["users"]
        }

    # ---- plumbing -------------------------------------------------------

    def to_control(self, url: str) -> str:
        if url.startswith(self.console_origin):
            return self.control + url[len(self.console_origin):]
        return url

    def psql(self, sql: str) -> str:
        completed = subprocess.run(
            ["psql", "-X", "-At", "-v", "ON_ERROR_STOP=1", "-d", self.database_url, "-c", sql],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return completed.stdout.strip()

    def session_count(self, subject: str | None = None) -> int:
        where = f" WHERE subject = '{subject}'" if subject else ""
        return int(self.psql(f"SELECT count(*) FROM xshield.management_browser_sessions{where}"))

    def open_transactions(self) -> int:
        return int(self.psql("SELECT count(*) FROM xshield.management_oidc_transactions"))

    def audit_events(self) -> list[dict]:
        environment = dict(os.environ)
        completed = subprocess.run(
            [self.dump_bin, self.audit_dir],
            capture_output=True,
            text=True,
            env=environment,
            timeout=60,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"audit dump failed: {completed.stderr.strip()}")
        return [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]

    # ---- the browser's side of the flow ----------------------------------

    def start_login(self) -> tuple[Response, Jar, str]:
        """GET /login; returns the 303, a jar holding the state cookie, and the state."""
        jar = Jar()
        response = request(self.control, "GET", "/control/v1/auth/oidc/start", jar)
        location = response.header("location") or ""
        state = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query)).get("state", "")
        return response, jar, state

    def keycloak_authenticate(self, authorization_url: str, username: str, kc_jar: Jar | None = None) -> Response:
        """Follows the authorization request, submits the login form, returns the redirect
        Keycloak sends back to the (rewritten) callback."""
        kc_jar = kc_jar if kc_jar is not None else Jar()
        page = request(self.keycloak, "GET", authorization_url, kc_jar)
        if page.status in (302, 303) and "error=" in (page.header("location") or ""):
            return page  # Keycloak refused the authorization request itself.
        if page.status != 200:
            raise RuntimeError(f"Keycloak authorization request returned {page.status}: {page.body[:300]!r}")
        parser = LoginFormParser()
        parser.feed(page.body.decode("utf-8"))
        if parser.action is None:
            raise RuntimeError("Keycloak login page has no kc-form-login form")
        _, password = self.users[username]
        form = dict(parser.fields)
        form["username"] = username
        form["password"] = password
        submit = request(
            self.keycloak,
            "POST",
            parser.action,
            kc_jar,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=urllib.parse.urlencode(form).encode(),
        )
        if submit.status not in (302, 303):
            raise RuntimeError(f"Keycloak login submit returned {submit.status}: {submit.body[:300]!r}")
        return submit

    def callback(self, redirect: Response | str, jar: Jar) -> Response:
        location = redirect if isinstance(redirect, str) else (redirect.header("location") or "")
        return request(self.control, "GET", self.to_control(location), jar)

    def full_login(self, username: str, kc_jar: Jar | None = None) -> tuple[Jar, dict[str, str], Response]:
        """A complete, honest login. Returns the control jar (session cookie), the
        session bootstrap document and the callback response."""
        start, jar, _ = self.start_login()
        assert start.status == 303, f"login start returned {start.status}"
        redirect = self.keycloak_authenticate(start.header("location") or "", username, kc_jar)
        callback = self.callback(redirect, jar)
        session_document: dict[str, str] = {}
        if callback.status == 303:
            read = request(self.control, "GET", "/control/v1/session", jar)
            if read.status == 200:
                session_document = read.json()
        return jar, session_document, callback

    def write_headers(self, csrf: str | None, origin: str | None = "console") -> dict[str, str]:
        headers: dict[str, str] = {}
        if origin == "console":
            headers["Origin"] = self.console_origin
        elif origin is not None:
            headers["Origin"] = origin
        if csrf is not None:
            headers["X-Xshield-Csrf"] = csrf
        return headers


def expect_refused(
    harness: Harness,
    name: str,
    response: Response,
    status: int,
    code: str,
    sessions_before: int,
) -> None:
    expect(
        response.status == status and response.error_code() == code,
        f"{name} -> {status} {code}",
        f"got {response.status} {response.error_code()}",
    )
    expect(
        not any(c.startswith("__Host-xshield-session=") and "Max-Age=0" not in c for c in response.set_cookies()),
        f"{name}: no session cookie issued",
    )
    expect(
        harness.session_count() == sessions_before,
        f"{name}: no session row created",
        f"{harness.session_count()} != {sessions_before}",
    )


def check_cookie(raw: str, name: str, max_age: str, label: str) -> None:
    cookie_name, value, attributes = parse_set_cookie(raw)
    expect(cookie_name == name, f"{label}: cookie name {name}", cookie_name)
    expect(cookie_name.startswith("__Host-"), f"{label}: __Host- prefix")
    expect("secure" in attributes, f"{label}: Secure")
    expect("httponly" in attributes, f"{label}: HttpOnly")
    expect(attributes.get("samesite", "").lower() == "lax", f"{label}: SameSite=Lax", str(attributes))
    expect(attributes.get("path") == "/", f"{label}: Path=/")
    expect("domain" not in attributes, f"{label}: no Domain (required by __Host-)")
    expect(attributes.get("max-age") == max_age, f"{label}: Max-Age={max_age}", str(attributes.get("max-age")))
    if max_age != "0":
        expect(re.fullmatch(r"[0-9a-f]{64}|[A-Za-z0-9_-]{16,128}", value) is not None, f"{label}: opaque random value")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    environment = os.environ.get
    parser.add_argument("--control-url", default=environment("XSHIELD_OIDC_TEST_CONTROL_URL"), required=not environment("XSHIELD_OIDC_TEST_CONTROL_URL"))
    parser.add_argument("--keycloak-url", default=environment("XSHIELD_OIDC_TEST_KEYCLOAK_URL"), required=not environment("XSHIELD_OIDC_TEST_KEYCLOAK_URL"))
    parser.add_argument("--console-origin", default=environment("XSHIELD_OIDC_TEST_CONSOLE_ORIGIN", "http://127.0.0.1:55173"))
    parser.add_argument("--database-url", default=environment("XSHIELD_OIDC_TEST_DATABASE_URL"), required=not environment("XSHIELD_OIDC_TEST_DATABASE_URL"))
    parser.add_argument("--audit-dir", default=environment("XSHIELD_OIDC_TEST_AUDIT_DIR"), required=not environment("XSHIELD_OIDC_TEST_AUDIT_DIR"))
    parser.add_argument("--dump-bin", default=environment("XSHIELD_OIDC_TEST_DUMP_BIN"), required=not environment("XSHIELD_OIDC_TEST_DUMP_BIN"))
    parser.add_argument("--realm-file", default=environment("XSHIELD_OIDC_TEST_REALM_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "dev", "keycloak", "xshield-dev-realm.json")))
    parser.add_argument("--skip-stale-wait", action="store_true", help="skip the ~2 minute step-up lapse checks (reported as SKIPPED, not passed)")
    args = parser.parse_args()
    harness = Harness(args)
    developer_id, _ = harness.users["developer"]
    observer_id, _ = harness.users["observer-only"]
    unprovisioned_id, _ = harness.users["unprovisioned"]
    run_started = time.time()

    # ------------------------------------------------------------------
    section("login start: authorization request and state cookie")
    start, state_jar, state = harness.start_login()
    location = start.header("location") or ""
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query, keep_blank_values=True))
    expect(start.status == 303, "GET /login -> 303", str(start.status))
    expect(location.startswith(f"{harness.keycloak}/realms/xshield-dev/protocol/openid-connect/auth?"), "redirects to the Keycloak authorization endpoint", location)
    expect(query.get("response_type") == "code", "response_type=code")
    expect(query.get("client_id") == "xshield-console-dev", "client_id")
    expect(query.get("redirect_uri") == f"{harness.console_origin}/control/v1/auth/oidc/callback", "redirect_uri is the console callback", query.get("redirect_uri", ""))
    expect(query.get("scope") == "openid", "scope=openid", query.get("scope", ""))
    expect(query.get("code_challenge_method") == "S256" and len(query.get("code_challenge", "")) == 43, "PKCE S256 challenge present")
    expect(len(query.get("state", "")) >= 16 and len(query.get("nonce", "")) >= 16, "state and nonce are random values")
    expect(query.get("acr_values") == "1", "acr_values carries the required ACR", query.get("acr_values", ""))
    expect("prompt" not in query and "max_age" not in query, "plain login does not force re-authentication")
    cookies = start.set_cookies()
    expect(len(cookies) == 1, "exactly one cookie set by login start", str(cookies))
    if cookies:
        check_cookie(cookies[0], "__Host-xshield-oidc-state", "300", "state cookie")
        expect(state_jar.values.get("__Host-xshield-oidc-state") == state, "state cookie value equals the state parameter")
    expect(start.header("cache-control") == "no-store", "login start is no-store")
    expect(harness.open_transactions() >= 1, "a server-side OIDC transaction is stored")

    # ------------------------------------------------------------------
    section("happy path: developer logs in through Keycloak")
    sessions_before = harness.session_count()
    kc_developer = Jar()
    redirect = harness.keycloak_authenticate(location, "developer", kc_developer)
    callback_location = redirect.header("location") or ""
    expect(harness.to_control(callback_location).startswith(harness.control + "/control/v1/auth/oidc/callback?"), "Keycloak redirects back to the registered callback", callback_location)
    callback_query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(callback_location).query))
    expect(callback_query.get("state") == state and "code" in callback_query, "callback carries code and the original state")
    login_callback = harness.callback(redirect, state_jar)
    expect(login_callback.status == 303, "callback -> 303", f"{login_callback.status} {login_callback.body[:200]!r}")
    expect(login_callback.header("location") == f"{harness.console_origin}/", "callback redirects to the console root", str(login_callback.header("location")))
    callback_cookies = login_callback.set_cookies()
    session_cookie = next((c for c in callback_cookies if c.startswith("__Host-xshield-session=")), None)
    expect(session_cookie is not None, "session cookie is set")
    if session_cookie:
        check_cookie(session_cookie, "__Host-xshield-session", "28800", "session cookie")
    cleared = next((c for c in callback_cookies if c.startswith("__Host-xshield-oidc-state=")), None)
    expect(cleared is not None and "Max-Age=0" in cleared and "Secure" in cleared and "HttpOnly" in cleared, "state cookie is cleared by the callback", str(cleared))
    expect("__Host-xshield-oidc-state" not in state_jar.values, "client state cookie gone after callback")
    expect(login_callback.header("cache-control") == "no-store", "callback is no-store")
    expect(harness.session_count() == sessions_before + 1, "exactly one session row created")
    session_token = state_jar.values.get("__Host-xshield-session", "")
    stored = harness.psql("SELECT encode(session_digest, 'hex') FROM xshield.management_browser_sessions ORDER BY created_at DESC LIMIT 1")
    expect(stored == hashlib.sha256(session_token.encode()).hexdigest() and stored != session_token, "database stores only the SHA-256 digest of the session token")

    session = request(harness.control, "GET", "/control/v1/session", state_jar)
    document = session.json() if session.status == 200 else {}
    expect(session.status == 200, "GET /session with cookie -> 200", str(session.status))
    expect(document.get("subject") == developer_id, "session subject is the Keycloak subject", str(document.get("subject")))
    expect(set(document.get("roles", [])) >= {"observer", "sensitive_evidence_reader", "policy_approver"}, "session roles come from the deployment mapping", str(document.get("roles")))
    expect(re.fullmatch(r"[0-9a-f]{64}", document.get("csrf_token", "")) is not None, "session returns a 64-hex CSRF token")
    expect(document.get("csrf_token") != session_token, "CSRF token is independent of the session token")
    expect(document.get("tenant_id") == "tenant_oidc" and document.get("site_id") == "site_oidc", "tenant/site scope is the deployment's")
    expect(document.get("step_up_valid") is False and document.get("last_reauthenticated_at") is None, "a fresh session has no step-up")
    expect(bool(document.get("session_expires_at")) and bool(document.get("idle_expires_at")), "expiry timestamps are returned")
    expect(session.header("cache-control") == "no-store", "session read is no-store")
    csrf = document.get("csrf_token", "")
    anonymous = request(harness.control, "GET", "/control/v1/session")
    expect(anonymous.status == 401 and anonymous.error_code() == "CONTROL_AUTH_REQUIRED", "GET /session without cookie -> 401 CONTROL_AUTH_REQUIRED", f"{anonymous.status} {anonymous.error_code()}")
    forged = Jar()
    forged.values["__Host-xshield-session"] = secrets.token_hex(32)
    forged_read = request(harness.control, "GET", "/control/v1/session", forged)
    expect(forged_read.status == 401 and forged_read.error_code() == "CONTROL_AUTH_REQUIRED", "a random well-formed session token is refused", f"{forged_read.status} {forged_read.error_code()}")

    # ------------------------------------------------------------------
    section("callback replay and state tampering")
    sessions_now = harness.session_count()
    replay_jar = Jar()
    replay_jar.values["__Host-xshield-oidc-state"] = state
    replay = harness.callback(callback_location, replay_jar)
    expect_refused(harness, "replayed callback", replay, 401, "CONTROL_OIDC_STATE_EXPIRED", sessions_now)

    start_b, jar_b, state_b = harness.start_login()
    redirect_b = harness.keycloak_authenticate(start_b.header("location") or "", "developer", Jar())
    callback_b = redirect_b.header("location") or ""
    tampered_query = urllib.parse.urlsplit(callback_b).query
    swapped = harness.to_control(callback_b.replace(f"state={state_b}", f"state={secrets.token_urlsafe(24)}"))
    expect_refused(harness, "callback whose state differs from the cookie", request(harness.control, "GET", swapped, jar_b), 401, "CONTROL_OIDC_STATE_INVALID", sessions_now)
    expect_refused(harness, "callback without the state cookie", request(harness.control, "GET", harness.to_control(callback_b)), 401, "CONTROL_OIDC_STATE_INVALID", sessions_now)
    forged_state = secrets.token_urlsafe(24)
    forged_jar = Jar()
    forged_jar.values["__Host-xshield-oidc-state"] = forged_state
    forged_callback = harness.to_control(callback_b.replace(f"state={state_b}", f"state={forged_state}"))
    expect_refused(harness, "callback with an unknown state in both cookie and query", request(harness.control, "GET", forged_callback, forged_jar), 401, "CONTROL_OIDC_STATE_EXPIRED", sessions_now)
    code_b = dict(urllib.parse.parse_qsl(tampered_query))["code"]
    bad_code = harness.to_control(re.sub(r"([?&])code=[^&]+", r"\g<1>code=" + secrets.token_urlsafe(40), callback_b))
    expect_refused(harness, "callback with a forged authorization code", request(harness.control, "GET", bad_code, jar_b), 401, "CONTROL_OIDC_TOKEN_REJECTED", sessions_now)
    expect_refused(harness, "the genuine code after the transaction was consumed", request(harness.control, "GET", harness.to_control(callback_b), jar_b), 401, "CONTROL_OIDC_STATE_EXPIRED", sessions_now)

    for label, mutate, status, code in (
        ("callback with an unknown parameter", lambda q: q + "&extra=1", 400, "CONTROL_OIDC_CALLBACK_INVALID"),
        ("callback with a duplicated parameter", lambda q: q + "&state=x", 400, "CONTROL_OIDC_CALLBACK_INVALID"),
        ("callback with no query", lambda q: None, 400, "CONTROL_OIDC_CALLBACK_INVALID"),
        ("callback with an IdP error", lambda q: "error=access_denied&state=" + state_b, 401, "CONTROL_OIDC_LOGIN_DENIED"),
        ("callback from a different issuer", lambda q: q + "&iss=" + urllib.parse.quote("http://evil.example/realms/x", safe=""), 401, "CONTROL_OIDC_ISSUER_MISMATCH"),
    ):
        _, jar_c, state_c = harness.start_login()
        mutated = mutate(f"code=abc&state={state_c}")
        path = "/control/v1/auth/oidc/callback" + (f"?{mutated}" if mutated is not None else "")
        expect_refused(harness, label, request(harness.control, "GET", path, jar_c), status, code, sessions_now)

    # ------------------------------------------------------------------
    section("PKCE and nonce are enforced by the real exchange")
    for label, rewrite, code in (
        (
            "authorization request carrying a different PKCE challenge (verifier mismatch)",
            lambda q: {**q, "code_challenge": pkce_challenge(secrets.token_urlsafe(48))},
            "CONTROL_OIDC_TOKEN_REJECTED",
        ),
        (
            "authorization request without any PKCE challenge",
            lambda q: {k: v for k, v in q.items() if not k.startswith("code_challenge")},
            "CONTROL_OIDC_LOGIN_DENIED",
        ),
        (
            "authorization request with a different nonce",
            lambda q: {**q, "nonce": secrets.token_urlsafe(24)},
            "CONTROL_OIDC_ID_TOKEN_REJECTED",
        ),
    ):
        start_p, jar_p, _ = harness.start_login()
        url = urllib.parse.urlsplit(start_p.header("location") or "")
        rebuilt = urllib.parse.urlunsplit(url._replace(query=urllib.parse.urlencode(rewrite(dict(urllib.parse.parse_qsl(url.query))))))
        redirect_p = harness.keycloak_authenticate(rebuilt, "developer", Jar())
        expect_refused(harness, label, harness.callback(redirect_p, jar_p), 401, code, sessions_now)

    # ------------------------------------------------------------------
    section("unprovisioned subject")
    start_u, jar_u, _ = harness.start_login()
    redirect_u = harness.keycloak_authenticate(start_u.header("location") or "", "unprovisioned", Jar())
    expect_refused(harness, "valid Keycloak user absent from the role mapping", harness.callback(redirect_u, jar_u), 403, "CONTROL_OIDC_SUBJECT_NOT_PROVISIONED", sessions_now)
    expect(harness.session_count(unprovisioned_id) == 0, "no session for the unprovisioned subject")

    # ------------------------------------------------------------------
    section("CSRF on a state-changing request")
    for label, headers in (
        ("POST without Origin and CSRF header", harness.write_headers(None, None)),
        ("POST with Origin but no CSRF header", harness.write_headers(None)),
        ("POST with the CSRF header but no Origin", harness.write_headers(csrf, None)),
        ("POST with the CSRF header and a foreign Origin", harness.write_headers(csrf, "http://evil.example")),
        ("POST with the right Origin and a wrong CSRF token", harness.write_headers("0" * 64)),
    ):
        refused = request(harness.control, "POST", "/control/v1/session/logout", state_jar, headers=headers)
        expect(refused.status == 403 and refused.error_code() == "CONTROL_CSRF_REQUIRED", f"{label} -> 403 CONTROL_CSRF_REQUIRED", f"{refused.status} {refused.error_code()}")
    still = request(harness.control, "GET", "/control/v1/session", state_jar)
    expect(still.status == 200, "the refused writes did not end the session")
    no_csrf_reauth = request(harness.control, "POST", "/control/v1/auth/oidc/reauth/start", state_jar, headers=harness.write_headers(None))
    expect(no_csrf_reauth.status == 403 and no_csrf_reauth.error_code() == "CONTROL_CSRF_REQUIRED", "step-up start without CSRF -> 403 CONTROL_CSRF_REQUIRED", f"{no_csrf_reauth.status} {no_csrf_reauth.error_code()}")
    with_body = request(harness.control, "POST", "/control/v1/auth/oidc/reauth/start", state_jar, headers={**harness.write_headers(csrf), "Content-Type": "application/json"}, body=b"{}")
    expect(with_body.status in (400, 413) and (with_body.error_code() or "").startswith("CONTROL_"), "step-up start with a body is refused", f"{with_body.status} {with_body.error_code()}")

    # ------------------------------------------------------------------
    section("step-up requires a role that may step up")
    observer_jar, observer_session, observer_callback = harness.full_login("observer-only")
    expect(observer_callback.status == 303 and observer_session.get("subject") == observer_id, "observer-only user logs in", f"{observer_callback.status}")
    observer_denied = request(harness.control, "POST", "/control/v1/auth/oidc/reauth/start", observer_jar, headers=harness.write_headers(observer_session.get("csrf_token")))
    expect(observer_denied.status == 403 and observer_denied.error_code() == "CONTROL_SCOPE_DENIED", "observer-only cannot start step-up -> 403 CONTROL_SCOPE_DENIED", f"{observer_denied.status} {observer_denied.error_code()}")

    # ------------------------------------------------------------------
    section("step-up re-authentication (developer)")
    reauth = request(harness.control, "POST", "/control/v1/auth/oidc/reauth/start", state_jar, headers=harness.write_headers(csrf))
    reauth_document = reauth.json() if reauth.status == 200 else {}
    expect(reauth.status == 200, "POST /reauth/start -> 200", f"{reauth.status} {reauth.body[:200]!r}")
    reauth_url = reauth_document.get("authorization_url", "")
    reauth_query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(reauth_url).query))
    expect(reauth_query.get("prompt") == "login" and reauth_query.get("max_age") == "0", "step-up forces a fresh login (prompt=login, max_age=0)", str(reauth_query))
    expect(reauth_query.get("code_challenge_method") == "S256" and reauth_query.get("acr_values") == "1", "step-up keeps PKCE S256 and the ACR requirement")
    reauth_state_cookie = next((c for c in reauth.set_cookies() if c.startswith("__Host-xshield-oidc-state=")), None)
    expect(reauth_state_cookie is not None, "step-up start sets a state cookie")
    if reauth_state_cookie:
        check_cookie(reauth_state_cookie, "__Host-xshield-oidc-state", "300", "step-up state cookie")
    expect(reauth.header("cache-control") == "no-store", "step-up start is no-store")

    # The browser still holds the developer's Keycloak session; prompt=login must
    # show the form anyway, otherwise Keycloak would reuse the old authentication.
    swap_jar = Jar()
    swap_jar.values.update(state_jar.values)
    page = request(harness.keycloak, "GET", reauth_url, Jar())
    expect(page.status == 200 and b"kc-form-login" in page.body, "Keycloak asks for credentials again at step-up")

    # An identity swap: a different, provisioned user authenticates at Keycloak for
    # the developer's step-up. The session must not gain a step-up.
    before_reauth = request(harness.control, "GET", "/control/v1/session", state_jar).json()
    redirect_swap = harness.keycloak_authenticate(reauth_url, "observer-only", Jar())
    swap = harness.callback(redirect_swap, swap_jar)
    expect(swap.status == 401 and swap.error_code() == "CONTROL_OIDC_REAUTH_SESSION_INVALID", "step-up completed by a different subject -> 401 CONTROL_OIDC_REAUTH_SESSION_INVALID", f"{swap.status} {swap.error_code()}")
    after_swap = request(harness.control, "GET", "/control/v1/session", state_jar).json()
    expect(after_swap.get("step_up_valid") is False and after_swap.get("last_reauthenticated_at") is None, "identity swap left the session without step-up")

    reauth = request(harness.control, "POST", "/control/v1/auth/oidc/reauth/start", state_jar, headers=harness.write_headers(csrf))
    reauth_url = reauth.json()["authorization_url"]
    redirect_reauth = harness.keycloak_authenticate(reauth_url, "developer", Jar())
    reauth_callback = harness.callback(redirect_reauth, state_jar)
    expect(reauth_callback.status == 303 and reauth_callback.header("location") == f"{harness.console_origin}/", "step-up callback -> 303 to console", f"{reauth_callback.status} {reauth_callback.body[:200]!r}")
    stepped_at = time.time()
    after = request(harness.control, "GET", "/control/v1/session", state_jar).json()
    expect(after.get("step_up_valid") is True, "session now reports step_up_valid")
    expect(bool(after.get("last_reauthenticated_at")), "last_reauthenticated_at is set", str(after.get("last_reauthenticated_at")))
    expect(after.get("subject") == developer_id and after.get("csrf_token") == csrf, "step-up keeps the same session, subject and CSRF token")
    expect("__Host-xshield-session" in state_jar.values and state_jar.values["__Host-xshield-session"] == session_token, "step-up does not rotate or drop the session cookie")

    # A second step-up is started and the user authenticates at Keycloak now; the
    # callback is delivered after the 60 s auth_time freshness bound has passed.
    reauth2 = request(harness.control, "POST", "/control/v1/auth/oidc/reauth/start", state_jar, headers=harness.write_headers(csrf))
    redirect_stale = harness.keycloak_authenticate(reauth2.json()["authorization_url"], "developer", Jar())
    stale_started = time.time()
    last_before_stale = after.get("last_reauthenticated_at")
    if harness.skip_stale_wait:
        print("SKIPPED step-up lapse and stale auth_time checks (--skip-stale-wait)", flush=True)
        stale_note = False
    else:
        stale_note = True
        time.sleep(max(0.0, stale_started + 62 - time.time()))
        stale = harness.callback(redirect_stale, state_jar)
        expect(stale.status == 401 and stale.error_code() == "CONTROL_OIDC_AUTH_TIME_STALE", "callback delivered >60 s after authentication -> 401 CONTROL_OIDC_AUTH_TIME_STALE", f"{stale.status} {stale.error_code()}")
        unchanged = request(harness.control, "GET", "/control/v1/session", state_jar).json()
        expect(unchanged.get("last_reauthenticated_at") == last_before_stale, "stale callback did not refresh last_reauthenticated_at")
        time.sleep(max(0.0, stepped_at + 122 - time.time()))
        lapsed = request(harness.control, "GET", "/control/v1/session", state_jar).json()
        expect(lapsed.get("step_up_valid") is False, "step-up lapses after the two-minute window", str(lapsed))
        expect(lapsed.get("last_reauthenticated_at") == last_before_stale, "lapse keeps the recorded last_reauthenticated_at")
        expect(lapsed.get("subject") == developer_id, "the session itself is still valid after the step-up lapsed")

    # ------------------------------------------------------------------
    section("logout")
    logout = request(harness.control, "POST", "/control/v1/session/logout", state_jar, headers=harness.write_headers(csrf))
    expect(logout.status == 204, "POST /logout -> 204", str(logout.status))
    cleared_session = next((c for c in logout.set_cookies() if c.startswith("__Host-xshield-session=")), None)
    expect(cleared_session is not None and "Max-Age=0" in cleared_session and "Secure" in cleared_session and "HttpOnly" in cleared_session, "logout clears the session cookie", str(cleared_session))
    replay_jar = Jar()
    replay_jar.values["__Host-xshield-session"] = session_token
    dead = request(harness.control, "GET", "/control/v1/session", replay_jar)
    expect(dead.status == 401 and dead.error_code() == "CONTROL_AUTH_REQUIRED", "the logged-out token is refused afterwards", f"{dead.status} {dead.error_code()}")
    revoked = harness.psql(f"SELECT revoked_at IS NOT NULL FROM xshield.management_browser_sessions WHERE session_digest = decode('{hashlib.sha256(session_token.encode()).hexdigest()}', 'hex')")
    expect(revoked == "t", "the session row is revoked in PostgreSQL", revoked)
    second = request(harness.control, "POST", "/control/v1/session/logout", replay_jar, headers=harness.write_headers(csrf))
    expect(second.status == 401, "a second logout with the dead token -> 401", str(second.status))
    observer_logout = request(harness.control, "POST", "/control/v1/session/logout", observer_jar, headers=harness.write_headers(observer_session.get("csrf_token")))
    expect(observer_logout.status == 204, "the observer-only session is logged out")

    # ------------------------------------------------------------------
    section("management audit journal")
    events = harness.audit_events()
    expect(len(events) > 0, "the access journal is readable and authenticated", str(len(events)))
    sequences = [event["producer_seq"] for event in events]
    expect(sequences == sorted(sequences) and len(set(sequences)) == len(sequences), "journal sequence is strictly increasing")
    expect(all(event["schema_version"] == 3 and event["producer_id"] == "xshield-control" for event in events), "every event has the control schema and producer")
    for event in events:
        if event["payload"]["outcome"] == "PASS":
            continue
        expect(event["payload"]["reason_code"].startswith("CONTROL_"), f"terminal state has a stable reason code ({event['payload']['reason_code']})")
    expect(not any(token in json.dumps(events) for token in (session_token, csrf, state, code_b)), "no session token, CSRF token, state or code appears in the audit")

    def count(event_type: str, reason: str, subject: str | None = None, outcome: str | None = None) -> int:
        return sum(
            1
            for event in events
            if event["event_type"] == event_type
            and event["payload"]["reason_code"] == reason
            and (subject is None or event["payload"].get("subject_ref") == subject)
            and (outcome is None or event["payload"]["outcome"] == outcome)
        )

    expectations = [
        ("console.auth.login", "CONTROL_OIDC_LOGIN_STARTED", None, "PASS", 1),
        ("console.auth.callback", "CONTROL_OIDC_LOGIN_COMPLETED", developer_id, "PASS", 1),
        ("console.auth.callback", "CONTROL_OIDC_LOGIN_COMPLETED", observer_id, "PASS", 1),
        ("console.auth.session.read", "CONTROL_BROWSER_SESSION_READ", developer_id, "PASS", 1),
        ("console.auth.callback", "CONTROL_OIDC_STATE_EXPIRED", None, None, 1),
        ("console.auth.callback", "CONTROL_OIDC_STATE_INVALID", None, None, 1),
        ("console.auth.callback", "CONTROL_OIDC_TOKEN_REJECTED", None, None, 1),
        ("console.auth.callback", "CONTROL_OIDC_ID_TOKEN_REJECTED", None, None, 1),
        ("console.auth.callback", "CONTROL_OIDC_LOGIN_DENIED", None, None, 1),
        ("console.auth.callback", "CONTROL_OIDC_CALLBACK_INVALID", None, None, 1),
        ("console.auth.callback", "CONTROL_OIDC_ISSUER_MISMATCH", None, None, 1),
        ("console.auth.callback", "CONTROL_OIDC_SUBJECT_NOT_PROVISIONED", None, None, 1),
        ("console.auth.callback", "CONTROL_OIDC_REAUTH_SESSION_INVALID", None, None, 1),
        ("console.auth.session.logout", "CONTROL_CSRF_REQUIRED", developer_id, None, 1),
        ("console.auth.reauth.start", "CONTROL_OIDC_REAUTH_STARTED", developer_id, "PASS", 1),
        ("console.auth.reauth.start", "CONTROL_SCOPE_DENIED", observer_id, None, 1),
        ("console.auth.reauth.start", "CONTROL_CSRF_REQUIRED", developer_id, None, 1),
        ("console.auth.reauth.callback", "CONTROL_OIDC_REAUTH_VERIFIED", developer_id, "PASS", 1),
        ("console.auth.session.logout", "CONTROL_BROWSER_SESSION_REVOKED", developer_id, "PASS", 1),
        ("console.auth.session.logout", "CONTROL_BROWSER_SESSION_REVOKED", observer_id, "PASS", 1),
    ]
    if stale_note:
        expectations.append(("console.auth.callback", "CONTROL_OIDC_AUTH_TIME_STALE", None, None, 1))
    for event_type, reason, subject, outcome, minimum in expectations:
        found = count(event_type, reason, subject, outcome)
        who = f" subject={subject}" if subject else ""
        expect(found >= minimum, f"audit has {event_type} / {reason}{who}", f"found {found}")
    outcomes = sorted({event["payload"]["outcome"] for event in events})
    print(f"     audit outcomes seen: {outcomes}")

    # ------------------------------------------------------------------
    failed = [item for item in RESULTS if not item[0]]
    print(f"\n{len(RESULTS) - len(failed)} passed, {len(failed)} failed, in {time.time() - run_started:.0f}s", flush=True)
    if args.skip_stale_wait:
        print("NOTE: the stale-step-up checks were skipped; this run proves less than the default run.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
