/** Real PostgreSQL hold history and independent administrator authority over HTTP. */
import assert from "node:assert/strict";
import { ApiError, ControlClient } from "../src/api.ts";

let phase = 1;
try {
  const loopback = (value: string | undefined) => {
    const url = new URL(value ?? "");
    assert.equal(url.protocol, "http:");
    assert.equal(url.hostname, "127.0.0.1");
    assert.equal(url.pathname, "/");
    assert.equal(url.username + url.password + url.search + url.hash, "");
    assert.ok(url.port);
    return url;
  };
  const owner = loopback(process.env.XSHIELD_CONSOLE_TEST_ORIGIN);
  const admin = loopback(process.env.XSHIELD_CONSOLE_TEST_ADMIN_ORIGIN);
  const observer = loopback(process.env.XSHIELD_CONSOLE_TEST_OBSERVER_ORIGIN);
  const foreignTenant = loopback(process.env.XSHIELD_CONSOLE_TEST_FOREIGN_TENANT_ORIGIN);
  const foreignSite = loopback(process.env.XSHIELD_CONSOLE_TEST_FOREIGN_SITE_ORIGIN);
  const tenant = process.env.XSHIELD_CONSOLE_TEST_TENANT!;
  const artifact = process.env.XSHIELD_CONSOLE_TEST_ARTIFACT!;
  const until = process.env.XSHIELD_CONSOLE_TEST_HOLD_UNTIL!;
  let origin = owner;
  const network = globalThis.fetch;
  const requestIds = new Set<string>();
  globalThis.fetch = async (input, options) => {
    const path = String(input);
    assert.match(path, /^\/control\/v1\/(?:cases|evidence-holds)(?:\/|\?|$)/);
    assert.equal(options?.credentials, "omit");
    assert.equal(options?.redirect, "error");
    assert.equal(options?.cache, "no-store");
    assert.equal(options?.referrerPolicy, "no-referrer");
    const response = await network(new URL(path, origin), options);
    assert.equal(response.headers.get("cache-control"), "private, no-store");
    const raw = await response.clone().json();
    assert.match(raw.request_id, /^req_[a-f0-9-]+$/);
    assert.ok(!requestIds.has(raw.request_id));
    requestIds.add(raw.request_id);
    if (response.ok) {
      assert.equal(raw.tenant_id, tenant);
      assert.equal(raw.site_id, "site_a");
    }
    for (const excluded of [
      "locator",
      "key_ref",
      "content_base64",
      "idempotency_digest",
      "request_digest",
      "payload_json",
    ])
      assert.ok(!JSON.stringify(raw).includes(excluded));
    return response;
  };
  const client = new ControlClient(process.env.XSHIELD_CONSOLE_TEST_TOKEN ?? "");
  const fails = (code: string, status: number) => (error: unknown) => {
    assert.ok(error instanceof ApiError);
    assert.equal(error.code, code);
    assert.equal(error.status, status);
    assert.ok(error.requestId && requestIds.has(error.requestId));
    return true;
  };
  const reason = "Wire sensitive retention reason";
  const releaseReason = "Wire sensitive release reason";
  phase = 2;
  const caseId = (await client.createCase("Wire retention investigation", "hold-wire-case-key"))
    .case_id;
  const otherCase = (
    await client.createCase("Wire other investigation", "hold-wire-other-case-key")
  ).case_id;
  await client.addCaseItem(caseId, artifact, "hold-wire-item-key");
  origin = admin;
  assert.deepEqual((await client.evidenceHolds(caseId)).items, []);
  const held = await client.createEvidenceHold(
    caseId,
    artifact,
    reason,
    until,
    "hold-wire-create-key",
  );
  assert.equal(held.created_by, "console-hold-admin");
  assert.equal(held.reason, reason);
  assert.equal(held.hold_until, until);
  assert.equal(held.replayed, false);
  assert.equal(held.released_event_id, null);
  const replay = await client.createEvidenceHold(
    caseId,
    artifact,
    reason,
    until,
    "hold-wire-create-key",
  );
  assert.equal(replay.replayed, true);
  assert.equal(replay.hold_id, held.hold_id);
  assert.equal(replay.created_at, held.created_at);
  phase = 3;
  await assert.rejects(
    client.createEvidenceHold(
      caseId,
      artifact,
      "Changed hold reason",
      until,
      "hold-wire-create-key",
    ),
    fails("CONTROL_EVIDENCE_HOLD_CONFLICT", 409),
  );
  const later = new Date(Date.parse(until) + 3_600_000).toISOString();
  await assert.rejects(
    client.createEvidenceHold(caseId, artifact, reason, later, "hold-wire-create-key"),
    fails("CONTROL_EVIDENCE_HOLD_CONFLICT", 409),
  );
  await assert.rejects(
    client.createEvidenceHold(caseId, artifact, reason, until, "hold-wire-natural-conflict"),
    fails("CONTROL_EVIDENCE_HOLD_CONFLICT", 409),
  );
  await assert.rejects(
    client.createEvidenceHold(otherCase, artifact, reason, until, "hold-wire-nonmember-key"),
    fails("CONTROL_EVIDENCE_HOLD_TARGET_UNAVAILABLE", 404),
  );
  phase = 4;
  for (const deniedOrigin of [owner, observer]) {
    origin = deniedOrigin;
    for (const action of [
      () => client.evidenceHolds(caseId),
      () => client.createEvidenceHold(caseId, artifact, reason, until, "hold-wire-denied-key"),
      () => client.releaseEvidenceHold(held.hold_id, releaseReason, "hold-wire-denied-key"),
    ])
      await assert.rejects(action(), fails("CONTROL_SCOPE_DENIED", 403));
  }
  for (const deniedOrigin of [foreignTenant, foreignSite]) {
    origin = deniedOrigin;
    for (const action of [
      () => client.evidenceHolds(caseId),
      () => client.createEvidenceHold(caseId, artifact, reason, until, "hold-wire-foreign-key"),
      () => client.releaseEvidenceHold(held.hold_id, releaseReason, "hold-wire-foreign-key"),
    ])
      await assert.rejects(action(), fails("CONTROL_EVIDENCE_HOLD_TARGET_UNAVAILABLE", 404));
  }
  phase = 5;
  origin = admin;
  const released = await client.releaseEvidenceHold(
    held.hold_id,
    releaseReason,
    "hold-wire-release-key",
  );
  assert.equal(released.replayed, false);
  assert.equal(released.released_by, "console-hold-admin");
  assert.equal(released.released_reason, releaseReason);
  assert.ok(released.released_at);
  assert.ok(released.released_event_id);
  const releaseReplay = await client.releaseEvidenceHold(
    held.hold_id,
    releaseReason,
    "hold-wire-release-key",
  );
  assert.equal(releaseReplay.replayed, true);
  assert.equal(releaseReplay.released_event_id, released.released_event_id);
  assert.equal(releaseReplay.released_at, released.released_at);
  await assert.rejects(
    client.releaseEvidenceHold(held.hold_id, "Changed release reason", "hold-wire-release-key"),
    fails("CONTROL_EVIDENCE_HOLD_CONFLICT", 409),
  );
  const renewed = await client.createEvidenceHold(
    caseId,
    artifact,
    reason,
    until,
    "hold-wire-renew-key",
  );
  assert.notEqual(renewed.hold_id, held.hold_id);
  phase = 6;
  const history = await client.evidenceHolds(caseId, undefined, new AbortController().signal);
  assert.equal(history.case_status, "open");
  assert.equal(history.items.length, 1);
  assert.equal(history.items[0]?.hold_id, held.hold_id);
  assert.equal(history.items[0]?.released_event_id, released.released_event_id);
  assert.equal(history.truncated, true);
  assert.ok(history.next_cursor);
  const next = await client.evidenceHolds(caseId, history.next_cursor);
  assert.equal(next.items.length, 1);
  assert.equal(next.items[0]?.hold_id, renewed.hold_id);
  assert.equal(next.items[0]?.released_event_id, null);
  assert.equal(next.truncated, false);
  assert.equal(next.next_cursor, null);
  await assert.rejects(
    client.evidenceHolds(otherCase, history.next_cursor),
    fails("CONTROL_CURSOR_INVALID", 400),
  );
  phase = 7;
  origin = owner;
  await client.closeCase(caseId, "Wire retention case complete", "hold-wire-close-key");
  origin = admin;
  assert.equal((await client.evidenceHolds(caseId)).case_status, "closed");
  await assert.rejects(
    client.createEvidenceHold(caseId, artifact, reason, until, "hold-wire-closed-key"),
    fails("CONTROL_EVIDENCE_HOLD_TARGET_UNAVAILABLE", 404),
  );
  const closedRelease = await client.releaseEvidenceHold(
    renewed.hold_id,
    releaseReason,
    "hold-wire-closed-release-key",
  );
  assert.equal(closedRelease.replayed, false);
  assert.equal(
    (
      await client.releaseEvidenceHold(
        renewed.hold_id,
        releaseReason,
        "hold-wire-closed-release-key",
      )
    ).replayed,
    true,
  );
  const closedHistory = await client.evidenceHolds(caseId);
  const closedNext = await client.evidenceHolds(caseId, closedHistory.next_cursor!);
  assert.equal(closedNext.case_status, "closed");
  assert.equal(closedNext.items[0]?.released_event_id, closedRelease.released_event_id);
  phase = 8;
  const invalid = new ControlClient("synthetic-invalid-management-token-000000000000");
  for (const action of [
    () => invalid.evidenceHolds(caseId),
    () => invalid.createEvidenceHold(caseId, artifact, reason, until, "hold-wire-invalid-key"),
    () => invalid.releaseEvidenceHold(held.hold_id, releaseReason, "hold-wire-invalid-key"),
  ])
    await assert.rejects(action(), fails("CONTROL_AUTH_REQUIRED", 401));
} catch {
  // Node communicates the failed phase without exposing server bodies or credentials.
  process.exitCode = phase;
}
