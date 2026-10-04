/** Real PostgreSQL authorization and encrypted vault bytes through the console client. */
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
  const requester = loopback(process.env.XSHIELD_CONSOLE_TEST_ORIGIN);
  const approver = loopback(process.env.XSHIELD_CONSOLE_TEST_APPROVER_ORIGIN);
  const selfApprover = loopback(process.env.XSHIELD_CONSOLE_TEST_SELF_APPROVER_ORIGIN);
  const observer = loopback(process.env.XSHIELD_CONSOLE_TEST_OBSERVER_ORIGIN);
  const foreign = loopback(process.env.XSHIELD_CONSOLE_TEST_FOREIGN_ORIGIN);
  let origin = requester;
  const artifact = process.env.XSHIELD_CONSOLE_TEST_ARTIFACT!;
  const network = globalThis.fetch;
  const requestIds = new Set<string>();
  globalThis.fetch = async (input, options) => {
    const path = String(input);
    assert.match(path, /^\/control\/v1\/(?:cases|artifacts|evidence-access-requests)(?:\/|\?|$)/);
    assert.equal(options?.credentials, "omit");
    assert.equal(options?.redirect, "error");
    assert.equal(options?.cache, "no-store");
    assert.equal(options?.referrerPolicy, "no-referrer");
    const response = await network(new URL(path, origin), options);
    assert.equal(response.headers.get("cache-control"), "private, no-store");
    let requestId: string;
    if (response.ok && path.endsWith("/content")) {
      requestId = response.headers.get("x-xshield-request-id")!;
      assert.equal(response.headers.get("x-xshield-tenant-id"), "tenant_console_access_wire");
      assert.equal(response.headers.get("x-xshield-site-id"), "site_a");
      assert.equal(response.headers.get("x-xshield-artifact-id"), artifact);
      assert.match(
        response.headers.get("x-xshield-evidence-access-request")!,
        /^access_[a-f0-9-]+$/,
      );
      assert.equal(response.headers.get("content-type"), "application/octet-stream");
      assert.equal(response.headers.get("x-content-type-options"), "nosniff");
      assert.equal(response.headers.get("content-length"), "17");
      assert.equal(await response.clone().text(), '{"approved":true}');
    } else {
      const raw = await response.clone().json();
      requestId = raw.request_id;
      if (response.ok && origin !== foreign) {
        assert.equal(raw.tenant_id, "tenant_console_access_wire");
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
    }
    assert.match(requestId, /^req_[a-f0-9-]+$/);
    assert.ok(!requestIds.has(requestId));
    requestIds.add(requestId);
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
  phase = 2;
  const investigation = await client.createCase("Wire investigation", "access-wire-case-key");
  const caseId = investigation.case_id;
  const requested = await client.requestEvidenceAccess(
    artifact,
    caseId,
    "Wire sensitive investigation",
    "access-wire-request-key",
  );
  const access = requested.access_request_id;
  assert.equal(requested.replayed, false);
  assert.equal(requested.status, "pending");
  const replay = await client.requestEvidenceAccess(
    artifact,
    caseId,
    "Wire sensitive investigation",
    "access-wire-request-key",
  );
  assert.equal(replay.replayed, true);
  assert.equal(replay.access_request_id, access);
  assert.equal(replay.requested_at, requested.requested_at);
  await assert.rejects(
    client.requestEvidenceAccess(
      artifact,
      caseId,
      "Changed justification",
      "access-wire-request-key",
    ),
    fails("CONTROL_IDEMPOTENCY_CONFLICT", 409),
  );
  const pending = await client.evidenceAccess(access, new AbortController().signal);
  assert.equal(pending.access_request.stored_status, "pending");
  assert.equal(pending.access_request.justification, "Wire sensitive investigation");
  assert.equal(pending.access_request.decided_by, null);
  assert.equal(pending.access_request.access_expires_at, null);
  assert.equal((await client.evidenceAccessList("mine")).items[0]?.access_request_id, access);
  await assert.rejects(client.evidenceAccessList("review"), fails("CONTROL_SCOPE_DENIED", 403));
  await assert.rejects(
    client.downloadEvidence(artifact, access),
    fails("CONTROL_EVIDENCE_READ_NOT_AVAILABLE", 404),
  );
  await assert.rejects(
    client.decideEvidenceAccess(
      access,
      "approve",
      "Wire independent approval",
      300,
      "access-wire-role-key",
    ),
    fails("CONTROL_SCOPE_DENIED", 403),
  );
  phase = 3;
  origin = selfApprover;
  assert.deepEqual((await client.evidenceAccessList("review")).items, []);
  assert.equal((await client.evidenceAccessList("mine")).items[0]?.access_request_id, access);
  await assert.rejects(
    client.decideEvidenceAccess(
      access,
      "approve",
      "Wire independent approval",
      300,
      "access-wire-self-key",
    ),
    fails("CONTROL_EVIDENCE_ACCESS_SELF_APPROVAL_DENIED", 403),
  );
  origin = foreign;
  assert.deepEqual((await client.evidenceAccessList("review")).items, []);
  await assert.rejects(
    client.evidenceAccess(access),
    fails("CONTROL_EVIDENCE_ACCESS_READ_NOT_AVAILABLE", 404),
  );
  await assert.rejects(
    client.decideEvidenceAccess(
      access,
      "approve",
      "Wire independent approval",
      300,
      "access-wire-foreign-key",
    ),
    fails("CONTROL_EVIDENCE_ACCESS_DECISION_TARGET_UNAVAILABLE", 404),
  );
  await assert.rejects(
    client.downloadEvidence(artifact, access),
    fails("CONTROL_EVIDENCE_READ_NOT_AVAILABLE", 404),
  );
  phase = 4;
  origin = approver;
  assert.equal((await client.evidenceAccessList("review")).items[0]?.access_request_id, access);
  assert.equal(
    (await client.evidenceAccess(access)).access_request.requested_by,
    "console-access-requester",
  );
  const approved = await client.decideEvidenceAccess(
    access,
    "approve",
    "Wire independent approval",
    300,
    "access-wire-approve-key",
  );
  assert.equal(approved.status, "approved");
  assert.equal(approved.decided_by, "console-independent-approver");
  assert.equal(approved.replayed, false);
  assert.deepEqual((await client.evidenceAccessList("review")).items, []);
  const repeated = await client.decideEvidenceAccess(
    access,
    "approve",
    "Wire independent approval",
    300,
    "access-wire-approve-key",
  );
  assert.equal(repeated.replayed, true);
  assert.equal(repeated.access_expires_at, approved.access_expires_at);
  await assert.rejects(
    client.decideEvidenceAccess(
      access,
      "approve",
      "Changed decision",
      300,
      "access-wire-approve-key",
    ),
    fails("CONTROL_EVIDENCE_ACCESS_DECISION_CONFLICT", 409),
  );
  await assert.rejects(
    client.downloadEvidence(artifact, access),
    fails("CONTROL_SCOPE_DENIED", 403),
  );
  phase = 5;
  origin = requester;
  const detail = (await client.evidenceAccess(access)).access_request;
  assert.equal(detail.stored_status, "approved");
  assert.equal(detail.decision_reason, "Wire independent approval");
  assert.equal(detail.capability_time_expired, false);
  const downloaded = await client.downloadEvidence(artifact, access, new AbortController().signal);
  assert.equal(downloaded.artifact_id, artifact);
  assert.equal(downloaded.access_request_id, access);
  assert.equal(downloaded.bytes, 17);
  assert.equal(downloaded.blob.type, "application/octet-stream");
  assert.deepEqual(
    new Uint8Array(await downloaded.blob.arrayBuffer()),
    new TextEncoder().encode('{"approved":true}'),
  );
  phase = 6;
  const denied = await client.requestEvidenceAccess(
    artifact,
    caseId,
    "Wire denial investigation",
    "access-wire-denied-request",
  );
  origin = approver;
  const denial = await client.decideEvidenceAccess(
    denied.access_request_id,
    "deny",
    "Access outside investigation",
    null,
    "access-wire-deny-key",
  );
  assert.equal(denial.status, "denied");
  assert.equal(denial.access_expires_at, null);
  assert.equal(
    (
      await client.decideEvidenceAccess(
        denied.access_request_id,
        "deny",
        "Access outside investigation",
        null,
        "access-wire-deny-key",
      )
    ).replayed,
    true,
  );
  origin = requester;
  assert.equal(
    (await client.evidenceAccess(denied.access_request_id)).access_request.stored_status,
    "denied",
  );
  await assert.rejects(
    client.downloadEvidence(artifact, denied.access_request_id),
    fails("CONTROL_EVIDENCE_READ_NOT_AVAILABLE", 404),
  );
  phase = 7;
  const expiring = await client.requestEvidenceAccess(
    artifact,
    caseId,
    "Wire temporary investigation",
    "access-wire-expiring-request",
  );
  origin = approver;
  await client.decideEvidenceAccess(
    expiring.access_request_id,
    "approve",
    "Short review window",
    1,
    "access-wire-expiring-approve",
  );
  await new Promise((resolve) => setTimeout(resolve, 1200));
  origin = requester;
  assert.equal(
    (await client.evidenceAccess(expiring.access_request_id)).access_request
      .capability_time_expired,
    true,
  );
  await assert.rejects(
    client.downloadEvidence(artifact, expiring.access_request_id),
    fails("CONTROL_EVIDENCE_READ_NOT_AVAILABLE", 404),
  );
  phase = 8;
  await client.closeCase(caseId, "Wire review complete", "access-wire-close-key");
  const history = await client.evidenceAccessList("mine");
  assert.equal(history.items[0]?.access_request_id, expiring.access_request_id);
  assert.equal(history.truncated, true);
  const older = await client.evidenceAccessList("mine", history.next_cursor!);
  assert.equal(older.items[0]?.access_request_id, denied.access_request_id);
  const oldest = await client.evidenceAccessList("mine", older.next_cursor!);
  assert.equal(oldest.items[0]?.access_request_id, access);
  assert.equal(oldest.next_cursor, null);
  assert.equal(oldest.truncated, false);
  assert.equal((await client.evidenceAccess(access)).access_request.case_status, "closed");
  await assert.rejects(
    client.downloadEvidence(artifact, access),
    fails("CONTROL_EVIDENCE_READ_NOT_AVAILABLE", 404),
  );
  await assert.rejects(
    client.requestEvidenceAccess(artifact, caseId, "Review closed case", "access-wire-closed-key"),
    fails("CONTROL_EVIDENCE_ACCESS_TARGET_UNAVAILABLE", 404),
  );
  phase = 9;
  origin = observer;
  for (const action of [
    () => client.evidenceAccessList("mine"),
    () => client.evidenceAccessList("review"),
    () => client.requestEvidenceAccess(artifact, caseId, "Review", "access-wire-observer-key"),
    () => client.evidenceAccess(access),
    () => client.decideEvidenceAccess(access, "deny", "Review", null, "access-wire-observer-key"),
    () => client.downloadEvidence(artifact, access),
  ])
    await assert.rejects(action(), fails("CONTROL_SCOPE_DENIED", 403));
  phase = 10;
  origin = requester;
  const invalid = new ControlClient("synthetic-invalid-management-token-000000000000");
  await assert.rejects(invalid.evidenceAccessList("mine"), fails("CONTROL_AUTH_REQUIRED", 401));
  await assert.rejects(invalid.evidenceAccess(access), fails("CONTROL_AUTH_REQUIRED", 401));
  await assert.rejects(
    invalid.downloadEvidence(artifact, access),
    fails("CONTROL_AUTH_REQUIRED", 401),
  );
} catch {
  // Keep server payloads and authorization headers within the test process.
  process.exitCode = phase;
}
