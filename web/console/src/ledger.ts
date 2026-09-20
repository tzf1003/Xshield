/** Redacted PostgreSQL ledger observations, never online admission decisions.
 * Decode only display fields; credentials, identities and resource fingerprints
 * stay outside this boundary. The server owns scope, expiry and access audit.
 */
import {
  bindingPattern,
  grantPattern,
  eventPattern,
  requestPattern,
  bool,
  choice,
  ensure,
  envelope,
  id,
  integer,
  name,
  nullable,
  object,
  timestamp,
} from "./api-contract.ts";
import type { Envelope } from "./api-contract.ts";

type BindingStatus = "anonymous" | "active" | "revoked" | "expired";
export type GrantBinding = {
  binding_id: string;
  current_auth_epoch: number;
  epoch_matches_grant: boolean;
  stored_status: BindingStatus;
  time_expired: boolean;
  expires_at: string;
};
export type Grant = {
  grant_id: string;
  auth_epoch: number;
  stored_status: "active" | "revoked" | "expired";
  time_expired: boolean;
  issued_at: string;
  expires_at: string;
  resource_type: string;
  operation_id: string;
  view_id: string;
  policy_revision: string;
  source_event_id: string;
  source_request_id: string;
  binding: GrantBinding;
};
export type Binding = {
  binding_id: string;
  current_auth_epoch: number;
  credential_generation: number;
  stored_status: BindingStatus;
  time_expired: boolean;
  expires_at: string;
  updated_at: string;
};
export type GrantResponse = Envelope & {
  schema_version: 3;
  source_grant_id: string;
  found: boolean;
  as_of: string | null;
  grant: Grant | null;
};
export type BindingResponse = Envelope & {
  schema_version: 3;
  source_binding_id: string;
  found: boolean;
  as_of: string | null;
  binding: Binding | null;
};

function ledgerTime(value: unknown): string {
  const result = timestamp(value);
  // The Rust DTO emits fixed UTC microseconds. Canonical strings compare
  // exactly, including expiry differences below Date's millisecond precision.
  ensure(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/.test(result));
  ensure(result >= "1970-01-01T00:00:00.000000Z");
  return result;
}

function bindingFacts(row: Record<string, unknown>) {
  return {
    binding_id: id(row.binding_id, bindingPattern),
    current_auth_epoch: integer(row.current_auth_epoch),
    stored_status: choice(row.stored_status, [
      "anonymous",
      "active",
      "revoked",
      "expired",
    ]),
    time_expired: bool(row.time_expired),
    expires_at: ledgerTime(row.expires_at),
  };
}

function observation(row: Record<string, unknown>) {
  ensure(row.schema_version === 3);
  const found = bool(row.found);
  const as_of = nullable(row.as_of, ledgerTime);
  ensure(found === (as_of !== null));
  return { ...envelope(row), schema_version: 3 as const, found, as_of };
}

/** Verify target identity, lifecycle consistency and exact database-time expiry.
 * Missing/foreign records retain the server's unified null observation. Unknown
 * fields are discarded, malformed or unsafe integer facts throw INVALID_RESPONSE.
 */
export function decodeGrantResponse(
  value: unknown,
  target: string,
): GrantResponse {
  const row = object(value);
  const base = observation(row);
  ensure(row.source_grant_id === target);
  const grant = nullable(row.grant, (value): Grant => {
    const data = object(value);
    const binding = object(data.binding);
    return {
      grant_id: id(data.grant_id, grantPattern),
      auth_epoch: integer(data.auth_epoch),
      stored_status: choice(data.stored_status, [
        "active",
        "revoked",
        "expired",
      ]),
      time_expired: bool(data.time_expired),
      issued_at: ledgerTime(data.issued_at),
      expires_at: ledgerTime(data.expires_at),
      resource_type: name(data.resource_type),
      operation_id: name(data.operation_id),
      view_id: name(data.view_id),
      policy_revision: name(data.policy_revision),
      source_event_id: id(data.source_event_id, eventPattern),
      source_request_id: id(data.source_request_id, requestPattern),
      binding: {
        ...bindingFacts(binding),
        epoch_matches_grant: bool(binding.epoch_matches_grant),
      },
    };
  });
  ensure(base.found === (grant !== null));
  if (grant) {
    ensure(base.as_of !== null && grant.grant_id === target);
    ensure(grant.issued_at < grant.expires_at);
    ensure(grant.time_expired === grant.expires_at <= base.as_of);
    ensure(
      grant.binding.time_expired === grant.binding.expires_at <= base.as_of,
    );
    ensure(grant.binding.current_auth_epoch >= grant.auth_epoch);
    ensure(
      grant.binding.epoch_matches_grant ===
        (grant.binding.current_auth_epoch === grant.auth_epoch),
    );
  }
  return { ...base, source_grant_id: target, grant };
}

/** Verify binding lifecycle metadata without exposing credential or subject data.
 * Updated time may follow expiry; neither timestamp is an authorization result.
 * Invalid responses fail closed before reaching application state.
 */
export function decodeBindingResponse(
  value: unknown,
  target: string,
): BindingResponse {
  const row = object(value);
  const base = observation(row);
  ensure(row.source_binding_id === target);
  const binding = nullable(row.binding, (value): Binding => {
    const data = object(value);
    return {
      ...bindingFacts(data),
      credential_generation: integer(data.credential_generation),
      updated_at: ledgerTime(data.updated_at),
    };
  });
  ensure(base.found === (binding !== null));
  if (binding) {
    ensure(base.as_of !== null && binding.binding_id === target);
    ensure(binding.time_expired === binding.expires_at <= base.as_of);
    if (binding.stored_status === "anonymous")
      ensure(
        binding.current_auth_epoch === 0 && binding.credential_generation === 0,
      );
    if (binding.stored_status === "active")
      ensure(
        binding.current_auth_epoch > 0 && binding.credential_generation > 0,
      );
  }
  return { ...base, source_binding_id: target, binding };
}
