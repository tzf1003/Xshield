/** Synthetic ledger wire observations, separate from online admission proofs. */
import type { BindingResponse, GrantResponse } from "../src/ledger.ts";
import { REQUEST_ID } from "./fixtures.ts";

export const GRANT_ID = "grant_018f2a3b-4c5d-7000-8000-000000000021";
export const OTHER_GRANT_ID = "grant_018f2a3b-4c5d-7000-8000-000000000022";
export const BINDING_ID = "auth_018f2a3b-4c5d-7000-8000-000000000023";
export const OTHER_BINDING_ID = "auth_018f2a3b-4c5d-7000-8000-000000000024";
const observation = {
  schema_version: 3 as const,
  request_id: "req_018f2a3b-4c5d-7000-8000-000000000099",
  tenant_id: "tenant_demo",
  site_id: "site_demo",
  found: true,
  as_of: "2026-09-20T08:10:30.123456Z",
};

export function grantFixture(grantId = GRANT_ID): GrantResponse {
  return {
    ...observation,
    source_grant_id: grantId,
    grant: {
      grant_id: grantId,
      auth_epoch: 4,
      stored_status: "active",
      time_expired: false,
      issued_at: "2026-09-20T08:00:00.000000Z",
      expires_at: "2026-09-20T09:00:00.000000Z",
      resource_type: "order",
      operation_id: "orders.read",
      view_id: "customer_detail",
      policy_revision: "policy-r1",
      source_event_id: "ev_018f2a3b-4c5d-7000-8000-000000000025",
      source_request_id: REQUEST_ID,
      binding: {
        binding_id: BINDING_ID,
        current_auth_epoch: 4,
        epoch_matches_grant: true,
        stored_status: "active",
        time_expired: false,
        expires_at: "2026-09-20T10:00:00.000000Z",
      },
    },
  };
}

export function bindingFixture(bindingId = BINDING_ID): BindingResponse {
  return {
    ...observation,
    source_binding_id: bindingId,
    binding: {
      binding_id: bindingId,
      current_auth_epoch: 4,
      credential_generation: 2,
      stored_status: "active",
      time_expired: false,
      expires_at: "2026-09-20T10:00:00.000000Z",
      updated_at: "2026-09-20T08:01:00.000000Z",
    },
  };
}
