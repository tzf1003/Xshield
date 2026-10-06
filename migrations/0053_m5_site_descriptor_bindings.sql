-- Bind each site's policy revision labels to one action-descriptor set.
--
-- A site configuration that declares page issuance makes the edge supply the
-- action descriptors derived from it under (tenant, site, policy_revision) and
-- bind that label to the set's digest in `policy_revisions`; a different set
-- under the same label is refused, which holds back every site of the tenant
-- (an apply is atomic per tenant). The control plane records here, in the
-- same transaction and under the same tenant lock as the write that makes a
-- revision eligible to reach the edge (a save that needs no approval, an
-- approval, a direct apply, or the first snapshot read of a revision written
-- before this table existed), which digest each label of each site denotes,
-- and refuses a configuration that would give a bound label another digest.
--
-- Rows are never updated or deleted, and deliberately have no foreign key to
-- the site: the edge's `policy_revisions` rows outlive a deleted site too, so
-- a site recreated under the same ID must not be able to reuse a label for
-- another set either.
--
-- Additive and idempotent. Older control services neither read nor write the
-- table; the refusal they would miss is still made by the edge.
CREATE TABLE IF NOT EXISTS xshield.site_descriptor_bindings (
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    policy_revision text NOT NULL CHECK (policy_revision ~ '^[A-Za-z0-9_.-]{1,128}$'),
    descriptor_digest bytea NOT NULL CHECK (octet_length(descriptor_digest) = 32),
    -- The site revision whose eligibility first bound the label, and how.
    bound_revision bigint NOT NULL CHECK (bound_revision >= 1),
    bound_by text NOT NULL CHECK (bound_by IN ('save', 'approval', 'snapshot')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, site_id, policy_revision)
);
