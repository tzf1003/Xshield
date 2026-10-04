-- Per-tenant internal listener allocation. The lease table is the durable
-- allocator; protected_site_configs remains the compatibility projection.
CREATE TABLE xshield.site_port_leases (
    tenant_id text NOT NULL CHECK (tenant_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    site_id text NOT NULL CHECK (site_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    listen_port integer NOT NULL CHECK (listen_port BETWEEN 6100 AND 65535),
    state text NOT NULL CHECK (state IN ('active', 'released')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, site_id)
);

INSERT INTO xshield.site_port_leases (tenant_id, site_id, listen_port, state)
SELECT tenant_id, site_id, listen_port, 'active'
FROM xshield.protected_site_configs
ON CONFLICT (tenant_id, site_id) DO UPDATE
SET listen_port = EXCLUDED.listen_port,
    state = 'active',
    updated_at = now();

CREATE INDEX site_port_leases_active
    ON xshield.site_port_leases (tenant_id, listen_port)
    WHERE state = 'active';

CREATE UNIQUE INDEX site_port_leases_active_unique
    ON xshield.site_port_leases (tenant_id, listen_port)
    WHERE state = 'active';
