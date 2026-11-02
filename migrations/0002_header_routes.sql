-- Header routes (docs/header-routes-design.md). A decision row now records the
-- logical path the request was judged by, the interface name a route read from
-- the request (or why it read none), and the names of the request headers. It
-- never records a header value.
--
-- This is an additive migration, not an edit of 0001: a database that already
-- applied the baseline would refuse a changed baseline by its checksum.
--
-- Rows written before this migration have no route. Their logical path is their
-- path, which the lists read with COALESCE; they have no interface name and no
-- header names.

ALTER TABLE decision_log
    ADD COLUMN logical_path text,
    ADD COLUMN api jsonb,
    ADD COLUMN request_headers text[] NOT NULL DEFAULT '{}';
