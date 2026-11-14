-- The object drawer's examples and Jev flows (docs/07 sections 7.8.3 and 7.9.16) find the decision rows whose
-- `trace.values` used one position, with `trace -> 'values' @> …`. Without an index that is a scan of every row
-- of the site in the window: in a synthetic test on PostgreSQL 16, 1.8 s for a position seen 20 times among
-- 600 000 rows, and 15 ms with this index, which cost about 15 % more time per batch insert and 8 % of the
-- table's size; jsonb_path_ops keeps it to containment, the only operator these queries use.
--
-- Built ON ONLY the parent, so this migration does not lock decision_log while it indexes the rows already
-- written. Partitions created from now on copy the index (partitions.rs builds them with LIKE … INCLUDING
-- INDEXES). The partitions already made for the days ahead are empty and are indexed here; today's and the
-- earlier ones stay without it and leave with the seven-day retention, and their rows are scanned as before.
-- The parent index stays marked invalid while such a partition is attached; the planner uses the index of each
-- partition that has one either way.

CREATE INDEX decision_log_values_idx ON ONLY decision_log USING gin ((trace -> 'values') jsonb_path_ops);

DO $$
DECLARE
    part text;
BEGIN
    FOR part IN
        SELECT child.relname
        FROM pg_inherits inherits
        JOIN pg_class child ON child.oid = inherits.inhrelid
        JOIN pg_class parent ON parent.oid = inherits.inhparent
        WHERE parent.relname = 'decision_log'
          AND child.relname ~ '^decision_log_p[0-9]{8}$'
          AND to_date(substr(child.relname, 15), 'YYYYMMDD') > (now() AT TIME ZONE 'UTC')::date
    LOOP
        EXECUTE format('CREATE INDEX %I ON %I USING gin ((trace -> ''values'') jsonb_path_ops)',
                       part || '_values_idx', part);
        EXECUTE format('ALTER INDEX decision_log_values_idx ATTACH PARTITION %I', part || '_values_idx');
    END LOOP;
END $$;
