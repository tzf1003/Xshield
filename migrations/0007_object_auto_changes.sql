-- The learning task's automatic changes to a site's object map are configuration
-- versions of their own (object-map design section 5): an automatic pause of a
-- confirmed position, and an automatic tightening once the learning task applies one.
-- The configuration history records each under its own change kind, so an automatic
-- version is told apart from one an administrator saved.

ALTER TABLE site_config_history DROP CONSTRAINT site_config_history_change_check;
ALTER TABLE site_config_history ADD CONSTRAINT site_config_history_change_check
    CHECK (change IN ('create', 'update', 'rollback', 'delete', 'import',
                      'auto_tighten', 'auto_pause'));
