-- How an administrator handled an automatic change (object-learning UI design, section 6 C2 to C4),
-- and the day from which a re-confirmed position's evidence counts.
--
-- A row records an event the administrator acknowledged or undid. An event with no row is open,
-- and one a later version changed is superseded: the console reads that from the configuration.
-- The rows belong to one configuration generation (the site's created_at), so a site created again
-- under the same name starts with none. Its version numbers start again too.
CREATE TABLE object_event_status (
    site            text NOT NULL,
    generation      timestamptz NOT NULL,
    event           text NOT NULL,              -- "v{version}-{index}", as the console lists it
    status          text NOT NULL,
    kind            text NOT NULL,
    slot            text NOT NULL,              -- the position the change moved or paused
    handled_by      text NOT NULL,
    handled_millis  bigint NOT NULL,
    handled_version bigint,                     -- the version the handling saved, when it saved one
    CONSTRAINT object_event_status_pkey PRIMARY KEY (site, generation, event),
    CONSTRAINT object_event_status_status_check CHECK (status IN ('acknowledged', 'undone')),
    CONSTRAINT object_event_status_kind_check CHECK (kind IN ('auto_tighten', 'auto_pause'))
);

-- Evidence before this day does not count for the position: the administrator confirmed it again
-- with that evidence in view, so the pass judges it by what it sees from then on.
ALTER TABLE object_positions ADD COLUMN baseline_day bigint;
