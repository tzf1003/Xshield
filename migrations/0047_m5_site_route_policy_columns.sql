ALTER TABLE xshield.site_routes
    ADD COLUMN IF NOT EXISTS source_action text,
    ADD COLUMN IF NOT EXISTS view_profile text,
    ADD COLUMN IF NOT EXISTS resource_query_parameter text,
    ADD COLUMN IF NOT EXISTS resource_path_parameter text,
    ADD COLUMN IF NOT EXISTS request_crypto jsonb,
    ADD COLUMN IF NOT EXISTS response_config jsonb;

ALTER TABLE xshield.site_routes
    ADD CONSTRAINT site_routes_request_crypto_object
        CHECK (request_crypto IS NULL OR jsonb_typeof(request_crypto) = 'object'),
    ADD CONSTRAINT site_routes_response_config_object
        CHECK (response_config IS NULL OR jsonb_typeof(response_config) = 'object');
