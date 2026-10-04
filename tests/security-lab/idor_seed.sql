INSERT INTO xshield.policy_revisions (
    tenant_id, site_id, revision, status, content_digest, artifact_ref
) VALUES (
    'tenant_lab', 'site_idor', 'lab-r1', 'active',
    repeat('a', 64), 'artifact_lab_policy_r1'
);

INSERT INTO xshield.action_descriptors (
    tenant_id, site_id, action_id, page_template, operation_id, method,
    route_template, target_rule, allowed_fields, field_profile,
    policy_revision, mapping_revision, status
) VALUES (
    'tenant_lab', 'site_idor', 'orders.open', 'orders_page',
    'orders.read', 'GET', '/orders/{order_id}',
    '{"kind":"resource","resource_type":"order"}', '["order_id"]',
    'customer_detail', 'lab-r1', 'mapping-r1', 'approved'
);
