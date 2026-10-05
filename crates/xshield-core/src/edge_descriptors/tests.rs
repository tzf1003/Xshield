use super::*;

/// One operation with owned values, so tests can borrow [`OperationFacts`].
#[derive(Clone)]
struct Op {
    operation_id: OperationId,
    method: HttpMethod,
    route: RouteTemplate,
    route_match: RouteMatch,
    admission: AdmissionClass,
    source_action: Option<ActionId>,
    resource: Option<(ResourceType, ViewProfile, FieldName)>,
    issued_by: Option<IssuedBy>,
    page_actions: Option<PageActions>,
    sensor_html: bool,
    resource_grant: Option<(OperationId, MappingRevision)>,
}

impl Op {
    fn new(operation_id: &str, method: HttpMethod, route: &str, admission: AdmissionClass) -> Self {
        Self {
            operation_id: OperationId::parse(operation_id).unwrap(),
            method,
            route: RouteTemplate::parse(route).unwrap(),
            route_match: if route.contains('{') {
                RouteMatch::FinalSegment
            } else {
                RouteMatch::Exact
            },
            admission,
            source_action: None,
            resource: None,
            issued_by: None,
            page_actions: None,
            sensor_html: false,
            resource_grant: None,
        }
    }

    fn facts(&self) -> OperationFacts<'_> {
        OperationFacts {
            operation_id: &self.operation_id,
            method: self.method,
            route: &self.route,
            route_match: self.route_match,
            admission: self.admission,
            source_action: self.source_action.as_ref(),
            resource: self
                .resource
                .as_ref()
                .map(|(resource_type, view_profile, field)| ResourceFacts {
                    resource_type,
                    view_profile,
                    field,
                }),
            issued_by: self.issued_by.as_ref(),
            page_actions: self.page_actions.as_ref(),
            sensor_html: self.sensor_html,
            resource_grant: self.resource_grant.as_ref().map(|(target, mapping)| {
                GrantTargetFacts {
                    target_operation_id: target,
                    target_mapping_revision: mapping,
                }
            }),
        }
    }
}

/// The same four operations the gateway's page-action tests compile from JSON.
fn page() -> Op {
    let mut page = Op::new(
        "app.page",
        HttpMethod::Get,
        "/app",
        AdmissionClass::AuthenticatedRoot,
    );
    page.page_actions = Some(PageActions::parse("mapping-r1".to_owned(), 8).unwrap());
    page.sensor_html = true;
    page
}

fn login() -> Op {
    Op::new(
        "auth.login",
        HttpMethod::Post,
        "/api/login",
        AdmissionClass::AuthenticationEntry,
    )
}

fn list() -> Op {
    let mut list = Op::new(
        "orders.list",
        HttpMethod::Get,
        "/orders",
        AdmissionClass::UiActionRequired,
    );
    list.source_action = Some(ActionId::parse("app.orders.list").unwrap());
    list.issued_by = Some(IssuedBy::parse("app.page".to_owned(), 600).unwrap());
    list.resource_grant = Some((
        OperationId::parse("orders.read").unwrap(),
        MappingRevision::parse("mapping-r2").unwrap(),
    ));
    list
}

fn detail() -> Op {
    let mut detail = Op::new(
        "orders.read",
        HttpMethod::Get,
        "/orders/{order_id}",
        AdmissionClass::UiActionRequired,
    );
    detail.source_action = Some(ActionId::parse("orders.open").unwrap());
    detail.resource = Some((
        ResourceType::parse("order").unwrap(),
        ViewProfile::parse("customer_detail").unwrap(),
        FieldName::parse("order_id").unwrap(),
    ));
    detail
}

fn policy() -> PolicyRevision {
    PolicyRevision::parse("policy-r1").unwrap()
}

fn derive_ops(operations: &[Op]) -> Result<Option<PageProvenance>, DescriptorError> {
    let facts = operations.iter().map(Op::facts).collect::<Vec<_>>();
    derive(&facts, &policy())
}

fn digest(operations: &[Op]) -> String {
    derive_ops(operations)
        .unwrap()
        .unwrap()
        .descriptors()
        .content_digest_hex()
}

#[test]
fn a_page_issues_exactly_its_declared_actions_and_all_descriptors_are_derived() {
    let provenance = derive_ops(&[page(), login(), list(), detail()])
        .unwrap()
        .unwrap();
    let plan = provenance
        .plan(&OperationId::parse("app.page").unwrap())
        .unwrap();
    assert_eq!(plan.page_template().as_str(), "app.page");
    assert_eq!(plan.mapping_revision().as_str(), "mapping-r1");
    assert_eq!(plan.max_active_pages(), 8);
    let [action] = plan.actions() else {
        panic!("one page action expected");
    };
    assert_eq!(action.ttl_seconds(), 600);
    assert_eq!(action.descriptor().operation_id().as_str(), "orders.list");
    assert_eq!(action.descriptor().target_rule(), &ActionTargetRule::None);
    assert!(action.descriptor().allowed_fields().is_empty());
    assert_eq!(action.descriptor().field_profile().as_str(), "none");
    assert!(
        provenance
            .plan(&OperationId::parse("orders.list").unwrap())
            .is_none()
    );
    assert_eq!(provenance.plans().count(), 1);

    let set = provenance.descriptors();
    let summary = set
        .descriptors()
        .iter()
        .map(|descriptor| {
            (
                descriptor.action_id().as_str(),
                descriptor.page_template().as_str(),
                descriptor.mapping_revision().as_str(),
                descriptor.route().as_str(),
                descriptor.policy_revision().as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        summary,
        [
            (
                "app.orders.list",
                "app.page",
                "mapping-r1",
                "/orders",
                "policy-r1"
            ),
            (
                "orders.open",
                "orders.read",
                "mapping-r2",
                "/orders/{order_id}",
                "policy-r1"
            ),
        ]
    );
    let target = &set.descriptors()[1];
    assert_eq!(
        target.target_rule(),
        &ActionTargetRule::Resource(ResourceType::parse("order").unwrap())
    );
    assert_eq!(
        target
            .allowed_fields()
            .iter()
            .map(FieldName::as_str)
            .collect::<Vec<_>>(),
        ["order_id"]
    );
    assert!(set.descriptors().iter().all(ActionDescriptor::is_active));
    assert_eq!(lower_hex(set.content_digest()), set.content_digest_hex());
}

// The gateway pins the same value from the same configuration expressed as
// JSON (`descriptor_digest_is_pinned_byte_for_byte`), computed before the
// derivation moved here; Python's hashlib over the documented encoding agrees:
// sha256(b"".join(f + b"\0" for f in [b"xshield-edge-descriptors-v1", b"2",
//   b"app.orders.list", b"mapping-r1", b"app.page", b"orders.list", b"GET",
//   b"/orders", b"none", b"0", b"none", b"orders.open", b"mapping-r2",
//   b"orders.read", b"orders.read", b"GET", b"/orders/{order_id}",
//   b"resource", b"order", b"1", b"order_id", b"customer_detail"]))
#[test]
fn the_digest_encoding_is_pinned_byte_for_byte() {
    assert_eq!(
        digest(&[page(), login(), list(), detail()]),
        "85129edcdc68fb7e82d233da50aaacfc954453b316f6591f0677092887270914"
    );
}

#[test]
fn the_digest_tracks_descriptor_content_but_not_leases_capacities_or_order() {
    let base = digest(&[page(), list(), detail()]);
    assert_eq!(base, digest(&[detail(), list(), page()]));
    let mut longer_lease = list();
    longer_lease.issued_by = Some(IssuedBy::parse("app.page".to_owned(), 1_200).unwrap());
    assert_eq!(base, digest(&[page(), longer_lease, detail()]));
    let mut more_pages = page();
    more_pages.page_actions = Some(PageActions::parse("mapping-r1".to_owned(), 900).unwrap());
    assert_eq!(base, digest(&[more_pages, list(), detail()]));

    let mut moved = list();
    moved.route = RouteTemplate::parse("/orders-all").unwrap();
    assert_ne!(base, digest(&[page(), moved, detail()]));
    let mut remapped = page();
    remapped.page_actions = Some(PageActions::parse("mapping-r9".to_owned(), 8).unwrap());
    assert_ne!(base, digest(&[remapped, list(), detail()]));
    let mut retargeted = list();
    retargeted.resource_grant = Some((
        OperationId::parse("orders.read").unwrap(),
        MappingRevision::parse("mapping-r3").unwrap(),
    ));
    assert_ne!(base, digest(&[page(), retargeted, detail()]));
    let mut other_view = detail();
    other_view.resource = Some((
        ResourceType::parse("order").unwrap(),
        ViewProfile::parse("admin_detail").unwrap(),
        FieldName::parse("order_id").unwrap(),
    ));
    assert_ne!(base, digest(&[page(), list(), other_view]));
}

// The policy revision is the row the digest is stored on, not part of the
// digest: the same descriptors under two labels hash alike, and the descriptor
// rows themselves carry their revision.
#[test]
fn every_descriptor_carries_the_policy_revision_it_was_derived_for() {
    let facts = [page(), list(), detail()];
    let facts = facts.iter().map(Op::facts).collect::<Vec<_>>();
    let other = PolicyRevision::parse("policy-r2").unwrap();
    let first = derive(&facts, &policy()).unwrap().unwrap();
    let second = derive(&facts, &other).unwrap().unwrap();
    assert_eq!(
        first.descriptors().content_digest(),
        second.descriptors().content_digest()
    );
    assert!(
        second
            .descriptors()
            .descriptors()
            .iter()
            .all(|descriptor| descriptor.policy_revision() == &other)
    );
}

#[test]
fn configurations_without_page_actions_derive_nothing() {
    let mut list = list();
    list.issued_by = None;
    let mut root = page();
    root.page_actions = None;
    assert!(derive_ops(&[root, list, detail()]).unwrap().is_none());
    assert!(derive_ops(&[login()]).unwrap().is_none());
}

#[test]
fn incoherent_page_and_issued_action_declarations_are_refused() {
    let mut unknown_page = list();
    unknown_page.issued_by = Some(IssuedBy::parse("missing.page".to_owned(), 60).unwrap());
    assert_eq!(
        derive_ops(&[page(), unknown_page.clone(), detail()]).unwrap_err(),
        DescriptorError::UnknownPage
    );
    // An unknown page is reported even when no page declares page actions.
    let mut no_page = page();
    no_page.page_actions = None;
    assert_eq!(
        derive_ops(&[no_page, unknown_page, detail()]).unwrap_err(),
        DescriptorError::UnknownPage
    );

    let mut root_issued = list();
    root_issued.admission = AdmissionClass::AuthenticatedRoot;
    root_issued.source_action = None;
    root_issued.resource_grant = None;
    assert_eq!(
        derive_ops(&[page(), root_issued, detail()]).unwrap_err(),
        DescriptorError::IssuedAction
    );
    let mut wrong_class = list();
    wrong_class.admission = AdmissionClass::Public;
    assert_eq!(
        derive_ops(&[page(), wrong_class, detail()]).unwrap_err(),
        DescriptorError::IssuedAction
    );
    let mut resource_issued = detail();
    resource_issued.issued_by = Some(IssuedBy::parse("app.page".to_owned(), 60).unwrap());
    resource_issued.route_match = RouteMatch::Exact;
    assert_eq!(
        derive_ops(&[page(), list(), resource_issued]).unwrap_err(),
        DescriptorError::IssuedAction
    );
    let mut parameterized = list();
    parameterized.route_match = RouteMatch::FinalSegment;
    assert_eq!(
        derive_ops(&[page(), parameterized, detail()]).unwrap_err(),
        DescriptorError::IssuedAction
    );

    for change in [
        (|page: &mut Op| page.admission = AdmissionClass::Public) as fn(&mut Op),
        |page| page.method = HttpMethod::Post,
        |page| page.route_match = RouteMatch::FinalSegment,
        |page| page.sensor_html = false,
    ] {
        let mut root = page();
        change(&mut root);
        assert_eq!(
            derive_ops(&[root, list(), detail()]).unwrap_err(),
            DescriptorError::PageRoot
        );
    }
    let mut unused = list();
    unused.issued_by = None;
    assert_eq!(
        derive_ops(&[page(), unused, detail()]).unwrap_err(),
        DescriptorError::PageActionCount
    );
}

#[test]
fn a_page_issues_at_most_sixteen_actions() {
    let extra = |index: usize| {
        let mut operation = Op::new(
            &format!("extra.{index}"),
            HttpMethod::Post,
            &format!("/extra/{index}"),
            AdmissionClass::UiActionRequired,
        );
        operation.source_action = Some(ActionId::parse(format!("app.extra.{index}")).unwrap());
        operation.issued_by = Some(IssuedBy::parse("app.page".to_owned(), 60).unwrap());
        operation
    };
    let mut operations = vec![page(), list(), detail()];
    operations.extend((1..MAX_PAGE_ACTIONS).map(extra));
    let provenance = derive_ops(&operations).unwrap().unwrap();
    let plan = provenance.plans().next().unwrap();
    assert_eq!(plan.actions().len(), MAX_PAGE_ACTIONS);
    let ids = plan
        .actions()
        .iter()
        .map(|action| action.descriptor().action_id().as_str())
        .collect::<Vec<_>>();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "actions are ordered by action ID");
    operations.push(extra(MAX_PAGE_ACTIONS));
    assert_eq!(
        derive_ops(&operations).unwrap_err(),
        DescriptorError::PageActionCount
    );
}

#[test]
fn grant_targets_must_be_resource_actions() {
    let mut missing = list();
    missing.resource_grant = Some((
        OperationId::parse("orders.missing").unwrap(),
        MappingRevision::parse("mapping-r2").unwrap(),
    ));
    assert_eq!(
        derive_ops(&[page(), missing, detail()]).unwrap_err(),
        DescriptorError::GrantTarget
    );
    let mut not_a_resource = detail();
    not_a_resource.resource = None;
    assert_eq!(
        derive_ops(&[page(), list(), not_a_resource]).unwrap_err(),
        DescriptorError::GrantTarget
    );
    let mut no_action = detail();
    no_action.source_action = None;
    assert_eq!(
        derive_ops(&[page(), list(), no_action]).unwrap_err(),
        DescriptorError::GrantTarget
    );
}

#[test]
fn one_action_and_mapping_cannot_mean_two_things() {
    let mut shadow = list();
    shadow.operation_id = OperationId::parse("orders.list.shadow").unwrap();
    shadow.route = RouteTemplate::parse("/orders-shadow").unwrap();
    shadow.resource_grant = None;
    assert_eq!(
        derive_ops(&[page(), list(), shadow, detail()]).unwrap_err(),
        DescriptorError::AmbiguousAction
    );
    // Two lists qualifying one target under one mapping collapse into one
    // descriptor instead of conflicting.
    let mut second_list = list();
    second_list.operation_id = OperationId::parse("orders.recent").unwrap();
    second_list.route = RouteTemplate::parse("/orders/recent").unwrap();
    second_list.source_action = Some(ActionId::parse("app.orders.recent").unwrap());
    let provenance = derive_ops(&[page(), list(), second_list, detail()])
        .unwrap()
        .unwrap();
    assert_eq!(provenance.descriptors().descriptors().len(), 3);
}

#[test]
fn leases_and_capacities_are_bounded_before_identifiers_are_parsed() {
    for ttl in [0, MAX_ISSUED_ACTION_TTL_SECONDS + 1] {
        assert_eq!(
            IssuedBy::parse("app.page".to_owned(), ttl).unwrap_err(),
            DescriptorError::IssuedActionLease
        );
        // The lease is checked first, as the edge compiler always reported.
        assert_eq!(
            IssuedBy::parse("bad page".to_owned(), ttl).unwrap_err(),
            DescriptorError::IssuedActionLease
        );
    }
    for bound in [1, MAX_ISSUED_ACTION_TTL_SECONDS] {
        assert_eq!(
            IssuedBy::parse("app.page".to_owned(), bound)
                .unwrap()
                .ttl_seconds(),
            bound
        );
    }
    assert!(matches!(
        IssuedBy::parse("bad page".to_owned(), 60),
        Err(DescriptorError::Domain(_))
    ));
    for capacity in [0, MAX_ACTIVE_PAGES + 1] {
        assert_eq!(
            PageActions::parse("mapping-r1".to_owned(), capacity).unwrap_err(),
            DescriptorError::PageCapacity
        );
        assert_eq!(
            PageActions::parse("bad mapping".to_owned(), capacity).unwrap_err(),
            DescriptorError::PageCapacity
        );
    }
    assert!(matches!(
        PageActions::parse("bad mapping".to_owned(), 1),
        Err(DescriptorError::Domain(_))
    ));
}

#[test]
fn errors_name_the_configuration_field_the_edge_compiler_reports() {
    for (error, field) in [
        (
            DescriptorError::IssuedActionLease,
            "operations.issued_by.ttl_seconds",
        ),
        (
            DescriptorError::PageCapacity,
            "operations.response.page_actions.max_active_pages",
        ),
        (
            DescriptorError::PageRoot,
            "operations.response.page_actions",
        ),
        (
            DescriptorError::PageActionCount,
            "operations.response.page_actions",
        ),
        (DescriptorError::IssuedAction, "operations.issued_by"),
        (
            DescriptorError::UnknownPage,
            "operations.issued_by.page_operation_id",
        ),
        (
            DescriptorError::GrantTarget,
            "operations.response.target_operation_id",
        ),
        (DescriptorError::AmbiguousAction, "operations.source_action"),
    ] {
        assert_eq!(error.field(), field);
        assert_eq!(error.to_string(), format!("invalid {field}"));
    }
    let domain = OperationId::parse("bad id").unwrap_err();
    assert_eq!(
        DescriptorError::Domain(domain).field(),
        "operation_id",
        "domain failures keep the identifier's own field name"
    );
}
