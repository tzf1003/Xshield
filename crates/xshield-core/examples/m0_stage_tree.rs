use xshield_core::{
    application::{RequestInput, RequestProcessor},
    domain::{RequestId, SiteId, TenantId},
    ports::{DisabledSiteStore, MockAuditSink, MockIds},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let audit = MockAuditSink::new();
    let ids = MockIds::default();
    let processor = RequestProcessor::new(&audit, &DisabledSiteStore, &ids);
    let report = processor.process(RequestInput {
        request_id: RequestId::parse("req_01a0afa6-3320-758a-9554-d0d3b561b8c6")?,
        tenant_id: TenantId::parse("tenant_demo")?,
        site_id: SiteId::parse("demo")?,
    })?;

    println!("request_id={}", report.request_id);
    for event in audit.events() {
        println!("{:02} {event}", event.request_seq);
    }
    Ok(())
}
