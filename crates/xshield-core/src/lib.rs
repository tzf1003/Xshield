//! Minimal M0 core for Xshield.
//!
//! This crate owns validated domain identifiers, management identity,
//! deterministic stage results, request orchestration, and the ports needed by
//! that orchestration. It performs no network, storage, or origin side effects.

#![warn(missing_docs)]

pub mod access;
pub mod admin;
pub mod admission;
pub mod application;
pub mod audit;
pub mod calibration;
pub mod constant_time;
pub mod domain;
pub mod edge_channel;
pub mod edge_descriptors;
pub mod grant;
pub mod identity;
pub mod investigation;
pub mod model_evaluation_admission;
pub mod ports;
pub mod provenance;
pub mod query;
pub mod query_pagination;
pub mod site;
pub use site::{
    GatewayApplyAck, GatewayApplyRequest, GatewayApplySite, SecurityEntry, SiteAuthBinding,
    SiteAuthRevoke, SiteAuthTransition, SiteConfig, SiteCryptoConfig, SiteHealthCheckConfig,
    SiteIdentityConfig, SiteIssuedBy, SiteLimitsConfig, SitePageActions, SitePolicyConfig,
    SiteRequestCrypto, SiteResourceGrant, SiteResponseCrypto, SiteRouteConfig, SiteSecretReference,
    SiteSensorHtml, SiteSensorHtmlAdapter, SiteShareIssue, SiteWafConfig,
};
