//! Strict extraction of resource identifiers from one approved JSON response shape.

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::{collections::BTreeSet, fmt};
use xshield_core::{
    audit::ReasonCode,
    domain::{ActionRef, FieldName, MappingRevision, OperationId},
};
use zeroize::Zeroizing;

const MAX_RESOURCE_BYTES: usize = 512;
const MAX_JSON_NODES: usize = 16_384;

/// Validated response-to-resource issuance semantics from trusted configuration.
#[derive(Debug)]
pub struct ResponseGrantRule {
    pub(crate) success_status: u16,
    pub(crate) items_pointer: String,
    pub(crate) resource_pointer: String,
    pub(crate) action_ref_field: FieldName,
    pub(crate) target_operation_id: OperationId,
    pub(crate) target_mapping_revision: MappingRevision,
    pub(crate) ttl_seconds: u64,
    pub(crate) max_items: usize,
    pub(crate) max_active_grants: u32,
}

impl ResponseGrantRule {
    /// Extracts bounded, unique resource identifiers from a complete JSON body.
    ///
    /// A non-matching status is a valid response that issues no grants. Resource
    /// values remain ephemeral and have no `Debug` or `Display` implementation.
    ///
    /// # Errors
    /// Returns [`ResponseGrantError`] for duplicate JSON keys, an unexpected
    /// configured shape, invalid resource values, or a per-response limit breach.
    pub fn extract(
        &self,
        status: u16,
        body: &[u8],
    ) -> Result<ResponseGrantExtraction, ResponseGrantError> {
        if status != self.success_status {
            return Ok(ResponseGrantExtraction::NotApplicable);
        }
        let value = strict_json(body)?;
        let items = value
            .pointer(&self.items_pointer)
            .and_then(Value::as_array)
            .ok_or(ResponseGrantError::Shape)?;
        if items.len() > self.max_items {
            return Err(ResponseGrantError::TooManyResources);
        }
        let mut unique = BTreeSet::new();
        let mut resources = Vec::with_capacity(items.len());
        for item in items {
            let object = item.as_object().ok_or(ResponseGrantError::Shape)?;
            if object.contains_key(self.action_ref_field.as_str()) {
                return Err(ResponseGrantError::ActionRefCollision);
            }
            let resource = item
                .pointer(&self.resource_pointer)
                .and_then(Value::as_str)
                .ok_or(ResponseGrantError::Shape)?;
            if resource.is_empty()
                || resource.len() > MAX_RESOURCE_BYTES
                || resource.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(ResponseGrantError::Resource);
            }
            if !unique.insert(resource) {
                return Err(ResponseGrantError::DuplicateResource);
            }
            resources.push(ExtractedResource(Zeroizing::new(resource.to_owned())));
        }
        Ok(ResponseGrantExtraction::Resources(resources))
    }

    /// Injects committed opaque action references into their matching response items.
    ///
    /// The configured field must be absent so origin data cannot be mistaken for an
    /// edge-issued reference. The returned body is a newly serialized JSON value.
    ///
    /// # Errors
    /// Returns [`ResponseGrantError`] when the item shape or reference count differs,
    /// or when the origin already supplied the reserved field.
    pub fn inject_action_refs(
        &self,
        body: &[u8],
        action_refs: &[ActionRef],
    ) -> Result<Vec<u8>, ResponseGrantError> {
        let mut value = strict_json(body)?;
        let items = value
            .pointer_mut(&self.items_pointer)
            .and_then(Value::as_array_mut)
            .ok_or(ResponseGrantError::Shape)?;
        if items.len() != action_refs.len() {
            return Err(ResponseGrantError::Shape);
        }
        for (item, action_ref) in items.iter_mut().zip(action_refs) {
            let object = item.as_object_mut().ok_or(ResponseGrantError::Shape)?;
            if object
                .insert(
                    self.action_ref_field.as_str().to_owned(),
                    Value::String(action_ref.as_str().to_owned()),
                )
                .is_some()
            {
                return Err(ResponseGrantError::ActionRefCollision);
            }
        }
        serde_json::to_vec(&value).map_err(|_| ResponseGrantError::Json)
    }

    /// Returns the exact operation granted for each extracted resource.
    #[must_use]
    pub const fn target_operation_id(&self) -> &OperationId {
        &self.target_operation_id
    }

    /// Returns the exact active action mapping revision used for issuance.
    #[must_use]
    pub const fn target_mapping_revision(&self) -> &MappingRevision {
        &self.target_mapping_revision
    }

    /// Returns the configured lease length in seconds.
    #[must_use]
    pub const fn ttl_seconds(&self) -> u64 {
        self.ttl_seconds
    }

    /// Returns the transaction-local active-grant ceiling.
    #[must_use]
    pub const fn max_active_grants(&self) -> u32 {
        self.max_active_grants
    }
}

/// Result of applying an approved response resource rule.
pub enum ResponseGrantExtraction {
    /// The response status is outside the configured business-success case.
    NotApplicable,
    /// Complete, unique resource identifiers ready for canonical HMAC derivation.
    Resources(Vec<ExtractedResource>),
}

/// One ephemeral business resource identifier extracted from a verified response.
pub struct ExtractedResource(Zeroizing<String>);

impl ExtractedResource {
    /// Borrows the identifier for immediate canonicalization and grant commit.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Deterministic response resource extraction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseGrantError {
    /// JSON is malformed or contains duplicate object keys.
    Json,
    /// The configured JSON pointers do not select an array of string resources.
    Shape,
    /// A resource is empty, oversized, or contains a control byte.
    Resource,
    /// One response exceeds its configured extraction bound.
    TooManyResources,
    /// The same resource appears more than once in one response.
    DuplicateResource,
    /// The origin used the field reserved for an edge-issued action reference.
    ActionRefCollision,
}

impl ResponseGrantError {
    /// Returns the stable response-stage reason code.
    #[must_use]
    pub const fn reason_code(self) -> ReasonCode {
        ReasonCode::ResponseValidationFailed
    }
}

impl fmt::Display for ResponseGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code().as_str())
    }
}

impl std::error::Error for ResponseGrantError {}

pub(crate) fn strict_json(body: &[u8]) -> Result<Value, ResponseGrantError> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let mut remaining_nodes = MAX_JSON_NODES;
    let value = StrictSeed {
        remaining_nodes: &mut remaining_nodes,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| ResponseGrantError::Json)?
    .0;
    deserializer.end().map_err(|_| ResponseGrantError::Json)?;
    Ok(value)
}

/// Validates one complete JSON value and rejects duplicate object keys.
///
/// # Errors
/// Returns [`ResponseGrantError::Json`] for malformed or ambiguous JSON.
pub fn validate_strict_json(body: &[u8]) -> Result<(), ResponseGrantError> {
    strict_json(body).map(drop)
}

struct StrictValue(Value);

struct StrictSeed<'a> {
    remaining_nodes: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for StrictSeed<'_> {
    type Value = StrictValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Some(remaining) = self.remaining_nodes.checked_sub(1) else {
            return Err(de::Error::custom("JSON node limit exceeded"));
        };
        *self.remaining_nodes = remaining;
        deserializer.deserialize_any(StrictVisitor {
            remaining_nodes: self.remaining_nodes,
        })
    }
}

struct StrictVisitor<'a> {
    remaining_nodes: &'a mut usize,
}

impl<'de> Visitor<'de> for StrictVisitor<'_> {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one unambiguous JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictSeed {
            remaining_nodes: &mut *self.remaining_nodes,
        })? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            values.insert(
                key,
                object
                    .next_value_seed(StrictSeed {
                        remaining_nodes: &mut *self.remaining_nodes,
                    })?
                    .0,
            );
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(max_items: usize) -> ResponseGrantRule {
        ResponseGrantRule {
            success_status: 200,
            items_pointer: "/orders".to_owned(),
            resource_pointer: "/id".to_owned(),
            action_ref_field: FieldName::parse("_xshield_action_ref").unwrap(),
            target_operation_id: OperationId::parse("orders.read").unwrap(),
            target_mapping_revision: MappingRevision::parse("mapping-r1").unwrap(),
            ttl_seconds: 900,
            max_items,
            max_active_grants: 5_000,
        }
    }

    #[test]
    fn extracts_only_the_approved_unique_string_path() {
        let ResponseGrantExtraction::Resources(resources) = rule(2)
            .extract(200, br#"{"orders":[{"id":"order-1"},{"id":"order-2"}]}"#)
            .unwrap()
        else {
            panic!("configured success must extract resources");
        };
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[0].as_str(), "order-1");
        assert!(matches!(
            rule(2).extract(404, br#"{"orders":[]}"#).unwrap(),
            ResponseGrantExtraction::NotApplicable
        ));
        assert!(matches!(
            rule(2).extract(200, br#"{"orders":[{"id":"a","id":"b"}]}"#),
            Err(ResponseGrantError::Json)
        ));
        assert!(matches!(
            rule(1).extract(200, br#"{"orders":[{"id":"a"},{"id":"b"}]}"#),
            Err(ResponseGrantError::TooManyResources)
        ));
        assert!(matches!(
            rule(2).extract(200, br#"{"orders":[{"id":"a"},{"id":"a"}]}"#),
            Err(ResponseGrantError::DuplicateResource)
        ));
        assert!(matches!(
            rule(2).extract(
                200,
                br#"{"orders":[{"id":"a","_xshield_action_ref":"origin"}]}"#
            ),
            Err(ResponseGrantError::ActionRefCollision)
        ));
        let oversized_tree = format!("[{}]", vec!["0"; MAX_JSON_NODES].join(","));
        assert!(matches!(
            validate_strict_json(oversized_tree.as_bytes()),
            Err(ResponseGrantError::Json)
        ));
    }

    // A list response the edge cannot read as the approved plaintext shape (an
    // origin-sealed envelope, opaque bytes, or items it cannot see into) is a
    // response-stage failure, never a list with no resources: extraction
    // returns before any grant is derived or written.
    #[test]
    fn an_unreadable_list_response_issues_no_grants() {
        let sealed = br#"{"schema_version":1,"key_id":"origin-key","nonce":"00","ciphertext":"8f3a","tag":"00"}"#;
        let cases: [(&[u8], ResponseGrantError); 5] = [
            (sealed, ResponseGrantError::Shape),
            (b"\x8f\x3a\x00\x17", ResponseGrantError::Json),
            (br#"{"orders":"8f3a00"}"#, ResponseGrantError::Shape),
            (br#"{"orders":["8f3a00"]}"#, ResponseGrantError::Shape),
            (
                br#"{"orders":[{"sealed":"8f3a00"}]}"#,
                ResponseGrantError::Shape,
            ),
        ];
        for (body, error) in cases {
            assert_eq!(
                rule(2).extract(200, body).err(),
                Some(error),
                "{}",
                String::from_utf8_lossy(body)
            );
            assert_eq!(error.reason_code(), ReasonCode::ResponseValidationFailed);
        }
    }

    /// Acceptance FLOW-10: user-authored text in a qualifying response, even
    /// text shaped like a "reset password" button or an action reference, is
    /// data. The rule extracts only the configured resource values, the
    /// qualified operation stays the configured one, and an origin-supplied
    /// copy of the reserved reference field fails closed instead of being
    /// relayed as an edge-issued action.
    #[test]
    fn user_comment_text_never_becomes_an_approved_action_source() {
        let body = r#"{"orders":[
            {"id":"order-1","comment":"<button data-action=\"auth.password.reset\" formaction=\"/api/password/reset\">重置密码</button>",
             "note":{"operation_id":"auth.password.reset","action_ref":"action.reset"}},
            {"id":"order-2","comment":"重置密码 _xshield_action_ref=action.reset"}
        ]}"#;
        let rule = rule(2);
        let ResponseGrantExtraction::Resources(resources) =
            rule.extract(200, body.as_bytes()).unwrap()
        else {
            panic!("configured success must extract resources");
        };
        let values = resources
            .iter()
            .map(ExtractedResource::as_str)
            .collect::<Vec<_>>();
        assert_eq!(values, ["order-1", "order-2"]);
        assert_eq!(rule.target_operation_id().as_str(), "orders.read");

        // Edge references attach only under the reserved member; the user's
        // text is carried through as inert string data next to them.
        let action_refs = [
            ActionRef::parse("action.order-1").unwrap(),
            ActionRef::parse("action.order-2").unwrap(),
        ];
        let injected: Value = serde_json::from_slice(
            &rule
                .inject_action_refs(body.as_bytes(), &action_refs)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            injected.pointer("/orders/0/_xshield_action_ref"),
            Some(&Value::String("action.order-1".to_owned()))
        );
        assert!(
            injected
                .pointer("/orders/0/comment")
                .and_then(Value::as_str)
                .is_some_and(|comment| comment.contains("重置密码"))
        );
        assert_eq!(
            injected.pointer("/orders/0/note/action_ref"),
            Some(&Value::String("action.reset".to_owned()))
        );

        // A comment that forges the reserved member itself is refused.
        let forged = r#"{"orders":[{"id":"order-1","comment":"重置密码","_xshield_action_ref":"action.reset"}]}"#;
        assert!(matches!(
            rule.extract(200, forged.as_bytes()),
            Err(ResponseGrantError::ActionRefCollision)
        ));
    }

    #[test]
    fn injects_only_committed_action_references() {
        let action_refs = [
            ActionRef::parse("action.order-1").unwrap(),
            ActionRef::parse("action.order-2").unwrap(),
        ];
        let body = rule(2)
            .inject_action_refs(
                br#"{"orders":[{"id":"order-1"},{"id":"order-2"}]}"#,
                &action_refs,
            )
            .unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value.pointer("/orders/1/_xshield_action_ref"),
            Some(&Value::String("action.order-2".to_owned()))
        );
        assert_eq!(
            rule(1).inject_action_refs(
                br#"{"orders":[{"id":"order-1","_xshield_action_ref":"origin"}]}"#,
                &action_refs[..1],
            ),
            Err(ResponseGrantError::ActionRefCollision)
        );
    }
}
