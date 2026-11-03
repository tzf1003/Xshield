//! Attribute-level over-exposure (W6, docs/07 section 7.9.17): a response that shows a user-class
//! object the session does not own, next to sensitive attributes such as phone numbers, emails or
//! ID numbers. The gateway records it as an alert. The response is forwarded as it is, and no
//! decision changes.

use std::collections::BTreeSet;

use xshield_core::context::{
    EXPOSURE_ATTRIBUTES_MAX, EXPOSURE_USERS_MAX, ExposedAttribute, Exposure, ExposureBasis,
    ExposureKind, IdentityRole, ObjectMap,
};

use crate::slots::response_slot;
use crate::values::ResponseValue;

/// The exposure a response shows, or `None` when it shows none. `method` and `path` are the
/// request's. `is_other_user` says whether a value at a user-class position is an id other than
/// the session's own user. A session that has shown no user says no to every value, so a site
/// without identity positions states no exposure.
#[must_use]
pub fn exposure(
    objects: &ObjectMap,
    method: &str,
    path: &str,
    values: &[ResponseValue],
    is_other_user: impl Fn(&str) -> bool,
) -> Option<Exposure> {
    // The user classes are the classes of the identity positions: a position that states who the
    // session is holds a user, so its class is the user class of the site.
    let user_classes: Vec<&str> = objects
        .slots()
        .iter()
        .filter(|slot| objects.identity_of(&slot.key) == Some(IdentityRole::User))
        .map(|slot| slot.class.as_str())
        .collect();
    if user_classes.is_empty() {
        return None;
    }
    let mut users = BTreeSet::new();
    let mut attributes = BTreeSet::new();
    for value in values {
        let Some(slot) = response_slot(method, path, &value.at) else {
            continue;
        };
        let user_class = objects
            .class_of(&slot)
            .is_some_and(|class| user_classes.contains(&class));
        if user_class && is_other_user(&value.value) {
            users.insert(slot);
        } else if let Some((kind, by)) = sensitive(&value.field, &value.value) {
            attributes.insert(ExposedAttribute { slot, kind, by });
        }
    }
    if users.is_empty() || attributes.is_empty() {
        return None;
    }
    let truncated = users.len() > EXPOSURE_USERS_MAX || attributes.len() > EXPOSURE_ATTRIBUTES_MAX;
    Some(Exposure {
        users: users.into_iter().take(EXPOSURE_USERS_MAX).collect(),
        attributes: attributes
            .into_iter()
            .take(EXPOSURE_ATTRIBUTES_MAX)
            .collect(),
        truncated,
    })
}

/// The sensitive kind a value is, and how it was recognised: by its field's name first, then by
/// the shape of the value. A blank value is never sensitive.
#[must_use]
pub fn sensitive(field: &str, value: &str) -> Option<(ExposureKind, ExposureBasis)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(kind) = kind_by_name(field) {
        return Some((kind, ExposureBasis::Name));
    }
    kind_by_format(value).map(|kind| (kind, ExposureBasis::Format))
}

/// The kind a field's name gives, from its English words (`phone`, `mobile_no`, `idCard`) or its
/// Chinese terms (手机, 邮箱, 身份证). Words are matched whole, so `hotel` is not a telephone and
/// `mailing_address` is not an email.
fn kind_by_name(field: &str) -> Option<ExposureKind> {
    if field.contains("手机") {
        return Some(ExposureKind::Phone);
    }
    if field.contains("邮箱") || field.contains("邮件") {
        return Some(ExposureKind::Email);
    }
    if field.contains("身份证") {
        return Some(ExposureKind::IdCard);
    }
    let words = name_words(field);
    let has = |word: &str| words.iter().any(|candidate| candidate == word);
    if [
        "phone",
        "mobile",
        "telephone",
        "tel",
        "cellphone",
        "mobilephone",
        "shouji",
    ]
    .iter()
    .any(|word| has(word))
    {
        return Some(ExposureKind::Phone);
    }
    if has("email") || has("mail") {
        return Some(ExposureKind::Email);
    }
    let identity = has("id") || has("identity");
    if [
        "idcard",
        "identitycard",
        "citizenid",
        "nationalid",
        "sfz",
        "shenfenzheng",
    ]
    .iter()
    .any(|word| has(word))
        || (identity && ["card", "no", "number"].iter().any(|word| has(word)))
    {
        return Some(ExposureKind::IdCard);
    }
    None
}

/// The lower-case words of a field name: `mobilePhone`, `mobile_phone` and `Mobile-Phone` all give
/// `mobile` and `phone`.
fn name_words(field: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous = ' ';
    for ch in field.chars() {
        if !ch.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            previous = ' ';
            continue;
        }
        if ch.is_ascii_uppercase() && previous.is_ascii_lowercase() && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        current.push(ch.to_ascii_lowercase());
        previous = ch;
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// The kind a value's shape gives: a mainland mobile number, an email address or a resident ID
/// number.
fn kind_by_format(value: &str) -> Option<ExposureKind> {
    if is_phone(value) {
        Some(ExposureKind::Phone)
    } else if is_email(value) {
        Some(ExposureKind::Email)
    } else if is_id_card(value) {
        Some(ExposureKind::IdCard)
    } else {
        None
    }
}

/// Eleven digits, starting with `1` and then `3` to `9`.
fn is_phone(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 11
        && bytes.iter().all(u8::is_ascii_digit)
        && bytes.first() == Some(&b'1')
        && bytes
            .get(1)
            .is_some_and(|second| (b'3'..=b'9').contains(second))
}

/// One `@`, a local part of letters, digits and `._%+-`, and a domain of letters, digits and `.-`
/// whose last label is at least two letters.
fn is_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    let local_ok = !local.is_empty()
        && local
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "._%+-".contains(ch));
    let domain_ok = domain.contains('.')
        && !domain.contains("..")
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-');
    let tld = domain.rsplit('.').next().unwrap_or_default();
    local_ok
        && domain_ok
        && value.len() <= 254
        && tld.len() >= 2
        && tld.chars().all(|ch| ch.is_ascii_alphabetic())
}

/// Eighteen characters: seventeen digits, a check character (ISO 7064 mod 11-2) and a plausible
/// birth date.
fn is_id_card(value: &str) -> bool {
    const WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const CHECKS: &[u8; 11] = b"10X98765432";
    if value.len() != 18 {
        return false;
    }
    let (Some(body), Some(tail)) = (value.get(..17), value.get(17..)) else {
        return false;
    };
    let check = match tail.as_bytes() {
        [byte] => byte.to_ascii_uppercase(),
        _ => return false,
    };
    let Some(digits) = body
        .chars()
        .map(|ch| ch.to_digit(10))
        .collect::<Option<Vec<u32>>>()
    else {
        return false;
    };
    let sum: u32 = digits
        .iter()
        .zip(WEIGHTS)
        .map(|(digit, weight)| digit * weight)
        .sum();
    let expected = usize::try_from(sum % 11)
        .ok()
        .and_then(|index| CHECKS.get(index))
        .copied();
    expected == Some(check) && birth_date_plausible(body)
}

/// Whether the eight digits from the seventh character read as a birth date from 1900 to 2099.
fn birth_date_plausible(body: &str) -> bool {
    let number =
        |range: std::ops::Range<usize>| body.get(range).and_then(|text| text.parse::<u32>().ok());
    matches!(
        (number(6..10), number(10..12), number(12..14)),
        (Some(1900..=2099), Some(1..=12), Some(1..=31))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_SLOT: &str = "GET /api/comments comments[].author.id";

    fn objects() -> ObjectMap {
        serde_json::from_str(
            r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":[
                {"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"user"},
                {"key":"GET /api/comments comments[].author.id","class":"doctor","source":"admin"}]}"#,
        )
        .unwrap()
    }

    fn value(at: &str, field: &str, text: &str) -> ResponseValue {
        ResponseValue {
            field: field.to_owned(),
            value: text.to_owned(),
            at: at.to_owned(),
        }
    }

    /// A comment whose author is `author`, with the author's name, phone and email.
    fn comment(author: &str) -> Vec<ResponseValue> {
        vec![
            value("comments[].author.id", "id", author),
            value("comments[].author.name", "name", "医生 B"),
            value("comments[].author.phone", "phone", "13800000002"),
            value("comments[].author.email", "email", "dr-b@emr.example"),
        ]
    }

    /// Whether a value is some user other than `own`.
    fn other_than(own: &'static str) -> impl Fn(&str) -> bool {
        move |value: &str| value != own
    }

    #[test]
    fn a_contact_detail_beside_another_users_id_is_an_exposure() {
        let found = exposure(
            &objects(),
            "GET",
            "/api/comments",
            &comment("DR-B"),
            other_than("DR-A"),
        )
        .expect("an exposure");
        assert_eq!(found.users, vec![USER_SLOT.to_owned()]);
        assert_eq!(
            found.attributes,
            vec![
                ExposedAttribute {
                    slot: "GET /api/comments comments[].author.email".to_owned(),
                    kind: ExposureKind::Email,
                    by: ExposureBasis::Name,
                },
                ExposedAttribute {
                    slot: "GET /api/comments comments[].author.phone".to_owned(),
                    kind: ExposureKind::Phone,
                    by: ExposureBasis::Name,
                },
            ]
        );
        assert!(!found.truncated);
    }

    #[test]
    fn the_session_own_user_states_no_exposure() {
        assert_eq!(
            exposure(
                &objects(),
                "GET",
                "/api/comments",
                &comment("DR-A"),
                other_than("DR-A"),
            ),
            None
        );
    }

    #[test]
    fn a_session_that_has_shown_no_user_states_no_exposure() {
        assert_eq!(
            exposure(&objects(), "GET", "/api/comments", &comment("DR-B"), |_| {
                false
            }),
            None
        );
    }

    #[test]
    fn a_site_without_an_identity_position_states_no_exposure() {
        let plain: ObjectMap = serde_json::from_str(
            r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":[
                {"key":"GET /api/comments comments[].author.id","class":"doctor","source":"admin"}]}"#,
        )
        .unwrap();
        assert_eq!(
            exposure(&plain, "GET", "/api/comments", &comment("DR-B"), |_| true),
            None
        );
    }

    #[test]
    fn a_paused_entry_states_nothing() {
        let paused: ObjectMap = serde_json::from_str(
            r#"{"classes":[{"id":"doctor","name":"医生"}],"slots":[
                {"key":"GET /api/home doctor.id","class":"doctor","source":"admin","identity":"user"},
                {"key":"GET /api/comments comments[].author.id","class":"doctor","source":"admin","paused":true}]}"#,
        )
        .unwrap();
        assert_eq!(
            exposure(&paused, "GET", "/api/comments", &comment("DR-B"), |_| true),
            None
        );
    }

    #[test]
    fn a_sensitive_value_is_recognised_by_its_shape_under_a_neutral_name() {
        assert_eq!(
            sensitive("contact", "13800000002"),
            Some((ExposureKind::Phone, ExposureBasis::Format))
        );
        assert_eq!(
            sensitive("ref", "dr-b@emr.example"),
            Some((ExposureKind::Email, ExposureBasis::Format))
        );
        assert_eq!(
            sensitive("ref", "11010519491231002X"),
            Some((ExposureKind::IdCard, ExposureBasis::Format))
        );
        assert_eq!(
            sensitive("ref", "11010519491231002x"),
            Some((ExposureKind::IdCard, ExposureBasis::Format))
        );
        // The check character is wrong.
        assert_eq!(sensitive("ref", "110105194912310021"), None);
        assert_eq!(sensitive("code", "1380000000"), None);
        assert_eq!(sensitive("code", "23800000002"), None);
        assert_eq!(sensitive("code", "not-an-email@"), None);
    }

    #[test]
    fn a_sensitive_field_name_is_recognised_whatever_the_value() {
        assert_eq!(
            sensitive("mobilePhone", "未填写"),
            Some((ExposureKind::Phone, ExposureBasis::Name))
        );
        assert_eq!(
            sensitive("user_id_card_no", "abc"),
            Some((ExposureKind::IdCard, ExposureBasis::Name))
        );
        assert_eq!(
            sensitive("手机号", "无"),
            Some((ExposureKind::Phone, ExposureBasis::Name))
        );
        assert_eq!(
            sensitive("e_mail", "无"),
            Some((ExposureKind::Email, ExposureBasis::Name))
        );
        assert_eq!(sensitive("mailing_address", "北京"), None);
        assert_eq!(sensitive("hotel", "北京"), None);
        assert_eq!(sensitive("phone", "  "), None);
    }

    #[test]
    fn a_long_list_of_attributes_is_cut_and_says_so() {
        let mut values = comment("DR-B");
        for index in 0..EXPOSURE_ATTRIBUTES_MAX {
            values.push(value(
                &format!("comments[].author.extra{index}"),
                "phone",
                "13800000002",
            ));
        }
        let found = exposure(
            &objects(),
            "GET",
            "/api/comments",
            &values,
            other_than("DR-A"),
        )
        .expect("an exposure");
        assert_eq!(found.attributes.len(), EXPOSURE_ATTRIBUTES_MAX);
        assert!(found.truncated);
    }

    #[test]
    fn an_id_card_needs_its_check_character_and_a_plausible_birth_date() {
        // Seventeen digits and a check character that matches, but a month of 13.
        assert!(!is_id_card("110105194913310021"));
        assert!(is_id_card("11010519491231002X"));
        assert!(!is_id_card("1101051949123100"));
    }
}
