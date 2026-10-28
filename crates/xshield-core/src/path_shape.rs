//! The shape of a request path that matched no configured route.
//!
//! Coverage reports list the endpoints a site's routes do not cover yet, so
//! the edge records which path a refused, unmatched request asked for. The
//! path is attacker-controlled and may carry identifiers, tokens or personal
//! data, so only its shape is kept: a segment survives only when it looks
//! like a fixed route word (a letter first, short, at most two digits, plain
//! characters); every other segment becomes `{}`. The query never enters.
//! The shape stays bounded whatever the request, and the publisher accepts
//! exactly the strings [`path_shape`] can produce.

/// Most segments kept; a deeper path ends in `/**`.
pub const PATH_SHAPE_SEGMENTS_MAX: usize = 10;
/// Longest segment kept as written.
pub const PATH_SHAPE_SEGMENT_BYTES_MAX: usize = 24;
/// Longest possible shape: ten kept segments and a trailing slash.
pub const PATH_SHAPE_BYTES_MAX: usize =
    PATH_SHAPE_SEGMENTS_MAX * (PATH_SHAPE_SEGMENT_BYTES_MAX + 1) + 1;

const PLACEHOLDER: &str = "{}";
const DEEPER: &str = "**";

fn kept(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    (1..=PATH_SHAPE_SEGMENT_BYTES_MAX).contains(&bytes.len())
        && bytes[0].is_ascii_alphabetic()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && bytes.iter().filter(|byte| byte.is_ascii_digit()).count() <= 2
}

/// The shape of `path` (a request target's path, without its query).
#[must_use]
pub fn path_shape(path: &str) -> String {
    let Some(rest) = path.strip_prefix('/') else {
        return format!("/{PLACEHOLDER}");
    };
    if rest.is_empty() {
        return "/".to_owned();
    }
    let (rest, trailing) = rest
        .strip_suffix('/')
        .map_or((rest, false), |rest| (rest, true));
    let segments = rest.split('/').collect::<Vec<_>>();
    let deeper = segments.len() > PATH_SHAPE_SEGMENTS_MAX;
    let shown = if deeper {
        &segments[..PATH_SHAPE_SEGMENTS_MAX - 1]
    } else {
        &segments[..]
    };
    let mut shape = String::with_capacity(PATH_SHAPE_BYTES_MAX);
    for segment in shown {
        shape.push('/');
        shape.push_str(if kept(segment) { segment } else { PLACEHOLDER });
    }
    if deeper {
        shape.push('/');
        shape.push_str(DEEPER);
    } else if trailing {
        shape.push('/');
    }
    shape
}

/// Whether `shape` is a string [`path_shape`] could have produced.
#[must_use]
pub fn valid_path_shape(shape: &str) -> bool {
    if shape == "/" {
        return true;
    }
    let Some(rest) = shape.strip_prefix('/') else {
        return false;
    };
    if shape.len() > PATH_SHAPE_BYTES_MAX {
        return false;
    }
    let segments = rest.split('/').collect::<Vec<_>>();
    let Some((last, before)) = segments.split_last() else {
        return false;
    };
    let named = |segment: &&str| *segment == PLACEHOLDER || kept(segment);
    if *last == DEEPER {
        before.len() == PATH_SHAPE_SEGMENTS_MAX - 1 && before.iter().all(named)
    } else if last.is_empty() {
        !before.is_empty() && before.len() <= PATH_SHAPE_SEGMENTS_MAX && before.iter().all(named)
    } else {
        segments.len() <= PATH_SHAPE_SEGMENTS_MAX && segments.iter().all(named)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_route_words_and_hides_values() {
        for (path, shape) in [
            ("/", "/"),
            ("/api/v1/users", "/api/v1/users"),
            ("/api/users/123/orders", "/api/users/{}/orders"),
            (
                "/api/users/018f2a3b-4c5d-7000-8000-000000000700",
                "/api/users/{}",
            ),
            ("/files/report.pdf/", "/files/report.pdf/"),
            ("/a//b", "/a/{}/b"),
            ("/user/alice%40example.com", "/user/{}"),
            ("/x/abc123", "/x/{}"),
            ("/x/averyveryverylongsegmentname", "/x/{}"),
            ("/.git/config", "/{}/config"),
            ("/../etc", "/{}/etc"),
            ("/éclair", "/{}"),
            ("*", "/{}"),
            ("", "/{}"),
        ] {
            assert_eq!(path_shape(path), shape, "{path}");
            assert!(valid_path_shape(shape), "{shape}");
        }
    }

    #[test]
    fn deep_paths_are_cut_and_every_shape_is_bounded() {
        let deep = "/a".repeat(PATH_SHAPE_SEGMENTS_MAX + 5);
        let shape = path_shape(&deep);
        assert_eq!(
            shape,
            format!("{}/**", "/a".repeat(PATH_SHAPE_SEGMENTS_MAX - 1))
        );
        assert!(valid_path_shape(&shape));
        let exact = format!("{}/", "/a".repeat(PATH_SHAPE_SEGMENTS_MAX));
        assert_eq!(path_shape(&exact), exact);
        let longest = format!(
            "{}/",
            format!("/{}", "a".repeat(PATH_SHAPE_SEGMENT_BYTES_MAX))
                .repeat(PATH_SHAPE_SEGMENTS_MAX)
        );
        assert_eq!(path_shape(&longest).len(), PATH_SHAPE_BYTES_MAX);
        assert!(valid_path_shape(&path_shape(&longest)));
        // A deterministic sweep of hostile paths: every shape validates.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let alphabet = b"/aZ09.-_%{}*?#\x00\xff ";
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let length = usize::try_from(state % 64).unwrap();
            let path = (0..length)
                .map(|index| {
                    let pick =
                        usize::try_from((state >> (index % 56)) % 64).unwrap() % alphabet.len();
                    char::from(alphabet[pick])
                })
                .collect::<String>();
            let shape = path_shape(&path);
            assert!(shape.len() <= PATH_SHAPE_BYTES_MAX, "{path:?}");
            assert!(valid_path_shape(&shape), "{path:?} -> {shape:?}");
        }
    }

    #[test]
    fn the_validator_accepts_only_producible_shapes() {
        for invalid in [
            "",
            "api",
            "//",
            "/api//x",
            "/api/123",
            "/api/{x}",
            "/api/**/x",
            "/**",
            "/a/**",
            "/a?b=1",
            "/a b",
            "/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}",
        ] {
            assert!(!valid_path_shape(invalid), "{invalid:?}");
        }
    }
}
