//! Hexadecimal digits: the decoder for keys and hashes given as text, and the digit value
//! that the percent-decoding of paths and bodies needs.

/// The value of one hexadecimal digit (`0`–`9`, `a`–`f` or `A`–`F`), or `None` for any other
/// byte.
#[must_use]
pub fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decodes hexadecimal text into bytes: an even number of digits in either case, and nothing
/// else. Empty text, an odd length, and any other byte (whitespace, a sign) give `None`. A
/// caller that accepts surrounding whitespace trims the text first.
#[must_use]
pub fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let digits = text.as_bytes();
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[high, low]| Some((hex_digit(high)? << 4) | hex_digit(low)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digit_is_its_value_in_either_case() {
        assert_eq!(hex_digit(b'0'), Some(0));
        assert_eq!(hex_digit(b'9'), Some(9));
        assert_eq!(hex_digit(b'a'), Some(10));
        assert_eq!(hex_digit(b'F'), Some(15));
        assert_eq!(hex_digit(b'g'), None);
        assert_eq!(hex_digit(b' '), None);
    }

    #[test]
    fn decodes_either_case_and_nothing_else() {
        assert_eq!(decode_hex("0a0B"), Some(vec![0x0a, 0x0b]));
        assert_eq!(decode_hex("ff"), Some(vec![0xff]));
        assert_eq!(decode_hex(""), None);
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex(" 0a"), None);
        assert_eq!(decode_hex("0a "), None);
        assert_eq!(decode_hex("+f"), None);
        assert_eq!(decode_hex("g0"), None);
    }

    #[test]
    fn non_ascii_input_is_rejected_without_slicing_a_character() {
        assert_eq!(decode_hex("é0"), None);
        assert_eq!(decode_hex("éé"), None);
    }
}
