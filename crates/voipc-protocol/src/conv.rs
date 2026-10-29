//! Conversation ids of the stored-message log (protocol v11): what the relay
//! files entries and key wraps under, and checks membership against. The
//! crypto that seals them is `voipc_crypto::log`.

/// Lowercase hex, the form account ids and relay ids travel in as text.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// An account id (or a relay id) back from its 32 hex digits.
///
/// As `hex` writes them and no other way: `from_str_radix` also took a `+`
/// and uppercase, so one DM conversation could be filed under several names
/// that `dm_parties` all read as the same two accounts.
pub fn unhex16(h: &str) -> Option<[u8; 16]> {
    unhex::<16>(h)
}

/// `N` bytes back from exactly the `2N` digits `hex` writes: lowercase, no
/// sign, nothing around them. One value has one spelling, so an id parsed
/// here and the same id compared as text never disagree.
pub fn unhex<const N: usize>(h: &str) -> Option<[u8; N]> {
    let digits = h.as_bytes();
    if digits.len() != N * 2 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (o, &[hi, lo]) in out.iter_mut().zip(digits.as_chunks::<2>().0) {
        *o = nibble(hi)? << 4 | nibble(lo)?;
    }
    Some(out)
}

/// A direct conversation's id: `d:` and the two account ids in hex, lower
/// first, so both ends name it alike.
pub fn dm_conv(a: &[u8; 16], b: &[u8; 16]) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    format!("d:{}:{}", hex(lo), hex(hi))
}

/// The two accounts of a `d:` conversation, if it is one (canonical order only).
pub fn dm_parties(conv: &str) -> Option<([u8; 16], [u8; 16])> {
    let (a, b) = conv.strip_prefix("d:")?.split_once(':')?;
    let (a, b) = (unhex16(a)?, unhex16(b)?);
    (a < b).then_some((a, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unhex_takes_only_what_hex_writes() {
        let bytes = [0x00, 0x7f, 0xa5, 0xff];
        assert_eq!(unhex::<4>(&hex(&bytes)), Some(bytes));
        assert_eq!(unhex::<4>("007fa5f"), None, "too short");
        assert_eq!(unhex::<4>("007fa5ff00"), None, "too long");
        assert_eq!(unhex::<4>("007FA5FF"), None, "uppercase");
        assert_eq!(
            unhex::<4>("+7+fa5ff"),
            None,
            "a sign, which from_str_radix takes"
        );
        assert_eq!(unhex::<4>("007fa5fg"), None);
        assert_eq!(unhex::<1>("é"), None, "two bytes, one character");
        assert_eq!(unhex::<0>(""), Some([]));
    }

    #[test]
    fn a_dm_conversation_is_named_alike_from_both_ends() {
        let (a, b) = ([1u8; 16], [2u8; 16]);
        let c = dm_conv(&b, &a);
        assert_eq!(c, dm_conv(&a, &b));
        assert_eq!(dm_parties(&c), Some((a, b)));
        assert_eq!(dm_parties("d:zz:yy"), None);
        assert_eq!(
            dm_parties(&format!("d:{}:{}", hex(&b), hex(&a))),
            None,
            "only the canonical order"
        );
        assert_eq!(
            dm_parties(&format!("d:{}:{}", hex(&a), hex(&a))),
            None,
            "not with oneself"
        );
        // One conversation, one name.
        let (a, b) = ([0xab; 16], [0xcd; 16]);
        assert_eq!(dm_parties(&dm_conv(&a, &b)), Some((a, b)));
        let upper = format!("d:{}:{}", hex(&a).to_uppercase(), hex(&b));
        assert_eq!(dm_parties(&upper), None, "uppercase");
        let signed = format!("d:+{}:{}", &hex(&a)[1..], hex(&b));
        assert_eq!(dm_parties(&signed), None, "a sign");
    }
}
