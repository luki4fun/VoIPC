//! Conversation ids of the stored-message log (protocol v11): what the relay
//! files entries and key wraps under, and checks membership against. The
//! crypto that seals them is `voipc_crypto::log`.

/// Lowercase hex, the form account ids and relay ids travel in as text.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// An account id (or a relay id) back from its 32 hex digits.
pub fn unhex16(h: &str) -> Option<[u8; 16]> {
    if h.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(h.get(i * 2..i * 2 + 2)?, 16).ok()?;
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
    }
}
