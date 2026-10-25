//! Port of `@remnawave/hashed-set`: a set of strings with an order-independent 64-bit
//! fingerprint. The panel computes the same value, so the string form must match
//! JavaScript byte for byte, including the quirks of its signed 32-bit XOR.

use std::collections::HashSet;

#[derive(Debug, Default, Clone)]
pub struct HashedSet {
    items: HashSet<String>,
    // JS keeps these as int32 (`^=` yields signed values).
    high: i32,
    low: i32,
}

/// DJB2-style dual hash over UTF-16 code units, wrapping at 32 bits.
fn djb2_dual(s: &str) -> (u32, u32) {
    let mut high: u32 = 5381;
    let mut low: u32 = 5387;
    for c in s.encode_utf16() {
        let c = c as u32;
        high = high.wrapping_shl(5).wrapping_add(high).wrapping_add(c);
        low = low
            .wrapping_shl(6)
            .wrapping_add(low)
            .wrapping_add(c.wrapping_mul(37));
    }
    (high, low)
}

/// `Number.prototype.toString(16).padStart(8, '0')` for an int32.
/// Negative values keep their sign *before* the padding, exactly like JS.
fn js_hex_pad8(v: i32) -> String {
    let s = if v < 0 {
        format!("-{:x}", -(v as i64))
    } else {
        format!("{v:x}")
    };
    format!("{s:0>8}")
}

impl HashedSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn add(&mut self, s: &str) {
        if self.items.insert(s.to_string()) {
            let (h, l) = djb2_dual(s);
            self.high ^= h as i32;
            self.low ^= l as i32;
        }
    }

    pub fn delete(&mut self, s: &str) {
        if self.items.remove(s) {
            let (h, l) = djb2_dual(s);
            self.high ^= h as i32;
            self.low ^= l as i32;
        }
    }

    pub fn hash64_string(&self) -> String {
        format!("{}{}", js_hex_pad8(self.high), js_hex_pad8(self.low))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_js_reference_vectors() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/hashed_set_vectors.json")).unwrap();
        let ids: Vec<&str> = v["ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        for pair in v["out"].as_array().unwrap() {
            let n = pair[0].as_u64().unwrap() as usize;
            let mut set = HashedSet::new();
            for id in &ids[..n] {
                set.add(id);
            }
            assert_eq!(set.hash64_string(), pair[1].as_str().unwrap(), "n={n}");
        }
        let mut uni = HashedSet::new();
        uni.add("тест");
        uni.add("a😀");
        assert_eq!(uni.hash64_string(), v["uni"].as_str().unwrap());
    }

    #[test]
    fn empty_set() {
        assert_eq!(HashedSet::new().hash64_string(), "0000000000000000");
    }

    #[test]
    fn order_independent_and_reversible() {
        let mut a = HashedSet::new();
        a.add("a");
        a.add("b");
        let mut b = HashedSet::new();
        b.add("b");
        b.add("a");
        assert_eq!(a.hash64_string(), b.hash64_string());
        a.delete("a");
        a.delete("b");
        assert_eq!(a.hash64_string(), "0000000000000000");
    }

    #[test]
    fn js_hex_quirks() {
        assert_eq!(js_hex_pad8(0), "00000000");
        assert_eq!(js_hex_pad8(-3), "000000-3");
        assert_eq!(js_hex_pad8(-0x1a2b3c4d), "-1a2b3c4d");
        assert_eq!(js_hex_pad8(i32::MIN), "-80000000");
    }
}
