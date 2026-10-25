//! Deterministic fuzz smoke tests: every parser that sees external bytes must return, never panic.

use crate::{
    payload::{canon, derive_sni, normalize_pem, parse_node_payload},
    plugin::{asn::decode_prefixes, extract_ip, is_ip_or_cidr, nft::normalize_addr},
    xray::{
        loader::valid_asset_name,
        process::{coerce_semver, redact_token},
    },
};

/// xorshift64*: tiny, dependency-free, reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max + 1);
        (0..n).map(|_| self.next() as u8).collect()
    }
    /// Text that leans on the characters the parsers care about, plus arbitrary unicode.
    fn text(&mut self, max: usize) -> String {
        const PIECES: &[&str] = &[
            "-----",
            "BEGIN ",
            "END ",
            "CERTIFICATE",
            "\n",
            "\r\n",
            "\\n",
            " ",
            ":",
            ".",
            "/",
            "[",
            "]",
            "tcp:",
            "udp:",
            "token=",
            "ext:",
            "0",
            "1",
            "255",
            "::",
            "ffff",
            "e",
            "é",
            "😀",
            "\u{0}",
            "%",
            "..",
            "-",
            "=",
            "+",
            "a",
        ];
        let n = self.below(max + 1);
        (0..n)
            .map(|_| {
                if self.below(4) == 0 {
                    char::from_u32((self.next() % 0x11_0000) as u32)
                        .unwrap_or('?')
                        .to_string()
                } else {
                    PIECES[self.below(PIECES.len())].to_string()
                }
            })
            .collect()
    }
}

const ROUNDS: usize = 20_000;

#[test]
fn text_parsers_never_panic() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..ROUNDS {
        let s = rng.text(24);
        let _ = normalize_pem(&s);
        let _ = canon(&s);
        let _ = derive_sni(&s, &s);
        let _ = extract_ip(Some(&s));
        let _ = coerce_semver(&s);
        let _ = redact_token(&s);
        let _ = is_ip_or_cidr(&s);
        let _ = normalize_addr(&s);
        let _ = valid_asset_name(&s);
        let _ = parse_node_payload(&s);
    }
}

#[test]
fn binary_parsers_never_panic() {
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for _ in 0..ROUNDS {
        let b = rng.bytes(64);
        let _ = decode_prefixes(&b);
        // valid base64 wrapping garbage JSON, the shape SECRET_KEY actually has
        use base64::Engine;
        let _ = parse_node_payload(&base64::engine::general_purpose::STANDARD.encode(&b));
    }
}

#[test]
fn redaction_never_leaks_a_token() {
    let mut rng = Rng(42);
    for _ in 0..2000 {
        let len = 8 + rng.below(40);
        // upper-case/digits only, so it cannot occur in the surrounding fixed text
        let secret: String = (0..len)
            .map(|_| b"QWXZ0123456789"[rng.below(14)] as char)
            .collect();
        let line = format!(
            "Reading config: @sock:/internal/get-config?token={secret}&x=1 token={secret} end"
        );
        let out = redact_token(&line);
        assert!(!out.contains(&secret), "token leaked: {out}");
        assert!(out.contains("token=***"));
    }
}

#[test]
fn request_bodies_never_panic_on_arbitrary_json() {
    use crate::dto::*;
    use serde_json::Value;
    let mut rng = Rng(7);
    for _ in 0..ROUNDS {
        let raw = rng.text(16);
        for candidate in [
            raw.clone(),
            format!("{{\"{raw}\":{raw}}}"),
            format!("[{raw}]"),
            format!("{{\"ips\":[\"{raw}\"]}}"),
        ] {
            let _ = serde_json::from_str::<AddUserRequest>(&candidate).map(|v| v.validate());
            let _ = serde_json::from_str::<AddUsersRequest>(&candidate).map(|v| v.validate());
            let _ = serde_json::from_str::<BlockIpsRequest>(&candidate).map(|v| v.validate());
            let _ = serde_json::from_str::<UnblockIpsRequest>(&candidate).map(|v| v.validate());
            let _ = serde_json::from_str::<DropIpsRequest>(&candidate).map(|v| v.validate());
            let _ = serde_json::from_str::<Value>(&candidate);
        }
    }
}
