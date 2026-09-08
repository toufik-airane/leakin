//! Private-key material detectors that need more than a regex: PEM blocks,
//! and base58check-validated wallet keys.

use regex::bytes::Regex;
use sha2::{Digest, Sha256};

use crate::rules::Kind;

pub struct Detector {
    pub title: &'static str,
    pub kind: Kind,
    pub severity: u8,
    pub re: Regex,
    /// Extra validation on capture group 1 (or the whole match when absent).
    pub validate: fn(&[u8]) -> bool,
}

fn always(_: &[u8]) -> bool {
    true
}

/// Base58check: 4-byte double-SHA256 checksum over the payload.
fn base58check(s: &[u8]) -> bool {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    for &c in s {
        let Some(mut carry) = ALPHABET.iter().position(|&a| a == c) else {
            return false;
        };
        for b in bytes.iter_mut() {
            carry += (*b as usize) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    for _ in s.iter().take_while(|&&c| c == b'1') {
        bytes.push(0);
    }
    bytes.reverse();
    if bytes.len() < 5 {
        return false;
    }
    let (payload, want) = bytes.split_at(bytes.len() - 4);
    let sum = Sha256::digest(Sha256::digest(payload));
    sum[..4] == *want
}

/// A PEM private-key block: header, base64 body, matching footer.
fn pem_block(m: &[u8]) -> bool {
    let body_len = m
        .iter()
        .filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        .count();
    body_len >= 64
}

pub fn detectors() -> Vec<Detector> {
    let mut d = Vec::new();
    let mut push = |title, kind, severity, pat: &str, validate: fn(&[u8]) -> bool| {
        d.push(Detector {
            title,
            kind,
            severity,
            re: Regex::new(pat).expect("builtin detector must compile"),
            validate,
        });
    };

    // PEM/OpenSSH/PGP blocks, body included so the finding shows real material.
    push(
        "PEM private key block",
        Kind::PrivateKey,
        10,
        r"(?s)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----.{0,8192}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
        pem_block,
    );
    // Truncated or headerless block: still a leak, lower confidence.
    push(
        "PEM private key header",
        Kind::PrivateKey,
        9,
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
        always,
    );
    push(
        "PuTTY private key",
        Kind::PrivateKey,
        10,
        r"PuTTY-User-Key-File-[0-9]+:",
        always,
    );
    push(
        "age secret key",
        Kind::PrivateKey,
        10,
        r"AGE-SECRET-KEY-1[0-9A-Z]{58}",
        always,
    );
    push(
        "Bitcoin WIF private key",
        Kind::PrivateKey,
        10,
        r"(?-u)\b([5KL][1-9A-HJ-NP-Za-km-z]{50,51})\b",
        base58check,
    );
    push(
        "BIP32 extended private key",
        Kind::PrivateKey,
        10,
        r"(?-u)\b((?:xprv|tprv|yprv|zprv)[1-9A-HJ-NP-Za-km-z]{100,115})\b",
        base58check,
    );
    // Raw 32-byte key material is indistinguishable from any hash, so require
    // a secret-ish keyword nearby.
    push(
        "Raw private key (hex, in secret context)",
        Kind::PrivateKey,
        8,
        r"(?i)(?:priv(?:ate)?[_-]?key|secret[_-]?key|seed|wallet|keystore)[^\n]{0,48}?\b(?:0x)?(?-u:([0-9a-fA-F]{64}))\b",
        always,
    );

    d
}

impl Detector {
    /// Reported span: capture group 1 when the pattern brackets context.
    pub fn span<'a>(&'a self, data: &'a [u8]) -> impl Iterator<Item = (usize, &'a [u8])> + 'a {
        let validate = self.validate;
        self.re.captures_iter(data).filter_map(move |c| {
            let whole = c.get(0)?;
            let target = c.get(1).unwrap_or(whole);
            if !validate(target.as_bytes()) {
                return None;
            }
            Some((target.start(), target.as_bytes()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(title: &str, data: &str) -> Vec<String> {
        let d = detectors();
        let det = d.iter().find(|d| d.title == title).unwrap();
        det.span(data.as_bytes())
            .map(|(_, m)| String::from_utf8_lossy(m).into_owned())
            .collect()
    }

    #[test]
    fn wif_checksum_gates_reporting() {
        // The canonical WIF encoding of private key 0x01 — the single most
        // published key in Bitcoin, used here only to exercise base58check.
        // Its address is permanently swept; never send anything to it.
        let good = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf";
        // Same string with one character changed: checksum fails.
        let bad = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDg";
        assert_eq!(find("Bitcoin WIF private key", good), vec![good.to_string()]);
        assert!(find("Bitcoin WIF private key", bad).is_empty());
    }

    /// Bodies in these fixtures are synthetic base64 filler, never real key
    /// material: `pem_block` only counts base64-alphabet bytes, so nothing is
    /// lost by keeping actual keys out of this repository.
    const FAKE_BODY: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2\nd3h5ejAxMjM0NTY3ODkrL0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFla";

    #[test]
    fn pem_block_captures_body_not_just_header() {
        let pem =
            format!("-----BEGIN RSA PRIVATE KEY-----\n{FAKE_BODY}\n-----END RSA PRIVATE KEY-----");
        let got = find("PEM private key block", &pem);
        assert_eq!(got.len(), 1);
        assert!(got[0].contains("QUJDREVGR0hJSkt"), "body must be included");
    }

    #[test]
    fn pem_block_requires_real_body() {
        let empty = "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----";
        assert!(find("PEM private key block", empty).is_empty());
        // The header-only detector still flags it.
        assert_eq!(find("PEM private key header", empty).len(), 1);
    }

    #[test]
    fn raw_hex_needs_secret_context() {
        let hex = "d1e4f2b3a5968778695a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e";
        assert!(find("Raw private key (hex, in secret context)", &format!("sha256 = {hex}")).is_empty());
        let got = find(
            "Raw private key (hex, in secret context)",
            &format!("private_key = 0x{hex}"),
        );
        assert_eq!(got, vec![hex.to_string()]);
    }
}
