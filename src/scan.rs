//! Buffer scanning: prefilter, rule matching, built-in detectors, and
//! finding normalisation (location, truncation, redaction).

use crate::keys::{self, Detector};
use crate::mnemonic::Bip39;
use crate::rules::{Kind, RuleSet};

#[derive(Debug, Clone)]
pub struct Finding {
    pub path: String,
    pub line: u32,
    /// 1-based byte column within the line.
    pub col: u32,
    pub offset: usize,
    pub rule: String,
    pub kind: Kind,
    pub severity: u8,
    pub secret: String,
}

pub struct Options {
    pub kinds: Vec<Kind>,
    pub min_severity: u8,
    pub redact: bool,
    pub max_match: usize,
    pub mnemonic_checksum: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            kinds: Kind::ALL.to_vec(),
            min_severity: 0,
            redact: false,
            max_match: 240,
            mnemonic_checksum: true,
        }
    }
}

pub struct Scanner {
    set: RuleSet,
    extra: Vec<Detector>,
    bip39: Option<Bip39>,
    opts: Options,
}

/// Per-thread reusable buffers: scanning a tree must not allocate per file.
pub struct Scratch {
    seen: Vec<bool>,
    cand: Vec<u32>,
    hits: Vec<Hit>,
}

struct Hit {
    offset: usize,
    len: usize,
    rule: usize,
    /// `usize::MAX` marks a built-in (non rule-table) detector.
    kind: Kind,
    severity: u8,
    title: String,
}

impl Scanner {
    pub fn new(opts: Options) -> Result<Scanner, String> {
        let set = RuleSet::load(&opts.kinds, opts.min_severity)?;
        let extra = keys::detectors()
            .into_iter()
            .filter(|d| opts.kinds.contains(&d.kind) && d.severity >= opts.min_severity)
            .collect();
        let bip39 = (opts.kinds.contains(&Kind::Mnemonic) && opts.min_severity <= 9)
            .then(|| Bip39::new(opts.mnemonic_checksum));
        Ok(Scanner { set, extra, bip39, opts })
    }

    pub fn rules(&self) -> usize {
        self.set.len() + self.extra.len()
    }

    pub fn always_run(&self) -> usize {
        self.set.always_run()
    }

    pub fn scratch(&self) -> Scratch {
        Scratch {
            seen: vec![false; self.set.len()],
            cand: Vec::new(),
            hits: Vec::new(),
        }
    }

    pub fn scan(&self, path: &str, data: &[u8], s: &mut Scratch) -> Vec<Finding> {
        s.hits.clear();

        self.set.candidates(data, &mut s.seen, &mut s.cand);
        for &idx in &s.cand {
            let rule = &self.set.rules[idx as usize];
            for m in rule.re.find_iter(data) {
                s.hits.push(Hit {
                    offset: m.start(),
                    len: m.len(),
                    rule: idx as usize,
                    kind: rule.kind,
                    severity: rule.severity,
                    title: rule.title.clone(),
                });
            }
        }

        for det in &self.extra {
            for (offset, m) in det.span(data) {
                s.hits.push(Hit {
                    offset,
                    len: m.len(),
                    rule: usize::MAX,
                    kind: det.kind,
                    severity: det.severity,
                    title: det.title.to_string(),
                });
            }
        }

        if let Some(b) = &self.bip39 {
            for m in b.find(data) {
                s.hits.push(Hit {
                    offset: m.start,
                    len: m.end - m.start,
                    rule: usize::MAX,
                    kind: Kind::Mnemonic,
                    severity: if m.checksum_ok { 10 } else { 6 },
                    title: if m.checksum_ok {
                        format!("BIP39 mnemonic ({} words, checksum valid)", m.words)
                    } else {
                        format!("BIP39 word sequence ({} words, checksum invalid)", m.words)
                    },
                });
            }
        }

        if s.hits.is_empty() {
            return Vec::new();
        }

        s.hits.sort_by(|a, b| {
            (a.offset, a.len, a.rule)
                .cmp(&(b.offset, b.len, b.rule))
                .then_with(|| a.title.cmp(&b.title))
        });
        s.hits.dedup_by(|a, b| {
            a.offset == b.offset && a.len == b.len && a.title == b.title
        });
        suppress_contained(&mut s.hits);

        let mut out = Vec::with_capacity(s.hits.len());
        let mut line = 1u32;
        let mut line_start = 0usize;
        let mut nl = memchr::memchr_iter(b'\n', data).peekable();
        for hit in s.hits.iter() {
            while let Some(&pos) = nl.peek() {
                if pos < hit.offset {
                    line += 1;
                    line_start = pos + 1;
                    nl.next();
                } else {
                    break;
                }
            }
            out.push(Finding {
                path: path.to_string(),
                line,
                col: (hit.offset - line_start) as u32 + 1,
                offset: hit.offset,
                rule: hit.title.clone(),
                kind: hit.kind,
                severity: hit.severity,
                secret: render(
                    &data[hit.offset..hit.offset + hit.len],
                    self.opts.max_match,
                    self.opts.redact,
                ),
            });
        }
        out
    }
}

/// Drop findings swallowed by a stronger enclosing finding: a PEM header
/// inside its own block, and keyword rules that "match" random base64 inside
/// a key body (a sendgrid-shaped run inside an RSA key is not a sendgrid key).
fn suppress_contained(hits: &mut Vec<Hit>) {
    let keep: Vec<bool> = hits
        .iter()
        .map(|h| {
            !hits.iter().any(|o| {
                let outranks = o.kind == h.kind && o.severity >= h.severity;
                let key_body = o.kind == Kind::PrivateKey && h.kind != Kind::PrivateKey;
                (outranks || key_body)
                    && (o.offset, o.len) != (h.offset, h.len)
                    && o.offset <= h.offset
                    && o.offset + o.len >= h.offset + h.len
            })
        })
        .collect();
    let mut i = 0;
    hits.retain(|_| {
        i += 1;
        keep[i - 1]
    });
}

/// Single-line, printable rendering of matched bytes.
fn render(raw: &[u8], max: usize, redact: bool) -> String {
    let cut = raw.len().min(max);
    // Keep UTF-8 boundaries intact when truncating.
    let mut end = cut;
    while end > 0 && end < raw.len() && (raw[end] & 0xc0) == 0x80 {
        end -= 1;
    }
    let mut s = String::with_capacity(end + 8);
    for ch in String::from_utf8_lossy(&raw[..end]).chars() {
        match ch {
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => s.push('.'),
            c => s.push(c),
        }
    }
    if end < raw.len() {
        s.push('…');
    }
    if redact {
        s = redacted(&s);
    }
    s
}

fn redacted(s: &str) -> String {
    let n = s.chars().count();
    if n <= 12 {
        return "*".repeat(n.max(1));
    }
    let head: String = s.chars().take(4).collect();
    let tail: String = s.chars().skip(n - 4).collect();
    format!("{head}***{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(data: &str) -> Vec<Finding> {
        let sc = Scanner::new(Options::default()).unwrap();
        let mut scratch = sc.scratch();
        sc.scan("t.txt", data.as_bytes(), &mut scratch)
    }

    #[test]
    fn reports_line_and_column_of_match() {
        let f = scan("clean line\nno secret here\nkey = AKIAIOSFODNN7EXAMPLE\n");
        let aws = f
            .iter()
            .find(|f| f.secret.contains("AKIAIOSFODNN7EXAMPLE"))
            .expect("aws key");
        assert_eq!((aws.line, aws.col), (3, 7));
        assert_eq!(aws.offset, 32);
    }

    #[test]
    fn pem_header_inside_block_is_suppressed() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----\n";
        let titles: Vec<String> = scan(pem).into_iter().map(|f| f.rule).collect();
        assert!(titles.contains(&"PEM private key block".to_string()));
        assert!(!titles.contains(&"PEM private key header".to_string()), "got {titles:?}");
    }

    #[test]
    fn keyword_rules_do_not_fire_inside_a_key_body() {
        // The body contains a sendgrid-shaped run ("SG.<16-32>.<16-64>"); it
        // is base64 of a key, not an API key.
        let pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rSG.abcdefghijklmnop.qrstuvwxyz0123456789ABCDEFte1kZAAAAB\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END OPENSSH PRIVATE KEY-----\n";
        let f = scan(pem);
        assert_eq!(f.len(), 1, "got {:?}", f.iter().map(|f| &f.rule).collect::<Vec<_>>());
        assert_eq!(f[0].kind, Kind::PrivateKey);
    }

    #[test]
    fn matched_bytes_are_single_line_and_capped() {
        // The ARN rule matches to end of line, so the raw match is huge.
        let long = format!("arn:aws:iam:us-east-1:123456789012:{}", "x".repeat(500));
        let f = scan(&long);
        assert!(!f.is_empty());
        for f in f {
            assert!(!f.secret.contains('\n'));
            assert!(f.secret.chars().count() <= 241, "{}", f.secret.len());
        }
    }

    #[test]
    fn redaction_hides_the_middle() {
        let sc = Scanner::new(Options {
            redact: true,
            ..Default::default()
        })
        .unwrap();
        let mut scratch = sc.scratch();
        let f = sc.scan("t", b"key = AKIAIOSFODNN7EXAMPLE", &mut scratch);
        let aws = f.iter().find(|f| f.rule.contains("Client ID")).unwrap();
        assert_eq!(aws.secret, "AKIA***MPLE");
    }

    #[test]
    fn kind_filter_excludes_other_detectors() {
        let sc = Scanner::new(Options {
            kinds: vec![Kind::Mnemonic],
            ..Default::default()
        })
        .unwrap();
        let mut scratch = sc.scratch();
        let f = sc.scan("t", b"key = AKIAIOSFODNN7EXAMPLE", &mut scratch);
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn finds_mnemonic_and_private_key_together() {
        let data = "seed: absurd avoid scissors anxiety gather lottery category door army half long camera\nAGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ\n";
        let kinds: Vec<Kind> = scan(data).into_iter().map(|f| f.kind).collect();
        assert!(kinds.contains(&Kind::Mnemonic), "{kinds:?}");
        assert!(kinds.contains(&Kind::PrivateKey), "{kinds:?}");
    }
}
