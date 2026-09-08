//! Rule set: embedded pattern definitions, compilation, and literal prefilter.

use aho_corasick::{AhoCorasick, MatchKind};
use regex::bytes::Regex;
use regex_syntax::hir::{Class, Hir, HirKind};
use serde::Deserialize;

/// Detector family. Used by `--only` / `--skip` filtering and in output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    ApiKey,
    Token,
    Password,
    PrivateKey,
    Mnemonic,
    Endpoint,
    Generic,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::ApiKey => "api-key",
            Kind::Token => "token",
            Kind::Password => "password",
            Kind::PrivateKey => "private-key",
            Kind::Mnemonic => "mnemonic",
            Kind::Endpoint => "endpoint",
            Kind::Generic => "generic",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Some(match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "api-key" | "apikey" | "key" => Kind::ApiKey,
            "token" => Kind::Token,
            "password" | "pw" => Kind::Password,
            "private-key" | "privatekey" | "pem" => Kind::PrivateKey,
            "mnemonic" | "seed" | "bip39" => Kind::Mnemonic,
            "endpoint" => Kind::Endpoint,
            "generic" => Kind::Generic,
            _ => return None,
        })
    }

    pub const ALL: [Kind; 7] = [
        Kind::ApiKey,
        Kind::Token,
        Kind::Password,
        Kind::PrivateKey,
        Kind::Mnemonic,
        Kind::Endpoint,
        Kind::Generic,
    ];
}

#[derive(Debug, Deserialize)]
struct RawRule {
    title: String,
    kind: String,
    severity: u8,
    regex: String,
}

pub struct Rule {
    pub title: String,
    pub kind: Kind,
    pub severity: u8,
    pub re: Regex,
}

/// Compiled rule set plus an Aho-Corasick prefilter over each rule's required
/// literal. A rule whose pattern has no required literal >= MIN_LITERAL bytes
/// lands in `always`, and is run against every candidate buffer.
pub struct RuleSet {
    pub rules: Vec<Rule>,
    prefilter: AhoCorasick,
    /// prefilter pattern id -> rule index
    owners: Vec<u32>,
    always: Vec<u32>,
}

const MIN_LITERAL: usize = 3;

const RULES_JSON: &str = include_str!("../rules.json");

impl RuleSet {
    /// Compile the embedded rule set, keeping only rules in `kinds` and with
    /// `severity >= min_severity`.
    pub fn load(kinds: &[Kind], min_severity: u8) -> Result<RuleSet, String> {
        let raw: Vec<RawRule> =
            serde_json::from_str(RULES_JSON).map_err(|e| format!("rules.json: {e}"))?;

        let mut rules = Vec::with_capacity(raw.len());
        let mut keys: Vec<Vec<u8>> = Vec::with_capacity(raw.len() * 2);
        let mut owners: Vec<u32> = Vec::with_capacity(raw.len() * 2);
        let mut always: Vec<u32> = Vec::new();

        for r in raw {
            let kind = Kind::parse(&r.kind).ok_or_else(|| format!("bad kind {}", r.kind))?;
            if !kinds.contains(&kind) || r.severity < min_severity {
                continue;
            }
            // ASCII semantics: every rule is an ASCII pattern, byte matching is
            // faster, and it keeps `(?i)` folding in step with the ASCII-only
            // Aho-Corasick prefilter (Unicode folding of `k`/`s` pulls in
            // U+212A/U+017F, which would make the prefilter unsound).
            let re = regex::bytes::RegexBuilder::new(&r.regex)
                .unicode(false)
                .build()
                .or_else(|_| Regex::new(&r.regex))
                .map_err(|e| format!("rule {}: {e}", r.title))?;
            let idx = rules.len() as u32;
            match required_literals(&r.regex) {
                Some(lits) => {
                    for l in lits {
                        keys.push(l);
                        owners.push(idx);
                    }
                }
                None => always.push(idx),
            }
            rules.push(Rule {
                title: r.title,
                kind,
                severity: r.severity,
                re,
            });
        }

        let prefilter = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&keys)
            .map_err(|e| format!("prefilter: {e}"))?;

        Ok(RuleSet {
            rules,
            prefilter,
            owners,
            always,
        })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn always_run(&self) -> usize {
        self.always.len()
    }

    /// Fill `cand` with the indices of rules that could match `data`.
    /// One Aho-Corasick pass replaces a full pass per rule.
    pub fn candidates(&self, data: &[u8], seen: &mut [bool], cand: &mut Vec<u32>) {
        cand.clear();
        for m in self.prefilter.find_overlapping_iter(data) {
            let rule = self.owners[m.pattern().as_usize()];
            let slot = &mut seen[rule as usize];
            if !*slot {
                *slot = true;
                cand.push(rule);
            }
        }
        for &rule in &self.always {
            let slot = &mut seen[rule as usize];
            if !*slot {
                *slot = true;
                cand.push(rule);
            }
        }
        for &rule in cand.iter() {
            seen[rule as usize] = false;
        }
    }
}

/// A set of literals such that every match of `pat` contains at least one of
/// them. `None` means no usable literal was found.
fn required_literals(pat: &str) -> Option<Vec<Vec<u8>>> {
    let hir = regex_syntax::ParserBuilder::new()
        .utf8(false)
        .unicode(false)
        .build()
        .parse(pat)
        .ok()?;
    let alts = extract(&hir)?;
    let mut out = Vec::with_capacity(alts.len());
    for a in alts {
        if a.len() < MIN_LITERAL {
            return None;
        }
        out.push(a.to_ascii_lowercase());
    }
    Some(out)
}

/// Best candidate = the alternative set whose shortest member is longest.
fn score(alts: &[Vec<u8>]) -> usize {
    alts.iter().map(|a| a.len()).min().unwrap_or(0)
}

fn better(a: Option<Vec<Vec<u8>>>, b: Option<Vec<Vec<u8>>>) -> Option<Vec<Vec<u8>>> {
    match (a, b) {
        (Some(x), Some(y)) => {
            if score(&y) > score(&x) {
                Some(y)
            } else {
                Some(x)
            }
        }
        (Some(x), None) => Some(x),
        (None, y) => y,
    }
}

fn extract(hir: &Hir) -> Option<Vec<Vec<u8>>> {
    match hir.kind() {
        HirKind::Literal(l) => Some(vec![l.0.to_vec()]),
        HirKind::Class(c) => single_byte(c).map(|b| vec![vec![b]]),
        HirKind::Capture(c) => extract(&c.sub),
        HirKind::Repetition(r) if r.min >= 1 => extract(&r.sub),
        HirKind::Concat(subs) => {
            // Adjacent literals (and single-byte classes, which `(?i)` produces)
            // concatenate into one required run.
            let mut best: Option<Vec<Vec<u8>>> = None;
            let mut run: Vec<u8> = Vec::new();
            for s in subs {
                let byte = match s.kind() {
                    HirKind::Literal(l) => {
                        run.extend_from_slice(&l.0);
                        continue;
                    }
                    HirKind::Class(c) => single_byte(c),
                    _ => None,
                };
                if let Some(b) = byte {
                    run.push(b);
                    continue;
                }
                if !run.is_empty() {
                    best = better(best, Some(vec![std::mem::take(&mut run)]));
                }
                best = better(best, extract(s));
            }
            if !run.is_empty() {
                best = better(best, Some(vec![run]));
            }
            best
        }
        HirKind::Alternation(subs) => {
            // Every branch must contribute, else the union is not required.
            let mut union = Vec::new();
            for s in subs {
                union.extend(extract(s)?);
            }
            Some(union)
        }
        _ => None,
    }
}

/// A class matching exactly one byte, or one ASCII letter in both cases
/// (what `(?i)literal` compiles to). Returned lowercased.
fn single_byte(c: &Class) -> Option<u8> {
    let mut chars: Vec<u32> = Vec::with_capacity(3);
    match c {
        Class::Unicode(u) => {
            for r in u.ranges() {
                let (s, e) = (r.start() as u32, r.end() as u32);
                if e - s > 1 {
                    return None;
                }
                for cp in s..=e {
                    if cp > 0x7f || chars.len() > 2 {
                        return None;
                    }
                    chars.push(cp);
                }
            }
        }
        Class::Bytes(b) => {
            for r in b.ranges() {
                let (s, e) = (r.start() as u32, r.end() as u32);
                if e - s > 1 {
                    return None;
                }
                for cp in s..=e {
                    if cp > 0x7f || chars.len() > 2 {
                        return None;
                    }
                    chars.push(cp);
                }
            }
        }
    }
    match chars.as_slice() {
        [a] => Some(*a as u8),
        [a, b] => {
            let (a, b) = (*a as u8, *b as u8);
            if a.to_ascii_lowercase() == b.to_ascii_lowercase() {
                Some(a.to_ascii_lowercase())
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lits(pat: &str) -> Option<Vec<String>> {
        required_literals(pat).map(|v| {
            v.into_iter()
                .map(|b| String::from_utf8(b).unwrap())
                .collect()
        })
    }

    #[test]
    fn extracts_literal_from_case_insensitive_pattern() {
        assert_eq!(lits("(?i)apikey[:]"), Some(vec!["apikey:".to_string()]));
    }

    #[test]
    fn extracts_every_alternation_branch() {
        let got = lits("(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}").unwrap();
        assert_eq!(got, vec!["a3t", "akia", "asia"]);
    }

    #[test]
    fn rejects_alternation_with_short_branch() {
        // "fb" is too short to prefilter on, so the whole rule must always run.
        assert_eq!(lits("(facebook|fb)(.{0,20})?['\"][0-9a-f]{32}['\"]"), None);
    }

    #[test]
    fn ignores_optional_literals() {
        // The literal inside a `{0,n}` repetition is not required.
        assert_eq!(lits("(secret)?[0-9a-f]{32}"), None);
    }

    #[test]
    fn prefilter_prunes_and_resets_scratch() {
        let set = RuleSet::load(&Kind::ALL, 0).unwrap();
        let mut seen = vec![false; set.len()];
        let mut cand = Vec::new();

        set.candidates(b"nothing to see here", &mut seen, &mut cand);
        assert!(
            cand.len() < set.len() / 10,
            "innocuous text should prune nearly every rule, got {}/{}",
            cand.len(),
            set.len()
        );
        assert!(seen.iter().all(|s| !s), "scratch state must be reset");

        set.candidates(b"aws_secret_access_key = x", &mut seen, &mut cand);
        let titles: Vec<&str> = cand
            .iter()
            .map(|&i| set.rules[i as usize].title.as_str())
            .collect();
        assert!(
            titles.iter().any(|t| t.contains("aws_secret_access_key")),
            "got {titles:?}"
        );
        assert!(seen.iter().all(|s| !s));
    }
}
