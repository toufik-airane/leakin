//! BIP39 mnemonic detection.
//!
//! Word-list membership alone is far too weak on real disks (any English prose
//! contains runs of BIP39 words), so a candidate is only reported when its
//! BIP39 checksum verifies. That drops 15/16 of accidental 12-word runs and
//! 255/256 of 24-word runs.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

const WORDLIST: &str = include_str!("../bip39-english.txt");
/// BIP39 mnemonic lengths, longest first so the longest match wins.
const LENGTHS: [usize; 5] = [24, 21, 18, 15, 12];
const MAX_WORD: usize = 8;
const MIN_WORD: usize = 3;
/// A seed phrase is at most 24 words. Longer unbroken runs of word-list words
/// are dictionaries, minified token streams, or prose — never a backup. A few
/// words of slack absorbs labels ("seed", "wallet") that happen to be in the
/// list. Without this cap such files emit a checksum-valid window roughly
/// every 16 offsets, drowning real findings.
const MAX_RUN: usize = 28;

pub struct Bip39 {
    index: HashMap<&'static str, u16>,
    /// Report checksum-invalid candidates too (non-English or partial backups).
    pub require_checksum: bool,
}

pub struct Match {
    pub start: usize,
    pub end: usize,
    pub words: usize,
    pub checksum_ok: bool,
}

/// Why a candidate word list is, or is not, a BIP39 mnemonic.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Valid { words: usize },
    /// Right words, wrong checksum: a typo, a made-up phrase, or a wrong order.
    BadChecksum { words: usize },
    /// Words outside the BIP39 English list, with their 1-based positions.
    UnknownWords(Vec<(usize, String)>),
    /// BIP39 allows 12, 15, 18, 21 or 24 words only.
    BadLength(usize),
}

impl Bip39 {
    pub fn new(require_checksum: bool) -> Bip39 {
        let mut index = HashMap::with_capacity(2048);
        for (i, w) in WORDLIST.split_whitespace().enumerate() {
            index.insert(w, i as u16);
        }
        debug_assert_eq!(index.len(), 2048);
        Bip39 {
            index,
            require_checksum,
        }
    }

    /// Validate an explicit word list: membership, length, then checksum.
    pub fn check(&self, phrase: &str) -> Verdict {
        let words: Vec<String> = phrase
            .split(|c: char| !c.is_ascii_alphabetic())
            .filter(|w| !w.is_empty())
            .map(|w| w.to_ascii_lowercase())
            .collect();

        let mut unknown = Vec::new();
        let mut idx = Vec::with_capacity(words.len());
        for (i, w) in words.iter().enumerate() {
            match self.index.get(w.as_str()) {
                Some(n) => idx.push(*n),
                None => unknown.push((i + 1, w.clone())),
            }
        }
        if !unknown.is_empty() {
            return Verdict::UnknownWords(unknown);
        }
        if !LENGTHS.contains(&idx.len()) {
            return Verdict::BadLength(idx.len());
        }
        if checksum_valid(&idx) {
            Verdict::Valid { words: idx.len() }
        } else {
            Verdict::BadChecksum { words: idx.len() }
        }
    }

    /// Scan `data` for mnemonic phrases. Non-overlapping, longest-first.
    pub fn find(&self, data: &[u8]) -> Vec<Match> {
        let mut out = Vec::new();
        let mut run: Vec<(u16, usize, usize)> = Vec::new();
        let mut i = 0usize;
        let mut word = [0u8; MAX_WORD];

        while i <= data.len() {
            // Collect one alphabetic run.
            let start = i;
            let mut len = 0usize;
            while i < data.len() && data[i].is_ascii_alphabetic() {
                if len < MAX_WORD {
                    word[len] = data[i].to_ascii_lowercase();
                }
                len += 1;
                i += 1;
            }

            let mut hit = None;
            if (MIN_WORD..=MAX_WORD).contains(&len) {
                if let Ok(s) = std::str::from_utf8(&word[..len]) {
                    hit = self.index.get(s).copied();
                }
            }

            match hit {
                Some(idx) => run.push((idx, start, i)),
                None if len > 0 => {
                    self.flush(&run, &mut out);
                    run.clear();
                }
                _ => {}
            }

            // Separator run: mnemonics are whitespace/punctuation separated.
            // Anything else (digits, long gaps) breaks the phrase.
            let sep_start = i;
            while i < data.len() && !data[i].is_ascii_alphabetic() {
                i += 1;
            }
            if !run.is_empty() && !separator_ok(&data[sep_start..i]) {
                self.flush(&run, &mut out);
                run.clear();
            }
            if i == data.len() && sep_start == i && len == 0 {
                break;
            }
            if i == data.len() {
                break;
            }
        }
        self.flush(&run, &mut out);
        out
    }

    fn flush(&self, run: &[(u16, usize, usize)], out: &mut Vec<Match>) {
        if run.len() < LENGTHS[LENGTHS.len() - 1] || run.len() > MAX_RUN {
            return;
        }
        let mut pos = 0usize;
        while pos < run.len() {
            let mut advanced = false;
            for n in LENGTHS {
                if pos + n > run.len() {
                    continue;
                }
                let win = &run[pos..pos + n];
                let mut idx = [0u16; 24];
                for (k, w) in win.iter().enumerate() {
                    idx[k] = w.0;
                }
                let ok = checksum_valid(&idx[..n]);
                if !diverse(&idx[..n]) {
                    continue;
                }
                if ok || !self.require_checksum {
                    out.push(Match {
                        start: win[0].1,
                        end: win[n - 1].2,
                        words: n,
                        checksum_ok: ok,
                    });
                    pos += n;
                    advanced = true;
                    break;
                }
            }
            if !advanced {
                pos += 1;
            }
        }
    }
}

/// A generated phrase draws words independently from 2048, so more than three
/// copies of one word is astronomically unlikely (< 1e-6 for 24 words) and in
/// practice means repeated filler such as `very very very …`. Published test
/// vectors (`abandon` x11) are rejected by design: they are not live secrets.
fn diverse(words: &[u16]) -> bool {
    words
        .iter()
        .all(|w| words.iter().filter(|o| *o == w).count() <= 3)
}

/// Words of a written-down phrase are separated by whitespace, optionally with
/// a single comma. Minified JavaScript and JSON arrays separate identifiers
/// with quotes, colons, brackets and hyphens — `["color","left",…]` is a token
/// stream, not a backup, and those were the dominant false positive on a real
/// 26 GB home directory.
fn separator_ok(sep: &[u8]) -> bool {
    if sep.len() > 3 {
        return false;
    }
    let commas = sep.iter().filter(|b| **b == b',').count();
    commas <= 1
        && sep
            .iter()
            .all(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b','))
}

/// Verify the BIP39 checksum: the first `words*11/33` bits of
/// SHA-256(entropy) must equal the trailing bits of the index bit string.
fn checksum_valid(words: &[u16]) -> bool {
    let total = words.len() * 11;
    let cs_bits = total / 33;
    let ent_bits = total - cs_bits;
    if cs_bits == 0 || ent_bits % 8 != 0 || ent_bits / 8 > 32 {
        return false;
    }

    let mut bits = [0u8; 34];
    for (i, idx) in words.iter().enumerate() {
        let idx = *idx as u32;
        for b in 0..11 {
            if idx & (1 << (10 - b)) != 0 {
                let p = i * 11 + b;
                bits[p / 8] |= 0x80 >> (p % 8);
            }
        }
    }

    let ent = &bits[..ent_bits / 8];
    let hash = Sha256::digest(ent);
    // cs_bits <= 8, so the checksum is the top cs_bits of hash[0].
    let expect = hash[0] >> (8 - cs_bits);
    let mut actual = 0u8;
    for b in 0..cs_bits {
        let p = ent_bits + b;
        let bit = (bits[p / 8] >> (7 - (p % 8))) & 1;
        actual = (actual << 1) | bit;
    }
    actual == expect
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid phrases with realistic vocabulary (entropy 0x0102..).
    const V12: &str =
        "absurd avoid scissors anxiety gather lottery category door army half long camera";
    const V24: &str = "absurd avoid scissors anxiety gather lottery category door army half long cage bachelor another expect people blade school educate curtain scrub monitor lady beyond";
    /// The published all-`abandon` vector: valid checksum, no vocabulary.
    const FILLER: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn accepts_valid_vectors() {
        let d = Bip39::new(true);
        let m = d.find(V12.as_bytes());
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].words, 12);
        assert_eq!(&V12[m[0].start..m[0].end], V12);

        let m = d.find(V24.as_bytes());
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].words, 24);
    }

    #[test]
    fn rejects_checksum_failure() {
        // Same words, last one swapped: valid word list, invalid checksum.
        let bad = V12.replace("camera", "zoo");
        assert!(Bip39::new(true).find(bad.as_bytes()).is_empty());
        assert_eq!(Bip39::new(false).find(bad.as_bytes()).len(), 1);
    }

    #[test]
    fn finds_phrase_embedded_in_text_and_quotes() {
        let hay = format!("# backup\nseed=\"{V12}\"\nother stuff\n");
        let m = Bip39::new(true).find(hay.as_bytes());
        assert_eq!(m.len(), 1);
        assert_eq!(&hay[m[0].start..m[0].end], V12);
    }

    #[test]
    fn digits_break_a_phrase() {
        // A numbered list is not a phrase; each word is separated by digits.
        let numbered = V12
            .split(' ')
            .enumerate()
            .map(|(i, w)| format!("{}. {w}", i + 1))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(Bip39::new(true).find(numbered.as_bytes()).is_empty());
    }

    #[test]
    fn non_wordlist_prose_yields_nothing() {
        let prose = "the quick brown fox jumps over the lazy dog while nobody watches the sunset";
        assert!(Bip39::new(true).find(prose.as_bytes()).is_empty());
    }

    #[test]
    fn word_list_soup_is_not_a_phrase() {
        // A dictionary file yields a checksum-valid 12-word window roughly
        // every 16 offsets; none of them is a backup.
        let soup: String = WORDLIST.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(Bip39::new(true).find(soup.as_bytes()).is_empty());

        // A real phrase surrounded by prose still reports.
        let mixed = format!("notes about the wallet\n{V12}\nend of file\n");
        assert_eq!(Bip39::new(true).find(mixed.as_bytes()).len(), 1);
    }

    #[test]
    fn check_explains_each_rejection_reason() {
        let d = Bip39::new(true);
        assert_eq!(d.check(V12), Verdict::Valid { words: 12 });
        assert_eq!(d.check(V24), Verdict::Valid { words: 24 });
        // Case and punctuation are normalised, as in a pasted backup.
        assert_eq!(
            d.check(&V12.to_uppercase().replace(' ', ", ")),
            Verdict::Valid { words: 12 }
        );
        assert_eq!(
            d.check(&V12.replace("camera", "zoo")),
            Verdict::BadChecksum { words: 12 }
        );
        assert_eq!(d.check("abandon about legal winner"), Verdict::BadLength(4));
        assert_eq!(
            d.check(&V12.replace("camera", "xyzzy")),
            Verdict::UnknownWords(vec![(12, "xyzzy".to_string())])
        );
        // `--check-mnemonic` validates what the user pasted, so the published
        // filler vector is still reported as a well-formed phrase.
        assert_eq!(d.check(FILLER), Verdict::Valid { words: 12 });
    }

    #[test]
    fn repeated_filler_words_are_not_a_phrase() {
        // "very very very …" appears in real test fixtures and minified code;
        // one window in sixteen has a valid checksum.
        let filler = "very ".repeat(20);
        assert!(Bip39::new(true).find(filler.as_bytes()).is_empty());
        // Same for the all-`abandon` published vector.
        assert!(Bip39::new(true).find(FILLER.as_bytes()).is_empty());
        // A generated phrase, which never repeats a word four times, reports.
        assert_eq!(Bip39::new(true).find(V12.as_bytes()).len(), 1);
    }
}
