**Secrets detection on local disk: API keys, private keys, BIP39 mnemonics.**

Rewritten in Rust. 761 regex rules behind an Aho-Corasick literal prefilter,
one worker per core, mmap'd reads. On a 27 MB / 2000-file tree: **0.22 s**
(226 MB/s) versus **23.6 s** for the Go version — 107x, identical findings.
A full 26 GB / 1.55 M-file home directory scans in **3.4 minutes**.

### Install
```bash
cargo install --path .
```

### Use
```bash
~ leakin ~/projects
~/projects/.env:1:19 [api-key sev6] AWS Client ID AKIAIOSFODNN7EXAMPLE
~/projects/wallet.txt:2:11 [mnemonic sev10] BIP39 mnemonic (12 words, checksum valid) abandon abandon … about
~/projects/.ssh/id_rsa:1:1 [private-key sev10] PEM private key block -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx4f…
```

Every finding carries `path:line:col`, the detector kind, a severity, the rule
name, and the matched string. Exit status is `0` clean, `1` findings, `2` error.

```bash
leakin -f ~/projects -o leaks.json --format json   # -f folder, -o output file
leakin ~/ --only mnemonic,private-key              # wallet material only
leakin . --min-severity 8 --redact                 # high signal, secrets masked
cat suspect.log | leakin -                         # read stdin
leakin --check-mnemonic "word1 word2 … word12"     # validate one word list
```

### Detectors

| kind | what |
|---|---|
| `private-key` | PEM/OpenSSH/PGP/PuTTY blocks, age keys, base58check-validated Bitcoin WIF and BIP32 `xprv`, raw 32-byte hex in a secret context |
| `mnemonic` | BIP39 phrases (12/15/18/21/24 words) with a **verified checksum** |
| `api-key` `token` `password` `generic` | 761 vendor and keyword rules, incl. modern prefixed tokens (`ghp_`, `github_pat_`, `glpat-`, `sk-ant-`, `hf_`, `npm_`, `xoxb-`, `dp.pt.`, `glsa_`); keyword rules capture the value, not just the name |
| `endpoint` | cloud hostnames and bucket URLs — asset inventory, **off by default** (`--only endpoint`) |

### Is this list of words a mnemonic?

```bash
$ leakin --check-mnemonic "absurd avoid scissors anxiety gather lottery category door army half long camera"
VALID: 12-word BIP39 mnemonic, checksum verified          # exit 0
$ leakin --check-mnemonic "absurd avoid scissors anxiety gather lottery category door army half long zoo"
INVALID: 12 BIP39 words but the checksum does not verify  # exit 1
$ leakin --check-mnemonic "absurd avoid xyzzy anxiety …"
INVALID: 1 word(s) are not in the BIP39 English list: #3 'xyzzy'
$ leakin --check-mnemonic "abandon about legal winner"
INVALID: 4 words; BIP39 allows 12, 15, 18, 21 or 24
```

Word-list membership alone is worthless as a signal, so a scanned phrase must
clear four gates: every word in the BIP39 English list, a valid length, a
**verified SHA-256 checksum**, and phrase-shaped context — whitespace
separators (not `["color","left"]` token streams), an unbroken run of at most
28 words (not a dictionary), and no word repeated more than three times (not
`very very very …`). Those four gates cut mnemonic hits on a real 26 GB home
directory from 2 551 to 499, all of which are genuine valid phrases in
crypto-library fixtures and logs. Findings enclosed by a private-key block are
suppressed, so base64 key bodies don't masquerade as vendor keys.

Measured on 22.6 MB of third-party Rust sources: **0 findings** — no false
positives at default settings. Rules that fired only on non-secrets across a
real 26 GB home directory were tightened or deleted (loose `github`/`facebook`
hash shapes, `6L`-prefixed reCAPTCHA keys, `ASIA`-prefixed base64, unescaped
`SG.` dots), cutting total findings from 97 733 to 20 164 with no loss of true
positives.

### Scanning behaviour

Hidden files and `.gitignore`d paths **are** scanned by default: `.env`,
`~/.aws/credentials`, and `~/.ssh/id_rsa` are exactly where secrets live. Files
containing NUL in their first 8 KB are skipped as binary.

```
--respect-ignore     honour .gitignore/.ignore
--no-hidden          skip dotfiles
--exclude GLOB       skip paths (repeatable)
--binary             scan binary files too
--max-size BYTES     skip larger files (default 32 MiB)
-j, --threads N      workers (default: one per core)
--loose-mnemonic     also report checksum-invalid word runs
--max-match N        truncate reported secrets (default 240 bytes)
--stats              throughput and rule counts on stderr
--check-mnemonic P   validate one word list and exit (no scan)
```

### Rules

`rules.json` is embedded at build time. Each entry is
`{id, title, kind, severity, regex}`, RE2 syntax, ASCII semantics. A rule
whose pattern has a required literal of 3+ bytes is dispatched by the
prefilter; the 7 that don't are run against every file.

### License
MIT
