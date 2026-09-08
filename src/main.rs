//! leakin — fast local-disk secret detection.

mod keys;
mod mnemonic;
mod output;
mod rules;
mod scan;
mod walk;

use std::io::{self, BufWriter, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use clap::Parser;
use parking_lot::Mutex;

use mnemonic::Verdict;
use output::{Format, Sink};
use rules::Kind;
use scan::{Options, Scanner};

/// Secrets detection on local disk: API keys, private keys, BIP39 mnemonics.
#[derive(Parser)]
#[command(name = "leakin", version, about, long_about = None)]
struct Cli {
    /// Files or directories to scan ("-" reads stdin).
    #[arg(value_name = "PATH", default_value = ".")]
    paths: Vec<PathBuf>,

    /// Folder (or file) to scan; repeatable. Same as a positional PATH.
    #[arg(short = 'f', long = "folder", alias = "path", value_name = "FOLDER")]
    extra_paths: Vec<PathBuf>,

    /// Write findings to this file instead of stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Output format: text, json, jsonl, csv.
    #[arg(long, default_value = "text", value_name = "FMT")]
    format: String,

    /// Only these detector kinds (api-key, token, password, private-key,
    /// mnemonic, endpoint, generic).
    #[arg(long, value_name = "KINDS", value_delimiter = ',')]
    only: Vec<String>,

    /// Skip these detector kinds.
    #[arg(long, value_name = "KINDS", value_delimiter = ',')]
    skip: Vec<String>,

    /// Drop findings below this severity (1-10).
    #[arg(long, default_value_t = 0, value_name = "N")]
    min_severity: u8,

    /// Worker threads (0 = one per core).
    #[arg(short = 'j', long, default_value_t = 0, value_name = "N")]
    threads: usize,

    /// Mask the middle of every reported secret.
    #[arg(long)]
    redact: bool,

    /// Report BIP39 word runs whose checksum does not verify.
    #[arg(long)]
    loose_mnemonic: bool,

    /// Validate one word list instead of scanning: reports whether it is a
    /// BIP39 mnemonic and why not. Use "-" to read the phrase from stdin.
    #[arg(long, value_name = "PHRASE")]
    check_mnemonic: Option<String>,

    /// Skip files larger than this many bytes.
    #[arg(long, default_value_t = 32 << 20, value_name = "BYTES")]
    max_size: u64,

    /// Truncate each reported secret to this many bytes.
    #[arg(long, default_value_t = 240, value_name = "N")]
    max_match: usize,

    /// Scan binary files too (default: skip files containing NUL).
    #[arg(long)]
    binary: bool,

    /// Honour .gitignore/.ignore files (default: scan everything).
    #[arg(long)]
    respect_ignore: bool,

    /// Skip hidden files and directories.
    #[arg(long)]
    no_hidden: bool,

    /// Exclude paths matching a glob (repeatable).
    #[arg(long, value_name = "GLOB")]
    exclude: Vec<String>,

    /// Never colourise output.
    #[arg(long)]
    no_color: bool,

    /// Print scan statistics to stderr.
    #[arg(long)]
    stats: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(found) => {
            if found {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("leakin: {e}");
            ExitCode::from(2)
        }
    }
}

fn kinds(only: &[String], skip: &[String]) -> Result<Vec<Kind>, String> {
    let parse = |v: &[String]| -> Result<Vec<Kind>, String> {
        v.iter()
            .filter(|s| !s.is_empty())
            .map(|s| Kind::parse(s).ok_or_else(|| format!("unknown kind '{s}'")))
            .collect()
    };
    let mut set = if only.is_empty() {
        // `endpoint` matches are cloud-asset inventory (hostnames, bucket
        // URLs), not secrets: thousands of hits on any real tree. Opt in with
        // `--only endpoint`.
        Kind::ALL
            .into_iter()
            .filter(|k| *k != Kind::Endpoint)
            .collect()
    } else {
        parse(only)?
    };
    let drop = parse(skip)?;
    set.retain(|k| !drop.contains(k));
    if set.is_empty() {
        return Err("no detector kinds selected".into());
    }
    Ok(set)
}

/// `--check-mnemonic`: validate one word list. Returns `true` (exit 1) when
/// the phrase is NOT a valid mnemonic, so it composes with shell `&&`.
fn check_mnemonic(phrase: &str) -> Result<bool, String> {
    let phrase = if phrase == "-" {
        let mut s = String::new();
        io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("stdin: {e}"))?;
        s
    } else {
        phrase.to_string()
    };

    match mnemonic::Bip39::new(true).check(&phrase) {
        Verdict::Valid { words } => {
            println!("VALID: {words}-word BIP39 mnemonic, checksum verified");
            Ok(false)
        }
        Verdict::BadChecksum { words } => {
            println!(
                "INVALID: {words} BIP39 words but the checksum does not verify \
                 (typo, wrong order, or not a real phrase)"
            );
            Ok(true)
        }
        Verdict::UnknownWords(bad) => {
            let list: Vec<String> = bad
                .iter()
                .take(8)
                .map(|(i, w)| format!("#{i} '{w}'"))
                .collect();
            println!(
                "INVALID: {} word(s) are not in the BIP39 English list: {}",
                bad.len(),
                list.join(", ")
            );
            Ok(true)
        }
        Verdict::BadLength(n) => {
            println!("INVALID: {n} words; BIP39 allows 12, 15, 18, 21 or 24");
            Ok(true)
        }
    }
}

fn run() -> Result<bool, String> {
    let cli = Cli::parse();
    let fmt = Format::parse(&cli.format).ok_or_else(|| format!("bad format '{}'", cli.format))?;

    if let Some(phrase) = &cli.check_mnemonic {
        return check_mnemonic(phrase);
    }

    let scanner = Scanner::new(Options {
        kinds: kinds(&cli.only, &cli.skip)?,
        min_severity: cli.min_severity,
        redact: cli.redact,
        max_match: cli.max_match.max(8),
        mnemonic_checksum: !cli.loose_mnemonic,
    })?;

    let (out, to_file): (Box<dyn Write + Send>, bool) = match &cli.output {
        Some(p) => (
            Box::new(BufWriter::new(std::fs::File::create(p).map_err(|e| {
                format!("cannot write {}: {e}", p.display())
            })?)),
            true,
        ),
        None => (Box::new(BufWriter::new(io::stdout())), false),
    };
    let color = !cli.no_color
        && !to_file
        && std::env::var_os("NO_COLOR").is_none()
        && io::stdout().is_terminal();
    let sink = Mutex::new(Sink::new(out, fmt, color));

    let mut paths: Vec<PathBuf> = cli.paths.clone();
    paths.extend(cli.extra_paths.iter().cloned());
    // A bare `-f DIR` must not also scan the default ".".
    if !cli.extra_paths.is_empty() && cli.paths == vec![PathBuf::from(".")] {
        paths.retain(|p| p != &PathBuf::from("."));
    }

    let files = AtomicU64::new(0);
    let bytes = AtomicU64::new(0);
    let skipped = AtomicU64::new(0);
    let started = Instant::now();

    let stdin_paths: Vec<&PathBuf> = paths.iter().filter(|p| p.as_os_str() == "-").collect();
    if !stdin_paths.is_empty() {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("stdin: {e}"))?;
        let mut scratch = scanner.scratch();
        let found = scanner.scan("<stdin>", &buf, &mut scratch);
        files.fetch_add(1, Ordering::Relaxed);
        bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
        sink.lock().write(&found).map_err(|e| e.to_string())?;
    }

    let disk: Vec<PathBuf> = paths
        .into_iter()
        .filter(|p| p.as_os_str() != "-")
        .collect();
    if !disk.is_empty() {
        walk::run(
            &disk,
            &walk::Config {
                threads: cli.threads,
                max_size: cli.max_size,
                binary: cli.binary,
                respect_ignore: cli.respect_ignore,
                hidden: !cli.no_hidden,
                exclude: cli.exclude.clone(),
            },
            &scanner,
            &mut |path, data, scratch| {
                files.fetch_add(1, Ordering::Relaxed);
                bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                let found = scanner.scan(path, data, scratch);
                if !found.is_empty() {
                    let _ = sink.lock().write(&found);
                }
            },
            &mut |_err| {
                skipped.fetch_add(1, Ordering::Relaxed);
            },
        )?;
    }

    let mut guard = sink.lock();
    guard.finish().map_err(|e| e.to_string())?;
    let count = guard.count;
    drop(guard);

    if cli.stats {
        let secs = started.elapsed().as_secs_f64();
        let mb = bytes.load(Ordering::Relaxed) as f64 / 1e6;
        eprintln!(
            "leakin: {} findings | {} files, {:.1} MB in {:.2}s ({:.0} MB/s) | {} rules ({} unfiltered) | {} unreadable",
            count,
            files.load(Ordering::Relaxed),
            mb,
            secs,
            mb / secs.max(1e-9),
            scanner.rules(),
            scanner.always_run(),
            skipped.load(Ordering::Relaxed),
        );
    }
    Ok(count > 0)
}
