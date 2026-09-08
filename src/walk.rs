//! Parallel filesystem traversal: one worker per core, mmap for large files,
//! binary and size gating.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use ignore::overrides::OverrideBuilder;
use ignore::{WalkBuilder, WalkState};
use memmap2::Mmap;

use crate::scan::{Scanner, Scratch};

/// Above this size, map instead of read: no copy, no big allocation.
const MMAP_THRESHOLD: u64 = 64 * 1024;
/// Bytes inspected when deciding whether a file is binary.
const SNIFF: usize = 8192;

pub struct Config {
    pub threads: usize,
    pub max_size: u64,
    pub binary: bool,
    pub respect_ignore: bool,
    pub hidden: bool,
    pub exclude: Vec<String>,
}

enum Body {
    Map(Mmap),
    Buf(Vec<u8>),
}

impl Body {
    fn bytes(&self) -> &[u8] {
        match self {
            Body::Map(m) => m,
            Body::Buf(b) => b,
        }
    }
}

pub fn run(
    paths: &[PathBuf],
    cfg: &Config,
    scanner: &Scanner,
    on_file: &(dyn Fn(&str, &[u8], &mut Scratch) + Send + Sync),
    on_error: &(dyn Fn(&str) + Send + Sync),
) -> Result<(), String> {
    let Some((first, rest)) = paths.split_first() else {
        return Ok(());
    };

    let mut builder = WalkBuilder::new(first);
    for p in rest {
        builder.add(p);
    }
    builder
        // Secrets live in dotfiles (.env, .aws/credentials, .ssh/id_rsa) and in
        // ignored build output, so ignore files are NOT honoured by default.
        .hidden(!cfg.hidden)
        .git_ignore(cfg.respect_ignore)
        .git_global(cfg.respect_ignore)
        .git_exclude(cfg.respect_ignore)
        .ignore(cfg.respect_ignore)
        .parents(cfg.respect_ignore)
        .follow_links(false);
    if cfg.threads > 0 {
        builder.threads(cfg.threads);
    }
    if !cfg.exclude.is_empty() {
        let mut ov = OverrideBuilder::new(".");
        for glob in &cfg.exclude {
            ov.add(&format!("!{glob}"))
                .map_err(|e| format!("bad --exclude '{glob}': {e}"))?;
        }
        builder.overrides(ov.build().map_err(|e| e.to_string())?);
    }

    builder.build_parallel().run(|| {
        let mut scratch = scanner.scratch();
        Box::new(move |entry| {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    on_error(&e.to_string());
                    return WalkState::Continue;
                }
            };
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                return WalkState::Continue;
            }
            let path = entry.path();
            let size = match entry.metadata() {
                Ok(m) => m.len(),
                Err(e) => {
                    on_error(&format!("{}: {e}", path.display()));
                    return WalkState::Continue;
                }
            };
            if size == 0 || size > cfg.max_size {
                return WalkState::Continue;
            }
            match load(path, size) {
                Ok(body) => {
                    let data = body.bytes();
                    if !cfg.binary && is_binary(data) {
                        return WalkState::Continue;
                    }
                    on_file(&path.to_string_lossy(), data, &mut scratch);
                }
                Err(e) => on_error(&format!("{}: {e}", path.display())),
            }
            WalkState::Continue
        })
    });

    Ok(())
}

fn load(path: &Path, size: u64) -> std::io::Result<Body> {
    let mut file = File::open(path)?;
    if size >= MMAP_THRESHOLD {
        // Safety: the file may be truncated concurrently, which can fault on
        // access. Accepted for a read-only scanner, as with ripgrep.
        if let Ok(map) = unsafe { Mmap::map(&file) } {
            return Ok(Body::Map(map));
        }
    }
    let mut buf = Vec::with_capacity(size as usize);
    file.read_to_end(&mut buf)?;
    Ok(Body::Buf(buf))
}

fn is_binary(data: &[u8]) -> bool {
    memchr::memchr(0, &data[..data.len().min(SNIFF)]).is_some()
}
