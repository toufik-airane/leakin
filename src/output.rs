//! Finding output: text, JSON, JSON Lines, CSV — to stdout or a file.

use std::io::{self, Write};

use crate::scan::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Jsonl,
    Csv,
}

impl Format {
    pub fn parse(s: &str) -> Option<Format> {
        Some(match s.to_ascii_lowercase().as_str() {
            "text" | "txt" => Format::Text,
            "json" => Format::Json,
            "jsonl" | "ndjson" => Format::Jsonl,
            "csv" => Format::Csv,
            _ => return None,
        })
    }
}

pub struct Sink {
    out: Box<dyn Write + Send>,
    fmt: Format,
    color: bool,
    started: bool,
    pub count: u64,
}

const CYAN: &str = "\x1b[36m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

impl Sink {
    pub fn new(out: Box<dyn Write + Send>, fmt: Format, color: bool) -> Sink {
        Sink {
            out,
            fmt,
            color,
            started: false,
            count: 0,
        }
    }

    pub fn write(&mut self, findings: &[Finding]) -> io::Result<()> {
        for f in findings {
            match self.fmt {
                Format::Text => self.text(f)?,
                Format::Json => {
                    if !self.started {
                        self.out.write_all(b"[\n")?;
                    } else {
                        self.out.write_all(b",\n")?;
                    }
                    self.json(f)?;
                }
                Format::Jsonl => {
                    self.json(f)?;
                    self.out.write_all(b"\n")?;
                }
                Format::Csv => {
                    if !self.started {
                        self.out
                            .write_all(b"path,line,col,offset,kind,severity,rule,secret\n")?;
                    }
                    self.csv(f)?;
                }
            }
            self.started = true;
            self.count += 1;
        }
        Ok(())
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if self.fmt == Format::Json {
            if self.started {
                self.out.write_all(b"\n]\n")?;
            } else {
                self.out.write_all(b"[]\n")?;
            }
        }
        self.out.flush()
    }

    fn text(&mut self, f: &Finding) -> io::Result<()> {
        if self.color {
            let sev = if f.severity >= 8 { RED } else { YELLOW };
            write!(
                self.out,
                "{CYAN}{}{RESET}{DIM}:{}:{}{RESET} {sev}[{} sev{}]{RESET} {BOLD}{}{RESET} {RED}{}{RESET}\n",
                f.path, f.line, f.col, f.kind.as_str(), f.severity, f.rule, f.secret
            )
        } else {
            writeln!(
                self.out,
                "{}:{}:{} [{} sev{}] {} {}",
                f.path,
                f.line,
                f.col,
                f.kind.as_str(),
                f.severity,
                f.rule,
                f.secret
            )
        }
    }

    fn json(&mut self, f: &Finding) -> io::Result<()> {
        let v = serde_json::json!({
            "path": f.path,
            "line": f.line,
            "col": f.col,
            "offset": f.offset,
            "kind": f.kind.as_str(),
            "severity": f.severity,
            "rule": f.rule,
            "secret": f.secret,
        });
        serde_json::to_writer(&mut self.out, &v).map_err(io::Error::other)
    }

    fn csv(&mut self, f: &Finding) -> io::Result<()> {
        writeln!(
            self.out,
            "{},{},{},{},{},{},{},{}",
            csv_field(&f.path),
            f.line,
            f.col,
            f.offset,
            f.kind.as_str(),
            f.severity,
            csv_field(&f.rule),
            csv_field(&f.secret)
        )
    }
}

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Kind;
    use parking_lot::Mutex;
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn finding(secret: &str) -> Finding {
        Finding {
            path: "a,b.txt".into(),
            line: 3,
            col: 7,
            offset: 42,
            rule: "AWS Client ID".into(),
            kind: Kind::ApiKey,
            severity: 6,
            secret: secret.into(),
        }
    }

    fn emit(fmt: Format, fs: &[Finding]) -> String {
        let buf = Buf::default();
        let mut sink = Sink::new(Box::new(buf.clone()), fmt, false);
        sink.write(fs).unwrap();
        sink.finish().unwrap();
        let bytes = buf.0.lock().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn text_line_is_editor_jumpable() {
        assert_eq!(
            emit(Format::Text, &[finding("AKIA...")]),
            "a,b.txt:3:7 [api-key sev6] AWS Client ID AKIA...\n"
        );
    }

    #[test]
    fn json_output_is_a_valid_array() {
        let out = emit(Format::Json, &[finding("s1"), finding("s2")]);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);
        assert_eq!(v[0]["line"], 3);
        assert_eq!(v[1]["secret"], "s2");
    }

    #[test]
    fn empty_json_run_still_parses() {
        let v: serde_json::Value = serde_json::from_str(&emit(Format::Json, &[])).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 0);
    }

    #[test]
    fn csv_quotes_commas_and_quotes() {
        let out = emit(Format::Csv, &[finding("a\"b,c")]);
        let last = out.lines().nth(1).unwrap();
        assert!(last.starts_with("\"a,b.txt\",3,7,42,api-key,6,"));
        assert!(last.ends_with("\"a\"\"b,c\""));
    }
}
