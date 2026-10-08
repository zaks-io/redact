pub mod parser;
pub mod policy;
pub mod render;

use crate::cli::{CommandKind, parse_arguments_for};
use crate::error::{ErrorKind, SafeError};
use crate::secret::SecretString;
use clap::Parser;
use policy::{Policy, Source, State, disclose};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::io::{Read, Write};

pub const MAX_FILE_BYTES: usize = 16_777_216;

#[derive(Parser)]
#[command(
    name = "rprintenv",
    bin_name = "rprintenv",
    version,
    about = "Inspect environment variables and explicit .env files with hidden values",
    after_help = "Fingerprints are stable across runs, files, names, and machines. Compare them for likely equal values; truncated fingerprints are not proof of equality. Fingerprints permit guessing weak values and are not encryption.\n\nMissing and empty are different. --exists includes empty values; --json NAME reports configuration state. Populated values do not establish provider authentication success. Select explicit sources to compare actual configuration.\n\n--allow prints full values that may enter logs and chat history. --redact always wins. Files use the documented literal dotenv dialect without interpolation or shell execution."
)]
struct Arguments {
    /// Include the current process environment alongside files
    #[arg(long = "env")]
    environment: bool,
    /// Read this explicit UTF-8 .env file; repeatable, never stdin
    #[arg(long, value_name = "PATH")]
    file: Vec<String>,
    /// Reveal the full value of this exact variable name
    #[arg(long, value_name = "NAME")]
    allow: Vec<String>,
    /// Keep this exact variable name hidden, overriding --allow
    #[arg(long, value_name = "NAME")]
    redact: Vec<String>,
    /// Check that every requested name exists in every source, including empty values
    #[arg(long)]
    exists: bool,
    /// Emit schema_version 2 JSON instead of text records
    #[arg(long)]
    json: bool,
    /// Exact case-sensitive variable names; omit to list each selected source
    #[arg(value_name = "NAME")]
    names: Vec<String>,
}

#[derive(Debug)]
pub struct Failure {
    pub source: Option<Source>,
    pub error: SafeError,
}

impl From<SafeError> for Failure {
    fn from(error: SafeError) -> Self {
        Self {
            source: None,
            error,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(source) = &self.source {
            let label = match source {
                Source::Environment => "environment",
                Source::File { path } => path,
            };
            let escaped = serde_json::to_string(label).map_err(|_| fmt::Error)?;
            write!(formatter, "{escaped}: ")?;
        }
        self.error.fmt(formatter)
    }
}

impl std::error::Error for Failure {}

fn environment_snapshot(
    entries: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<BTreeMap<String, SecretString>, SafeError> {
    entries
        .into_iter()
        .map(|(name, value)| {
            let name = name
                .into_string()
                .map_err(|_| {
                    SafeError::new(
                        "environment contains a non-UTF-8 variable name. Supply UTF-8 environment names and retry.",
                    )
                })?;
            let value = value
                .into_string()
                .map_err(|_| {
                    SafeError::new(
                        "environment contains a non-UTF-8 variable value. Supply UTF-8 environment values and retry.",
                    )
                })?;
            Ok((name, SecretString::new(value)))
        })
        .collect()
}

pub fn run(
    args: impl IntoIterator<Item = OsString>,
    output: &mut impl Write,
) -> Result<u8, Failure> {
    let Some(args) = parse_arguments_for::<Arguments>(args, output, CommandKind::Rprintenv)? else {
        return Ok(0);
    };
    validate_arguments(&args)?;
    let mut sources = Vec::new();
    if args.environment || args.file.is_empty() {
        let source = Source::Environment;
        let entries = environment_snapshot(std::env::vars_os()).map_err(|error| Failure {
            source: Some(source.clone()),
            error,
        })?;
        sources.push((source, entries));
    }
    for path in args.file {
        let source = Source::File { path: path.clone() };
        let contents = read_file(&path).map_err(|error| Failure {
            source: Some(source.clone()),
            error,
        })?;
        let entries = parser::parse_dotenv(&contents).map_err(|error| Failure {
            source: Some(source.clone()),
            error,
        })?;
        sources.push((source, entries));
    }
    let names: BTreeSet<_> = args.names.into_iter().collect();
    let policy = Policy {
        allow: args.allow.into_iter().collect(),
        redact: args.redact.into_iter().collect(),
    };
    let mut records = Vec::new();
    let mut missing = false;
    for (source, entries) in sources {
        let selected: Vec<_> = if names.is_empty() {
            entries.keys().collect()
        } else {
            names.iter().collect()
        };
        for name in selected {
            let record = disclose(source.clone(), name.clone(), entries.get(name), &policy);
            missing |= matches!(record.state, State::Missing);
            if !args.exists {
                records.push(record);
            }
        }
    }
    if !args.exists {
        render::render(&records, args.json, output)?;
    }
    Ok(u8::from(missing))
}

fn read_file(path: &str) -> Result<Vec<u8>, SafeError> {
    let metadata = std::fs::metadata(path).map_err(file_read_error)?;
    if !metadata.is_file() {
        return Err(SafeError::new(ErrorKind::SourceNotRegular));
    }
    let file = std::fs::File::open(path).map_err(file_read_error)?;
    if !file.metadata().map_err(file_read_error)?.is_file() {
        return Err(SafeError::new(ErrorKind::SourceNotRegular));
    }
    let mut bytes = Vec::new();
    file.take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(file_read_error)?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(SafeError::new(
            "file exceeds 16 MiB. Supply a smaller .env file and retry.",
        ));
    }
    Ok(bytes)
}

fn file_read_error(error: std::io::Error) -> SafeError {
    match error.kind() {
        std::io::ErrorKind::NotFound => SafeError::new(ErrorKind::SourceNotFound),
        std::io::ErrorKind::PermissionDenied => SafeError::new(ErrorKind::SourcePermissionDenied),
        _ => SafeError::new(
            "file read failed. Check the explicit path and read permissions, then retry.",
        ),
    }
}

fn validate_arguments(args: &Arguments) -> Result<(), SafeError> {
    let message = if args.exists && args.names.is_empty() {
        Some(
            "--exists requires at least one NAME. Use rprintenv --exists NAME [NAME...] to check presence, including empty values. Use --help for supported syntax.",
        )
    } else if args.exists && args.json {
        Some(
            "--exists cannot be combined with --json because presence checks write no records. Remove --json for an exit-status check, or remove --exists for state records. Use --help for supported syntax.",
        )
    } else if args.exists && (!args.allow.is_empty() || !args.redact.is_empty()) {
        Some(
            "--exists cannot be combined with --allow or --redact because presence checks write no values. Remove disclosure flags, or remove --exists to inspect values. Use --help for supported syntax.",
        )
    } else if args.file.iter().any(|path| path == "-") {
        Some(
            "--file - is unsupported because rprintenv does not read stdin. Supply --file PATH for an explicit .env file, or use rstr to filter piped text. Use --help for supported syntax.",
        )
    } else if args.file.iter().collect::<BTreeSet<_>>().len() != args.file.len() {
        Some(
            "duplicate --file source. Supply each explicit path once to inspect or compare sources. Use --help for supported syntax.",
        )
    } else {
        None
    };
    match message {
        Some(message) => Err(SafeError::new(message)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_io_diagnostics_are_discarded() {
        for (kind, expected) in [
            (std::io::ErrorKind::NotFound, ErrorKind::SourceNotFound),
            (
                std::io::ErrorKind::PermissionDenied,
                ErrorKind::SourcePermissionDenied,
            ),
            (
                std::io::ErrorKind::Other,
                ErrorKind::Category(
                    "file read failed. Check the explicit path and read permissions, then retry.",
                ),
            ),
        ] {
            let error = file_read_error(std::io::Error::new(
                kind,
                "synthetic-secret-nested-io-canary-1849",
            ));
            assert_eq!(error.kind, expected);
            assert!(std::error::Error::source(&error).is_none());
            assert!(
                !error
                    .to_string()
                    .contains("synthetic-secret-nested-io-canary-1849")
            );
            assert!(
                !format!("{:?}", Some(vec![error]))
                    .contains("synthetic-secret-nested-io-canary-1849")
            );
        }
    }

    #[test]
    fn failures_escape_source_paths_to_one_line() {
        let Err(error) = parser::parse_dotenv(b"A=one\n#comment\nA=two\n") else {
            panic!("duplicate accepted")
        };
        let failure = Failure {
            source: Some(Source::File {
                path: "synthetic\n.env".to_owned(),
            }),
            error,
        };
        assert_eq!(
            failure.to_string(),
            "\"synthetic\\n.env\": line 3: previous definition on line 1: \
             duplicate variable name. Keep one definition per source and retry."
        );
    }
}
