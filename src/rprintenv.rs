pub mod parser;
pub mod policy;
pub mod render;

use crate::error::{ErrorKind, SafeError};
use crate::secret::SecretString;
use clap::Parser;
use policy::{Policy, Source, State, disclose};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::io::Write;

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
    /// Emit schema_version 1 JSON instead of text records
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

pub fn environment_snapshot(
    entries: impl IntoIterator<Item = (OsString, OsString)>,
) -> Result<BTreeMap<String, SecretString>, SafeError> {
    entries
        .into_iter()
        .map(|(name, value)| {
            let name = name
                .into_string()
                .map_err(|_| SafeError::new(ErrorKind::Encoding))?;
            let value = value
                .into_string()
                .map_err(|_| SafeError::new(ErrorKind::Encoding))?;
            Ok((name, SecretString::new(value)))
        })
        .collect()
}

pub fn run(
    args: impl IntoIterator<Item = OsString>,
    output: &mut impl Write,
) -> Result<u8, Failure> {
    let args = match Arguments::try_parse_from(args) {
        Ok(args) => args,
        Err(error) => match error.kind() {
            clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                output
                    .write_all(error.to_string().as_bytes())
                    .and_then(|()| output.flush())
                    .map_err(|_| SafeError::new(ErrorKind::Output))?;
                return Ok(0);
            }
            _ => return Err(SafeError::new(ErrorKind::Usage).into()),
        },
    };
    if (args.exists
        && (args.names.is_empty()
            || args.json
            || !args.allow.is_empty()
            || !args.redact.is_empty()))
        || args.file.iter().any(|path| path == "-")
        || args.file.iter().collect::<BTreeSet<_>>().len() != args.file.len()
    {
        return Err(SafeError::new(ErrorKind::Usage).into());
    }
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
        let contents = std::fs::read(&path).map_err(|_| Failure {
            source: Some(source.clone()),
            error: SafeError::new(ErrorKind::Input),
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
