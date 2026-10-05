use clap::{Parser, error::ErrorKind};
use redact::{
    dotenv,
    environment::{self, Options, RawVariables, Snapshot, Source, State},
    error::SafeError,
};
use std::collections::BTreeSet;
use std::io::{self, Read, Write};

const MAX_FILE_BYTES: usize = 16_777_216;

#[derive(Parser)]
#[command(
    version,
    about = "Inspect explicit environment sources with hidden-by-default values.",
    after_help = "Fingerprints are stable across runs, files, names, and machines. Compare truncated fingerprints for likely equal values, never for authentication. They permit guessing weak values and are not encryption.\n\nMissing and empty differ. --exists includes empty values; use --json NAME to inspect configuration state. Populated values do not establish provider authentication success. Inspect explicit sources to compare the actual configuration.\n\n--allow prints full values that may enter logs and chat history. Files use a literal dotenv dialect with no interpolation or shell execution. Errors describe safe recovery without raw input."
)]
struct Arguments {
    #[arg(long = "env", help = "Include the current process environment")]
    environment: bool,
    #[arg(
        long,
        value_name = "PATH",
        help = "Read an explicit .env file; repeatable"
    )]
    file: Vec<String>,
    #[arg(
        long,
        value_name = "NAME",
        help = "Reveal the complete value for an exact name; repeatable"
    )]
    allow: Vec<String>,
    #[arg(
        long,
        value_name = "NAME",
        help = "Force an exact name to remain hidden; repeatable"
    )]
    redact: Vec<String>,
    #[arg(long, help = "Check presence, including empty values, without output")]
    exists: bool,
    #[arg(long, help = "Emit the versioned JSON format")]
    json: bool,
    #[arg(value_name = "NAME", help = "Select exact, case-sensitive names")]
    names: Vec<String>,
}

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "rprintenv: {error}");
            2
        }
    };
    std::process::exit(i32::from(code));
}

fn run() -> Result<u8, SafeError> {
    let arguments = match Arguments::try_parse() {
        Ok(arguments) => arguments,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            io::stdout()
                .lock()
                .write_all(error.to_string().as_bytes())
                .map_err(|_| output_error())?;
            return Ok(0);
        }
        Err(_) => {
            return Err(SafeError::new(
                "invalid command arguments. Use --help for supported options.",
            ));
        }
    };
    if arguments.exists
        && (arguments.names.is_empty()
            || arguments.json
            || !arguments.allow.is_empty()
            || !arguments.redact.is_empty())
    {
        return Err(SafeError::new(
            "--exists requires names and cannot combine with output options. Use --help for supported options.",
        ));
    }
    let unique_files: BTreeSet<_> = arguments.file.iter().collect();
    if unique_files.len() != arguments.file.len() || arguments.file.iter().any(|path| path == "-") {
        return Err(SafeError::new(
            "invalid file selection. Supply each explicit file once; stdin is unsupported.",
        ));
    }
    let options = Options {
        include_environment: arguments.environment || arguments.file.is_empty(),
        files: arguments.file,
        allow: arguments.allow.into_iter().collect(),
        redact: arguments.redact.into_iter().collect(),
        names: arguments.names.into_iter().collect(),
        exists: arguments.exists,
        json: arguments.json,
    };
    let snapshots = read_sources(&options)?;
    if options.exists {
        return Ok(u8::from(snapshots.iter().any(|snapshot| {
            options
                .names
                .iter()
                .any(|name| !snapshot.values.contains_key(name))
        })));
    }
    let records = environment::sanitize(&snapshots, &options);
    let missing = records.iter().any(|record| record.state == State::Missing);
    let output = if options.json {
        environment::render_json(&records)?
    } else {
        environment::render_text(&records)?
    };
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(output.as_bytes())
        .map_err(|_| output_error())?;
    stdout.flush().map_err(|_| output_error())?;
    Ok(u8::from(missing))
}

fn read_sources(options: &Options) -> Result<Vec<Snapshot>, SafeError> {
    let mut snapshots = Vec::new();
    if options.include_environment {
        let mut pairs = Vec::new();
        for (name, value) in std::env::vars_os() {
            let name = name.into_string().map_err(|_| {
                SafeError::new(
                    "environment encoding error. Supply UTF-8 environment names and retry.",
                )
            })?;
            let value = value.into_string().map_err(|_| {
                SafeError::new(
                    "environment encoding error. Supply UTF-8 environment values and retry.",
                )
            })?;
            pairs.push((name, value));
        }
        snapshots.push(Snapshot {
            source: Source::Environment,
            values: RawVariables::from_pairs(pairs),
        });
    }
    for path in &options.files {
        let read_error = || {
            SafeError::new(
                "file read failed. Check the explicit path and read permissions, then retry.",
            )
            .with_source(path)
        };
        let metadata = std::fs::metadata(path).map_err(|_| read_error())?;
        if !metadata.is_file() {
            return Err(SafeError::new(
                "source is not a regular file. Supply an explicit UTF-8 .env file and retry.",
            )
            .with_source(path));
        }
        let file = std::fs::File::open(path).map_err(|_| read_error())?;
        if !file.metadata().map_err(|_| read_error())?.is_file() {
            return Err(SafeError::new(
                "source is not a regular file. Supply an explicit UTF-8 .env file and retry.",
            )
            .with_source(path));
        }
        let mut bytes = Vec::new();
        file.take((MAX_FILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| read_error())?;
        if bytes.len() > MAX_FILE_BYTES {
            return Err(SafeError::new(
                "file exceeds 16 MiB. Supply a smaller .env file and retry.",
            )
            .with_source(path));
        }
        snapshots.push(Snapshot {
            source: Source::File { path: path.clone() },
            values: dotenv::parse(&bytes, path)?,
        });
    }
    Ok(snapshots)
}

fn output_error() -> SafeError {
    SafeError::new("output write failed. Retry with a writable output destination.")
}
