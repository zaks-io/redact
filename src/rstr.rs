//! Stdin-only filtering. Detection and rendering live at the crate root.

use std::io::{Read, Write};

use crate::context::RecordEnd;
use crate::error::{ErrorKind, SafeError};
use crate::{MAX_INPUT_BYTES, RedactionReport, filter_with_evidence};

mod framing;
use framing::{Boundary, Framer};

pub fn read_input(reader: impl Read) -> Result<Vec<u8>, SafeError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| SafeError::new(ErrorKind::Input))?;
    Ok(bytes)
}

/// Emit settled records while retaining undecided structured input in memory.
pub fn filter_to_writer(
    mut reader: impl Read,
    mut writer: impl Write,
) -> Result<RedactionReport, SafeError> {
    let mut stream = Stream::new();
    let mut bytes = [0; 8192];
    loop {
        let count = match reader.read(&mut bytes) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(stream.error(ErrorKind::Input)),
        };
        if count == 0 {
            let result = stream.finish();
            stream.flush(&mut writer)?;
            result?;
            return Ok(stream.report);
        }
        let result = stream.push(&bytes[..count]);
        stream.flush(&mut writer)?;
        result?;
    }
}

// Raw pending input deliberately has no formatting or serialization implementation.
struct Stream {
    pending: Vec<u8>,
    line_start: usize,
    output: Vec<u8>,
    output_first_line: usize,
    first_line: usize,
    emitted: bool,
    framer: Framer,
    report: RedactionReport,
}

impl Stream {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
            line_start: 0,
            output: Vec::new(),
            output_first_line: 1,
            first_line: 1,
            emitted: false,
            framer: Framer::new(),
            report: RedactionReport::default(),
        }
    }

    fn error(&self, kind: impl Into<ErrorKind>) -> SafeError {
        SafeError::new(kind).in_stream(self.first_line, self.emitted)
    }

    fn finish(&mut self) -> Result<(), SafeError> {
        if let Err(error) = crate::validate_input(&self.pending[self.line_start..]) {
            return Err(self.invalid_line(error)?);
        }
        self.emit(self.pending.len())
    }

    fn push(&mut self, mut bytes: &[u8]) -> Result<(), SafeError> {
        while !bytes.is_empty() {
            let count = bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |at| at + 1);
            let fragment = &bytes[..count];
            if self.pending.len() + fragment.len() > MAX_INPUT_BYTES {
                return Err(self.error(self.framer.pending_limit_diagnostic()));
            }
            self.pending.extend_from_slice(fragment);
            bytes = &bytes[count..];
            if fragment.last() != Some(&b'\n') {
                continue;
            }
            let line = match crate::validate_input(&self.pending[self.line_start..]) {
                Ok(line) => line,
                Err(error) => {
                    return Err(self.invalid_line(error)?);
                }
            };
            let mut boundary = self
                .framer
                .line(line, &self.pending, self.line_start)
                .map_err(|error| error.in_stream(self.first_line, self.emitted))?;
            if matches!(boundary, Boundary::Previous) {
                if !self.try_emit(self.line_start, RecordEnd::NonDelimiter)? {
                    self.line_start = self.pending.len();
                    continue;
                }
                let line = crate::validate_input(&self.pending)
                    .map_err(|error| error.in_stream(self.first_line, self.emitted))?;
                boundary = self
                    .framer
                    .line(line, &self.pending, 0)
                    .map_err(|error| error.in_stream(self.first_line, self.emitted))?;
            }
            match boundary {
                Boundary::Complete => {
                    self.try_emit(self.pending.len(), RecordEnd::Newline)?;
                }
                Boundary::Hold => {}
                Boundary::Document => {
                    self.try_emit(self.line_start, RecordEnd::Document)?;
                }
                Boundary::Previous => {
                    return Err(self.error("stream framing did not settle. Report the version and a synthetic reproduction."));
                }
            }
            self.line_start = self.pending.len();
        }
        Ok(())
    }

    fn emit(&mut self, end: usize) -> Result<(), SafeError> {
        if end == 0 {
            return Ok(());
        }
        let filtered = filter_with_evidence(&self.pending[..end])
            .map_err(|error| error.in_stream(self.first_line, self.emitted))?;
        self.commit(end, filtered)
    }

    fn try_emit(&mut self, end: usize, boundary: RecordEnd) -> Result<bool, SafeError> {
        if end == 0 {
            return Ok(true);
        }
        let filtered = crate::text::filter_candidate(&self.pending[..end], boundary)
            .map_err(|error| error.in_stream(self.first_line, self.emitted))?;
        let Some(filtered) = filtered else {
            // A disagreement must retain context once, rather than re-detect growing prefixes.
            self.framer.hold_until_eof();
            return Ok(false);
        };
        self.commit(end, filtered)?;
        Ok(true)
    }

    fn commit(&mut self, end: usize, filtered: crate::Filtered) -> Result<(), SafeError> {
        self.report
            .observe(&filtered.redactions, self.first_line)
            .map_err(|error| error.in_stream(self.first_line, self.emitted))?;
        let next_line = self
            .first_line
            .checked_add(
                self.pending[..end]
                    .iter()
                    .filter(|byte| **byte == b'\n')
                    .count(),
            )
            .ok_or_else(|| self.line_limit())?;
        // Detector context follows record boundaries, never the producer's read timing.
        if self.output.is_empty() {
            self.output_first_line = self.first_line;
        }
        self.output.extend_from_slice(filtered.output.as_bytes());
        self.emitted |= !filtered.output.is_empty();
        self.first_line = next_line;
        self.pending.copy_within(end.., 0);
        self.pending.truncate(self.pending.len() - end);
        self.framer.discard_prefix(end);
        self.line_start = self.line_start.saturating_sub(end);
        Ok(())
    }

    fn flush(&mut self, writer: &mut impl Write) -> Result<(), SafeError> {
        if self.output.is_empty() {
            return Ok(());
        }
        writer
            .write_all(&self.output)
            .and_then(|()| writer.flush())
            .map_err(|_| {
                SafeError::new(ErrorKind::Output).in_stream(self.output_first_line, true)
            })?;
        self.output.clear();
        Ok(())
    }

    fn line_limit(&self) -> SafeError {
        self.error("stream line count exceeds supported limit. Start a new filtered stream at a complete record boundary.")
    }

    fn invalid_line(&self, error: SafeError) -> Result<SafeError, SafeError> {
        let line = self
            .first_line
            .checked_add(
                self.pending[..self.line_start]
                    .iter()
                    .filter(|byte| **byte == b'\n')
                    .count(),
            )
            .ok_or_else(|| self.line_limit())?;
        Ok(error.in_stream(line, self.emitted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::synthetic::*;
    use std::io;

    const CANARY: &str = "SYNTHETIC_STREAM_FLUSH_FAILURE_CANARY_0123456789";

    struct FailedFlush(Vec<u8>);
    impl Write for FailedFlush {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other(CANARY))
        }
    }

    #[test]
    fn flush_failure_retains_only_filtered_output_and_an_opaque_error() {
        let mut writer = FailedFlush(Vec::new());
        let error =
            filter_to_writer(format!("password={CANARY}\n").as_bytes(), &mut writer).must_err();
        assert_eq!(error.kind, ErrorKind::Output);
        assert_eq!(error.line, Some(1));
        assert!(!String::from_utf8(writer.0).must().contains(CANARY));
        assert!(!format!("{error:?} {error}").contains(CANARY));
    }

    #[test]
    fn failures_flush_only_filtered_records_and_surface_a_prior_write_failure() {
        let mut input = format!("status=401\npassword={CANARY}\n").into_bytes();
        input.extend_from_slice(&[0xff, b'\n']);
        let expected = crate::filter(&input[..input.len() - 2]).must();
        let mut output = Vec::new();
        let error = filter_to_writer(input.as_slice(), &mut output).must_err();
        assert!(output == expected.as_bytes());
        assert_eq!(error.line, Some(3));
        assert!(error.earlier_output_emitted);
        let mut writer = FailedFlush(Vec::new());
        let error = filter_to_writer(input.as_slice(), &mut writer).must_err();
        assert!(writer.0 == expected.as_bytes());
        assert_eq!(error.kind, ErrorKind::Output);
        assert_eq!(error.line, Some(1));
        assert!(error.earlier_output_emitted);
        assert!(!format!("{error:?} {error}").contains(CANARY));
    }

    #[test]
    fn a_detector_failure_in_the_same_read_flushes_only_prior_filtered_records() {
        let prefix = format!("password={CANARY}\n");
        let input = format!("{prefix}password=\"\\q\" status=401\n");
        let expected = crate::filter(prefix.as_bytes()).must();
        let mut output = Vec::new();
        let error = filter_to_writer(input.as_bytes(), &mut output).must_err();
        assert!(output == expected.as_bytes());
        assert_eq!(error.line, Some(2));
        assert!(error.earlier_output_emitted);
        assert!(
            error
                .to_string()
                .contains("unsupported quoted-value escape")
        );
        assert!(!format!("{error:?} {error}").contains(CANARY));
    }

    struct InterruptedOnce {
        interrupted: bool,
        input: io::Cursor<&'static [u8]>,
    }
    impl Read for InterruptedOnce {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.input.read(bytes)
        }
    }

    #[test]
    fn interrupted_reads_retry_the_same_filtered_stream() {
        let input = InterruptedOnce {
            interrupted: false,
            input: io::Cursor::new(b"status=401\n"),
        };
        let mut output = Vec::new();
        filter_to_writer(input, &mut output).must();
        assert_eq!(output, b"status=401\n");
    }
}
