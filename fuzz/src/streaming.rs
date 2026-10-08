use std::io::{self, Read};

use redact::{error::SafeError, filter, rstr::filter_to_writer};

use crate::{CANARY, check_error};

struct Chunks<'a> {
    remaining: &'a [u8],
    size: usize,
}

impl Read for Chunks<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = output.len().min(self.remaining.len()).min(self.size);
        output[..count].copy_from_slice(&self.remaining[..count]);
        self.remaining = &self.remaining[count..];
        Ok(count)
    }
}

#[derive(PartialEq, Eq)]
struct Outcome {
    output: Vec<u8>,
    report: Vec<u8>,
    error: Option<SafeError>,
}

fn streamed(input: &[u8], size: usize) -> Outcome {
    let mut output = Vec::new();
    let mut report = Vec::new();
    let result = filter_to_writer(
        Chunks {
            remaining: input,
            size,
        },
        &mut output,
    );
    let error = match result {
        Ok(metadata) => {
            assert!(metadata.write(&mut report).is_ok(), "report write failed");
            None
        }
        Err(error) => {
            check_error(&error);
            Some(error)
        }
    };
    assert!(
        !String::from_utf8_lossy(&report).contains(CANARY),
        "stream report disclosed synthetic input"
    );
    Outcome {
        output,
        report,
        error,
    }
}

pub fn exercise(data: &[u8]) {
    // This is a campaign cost bound, not a production input limit.
    let input = &data[..data.len().min(4096)];
    let size = 1 + usize::from(data.first().copied().unwrap_or_default()) % 31;
    let whole = streamed(input, usize::MAX);
    assert!(
        whole == streamed(input, size),
        "stream output, report or error changed with read size"
    );
    assert!(
        filter(input).is_err() || whole.error.is_none(),
        "stream rejected complete input accepted by batch"
    );
    supported_record(data);
    super::streaming_boundaries::exercise(data);
}

fn supported_record(data: &[u8]) {
    let selector = usize::from(data.first().copied().unwrap_or_default());
    let tail: String = data
        .iter()
        .skip(1)
        .take(32)
        .map(|byte| char::from(b'a' + byte % 26))
        .collect();
    let canary = format!("{CANARY}_{tail}");
    let token = format!("\"token\":\n\"{canary}\"\n]\nafter\n");
    let input = match selector % 8 {
        0 => format!("password=\\\"a [x\\\" host=h dbname=d\nsee http://h/x[\n{token}"),
        1 => format!("AccountKey=\\\"a;[x\\\";AccountName=n\nsee http://h/x[\n{token}"),
        2 => format!("[\npassword: a\n ]\nx\nsee http://h/x[\n{token}"),
        3 => format!("[\npassword: |\n ]\nx\nsee http://h/x[\n{token}"),
        4 => format!("[\n\"api_key\":\n|\n ]\nx\nsee http://h/x[\n{token}"),
        5 => format!("see http://h/x[\n'token': a] 'x\n'\n password': v\n {canary}\n"),
        6 => format!("[}}\n'token': a] 'x\n'\n password': v\n {canary}\n"),
        _ => format!(
            "[\npassword=-----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY----- 'token': \\\"a ]\\\"\nx\nsee http://h/x[\n{token}"
        ),
    };
    let expected = filter(input.as_bytes());
    assert!(expected.is_ok(), "supported synthetic record rejected");
    if let Ok(expected) = expected {
        assert!(
            !expected.contains(&canary),
            "batch fixture does not protect the synthetic canary"
        );
        let whole = streamed(input.as_bytes(), usize::MAX);
        let chunks = streamed(input.as_bytes(), 1 + selector % 31);
        assert!(whole == chunks, "supported record changed with reads");
        assert!(
            whole.error.is_none() && whole.output == expected.as_bytes(),
            "stream split a supported synthetic record"
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn supported_records_cover_connection_continuation_depth_and_private_keys() {
        for selector in 0..8 {
            super::exercise(&[selector, 1, 2, 255]);
        }
    }
}
