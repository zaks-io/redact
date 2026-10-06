use super::Frame;
use crate::{Span, context::sensitive_name, error::SafeError};

pub(super) fn detect(
    input: &str,
    frames: &[Frame],
    spans: &mut Vec<Span>,
) -> Result<(), SafeError> {
    let matcher = pattern!(r#"[?&#;,]([^?&#;,/=\s<>"']+)="#)?;
    let fields: Vec<_> = matcher
        .captures_iter(input)
        .filter_map(|capture| {
            let complete = capture.get(0)?;
            let name = capture.get(1)?;
            let frame_index = frames
                .partition_point(|frame| frame.start <= complete.start())
                .checked_sub(1)?;
            let frame = &frames[frame_index];
            if complete.start() < frame.parameters_start || complete.start() >= frame.end {
                return None;
            }
            let decoded = percent_encoding::percent_decode_str(name.as_str())
                .decode_utf8()
                .ok()?;
            Some((
                decoded.into_owned(),
                complete.start(),
                complete.end(),
                frame_index,
            ))
        })
        .collect();
    let hard_delimiters: Vec<_> = input
        .char_indices()
        .filter_map(|(index, ch)| {
            (matches!(ch, '&' | '#')
                || ch.is_whitespace()
                || ch.is_control()
                || matches!(ch, '<' | '>' | '"' | '\'' | '{' | '}'))
            .then_some(index)
        })
        .collect();
    let mut signed_frames = vec![0u8; frames.len()];
    for (name, _, _, frame) in &fields {
        if name.eq_ignore_ascii_case("sv") {
            signed_frames[*frame] |= 1;
        }
        if ["se", "sp", "sr", "ss", "srt"]
            .iter()
            .any(|expected| name.eq_ignore_ascii_case(expected))
        {
            signed_frames[*frame] |= 2;
        }
    }
    let mut hard_cursor = hard_delimiters.len();
    let mut hard_end = input.len();
    for index in (0..fields.len()).rev() {
        let (name, _, start, frame) = &fields[index];
        while hard_cursor > 0 && hard_delimiters[hard_cursor - 1] >= *start {
            hard_cursor -= 1;
            hard_end = hard_delimiters[hard_cursor];
        }
        let next_field = fields.get(index + 1).map_or(input.len(), |field| field.1);
        let end = hard_end.min(next_field).min(frames[*frame].end);
        let signed = [
            "x-amz-credential",
            "x-amz-signature",
            "x-amz-security-token",
        ]
        .iter()
        .any(|expected| name.eq_ignore_ascii_case(expected))
            || signed_frames[*frame] == 3 && name.eq_ignore_ascii_case("sig");
        if end > *start && (signed || sensitive_name(name)) {
            spans.push(*start..end);
        }
    }
    Ok(())
}
