use super::{RecordEnd, detect_with_state};
use crate::synthetic::*;

#[test]
fn end_state_requires_observed_closure_for_every_cross_line_context() {
    let cases = [
        ("status=401\n", true, true, true),
        ("token=\n", true, true, true),
        ("token=", false, false, false),
        ("[ http://h/x]\n", false, false, false),
        ("[http://h/x]\n", true, true, true),
        ("\"ordinary\"\n", false, true, true),
        ("\"ordinary\n", false, false, false),
        ("'ordinary\n", false, false, false),
        ("\"token\":\n", false, false, true),
        ("[ \"token\":\n", false, false, false),
        ("token: value\n", false, false, true),
        ("token: |\n value\n", false, false, true),
        ("token:\n value\nstatus=401\n", true, true, true),
        ("{\"token\": \"SYNTHETIC_VALUE\"}\n", true, true, true),
        ("token=\\\"SYNTHETIC_VALUE\\\"\n", true, true, true),
    ];
    for (input, newline, non_delimiter, document) in cases {
        let structured = crate::structured::detect_with_contexts(input).must();
        let state = detect_with_state(input, &structured.contexts, 0).must().end;
        assert_eq!(state.settled(RecordEnd::Newline), newline);
        assert_eq!(state.settled(RecordEnd::NonDelimiter), non_delimiter);
        assert_eq!(state.settled(RecordEnd::Document), document);
    }
}
