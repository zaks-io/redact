#[allow(dead_code, reason = "shared synthetic assertions across test suites")]
#[path = "support/synthetic.rs"]
mod synthetic;
use synthetic::*;

use proptest::prelude::*;
use redact::{
    error::{ErrorKind, SafeError},
    filter_with_evidence,
    rstr::filter_to_writer,
};
use std::{
    io::{self, Read},
    process::Command,
};

const CANARY: &str = "SYNTHETIC_R7_FINDING_CANARY";

#[derive(serde::Deserialize)]
struct StateCase {
    name: String,
    input: String,
    expected: Option<String>,
    report: String,
    batch_error: Option<String>,
    protected: Vec<String>,
    withhold: bool,
}

fn cases() -> Vec<StateCase> {
    serde_json::from_str(r###"[
{"name":"R7-1 J backslash before stray END LF","family":"J","input":"'\\-----END A PRIVATE KEY-----\"'\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\nafter\n","expected":"'\\-----END A PRIVATE KEY-----\"'\nx\" [REDACTED sha256=398becb07111d94b]x\"\nafter\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"R7-1 J backslash before stray END CRLF","family":"J","input":"'\\-----END A PRIVATE KEY-----\"'\r\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\nafter\r\n","expected":"'\\-----END A PRIVATE KEY-----\"'\r\nx\" [REDACTED sha256=398becb07111d94b]x\"\r\nafter\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"R7-1 J real block after backslash LF","family":"J","input":"'\\-----BEGIN A PRIVATE KEY-----\nMII\n-----END A PRIVATE KEY-----\"'\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\nafter\n","expected":"'\\[REDACTED sha256=cf348d1b2be33859]\"'\nx\" [REDACTED sha256=398becb07111d94b]x\"\nafter\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=cf348d1b2be33859; private-key block + sensitive field or quoted credential\nrstr: line 4: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"R7-1 J real block after backslash CRLF","family":"J","input":"'\\-----BEGIN A PRIVATE KEY-----\r\nMII\r\n-----END A PRIVATE KEY-----\"'\r\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\nafter\r\n","expected":"'\\[REDACTED sha256=629116c04000dde0]\"'\r\nx\" [REDACTED sha256=398becb07111d94b]x\"\r\nafter\r\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=629116c04000dde0; private-key block + sensitive field or quoted credential\nrstr: line 4: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"R7-1 J grep-style quoted marker LF","family":"J","input":"\"\\-----END A PRIVATE KEY-----\"x\"\n\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\nafter\n","expected":"\"\\-----END A PRIVATE KEY-----\"x\"\n\"[REDACTED sha256=5538282a7c9a4dc1]\nafter\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=5538282a7c9a4dc1; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"R7-1 J grep-style quoted marker CRLF","family":"J","input":"\"\\-----END A PRIVATE KEY-----\"x\"\r\n\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\r\nafter\r\n","expected":"\"\\-----END A PRIVATE KEY-----\"x\"\r\n\"[REDACTED sha256=5538282a7c9a4dc1]\r\nafter\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=5538282a7c9a4dc1; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"R7-1 K overlapping BEGIN BEGIN LF","family":"K","input":"-----BEGIN A PRIVATE KEY-----BEGIN B PRIVATE KEY-----\nMII\n-----END A PRIVATE KEY-----x\"\n-----END B PRIVATE KEY-----\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\nafter\n","expected":"[REDACTED sha256=a8928eaa9aa3ec15]x\"\n-----END B PRIVATE KEY-----\nx\" [REDACTED sha256=398becb07111d94b]x\"\nafter\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=a8928eaa9aa3ec15; private-key block\nrstr: line 5: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"R7-1 K overlapping BEGIN BEGIN CRLF","family":"K","input":"-----BEGIN A PRIVATE KEY-----BEGIN B PRIVATE KEY-----\r\nMII\r\n-----END A PRIVATE KEY-----x\"\r\n-----END B PRIVATE KEY-----\r\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\nafter\r\n","expected":"[REDACTED sha256=cfe4518380f1719e]x\"\r\n-----END B PRIVATE KEY-----\r\nx\" [REDACTED sha256=398becb07111d94b]x\"\r\nafter\r\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=cfe4518380f1719e; private-key block\nrstr: line 5: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"R7-1 K' quote inside block body LF","family":"K","input":"n\"-----BEGIN B PRIVATE KEY-----\"-----END B PRIVATE KEY-----\"\"\"x\"y\"\n\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\nafter\n","expected":"n\"[REDACTED sha256=fe11d27c55dad0f8]\"\"\"x\"y\"\n\"[REDACTED sha256=5538282a7c9a4dc1]\nafter\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=fe11d27c55dad0f8; private-key block\nrstr: line 2: sha256=5538282a7c9a4dc1; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"R7-1 K' quote inside block body CRLF","family":"K","input":"n\"-----BEGIN B PRIVATE KEY-----\"-----END B PRIVATE KEY-----\"\"\"x\"y\"\r\n\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\r\nafter\r\n","expected":"n\"[REDACTED sha256=fe11d27c55dad0f8]\"\"\"x\"y\"\r\n\"[REDACTED sha256=5538282a7c9a4dc1]\r\nafter\r\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=fe11d27c55dad0f8; private-key block\nrstr: line 2: sha256=5538282a7c9a4dc1; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"R7-1 J CRLF LF","family":"J","input":"'\\-----END A PRIVATE KEY-----\"'\r\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\nafter\r\n","expected":"'\\-----END A PRIVATE KEY-----\"'\r\nx\" [REDACTED sha256=398becb07111d94b]x\"\r\nafter\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"R7-1 J CRLF CRLF","family":"J","input":"'\\-----END A PRIVATE KEY-----\"'\r\r\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\r\nafter\r\r\n","expected":"'\\-----END A PRIVATE KEY-----\"'\r\r\nx\" [REDACTED sha256=398becb07111d94b]x\"\r\r\nafter\r\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"control: probe line alone LF","family":"control","input":"x\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\nafter\n","expected":"x\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\nafter\n","report":"","batch_error":null,"protected":[],"withhold":false},
{"name":"control: probe line alone CRLF","family":"control","input":"x\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\nafter\r\n","expected":"x\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\nafter\r\n","report":"","batch_error":null,"protected":[],"withhold":false},
{"name":"control: J without backslash LF","family":"J","input":"'-----END A PRIVATE KEY-----\"'\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\nafter\n","expected":"'-----END A PRIVATE KEY-----\"'\nx\" [REDACTED sha256=398becb07111d94b]x\"\nafter\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"control: J without backslash CRLF","family":"J","input":"'-----END A PRIVATE KEY-----\"'\r\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\nafter\r\n","expected":"'-----END A PRIVATE KEY-----\"'\r\nx\" [REDACTED sha256=398becb07111d94b]x\"\r\nafter\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"control: J with escaped backslash LF","family":"J","input":"'\\\\-----END A PRIVATE KEY-----\"'\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\nafter\n","expected":"'\\\\-----END A PRIVATE KEY-----\"'\nx\" [REDACTED sha256=398becb07111d94b]x\"\nafter\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"control: J with escaped backslash CRLF","family":"J","input":"'\\\\-----END A PRIVATE KEY-----\"'\r\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\nafter\r\n","expected":"'\\\\-----END A PRIVATE KEY-----\"'\r\nx\" [REDACTED sha256=398becb07111d94b]x\"\r\nafter\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"control: K with separate BEGIN B LF","family":"K","input":"-----BEGIN A PRIVATE KEY----- -----BEGIN B PRIVATE KEY-----\nMII\n-----END A PRIVATE KEY-----x\"\n-----END B PRIVATE KEY-----\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\n","expected":"[REDACTED sha256=e673ad8b9c9a2f73]\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=e673ad8b9c9a2f73; private-key block\n","batch_error":null,"protected":[],"withhold":false},
{"name":"control: K with separate BEGIN B CRLF","family":"K","input":"-----BEGIN A PRIVATE KEY----- -----BEGIN B PRIVATE KEY-----\r\nMII\r\n-----END A PRIVATE KEY-----x\"\r\n-----END B PRIVATE KEY-----\r\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\n","expected":"[REDACTED sha256=66bcc02e59343142]\r\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=66bcc02e59343142; private-key block\n","batch_error":null,"protected":[],"withhold":false},
{"name":"R7-2 JSON log empty AccountKey LF","family":"K","input":"{\"conn\":\"AccountName=dev;AccountKey=\"}\n{\"msg\":\"ok\"}\n","expected":"{\"conn\":\"AccountName=dev;AccountKey=\"[REDACTED sha256=ff17f5c9644fdc05]\"msg\":\"ok\"}\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=ff17f5c9644fdc05; connection-string credential\n","batch_error":null,"protected":[],"withhold":true},
{"name":"R7-2 JSON log empty AccountKey CRLF","family":"K","input":"{\"conn\":\"AccountName=dev;AccountKey=\"}\r\n{\"msg\":\"ok\"}\r\n","expected":"{\"conn\":\"AccountName=dev;AccountKey=\"[REDACTED sha256=b281520815660f99]\"msg\":\"ok\"}\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=b281520815660f99; connection-string credential\n","batch_error":null,"protected":[],"withhold":true},
{"name":"R7-2 quoted DSN empty password LF","family":"connection","input":"dsn=\"host=db dbname=app user=app password=\"\nINFO started \"ok\"\nGET /health 200\n","expected":"dsn=\"host=db dbname=app user=app password=\"[REDACTED sha256=2d56a8ad74ab746a]\"ok\"\nGET /health 200\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=2d56a8ad74ab746a; connection-string credential\n","batch_error":null,"protected":[],"withhold":true},
{"name":"R7-2 quoted DSN empty password CRLF","family":"connection","input":"dsn=\"host=db dbname=app user=app password=\"\r\nINFO started \"ok\"\r\nGET /health 200\r\n","expected":"dsn=\"host=db dbname=app user=app password=\"[REDACTED sha256=2b31c509d85e7cd6]\"ok\"\r\nGET /health 200\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=2b31c509d85e7cd6; connection-string credential\n","batch_error":null,"protected":[],"withhold":true},
{"name":"control: DSN with later field on line LF","family":"control","input":"level=info dsn=\"host=db dbname=app user=app password=\" msg=\"x\"\nlevel=info msg=\"ready\"\n","expected":"level=info dsn=\"host=db dbname=app user=app password=\"[REDACTED sha256=2982a9074eda7a44]\"x\"\nlevel=info msg=\"ready\"\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=2982a9074eda7a44; connection-string credential\n","batch_error":null,"protected":[],"withhold":false},
{"name":"control: DSN with later field on line CRLF","family":"control","input":"level=info dsn=\"host=db dbname=app user=app password=\" msg=\"x\"\r\nlevel=info msg=\"ready\"\r\n","expected":"level=info dsn=\"host=db dbname=app user=app password=\"[REDACTED sha256=2982a9074eda7a44]\"x\"\r\nlevel=info msg=\"ready\"\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=2982a9074eda7a44; connection-string credential\n","batch_error":null,"protected":[],"withhold":false},
{"name":"control: DSN, no later quote LF","family":"control","input":"dsn=\"host=db dbname=app user=app password=\"\nINFO started\n","expected":null,"report":"","batch_error":"line 1: unterminated quoted value. Close the quoted value and retry.","protected":[],"withhold":false},
{"name":"control: DSN, no later quote CRLF","family":"control","input":"dsn=\"host=db dbname=app user=app password=\"\r\nINFO started\r\n","expected":null,"report":"","batch_error":"line 1: unterminated quoted value. Close the quoted value and retry.","protected":[],"withhold":false},
{"name":"R7-3 BEGIN/END shared dashes LF","family":"overlap","input":"-----BEGIN A PRIVATE KEY-----END A PRIVATE KEY-----\nstatus=ok\npassword=SYNTHETIC_R7_FINDING_CANARY\n-----END A PRIVATE KEY-----\n","expected":"[REDACTED sha256=7913920ff1981655]\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=7913920ff1981655; private-key block\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"R7-3 BEGIN/END shared dashes CRLF","family":"overlap","input":"-----BEGIN A PRIVATE KEY-----END A PRIVATE KEY-----\r\nstatus=ok\r\npassword=SYNTHETIC_R7_FINDING_CANARY\r\n-----END A PRIVATE KEY-----\r\n","expected":"[REDACTED sha256=52477d6013aa2801]\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=52477d6013aa2801; private-key block\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"control: no later END LF","family":"control","input":"-----BEGIN A PRIVATE KEY-----END A PRIVATE KEY-----\nstatus=ok\n","expected":null,"report":"","batch_error":"line 1: unterminated private-key block. Add its matching END marker and retry.","protected":[],"withhold":false},
{"name":"control: no later END CRLF","family":"control","input":"-----BEGIN A PRIVATE KEY-----END A PRIVATE KEY-----\r\nstatus=ok\r\n","expected":null,"report":"","batch_error":"line 1: unterminated private-key block. Add its matching END marker and retry.","protected":[],"withhold":false},
{"name":"PEM parity prefix 0 container 0 LF","family":"parity","input":"'\\-----END A PRIVATE KEY-----\"'\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\nafter\n","expected":"'\\-----END A PRIVATE KEY-----\"'\nx\" [REDACTED sha256=398becb07111d94b]x\"\nafter\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 0 container 0 CRLF","family":"parity","input":"'\\-----END A PRIVATE KEY-----\"'\r\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\nafter\r\n","expected":"'\\-----END A PRIVATE KEY-----\"'\r\nx\" [REDACTED sha256=398becb07111d94b]x\"\r\nafter\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 0 container 1 LF","family":"parity","input":"'\\-----END A PRIVATE KEY-----\"'\n\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\nafter\n","expected":"'\\-----END A PRIVATE KEY-----\"'\n\"[REDACTED sha256=5538282a7c9a4dc1]\nafter\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=5538282a7c9a4dc1; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 0 container 1 CRLF","family":"parity","input":"'\\-----END A PRIVATE KEY-----\"'\r\n\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\r\nafter\r\n","expected":"'\\-----END A PRIVATE KEY-----\"'\r\n\"[REDACTED sha256=5538282a7c9a4dc1]\r\nafter\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=5538282a7c9a4dc1; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 0 container 2 LF","family":"parity","input":"'\\-----END A PRIVATE KEY-----\"'\n\"{\"kind\":\"Secret\",\"data\":{\"tls.crt\":\"SYNTHETIC_R7_FINDING_CANARY\"}}\nafter\n","expected":"'\\-----END A PRIVATE KEY-----\"'\n\"[REDACTED sha256=fac61d235726ebee]\nafter\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=fac61d235726ebee; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 0 container 2 CRLF","family":"parity","input":"'\\-----END A PRIVATE KEY-----\"'\r\n\"{\"kind\":\"Secret\",\"data\":{\"tls.crt\":\"SYNTHETIC_R7_FINDING_CANARY\"}}\r\nafter\r\n","expected":"'\\-----END A PRIVATE KEY-----\"'\r\n\"[REDACTED sha256=fac61d235726ebee]\r\nafter\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=fac61d235726ebee; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 1 container 0 LF","family":"parity","input":"'\\-----BEGIN A PRIVATE KEY-----\nMII\n-----END A PRIVATE KEY-----\"'\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\nafter\n","expected":"'\\[REDACTED sha256=cf348d1b2be33859]\"'\nx\" [REDACTED sha256=398becb07111d94b]x\"\nafter\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=cf348d1b2be33859; private-key block + sensitive field or quoted credential\nrstr: line 4: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 1 container 0 CRLF","family":"parity","input":"'\\-----BEGIN A PRIVATE KEY-----\r\nMII\r\n-----END A PRIVATE KEY-----\"'\r\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\nafter\r\n","expected":"'\\[REDACTED sha256=629116c04000dde0]\"'\r\nx\" [REDACTED sha256=398becb07111d94b]x\"\r\nafter\r\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=629116c04000dde0; private-key block + sensitive field or quoted credential\nrstr: line 4: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 1 container 1 LF","family":"parity","input":"'\\-----BEGIN A PRIVATE KEY-----\nMII\n-----END A PRIVATE KEY-----\"'\n\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\nafter\n","expected":"'\\[REDACTED sha256=cf348d1b2be33859]\"'\n\"[REDACTED sha256=5538282a7c9a4dc1]\nafter\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=cf348d1b2be33859; private-key block + sensitive field or quoted credential\nrstr: line 4: sha256=5538282a7c9a4dc1; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 1 container 1 CRLF","family":"parity","input":"'\\-----BEGIN A PRIVATE KEY-----\r\nMII\r\n-----END A PRIVATE KEY-----\"'\r\n\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\r\nafter\r\n","expected":"'\\[REDACTED sha256=629116c04000dde0]\"'\r\n\"[REDACTED sha256=5538282a7c9a4dc1]\r\nafter\r\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=629116c04000dde0; private-key block + sensitive field or quoted credential\nrstr: line 4: sha256=5538282a7c9a4dc1; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 1 container 2 LF","family":"parity","input":"'\\-----BEGIN A PRIVATE KEY-----\nMII\n-----END A PRIVATE KEY-----\"'\n\"{\"kind\":\"Secret\",\"data\":{\"tls.crt\":\"SYNTHETIC_R7_FINDING_CANARY\"}}\nafter\n","expected":"'\\[REDACTED sha256=cf348d1b2be33859]\"'\n\"[REDACTED sha256=fac61d235726ebee]\nafter\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=cf348d1b2be33859; private-key block + sensitive field or quoted credential\nrstr: line 4: sha256=fac61d235726ebee; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 1 container 2 CRLF","family":"parity","input":"'\\-----BEGIN A PRIVATE KEY-----\r\nMII\r\n-----END A PRIVATE KEY-----\"'\r\n\"{\"kind\":\"Secret\",\"data\":{\"tls.crt\":\"SYNTHETIC_R7_FINDING_CANARY\"}}\r\nafter\r\n","expected":"'\\[REDACTED sha256=629116c04000dde0]\"'\r\n\"[REDACTED sha256=fac61d235726ebee]\r\nafter\r\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=629116c04000dde0; private-key block + sensitive field or quoted credential\nrstr: line 4: sha256=fac61d235726ebee; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 2 container 0 LF","family":"parity","input":"-----BEGIN A PRIVATE KEY-----BEGIN B PRIVATE KEY-----\nMII\n-----END A PRIVATE KEY-----x\"\n-----END B PRIVATE KEY-----\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\nafter\n","expected":"[REDACTED sha256=a8928eaa9aa3ec15]x\"\n-----END B PRIVATE KEY-----\nx\" [REDACTED sha256=398becb07111d94b]x\"\nafter\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=a8928eaa9aa3ec15; private-key block\nrstr: line 5: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 2 container 0 CRLF","family":"parity","input":"-----BEGIN A PRIVATE KEY-----BEGIN B PRIVATE KEY-----\r\nMII\r\n-----END A PRIVATE KEY-----x\"\r\n-----END B PRIVATE KEY-----\r\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\nafter\r\n","expected":"[REDACTED sha256=cfe4518380f1719e]x\"\r\n-----END B PRIVATE KEY-----\r\nx\" [REDACTED sha256=398becb07111d94b]x\"\r\nafter\r\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=cfe4518380f1719e; private-key block\nrstr: line 5: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 2 container 1 LF","family":"parity","input":"-----BEGIN A PRIVATE KEY-----BEGIN B PRIVATE KEY-----\nMII\n-----END A PRIVATE KEY-----x\"\n-----END B PRIVATE KEY-----\n\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\nafter\n","expected":"[REDACTED sha256=a8928eaa9aa3ec15]x\"\n-----END B PRIVATE KEY-----\n\"[REDACTED sha256=5538282a7c9a4dc1]\nafter\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=a8928eaa9aa3ec15; private-key block\nrstr: line 5: sha256=5538282a7c9a4dc1; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 2 container 1 CRLF","family":"parity","input":"-----BEGIN A PRIVATE KEY-----BEGIN B PRIVATE KEY-----\r\nMII\r\n-----END A PRIVATE KEY-----x\"\r\n-----END B PRIVATE KEY-----\r\n\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\r\nafter\r\n","expected":"[REDACTED sha256=cfe4518380f1719e]x\"\r\n-----END B PRIVATE KEY-----\r\n\"[REDACTED sha256=5538282a7c9a4dc1]\r\nafter\r\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=cfe4518380f1719e; private-key block\nrstr: line 5: sha256=5538282a7c9a4dc1; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 2 container 2 LF","family":"parity","input":"-----BEGIN A PRIVATE KEY-----BEGIN B PRIVATE KEY-----\nMII\n-----END A PRIVATE KEY-----x\"\n-----END B PRIVATE KEY-----\n\"{\"kind\":\"Secret\",\"data\":{\"tls.crt\":\"SYNTHETIC_R7_FINDING_CANARY\"}}\nafter\n","expected":"[REDACTED sha256=a8928eaa9aa3ec15]x\"\n-----END B PRIVATE KEY-----\n\"[REDACTED sha256=fac61d235726ebee]\nafter\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=a8928eaa9aa3ec15; private-key block\nrstr: line 5: sha256=fac61d235726ebee; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 2 container 2 CRLF","family":"parity","input":"-----BEGIN A PRIVATE KEY-----BEGIN B PRIVATE KEY-----\r\nMII\r\n-----END A PRIVATE KEY-----x\"\r\n-----END B PRIVATE KEY-----\r\n\"{\"kind\":\"Secret\",\"data\":{\"tls.crt\":\"SYNTHETIC_R7_FINDING_CANARY\"}}\r\nafter\r\n","expected":"[REDACTED sha256=cfe4518380f1719e]x\"\r\n-----END B PRIVATE KEY-----\r\n\"[REDACTED sha256=fac61d235726ebee]\r\nafter\r\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=cfe4518380f1719e; private-key block\nrstr: line 5: sha256=fac61d235726ebee; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 3 container 0 LF","family":"parity","input":"\"\\-----END A PRIVATE KEY-----\"x\"\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\nafter\n","expected":"\"\\-----END A PRIVATE KEY-----\"x\"\nx\" [REDACTED sha256=398becb07111d94b]x\"\nafter\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 3 container 0 CRLF","family":"parity","input":"\"\\-----END A PRIVATE KEY-----\"x\"\r\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\nafter\r\n","expected":"\"\\-----END A PRIVATE KEY-----\"x\"\r\nx\" [REDACTED sha256=398becb07111d94b]x\"\r\nafter\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 3 container 1 LF","family":"parity","input":"\"\\-----END A PRIVATE KEY-----\"x\"\n\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\nafter\n","expected":"\"\\-----END A PRIVATE KEY-----\"x\"\n\"[REDACTED sha256=5538282a7c9a4dc1]\nafter\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=5538282a7c9a4dc1; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 3 container 1 CRLF","family":"parity","input":"\"\\-----END A PRIVATE KEY-----\"x\"\r\n\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\r\nafter\r\n","expected":"\"\\-----END A PRIVATE KEY-----\"x\"\r\n\"[REDACTED sha256=5538282a7c9a4dc1]\r\nafter\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=5538282a7c9a4dc1; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 3 container 2 LF","family":"parity","input":"\"\\-----END A PRIVATE KEY-----\"x\"\n\"{\"kind\":\"Secret\",\"data\":{\"tls.crt\":\"SYNTHETIC_R7_FINDING_CANARY\"}}\nafter\n","expected":"\"\\-----END A PRIVATE KEY-----\"x\"\n\"[REDACTED sha256=fac61d235726ebee]\nafter\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=fac61d235726ebee; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 3 container 2 CRLF","family":"parity","input":"\"\\-----END A PRIVATE KEY-----\"x\"\r\n\"{\"kind\":\"Secret\",\"data\":{\"tls.crt\":\"SYNTHETIC_R7_FINDING_CANARY\"}}\r\nafter\r\n","expected":"\"\\-----END A PRIVATE KEY-----\"x\"\r\n\"[REDACTED sha256=fac61d235726ebee]\r\nafter\r\n","report":"rstr: 1 redaction; labels describe local syntax evidence, not credential validity.\nrstr: line 2: sha256=fac61d235726ebee; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 4 container 0 LF","family":"parity","input":"n\"-----BEGIN B PRIVATE KEY-----\"-----END B PRIVATE KEY-----\"\"\"x\"y\"\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\nafter\n","expected":"n\"[REDACTED sha256=fe11d27c55dad0f8]\"\"\"x\"y\"\nx\" [REDACTED sha256=398becb07111d94b]x\"\nafter\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=fe11d27c55dad0f8; private-key block\nrstr: line 2: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 4 container 0 CRLF","family":"parity","input":"n\"-----BEGIN B PRIVATE KEY-----\"-----END B PRIVATE KEY-----\"\"\"x\"y\"\r\nx\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\r\nafter\r\n","expected":"n\"[REDACTED sha256=fe11d27c55dad0f8]\"\"\"x\"y\"\r\nx\" [REDACTED sha256=398becb07111d94b]x\"\r\nafter\r\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=fe11d27c55dad0f8; private-key block\nrstr: line 2: sha256=398becb07111d94b; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 4 container 1 LF","family":"parity","input":"n\"-----BEGIN B PRIVATE KEY-----\"-----END B PRIVATE KEY-----\"\"\"x\"y\"\n\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\nafter\n","expected":"n\"[REDACTED sha256=fe11d27c55dad0f8]\"\"\"x\"y\"\n\"[REDACTED sha256=5538282a7c9a4dc1]\nafter\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=fe11d27c55dad0f8; private-key block\nrstr: line 2: sha256=5538282a7c9a4dc1; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 4 container 1 CRLF","family":"parity","input":"n\"-----BEGIN B PRIVATE KEY-----\"-----END B PRIVATE KEY-----\"\"\"x\"y\"\r\n\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\r\nafter\r\n","expected":"n\"[REDACTED sha256=fe11d27c55dad0f8]\"\"\"x\"y\"\r\n\"[REDACTED sha256=5538282a7c9a4dc1]\r\nafter\r\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=fe11d27c55dad0f8; private-key block\nrstr: line 2: sha256=5538282a7c9a4dc1; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 4 container 2 LF","family":"parity","input":"n\"-----BEGIN B PRIVATE KEY-----\"-----END B PRIVATE KEY-----\"\"\"x\"y\"\n\"{\"kind\":\"Secret\",\"data\":{\"tls.crt\":\"SYNTHETIC_R7_FINDING_CANARY\"}}\nafter\n","expected":"n\"[REDACTED sha256=fe11d27c55dad0f8]\"\"\"x\"y\"\n\"[REDACTED sha256=fac61d235726ebee]\nafter\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=fe11d27c55dad0f8; private-key block\nrstr: line 2: sha256=fac61d235726ebee; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"PEM parity prefix 4 container 2 CRLF","family":"parity","input":"n\"-----BEGIN B PRIVATE KEY-----\"-----END B PRIVATE KEY-----\"\"\"x\"y\"\r\n\"{\"kind\":\"Secret\",\"data\":{\"tls.crt\":\"SYNTHETIC_R7_FINDING_CANARY\"}}\r\nafter\r\n","expected":"n\"[REDACTED sha256=fe11d27c55dad0f8]\"\"\"x\"y\"\r\n\"[REDACTED sha256=fac61d235726ebee]\r\nafter\r\n","report":"rstr: 2 redactions; labels describe local syntax evidence, not credential validity.\nrstr: line 1: sha256=fe11d27c55dad0f8; private-key block\nrstr: line 2: sha256=fac61d235726ebee; credential container\n","batch_error":null,"protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":false},
{"name":"container probe 0 alone","family":"control","input":"x\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\nafter\n","expected":"x\" {\"kty\":\"oct\",\"k\":\"SYNTHETIC_R7_FINDING_CANARY\"}x\"\nafter\n","report":"","batch_error":null,"protected":[],"withhold":false},
{"name":"container probe 1 alone","family":"control","input":"\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\nafter\n","expected":"\"{\"auths\":{\"r\":{\"auth\":\"SYNTHETIC_R7_FINDING_CANARY\"}}}\nafter\n","report":"","batch_error":null,"protected":[],"withhold":false},
{"name":"container probe 2 alone","family":"control","input":"\"{\"kind\":\"Secret\",\"data\":{\"tls.crt\":\"SYNTHETIC_R7_FINDING_CANARY\"}}\nafter\n","expected":"\"{\"kind\":\"Secret\",\"data\":{\"tls.crt\":\"SYNTHETIC_R7_FINDING_CANARY\"}}\nafter\n","report":"","batch_error":null,"protected":[],"withhold":false},
{"name":"deferred invalid EOF 0","family":"deferred","input":"dsn=\"host=db dbname=app user=app password=\"\nINFO started \"ok\"\npassword=\"\\qSYNTHETIC_R7_FINDING_CANARY\"\n","expected":null,"report":"","batch_error":"unsupported quoted-value escape. Use documented escapes and retry.","protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"deferred invalid EOF 1","family":"deferred","input":"{\"conn\":\"AccountName=dev;AccountKey=\"}\n{\"msg\":\"ok\"}\npassword=\"\\qSYNTHETIC_R7_FINDING_CANARY\"\n","expected":null,"report":"","batch_error":"unsupported quoted-value escape. Use documented escapes and retry.","protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true},
{"name":"deferred invalid EOF 2","family":"deferred","input":"-----BEGIN A PRIVATE KEY-----END A PRIVATE KEY-----\nstatus=ok\npassword=SYNTHETIC_R7_FINDING_CANARY\n","expected":null,"report":"","batch_error":"line 1: unterminated private-key block. Add its matching END marker and retry.","protected":["SYNTHETIC_R7_FINDING_CANARY"],"withhold":true}
]"###).must()
}

struct Reads<'a> {
    input: &'a [u8],
    position: usize,
    cuts: Vec<usize>,
    size: usize,
    interrupt: bool,
}

impl Read for Reads<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.interrupt && self.position == self.input.len() {
            return Err(io::Error::other("synthetic interrupted producer"));
        }
        let end = self
            .cuts
            .iter()
            .copied()
            .find(|cut| *cut > self.position)
            .unwrap_or(self.input.len());
        let count = (end - self.position).min(output.len()).min(self.size);
        output[..count].copy_from_slice(&self.input[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

#[derive(PartialEq, Eq)]
struct Outcome {
    output: Vec<u8>,
    report: Vec<u8>,
    error: Option<SafeError>,
}

fn streamed(input: &[u8], cuts: Vec<usize>, size: usize, interrupt: bool) -> Outcome {
    let mut output = Vec::new();
    let mut report = Vec::new();
    let error = match filter_to_writer(
        Reads {
            input,
            position: 0,
            cuts,
            size,
            interrupt,
        },
        &mut output,
    ) {
        Ok(metadata) => {
            metadata.write(&mut report).must();
            None
        }
        Err(error) => Some(error),
    };
    Outcome {
        output,
        report,
        error,
    }
}

fn line_ends(input: &[u8]) -> Vec<usize> {
    input
        .iter()
        .enumerate()
        .filter_map(|(at, byte)| (*byte == b'\n').then_some(at + 1))
        .collect()
}

fn schedule(input: &[u8], cuts: &[usize]) -> Vec<usize> {
    let mut cuts: Vec<_> = cuts.iter().map(|cut| cut % (input.len() + 1)).collect();
    cuts.sort_unstable();
    cuts.dedup();
    cuts
}

fn approved_batch(input: &[u8]) -> Result<(String, Vec<u8>), SafeError> {
    let filtered = filter_with_evidence(input)?;
    let mut metadata = redact::RedactionReport::default();
    let mut report = Vec::new();
    metadata.observe(&filtered.redactions, 1).must();
    metadata.write(&mut report).must();
    Ok((filtered.output, report))
}

fn check_case(case: &StateCase) -> Outcome {
    let batch = approved_batch(case.input.as_bytes());
    if let Some(expected) = &case.expected {
        let (output, report) = batch.must();
        assert!(
            output == *expected && report == case.report.as_bytes(),
            "batch changed pinned spans/evidence for {}",
            case.name
        );
    } else {
        assert!(
            batch.must_err().to_string() == *case.batch_error.as_ref().must(),
            "batch changed pinned failure for {}",
            case.name
        );
    }
    let whole = streamed(case.input.as_bytes(), Vec::new(), usize::MAX, false);
    match &case.expected {
        Some(expected) => {
            assert!(
                whole.error.is_none(),
                "batch-success input failed in stream for {}",
                case.name
            );
            assert!(
                whole.output == expected.as_bytes(),
                "stream changed pinned spans for {}",
                case.name
            );
            assert!(
                whole.report == case.report.as_bytes(),
                "stream changed pinned evidence for {}",
                case.name
            );
        }
        None => {
            let batch = approved_batch(case.input.as_bytes()).must_err();
            let error = whole.error.as_ref().must();
            assert!(
                error.kind == batch.kind,
                "stream changed failure category for {}",
                case.name
            );
            assert!(
                whole.output.is_empty() && whole.report.is_empty(),
                "failed held input was released for {}",
                case.name
            );
        }
    }
    for canary in &case.protected {
        assert!(
            !whole
                .output
                .windows(canary.len())
                .any(|bytes| bytes == canary.as_bytes())
        );
        assert!(!String::from_utf8_lossy(&whole.report).contains(canary));
        if let Some(error) = &whole.error {
            assert!(!format!("{error:?} {error}").contains(canary));
        }
    }
    whole
}

#[test]
fn private_marker_json_parity_and_connection_cases_pin_actual_batch_spans_and_evidence() {
    for case in cases() {
        let whole = check_case(&case);
        for split in 0..=case.input.len() {
            assert!(
                streamed(case.input.as_bytes(), vec![split], usize::MAX, false) == whole,
                "{} changed at split {split}",
                case.name
            );
        }
        for size in [1, 2, 7, 31] {
            assert!(
                streamed(case.input.as_bytes(), Vec::new(), size, false) == whole,
                "{} changed at size {size}",
                case.name
            );
        }
        assert!(
            streamed(
                case.input.as_bytes(),
                line_ends(case.input.as_bytes()),
                usize::MAX,
                false
            ) == whole,
            "{} changed on line reads",
            case.name
        );
    }
}

#[test]
fn unfinished_candidate_input_errors_withhold_output_and_fingerprints_at_every_split() {
    for input in [
        "'\\-----END A PRIVATE KEY-----\"'\n",
        "'\\-----BEGIN A PRIVATE KEY-----\nMII\n-----END A PRIVATE KEY-----\"'\n",
        "-----BEGIN A PRIVATE KEY-----BEGIN B PRIVATE KEY-----\nMII\n-----END A PRIVATE KEY-----x\"\n-----END B PRIVATE KEY-----\n",
        "{\"conn\":\"AccountName=dev;AccountKey=\"}\n",
        "dsn=\"host=db dbname=app user=app password=\"\n",
        "-----BEGIN A PRIVATE KEY-----END A PRIVATE KEY-----\nstatus=ok\n",
    ] {
        let input = format!("status=200\n{input}");
        let whole = streamed(input.as_bytes(), Vec::new(), usize::MAX, true);
        let error = whole.error.as_ref().must();
        assert_eq!(error.kind, ErrorKind::Input);
        assert!(error.earlier_output_emitted);
        assert!(whole.output == b"status=200\n" && whole.report.is_empty());
        assert!(!format!("{error:?} {error}").contains(CANARY));
        for split in 0..=input.len() {
            assert!(
                streamed(input.as_bytes(), vec![split], usize::MAX, true) == whole,
                "interrupted held candidate changed across splits"
            );
        }
        for size in [1, 7, 31] {
            assert!(streamed(input.as_bytes(), Vec::new(), size, true) == whole);
        }
    }
}

#[test]
fn deferred_invalid_eof_preserves_only_prior_filtered_output_and_global_error_metadata() {
    for case in cases().into_iter().filter(|case| case.expected.is_none()) {
        let input = format!("status=200\n{}", case.input);
        let whole = streamed(input.as_bytes(), Vec::new(), usize::MAX, false);
        let error = whole.error.as_ref().must();
        let batch = approved_batch(case.input.as_bytes()).must_err();
        assert!(error.kind == batch.kind);
        assert_eq!(error.line, Some(batch.line.map_or(2, |line| line + 1)));
        assert!(error.earlier_output_emitted);
        assert!(whole.output == b"status=200\n" && whole.report.is_empty());
        assert!(!format!("{error:?} {error}").contains(CANARY));
        for split in 0..=input.len() {
            assert!(streamed(input.as_bytes(), vec![split], usize::MAX, false) == whole);
        }
        for size in [1, 7, 31] {
            assert!(streamed(input.as_bytes(), Vec::new(), size, false) == whole);
        }
    }
}

#[test]
fn staged_detector_holds_emit_no_bytes_or_fingerprints_and_preserve_final_cli_results() {
    let records: Vec<_> = cases().into_iter().map(|case| {
        let result = check_case(&case);
        let stderr = result.error.as_ref().map_or_else(
            || String::from_utf8(result.report).must(),
            |error| format!("rstr: {error}\n"),
        );
        serde_json::json!({"name":case.name,"input":case.input,"expected":String::from_utf8(result.output).must(),"stderr":stderr,"exit":if result.error.is_some(){2}else{0},"withhold":case.withhold,"protected":case.protected})
    }).collect();
    let output = Command::new("python3").env_clear().env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .args(["-c", r#"
import json, os, select, subprocess, sys
for case in json.loads(sys.argv[2]):
    p = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={})
    emitted = b''
    try:
        for line in case['input'].splitlines(keepends=True):
            p.stdin.write(line.encode()); p.stdin.flush()
            ready = select.select([p.stdout, p.stderr], [], [], .01)[0]
            if case['withhold']:
                assert not ready and p.poll() is None, 'unfinished detector candidate released bytes/metadata: ' + case['name']
            else:
                assert p.stderr not in ready, 'report/error was published before EOF'
                if p.stdout in ready:
                    part = os.read(p.stdout.fileno(), 8192)
                    assert part, 'filter exited before EOF'
                    emitted += part
                    assert case['expected'].encode().startswith(emitted), 'staged prefix differs from batch'
        p.stdin.close(); p.stdin = None
        out, err = p.communicate(timeout=5)
        assert p.returncode == case['exit'], 'final status differs from batch'
        assert emitted + out == case['expected'].encode(), 'final output differs from batch'
        assert err == case['stderr'].encode(), 'final report/error differs from library'
        for canary in case['protected']:
            assert canary.encode() not in emitted + out + err, 'staged detector hold disclosed a canary'
    finally:
        if p.poll() is None: p.kill(); p.wait()
"#, env!("CARGO_BIN_EXE_rstr"), &serde_json::to_string(&records).must()]).output().must();
    assert!(
        output.status.success(),
        "detector-state staged CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn probe(kind: usize, canary: &str) -> String {
    match kind {
        0 => format!("x\" {{\"kty\":\"oct\",\"k\":\"{canary}\"}}x\"\nafter\n"),
        1 => format!("\"{{\"auths\":{{\"r\":{{\"auth\":\"{canary}\"}}}}}}\nafter\n"),
        _ => format!("\"{{\"kind\":\"Secret\",\"data\":{{\"tls.crt\":\"{canary}\"}}}}\nafter\n"),
    }
}

fn state_grammar() -> impl Strategy<Value = String> {
    (
        0usize..9,
        prop::sample::select(vec!["\n", "\r\n", "\r"]),
        (0usize..5, 0usize..4, any::<bool>()),
        (
            prop::sample::select(vec!["A", "RSA", "OPENSSH"]),
            prop::sample::select(vec!["B", "EC", "ENCRYPTED"]),
        ),
        (0usize..3, any::<bool>()),
        "[a-z0-9秘密é_-]{1,16}",
    )
        .prop_map(
            |(kind, eol, (slashes, quotes, later), (first, second), (tail, spacing), suffix)| {
                let canary = format!("{CANARY}_{suffix}");
                let pb = format!("-----BEGIN {first} PRIVATE KEY-----");
                let pe = format!("-----END {first} PRIVATE KEY-----");
                let qb = format!("-----BEGIN {second} PRIVATE KEY-----");
                let qe = format!("-----END {second} PRIVATE KEY-----");
                let slash = "\\".repeat(slashes);
                let body_quote = "\"".repeat(quotes);
                let gap = if spacing { " " } else { "" };
                let mut input = match kind {
                    0 => format!("'{slash}{pe}\"'\n"),
                    1 => format!("'{slash}{pb}\nMII{body_quote}synthetic\n{pe}\"'\n"),
                    2 => format!("\"{slash}{pe}\"x\"\n"),
                    3 => format!(
                        "{pb}BEGIN {second} PRIVATE KEY-----\nMII{body_quote}\n{pe}x\"\n{qe}\n"
                    ),
                    4 => format!("n\"{pb}{body_quote}{pe}\"\"\"x\"y\"\n"),
                    5 => format!("{pb}{gap}{qb}\nMII{body_quote}\n{pe}x\"\n{qe}\n"),
                    6 => "{\"conn\":\"AccountName=dev;AccountKey=\"}\n".to_string(),
                    7 => "dsn=\"host=db dbname=app user=app password=\"\n".to_string(),
                    _ => format!("{pb}END {first} PRIVATE KEY-----\nstatus=ok\n"),
                };
                if kind >= 6 {
                    if later {
                        input.push_str(&format!("INFO started \"{canary}\"\n"));
                        if kind == 8 {
                            input.push_str(&format!("{pe}\n"));
                        }
                    }
                    input.push_str(&format!("password='{canary}'\n"));
                } else {
                    input.push_str(&probe(tail, &canary));
                }
                input.replace('\n', eol)
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 384, failure_persistence: None, ..ProptestConfig::default() })]
    #[test]
    fn generic_batch_success_requires_stream_success_and_exact_evidence(
        input in state_grammar(),
        size in 1usize..128,
        cuts in prop::collection::vec(0usize..4096, 0..12),
    ) {
        let whole = streamed(input.as_bytes(), Vec::new(), usize::MAX, false);
        if let Ok((expected, report)) = approved_batch(input.as_bytes()) {
            prop_assert!(whole.error.is_none(), "batch-success private/connection grammar failed in stream");
            prop_assert!(whole.output == expected.as_bytes(), "private/connection grammar changed exact batch spans");
            prop_assert!(whole.report == report, "private/connection grammar changed exact batch evidence");
        }
        if let Some(error) = &whole.error { prop_assert!(!format!("{error:?} {error}").contains(CANARY), "safe error exposed a synthetic canary"); }
        for result in [streamed(input.as_bytes(), Vec::new(), 1, false), streamed(input.as_bytes(), line_ends(input.as_bytes()), usize::MAX, false), streamed(input.as_bytes(), schedule(input.as_bytes(), &cuts), size, false)] {
            prop_assert!(result == whole, "private/connection grammar changed status/output/evidence across reads");
        }
    }

    #[test]
    fn pinned_detector_state_cases_preserve_generated_read_schedules(
        index in 0usize..68,
        size in 1usize..128,
        cuts in prop::collection::vec(0usize..4096, 0..12),
    ) {
        let case = cases().into_iter().nth(index).must();
        let whole = check_case(&case);
        prop_assert!(streamed(case.input.as_bytes(), schedule(case.input.as_bytes(), &cuts), size, false) == whole, "pinned detector state changed across generated reads");
    }
}
