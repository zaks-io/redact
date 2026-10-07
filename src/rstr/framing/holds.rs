pub(super) enum HoldReason {
    PrivateKey,
    Yaml,
    Quote,
    Container,
    Ambiguous,
    Unfinished,
}

impl HoldReason {
    pub(super) fn diagnostic(self) -> &'static str {
        match self {
            Self::PrivateKey => {
                "unfinished record exceeds 16 MiB while holding a private-key block. Add its matching END marker or use smaller complete input and retry."
            }
            Self::Yaml => {
                "unfinished record exceeds 16 MiB while holding a YAML-like document. Finish at a document boundary or EOF; use smaller complete documents and retry."
            }
            Self::Quote => {
                "unfinished record exceeds 16 MiB while holding a quoted value. Close its quote or use smaller complete input and retry."
            }
            Self::Container => {
                "unfinished record exceeds 16 MiB while holding a container. Close its delimiters or use smaller complete input and retry."
            }
            Self::Ambiguous => {
                "unfinished record exceeds 16 MiB while holding an ambiguous assignment. Its context must remain together through EOF; use smaller complete input and retry."
            }
            Self::Unfinished => {
                "unfinished record exceeds 16 MiB while holding an unfinished line or assignment. Finish its line or value, or use smaller complete input and retry."
            }
        }
    }
}
