# Integrity, not validity

thoughtmark proves **integrity-of-record** — that a record existed at a time, in a lineage, unaltered since
capture; that a log is append-only; and that a signature binds a record to a signer. It does **not** prove
validity, faithfulness, split-view resistance without witnesses, or truth-at-capture.

See the full [threat model](https://github.com/OWNER/thoughtmark/blob/main/docs/threat-model.md). Never let a
green check be read as a claim about the content being notarized.
