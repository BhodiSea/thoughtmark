# The conformance corpus

`spec/vectors/` is the executable spec. Every case carries a stable `vector_id`, a `spec_req` traced to SPEC.md,
and an expected output. A required CI job runs the corpus through the native Rust core **and** the compiled
WASM/TS binding and asserts byte-equality of every output (CORE-1/CORE-2). The corpus is versioned independently
(its own SemVer in `spec/vectors/VERSION`); changing any expected value is a breaking spec change.
