# Conformance corpus — CHANGELOG

The corpus is versioned independently from the code (its own SemVer in `VERSION`). This log is **append-only**.
**Changing any expected value (e.g. an expected hash or expected bytes) is a BREAKING change** and requires a
MAJOR corpus release. Three version axes are never conflated: code SemVer, corpus SemVer, and the format
identifiers baked into hashed bytes (arch P4).

## [0.0.0] — Phase 0 (unreleased)

- Initial skeleton. Every non-negative operation has at least one vector whose expected output is the canonical
  `NOT_IMPLEMENTED` envelope (SPEC.md §4). One negative vector asserts the stable error code.
- No real expected hashes yet; those arrive with Tier-0 logic in Phase 1 (`canon`, `hash`, `cid`).
