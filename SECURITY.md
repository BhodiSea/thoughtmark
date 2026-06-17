<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security Policy

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.** thoughtmark is a cryptographic integrity library; a
disclosed defect in canonicalization, hashing, Merkle/consistency proofs, or signature verification can undermine
every downstream guarantee.

Report privately via **GitHub Security Advisories** ("Report a vulnerability" on the repository's *Security* tab).
If you cannot use that channel, contact the maintainers listed in `CITATION.cff`.

Please include: affected version(s) and corpus `VERSION`, a reproduction (ideally a `spec/vectors/` case or a
failing conformance diff), and the impact (which invariant — I1–I8 — is affected).

## Coordination

For vulnerabilities in a dependency we will coordinate with **RUSTSEC** / the upstream maintainers and, where a
fix changes hashed bytes, follow the format-identifier evolution rule (old artifacts remain verifiable; unknown
versions FAIL CLOSED).

## Scope

In scope: anything that breaks **integrity-of-record** (byte-identity divergence across Rust/WASM/TS, a malleable
signature accepted, an invalid inclusion/consistency proof accepted, ambient nondeterminism on the hashed path).
Out of scope: claims about **validity** or **faithfulness** of notarized content — by design the system does not
make those claims (see `docs/threat-model.md`).

## Supported versions

Pre-1.0 (Phase 0–2): only the latest `main` is supported. A support policy is published at the 1.0 freeze.
