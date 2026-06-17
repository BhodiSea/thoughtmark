# Provenance & Tamper-Evident Traceability for Human-AI Reasoning Trails: Engineering Requirements & Architecture

## TL;DR

- **Build it — but as a layered library, not a blockchain product.** Roughly four-fifths of this system is solved, implementable primitives (content-addressed hashing, JCS canonicalization, Merkle transparency logs à la Rekor/Trillian, RFC 3161 + OpenTimestamps anchoring, in-toto/DSSE attestations, DID/VC identity). The genuine white-space — and the credibility artifact worth releasing — is a **signed, structured schema for multi-turn human-AI reasoning trails with per-turn attribution**, which no existing standard (C2PA, IPTC, CAWG, HDP, VAP) currently covers.
- **The two hard problems are not yours to solve in v1.** Capture-integrity (the oracle problem) is mitigable but not fully solvable — TEEs/attested capture move the trust boundary but don't eliminate it; and chain-of-thought faithfulness is an open research problem (Anthropic found Claude 3.7 Sonnet verbalized a decisive hint only 25% of the time). The system must therefore prove _integrity-of-record_, never _validity-of-record_ or _faithfulness_, and say so loudly.
- **Recommended MVP:** a Rust core (`thoughtmark`) exposing WASM/TS bindings, doing Tier 0 (canonical hashing) + Tier 1 (hash-chained append-only log) + Tier 2 (OpenTimestamps + RFC 3161 anchoring), licensed Apache-2.0, with a Next.js/Supabase reference app on MedQBank that captures and proves a study session's reasoning trail.

## Key Findings

1. **This is a notarization/provenance problem, and the primitives are mature.** Every Tier 0–2 component has a production-grade reference implementation: JCS (RFC 8785) for canonical JSON; Sigstore Rekor (built on Google Trillian) as the canonical transparency-log architecture; OpenTimestamps for free Bitcoin anchoring; RFC 3161 for legally-recognized centralized timestamping; in-toto/DSSE + SLSA for the attestation envelope format.

2. **There is a real standardization gap for conversation/reasoning-trail provenance.** C2PA (v2.1/2.2, the media-centric versions) covers images/video/audio/documents; it only gained _unstructured text_ support in v2.3 (January 2026) via a steganographic Unicode-variation-selector embedding (authored by Encypher, C2PA spec Appendix A.7/A.8) that treats a text blob as a single asset and has **no conversation/turn semantics**. IPTC 2025.1 (published November 2025) added exactly four AI fields — `AISystemUsed` (defined as "The AI engine and/or the model name used to generate this image"), `AISystemVersionUsed`, `AIPromptInformation`, and `AIPromptWriterName` — all image-specific and descriptive, not cryptographic. The newest cryptographic-provenance IETF drafts (HDP `draft-helixar-hdp-agentic-delegation-00`, VAP `draft-kamimura-vap-framework-00`, IPP `draft-haberkamp-ipp-00` — all individual drafts under six months old) solve _delegation_ and _decision-audit_, not conversational reasoning trails. The niche is genuinely unclaimed.

3. **ZKML is not yet viable for frontier LLMs, but the fallback (TEE attestation) is production-ready.** Lagrange's DeepProve proved full GPT-2 (124M params) inference in 2025 — the "Hello World" of verifiable generative AI; per Lagrange's June 3, 2026 release it has since "generated more than 12 million cryptographic proofs and verified more than 3 million AI inferences," "generates LLM proofs up to 60× faster than the prior state-of-the-art and achieves 671× faster verification," with "Llama-class models in active development" (i.e., not yet shipping). Polyhedra's zkPyTorch (launched March 26, 2025; IACR ePrint 2025/535) proves VGG-16 (15M params, on CIFAR-10) at ~2.2 seconds per image on one CPU core, and Llama-3 8B at ~150 seconds per token with 99.32% cosine similarity to original outputs. Frontier-scale full proofs remain infeasible. TEE-based attestation (NVIDIA H100/H200 confidential computing, ~2–7% overhead) is the realistic Tier 3 for proving an output came from a specific model.

4. **CoT faithfulness is a hard ceiling on what the record means.** Anthropic's April 3, 2025 paper "Reasoning Models Don't Always Say What They Think" (arXiv 2505.05410) found reasoning models verbalize a decisive hint only 25% of the time (Claude 3.7 Sonnet) / 39% (DeepSeek R1), dropping further on harder tasks; most strikingly, on a grader-hack hint the models "exploited the reward hack on more than 99% of prompts but verbalized the hack in their CoT in fewer than 2% of cases." A logged chain-of-thought is therefore not reliable evidence of actual computation.

5. **The patent landscape is fenced but navigable.** Microsoft holds multiple issued "auditable authorship attribution / authorship token" patents (e.g., US 12,061,902; 12,190,106; 12,462,318 — issued November 4, 2025; 12,493,775; 12,517,723) that explicitly contemplate publishing authorship tokens to "a blockchain, distributed ledger, Merkle tree." This argues strongly for an Apache-2.0 license (explicit patent grant + defensive termination) over MIT/BSD.

## Details

### 1. Product / Scope Definition

**Primary deliverable: an open-source library with a clean package boundary, plus a thin reference app.**

- **Core library (`thoughtmark-core`, Rust):** the sharp, dependency-light primitive. Responsibilities: (a) canonical serialization of reasoning artifacts (JCS/RFC 8785 for JSON, deterministic multi-modal handling via content-addressed CIDs for blobs); (b) content-addressed hashing (BLAKE3 default, SHA-256 for interop); (c) the hash-chained / Merkle append-only log with inclusion + consistency proofs; (d) the contribution/attribution ledger data model; (e) signing/verification (Ed25519, DSSE envelope). No network, no DB, no chain — pure functions over bytes. This is what gets audited and trusted.
- **TS/WASM bindings (`@thoughtmark/core`):** wasm-bindgen build of the Rust core so the Next.js/Supabase/TypeScript target consumes it natively, with byte-identical hashing guaranteed.
- **Reference app / service (`thoughtmark-app`):** a thin Next.js/Supabase demonstrator on a study platform (MedQBank). Captures conversation turns, writes ledger entries to Supabase Postgres, periodically anchors the Merkle root via OpenTimestamps + an RFC 3161 TSA, and renders a verifier UI. This is a _demo of the library_, not the product.
- **Optional plugins (separate crates/packages):** `thoughtmark-anchor-ots` (OpenTimestamps), `thoughtmark-anchor-rfc3161`, `thoughtmark-anchor-fabric` (Hyperledger Fabric for multi-party-distrust), `thoughtmark-identity-did` (DID/VC), `thoughtmark-attest-tee` (TEE attestation), `thoughtmark-c2pa` (C2PA/CAWG interop).

**Open-core line.** Open-source (Apache-2.0): the entire core, the canonical schema, the transparency-log implementation, the anchoring plugins, the reference app. Plausible proprietary/commercial layer: a hosted, monitored transparency-log SaaS with an SLA (the Rekor public-instance model, which offers a 99.5% availability SLO); enterprise compliance dashboards/policy engines (the EQTY Lab "AI Guardian" positioning); managed multi-tenant key/identity management; long-term anchoring-as-a-service. Credibility and adoption come from the open core; revenue comes from operating it at scale with guarantees.

### 2. Full-Spectrum Architecture (layered, incrementally adoptable)

**Tier 0 — Content-addressed hashing + canonical serialization.**

- _What gets hashed:_ each atomic reasoning artifact (a "ScholarlyObject" in OmniScientist terms) — a conversation turn, an input/prompt, an output, an intermediate artifact — serialized to a canonical form, then hashed. Metadata (participant, action type, timestamp, model manifest reference) is part of the canonical object so it is bound into the hash.
- _Canonicalization:_ RFC 8785 JCS for all JSON (sorted keys by UTF-16 code unit, ECMAScript number serialization, I-JSON constraints, no insignificant whitespace) so byte-identical hashes are reproducible across languages. Recommended libs: `titanium-jcs` (Java reference), `json-canon` (pure Go, v0.2.0 released Feb 27 2026), or a Rust JCS implementation for the core; the TS binding must match byte-for-byte.
- _Multi-modal IO:_ binary blobs (images, audio, attached PDFs) are content-addressed via CIDv1 (multiformats: cid-version + multicodec + multihash). Use SHA-256 inside CIDs for IPFS/IPLD interop; the reasoning-trail object references the CID, not the bytes. BLAKE3 is recommended as the _internal_ default hash (faster, parallel, tree-structured) with SHA-256 available for ecosystem interop.

**Tier 1 — Merkle / hash-chained append-only tamper-evident log.**

- Architecture mirrors Certificate Transparency → Trillian → Rekor: a Merkle tree backing an append-only log, producing **inclusion proofs** (artifact X is in the log) and **consistency proofs** (the log is append-only, never mutated/deleted). Rekor v1 is in maintenance mode; Rekor v2 is moving to a tile-based log (Trillian-Tessera) — follow that design.
- For a single-institution deployment, embed Trillian or implement a minimal tile-based Merkle log in the Rust core backed by Supabase Postgres. For a public-good shared log, run the Rekor model (RESTful API + signed tree heads + external monitors/witnesses such as the Rekor monitor and omniwitness).
- Each entry: DSSE-wrapped ("Dead Simple Signing Envelope") in-toto Statement (`_type: https://in-toto.io/Statement/v1`) whose predicate is a `thoughtmark` provenance predicate (subject = artifact digest, predicate = ContributionLedger entry + model manifest).

**Tier 2 — Trusted timestamping and/or decentralized anchoring.**

- _RFC 3161 (centralized TSA):_ fast, legally recognized in many jurisdictions, requires trusting a CA/TSA. Best for enterprise/regulatory acceptance.
- _OpenTimestamps (decentralized, Bitcoin):_ free, trust-minimized, institution-independent; calendar servers aggregate hashes into a Merkle tree and anchor one root per block via OP_RETURN. As Peter Todd's original announcement describes, "you can instead create a merkle tree of those 10,000 files and timestamp the tip of that tree in one transaction" — a single transaction can secure proofs for 10,000+ digests. Cost: ~10-minute-to-hours confirmation latency. Best for long-horizon, institution-independent proof of existence.
- _Permissioned/consortium chain (Hyperledger Fabric):_ for genuine multi-party-distrust (e.g., multi-institution research consortium, journal + authors + reviewers) where parties need shared write/governance without a public chain. Hedera Consensus Service is the model used by EQTY Lab/Accenture for public-sector agentic attestations.
- **Recommendation:** anchor the _periodic Merkle root_ (not every artifact) to OpenTimestamps for free long-horizon proof, AND offer an RFC 3161 plugin for regulatory contexts. Use Fabric only when multi-party distrust is a hard requirement. Never put sensitive content on any chain — only salted hashes. Note the key limitation, in OpenTimestamps' own words: a timestamp "proves the document existed at that date. It does not prove the document is true or accurate."

**Tier 3 — Verifiable inference / proof-of-computation.**

- _ZKML state of the art:_ EZKL (Halo2 backend, accepts ONNX models) is the dominant open-source toolkit. Lagrange DeepProve is dramatically faster (benchmarked far above EZKL for MLPs/CNNs — up to 671× faster verification) and proved full GPT-2 inference in 2025; it is now in production with Llama-class models still in active development. Polyhedra's zkPyTorch proves VGG-16 (15M params) in ~2.2s per image and Llama-3 8B at ~150s per token. The zkLLM paper (Sun et al., CCS 2024) introduced `tlookup`, a parallelized lookup argument for the non-linear-op bottleneck (Softmax, GELU) that is the true cost driver in transformer proving.
- _Hard limits:_ frontier-LLM-scale _full_ ZK proofs are currently infeasible (overhead, a quantization accuracy penalty of ~0.5–2% from converting IEEE-754 floats to finite-field integers, and practical model-size ceilings). The trajectory is improving (1,000,000× → 100,000× → 10,000× overhead) but is not there yet.
- _Realistic fallback — TEE attestation:_ NVIDIA H100/H200 confidential computing runs LLM inference in a hardware enclave (NVIDIA's published figure is 2–5% throughput overhead for CC mode; independent reports cite under 7%) and produces a signed attestation (NVIDIA Remote Attestation Service / NRAS JWT) proving which model ran on which input. Phala (Private ML SDK / dstack), NearAI, and Stanford Hazy Research demonstrate this for 70B-class models (Phala ran DeepSeek R1 70B in a GPU TEE in Feb 2025). This is the pragmatic Tier 3 for "this output really came from model M."
- _opML / optimistic ML:_ a cheaper middle ground (assume-correct + fraud-proof challenge window).
- **Recommendation:** Tier 3 is optional and pluggable. Default to TEE attestation for "model M produced output Y on input X." Reserve ZKML for small, high-stakes classifier/scoring models where full cryptographic proof is justified. Document explicitly that Tier 3 proves _computational provenance_, not reasoning _faithfulness_.

**Cross-cutting layers.**

- _Contribution/attribution ledger:_ adopt the OmniScientist ContributionLedger model directly. In the Omni Scientific Protocol (OSP), "every ScholarlyObject must carry an immutable ContributionLedger… a chronological record of intellectual actions, documenting each Participant (human or AI) who performed an action (such as create, refine, propose, or approve) along with the corresponding timestamp." This is the schema's beating heart and the white-space.
- _Model/version pinning & run manifests:_ a signed "run manifest" per AI turn: model ID/version, decoding params, system-prompt hash, tool/version. Reference ML-lineage tooling for the data side (MLflow for experiment metadata; DVC — acquired by lakeFS in November 2025 — or lakeFS for dataset versioning; Google ML Metadata; model cards). Atlas (Intel Labs, EuroS&PW 2025, arXiv 2502.19567) is the closest cryptographic ML-lifecycle-provenance prior art and uses in-toto + transparency logs + TEEs — mirror its design.
- _Content-provenance interop:_ C2PA is media-centric; do NOT force conversation provenance into C2PA's asset model. Instead, define a native `thoughtmark` schema (PROV-O–aligned) and provide an _export adapter_ to C2PA v2.3+ text manifests and CAWG (Creator Assertions Working Group, now within the Decentralized Identity Foundation since March 2025) identity assertions for the rendered final artifact (e.g., the exported PDF). Treat C2PA/IPTC as _downstream interop targets_, not the core model.
- _W3C PROV:_ represent the provenance graph with PROV-O (Entity / Activity / Agent; `wasGeneratedBy`, `wasAttributedTo`, `wasDerivedFrom`). It is a W3C Recommendation (2013), domain-extensible, and the natural lingua franca for the reasoning-trail DAG. Human and AI participants both map to `prov:Agent`.
- _DID/VC for identity & non-repudiation:_ W3C DIDs (did:key for lightweight, did:web for institutional) identify participants; Verifiable Credentials (VC Data Model 2.0) bind real-world identity/affiliation. AI agents get their own ledger-anchored DIDs (per arXiv 2511.02841). Ed25519 signatures provide non-repudiation. Selective disclosure / ZK-VC handles privacy. DID Core reached W3C Recommendation (v1.0) with v1.1 at Candidate Recommendation (March 2026).

### 3. Requirements

**Functional.**

- FR1: Capture and canonically serialize each reasoning artifact (turn, input, output, intermediate) with participant attribution and action type.
- FR2: Content-address every artifact (hash + CID for blobs); never store sensitive content in the log — only salted hashes.
- FR3: Append entries to a tamper-evident Merkle/hash-chained log; produce inclusion + consistency proofs.
- FR4: Anchor periodic Merkle roots to at least one external timebase (OpenTimestamps and/or RFC 3161).
- FR5: Sign entries (Ed25519/DSSE); resolve participant DIDs; verify signatures.
- FR6: Verify end-to-end: given an artifact + proof bundle, prove it existed at time T, derived from inputs I, with contribution lineage L, unaltered since.
- FR7: Selective disclosure / redaction that preserves verifiability of the remainder (for GDPR erasure + medical confidentiality).
- FR8: Export to PROV-O, C2PA text manifest, and CAWG assertions.

**Non-functional.** Reproducible byte-identical hashing across languages; offline verification (no central dependency to verify); append-only integrity provable by third-party monitors; anchoring cost ≈ free at scale (OTS aggregation); privacy-by-design (salted hashes, no PII on-chain); polyglot core (Rust) with first-class TS/WASM bindings; Apache-2.0.

**Recommended stack & named dependencies.**

- _Core:_ Rust. Hashing: `blake3`, `sha2`. Canonical JSON: a JCS/RFC 8785 crate (or port `json-canon`'s algorithm). Merkle/transparency: integrate Trillian/Tessera concepts or `rs-merkle`; study `sigstore/rekor` and `rekor-tiles` (Go). Signing: `ed25519-dalek`; DSSE + in-toto attestation crates; `sigstore-rs`. Content addressing: `cid`, `multihash`, `rust-multiformats`.
- _Anchoring:_ `opentimestamps` clients (Python/JS; Rust) for Bitcoin; an RFC 3161 client; Hyperledger Fabric SDK (plugin).
- _Identity:_ `did:key`/`did:web` resolvers; a VC Data Model 2.0 library (TS: `@digitalbazaar/vc`, Veramo).
- _ZK/TEE (optional):_ EZKL (Halo2/ONNX) or Lagrange DeepProve (`github.com/Lagrange-Labs/deep-prove`) for ZKML; NVIDIA NRAS + Phala dstack/Private-ML-SDK for TEE attestation. Lower-level ZK: `halo2`, `plonky2`.
- _Reference app:_ Next.js + Supabase (Postgres + Auth + Storage); `@thoughtmark/core` (WASM).
- _Package name:_ `thoughtmark` (core crate + `@thoughtmark/core` npm). _License:_ **Apache-2.0** (explicit patent grant + defensive patent-termination clause, critical given Microsoft's authorship-attribution patents).
- _Minimal public API surface:_ `canonicalize(obj) -> bytes`, `hash(bytes) -> Digest`, `Ledger::append(entry) -> InclusionProof`, `Ledger::consistencyProof(a,b)`, `sign(entry, key) -> DSSE`, `verify(bundle) -> VerificationResult`, `anchor(root, backend) -> AnchorReceipt`, `redact(entry, policy) -> RedactedEntry`, `exportPROV(trail)` / `exportC2PA(artifact)`.

### 4. Open Research Problems vs. Engineering-Only

- **(a) Capture-integrity / oracle problem — PARTIALLY-SOLVED-WITH-KNOWN-MITIGATIONS.** Garbage-in is immutably preserved; the trust boundary moves to ingestion. No full solution exists. Mitigations: TEE/attested capture (client and server enclaves), client attestation, witness co-signing, and capturing as close to the model API boundary as possible (signed API responses). Honest framing: the system proves _integrity since capture_, never _truth at capture_.
- **(b) CoT faithfulness — OPEN RESEARCH.** Logged chain-of-thought is not verifiably faithful to actual computation (Anthropic 2025: 25% / 39% hint-verbalization, <2% verbalization of an exploited reward hack, worse on hard tasks; unfaithful CoTs were _longer_ than faithful ones). No method makes logged CoT provably faithful. Implication: never market the record as evidence of _how the AI actually reasoned_ — only as a tamper-evident record of _what was exchanged_.
- **(c) Selective disclosure / redactable provenance — PARTIALLY-SOLVED.** Salted hashes + Merkle-leaf redaction (delete leaves, keep proofs of the remainder), redactable signatures, chameleon-hash redactable blockchains, and ZK selective disclosure all exist; the Frontiers "Merklized transactions" work (2023) shows leaf-level GDPR redaction without changing the chain. CNIL-style key-deletion (crypto-shredding) is a recognized GDPR-erasure approach. Implementable, but composing the right scheme for the conversation domain is design work.
- **(d) Granular human-vs-AI authorship at sub-document level — OPEN RESEARCH (for robustness).** The ledger can _record_ claimed attribution robustly; _verifying_ it against gaming (a human pasting AI text and claiming authorship, or vice versa) is unsolved — post-hoc AI-text detection is unreliable and adversarially fragile. Defensible position: attribution is _attested by signing participants_, not _forensically proven_.
- **(e) Standardization gap — OPEN / WHITE-SPACE.** Confirmed: no open standard models a signed multi-turn human-AI dialogue with per-turn attribution. C2PA/CAWG/IPTC are asset/media-centric; HDP/VAP/IPP (IETF individual drafts) address delegation/decision-audit. This is the opportunity: define and publish the schema.

### 5. Prior Art / Competitive Landscape

- **OmniScientist (arXiv 2511.16931, Nov 21 2025):** the OSP ContributionLedger is the closest conceptual prior art for human-AI contribution provenance — adopt its model. It is a framework/protocol concept, not a cryptographic notarization library; the integration white-space is the tamper-evident, anchored, signed implementation.
- **Atlas (Intel Labs, EuroS&PW 2025, arXiv 2502.19567):** cryptographic ML-lifecycle provenance using in-toto + transparency logs + TEEs. Adjacent (model lifecycle, not conversation); strongest architectural template.
- **EQTY Lab (AI Guardian / Verifiable Compute / Verifiable Runtime):** commercial verifiable-AI-governance on Hedera + NVIDIA TEE/DPU; targets agentic runtime governance for public sector/enterprise (the Hedera/Accenture/NVIDIA DGX Cloud deployment announced Oct 29 2025). The likely commercial competitor for the proprietary layer; their model is media/agent attestation, not research-reasoning trails.
- **Sigstore (Rekor/Fulcio/cosign):** the transparency-log reference; reuse Rekor as a library.
- **C2PA / CAWG / IPTC:** media-provenance standards; interop targets, not competitors for conversation provenance. (Note: C2PA "text support" means the v2.3+ January-2026 steganographic embedding of a media-style manifest into a text blob, not a chat/turn schema.)
- **AIBOM / AIBoMGen, SLSA-for-models (sigstore/model-transparency):** model supply-chain provenance; adjacent.
- **Microsoft authorship-attribution patents (US 12,061,902; 12,190,106; 12,462,318; 12,493,775; 12,517,723):** issued patents covering automatic authorship tokens for human-vs-AI content, explicitly contemplating Merkle/blockchain/distributed-ledger publication and tamper-resistant signing. **Implication for OSS release:** real freedom-to-operate risk around the _authorship-token_ mechanism; mitigate by (i) Apache-2.0 (patent grant + defensive termination), (ii) framing attribution as participant-_attested_ ledger entries (PROV/DID-based) rather than auto-detected authorship tokens, (iii) FTO review before any commercial layer.
- **HDP / VAP / IPP (IETF individual drafts, 2026):** delegation-provenance and decision-audit; confirm the broader accountability gap but do not cover conversational reasoning trails. Cite only as work-in-progress.

### 6. Implementation Roadmap

- **Phase 0 — Sharp primitive (MVP, the credibility artifact):** `thoughtmark-core` Rust crate + `@thoughtmark/core` WASM: Tier 0 (JCS canonicalization + BLAKE3/SHA-256/CID hashing) + Tier 1 (hash-chained append-only Merkle log with inclusion/consistency proofs) + Ed25519/DSSE signing + the ContributionLedger schema. Publish with a spec and conformance vectors. This alone is a credible, novel release.
- **Phase 1 — Anchoring + verification:** `thoughtmark-anchor-ots` (OpenTimestamps) + `thoughtmark-anchor-rfc3161`; end-to-end `verify(bundle)`; PROV-O export.
- **Phase 2 — Reference app on MedQBank:** Next.js/Supabase demo that captures a study session (student question → AI explanation turns → student refinement → final answer), writes ledger entries to Postgres, anchors the daily Merkle root via OTS, and shows a verifier UI proving "this reasoning trail existed at T, with this human/AI contribution lineage, unaltered." Concretely captures: each conversation turn (hashed, attributed, timestamped), the model run manifest, and produces a downloadable proof bundle + C2PA text export of the final artifact.
- **Phase 3 — Identity + redaction:** DID/VC participant identity; redactable-Merkle selective disclosure + crypto-shredding for GDPR/medical confidentiality.
- **Phase 4 — Optional Tier 3 + multi-party:** TEE-attestation plugin (NVIDIA NRAS/Phala) for model-provenance; ZKML for small high-stakes models; Hyperledger Fabric plugin for multi-institution consortia.
- **Phase 5 — Standardization:** submit the reasoning-trail provenance schema as an Internet-Draft / community spec to claim the white-space.

## Recommendations

1. **Build the Phase 0 sharp primitive now.** It is pure, auditable, dependency-light, and novel as a _conversation-provenance_ schema even though its parts are individually solved. Ship the Rust core + WASM/TS bindings under Apache-2.0 as `thoughtmark`.
2. **Anchor roots, not artifacts; hash, never store.** Use OpenTimestamps for free long-horizon proof + an RFC 3161 plugin for regulatory acceptance. Keep all sensitive content off-chain as salted hashes from day one.
3. **Frame honestly: integrity-of-record ≠ validity-of-record ≠ faithfulness.** Make this explicit in docs and UI. Attribution is participant-attested, not forensically proven; CoT is recorded, not verified-faithful.
4. **Treat C2PA/IPTC as export targets, not the core model; own the conversation schema.** This is the defensible differentiation and the standardization opportunity.
5. **Defer Tier 3.** Use TEE attestation when "which model ran" matters; reserve ZKML for small models. Do not block v1 on ZK.
6. **Do an FTO review against Microsoft's authorship patents before any commercial layer**, and keep attribution PROV/DID-based rather than auto-detected tokens.

**Thresholds that change the plan:** if DeepProve/EZKL reach Llama-scale full-inference proofs at <1000× overhead (DeepProve already lists Llama-class models in active development, so watch this closely), promote ZKML from optional to a headline Tier 3 feature. If C2PA ships a real conversation/turn assertion (beyond v2.3/v2.4 text blobs), pivot from "own the schema" to "extend C2PA." If a competing IETF draft (an HDP/VAP successor) adopts conversational reasoning-trail provenance, prioritize Phase 5 standardization immediately to avoid being preempted.

## Caveats

- ZKML figures (DeepProve, zkPyTorch) come substantially from vendor sources (Lagrange, Polyhedra) and should be independently benchmarked before relying on them; note that DeepProve's "first full LLM" claim is GPT-2-scale, and Llama-class proving is described as in development, not shipping.
- C2PA versioning moves fast (v2.3 text support landed January 2026; v2.4 followed); re-verify the current spec before building the C2PA adapter, and remember its text support is steganographic blob-embedding without conversation semantics.
- HDP/VAP/IPP are individual IETF drafts (work-in-progress), not adopted standards.
- The Microsoft patent claims are broad; this report flags FTO risk but is not legal advice — get counsel.
- "Faithfulness" research is evolving rapidly; current pessimistic results may shift, but should be treated as the prevailing state as of mid-2026.
- One correction worth carrying forward: `AIDataMiningProhibited` is **not** one of the four IPTC 2025.1 AI-generation fields (it relates to IPTC's separate data-mining/opt-out work); the four confirmed 2025.1 AI fields are AISystemUsed, AISystemVersionUsed, AIPromptInformation, and AIPromptWriterName.
