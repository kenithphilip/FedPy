# Section 889 reasonable-inquiry methodology

> **Operator-authored.** This file is seeded by LOOP-W.W4 and is meant to be
> edited by the CSP. Its SHA-256 is embedded verbatim into every FAR 52.204-26
> annual-representation envelope (`out/section889-annual-rep.json`) and rendered
> in the `.docx` so a 3PAO can confirm the representation cites the methodology
> that was actually in force when the representation was signed.

FAR 52.204-25(a) defines a **reasonable inquiry** as "an inquiry designed to
uncover any information in the entity's possession about the identity of the
producer or provider of covered telecommunications equipment or services used by
the entity that excludes the need to include an internal or third-party audit."

This document records the inquiry the CSP performs before each FAR 52.204-26
representation. It is the human-readable companion to the automated W.W2 screen
(`out/prohibited-vendors-screen-result.json`), which supplies the
machine-verifiable evidence.

## 1. Surfaces inquired

The W.W2 screen walks four surfaces against the W.W1 prohibited-vendor catalog
(FAR 52.204-25 named entities + NDAA §1634 Kaspersky + OFAC SDN + BIS Entity
List + SAM Exclusions + FASCSA):

1. **Subprocessor sheet** — every vendor the CSP relies on to deliver its
   service (SA-9 subprocessor inventory).
2. **SBOM (transitive)** — every package in the software bill of materials,
   walked to the configured dependency depth.
3. **OCI image publishers** — every container image publisher attested by
   cosign / Rekor.
4. **Inventory provider-tag / SKU** — every inventory asset's vendor tag and
   stock-keeping unit.

## 2. Catalog freshness

The representation embeds the catalog snapshot id + SHA-256 + generation date.
The CSP refreshes the catalog (W.W1) within 24 hours of signing the
representation so a newly-designated entity cannot be missed. Strict mode refuses
to emit a representation against a catalog snapshot older than 24 hours.

## 3. Operator triage of matches

Each W.W2 match carries a confidence band and a catalog→surface provenance
chain. The CSP reviews every match:

- A confirmed covered-entity match drives the representation toward "does".
- A confirmed false positive is suppressed in
  `prohibited-vendors-overrides.yaml` with a written justification; suppressed
  matches do not drive the representation but remain visible in the audit trail.

The CSP MUST NOT suppress a match merely to keep the representation at "does
not"; suppression is reserved for genuine false positives (name collisions,
unrelated entities) with documented justification.

## 4. Cadence

The representation is re-issued:

- at each SAM.gov registration renewal (annually, per FAR 52.204-8(d));
- whenever the W.W2 screen flips a representation answer from "does not" to
  "does" (a covered entity newly entered the supply chain); and
- at each solicitation response that incorporates FAR 52.204-26 by reference.

## 5. Records retained

- The signed W.W2 screen-result envelope.
- The signed FAR 52.204-26 representation envelope + `.docx`.
- The append-only annual-representation ledger (`section889-annual-reps.jsonl`).
- This methodology document, version-controlled.

_Replace the bracketed sections below with CSP-specific detail before signing._

> [CSP-specific inquiry narrative: name the personnel who perform the inquiry,
> the procurement controls that gate new vendors, and the cadence of subprocessor
> sheet review.]
