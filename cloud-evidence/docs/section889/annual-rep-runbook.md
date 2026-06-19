# Operator runbook — FAR 52.204-26 Section 889 annual representation (LOOP-W.W4)

This runbook describes the annual ceremony for producing, signing, and filing
the FAR 52.204-26 "Covered Telecommunications Equipment or Services —
Representation" that every CSP with an active SAM.gov registration owes.

> **The system never files the representation in SAM.gov for you.** REO Rule 4
> forbids the tooling from acting on the operator's behalf on a regulatory
> submission. W.W4 produces the artifact pair (`out/section889-annual-rep.json`
> + `out/section889-annual-rep.docx`); a human officer signs and submits.

## 1. Prerequisites

1. **W.W1 catalog is fresh.** Run the catalog extractor / `--prohibited-vendors-catalog`
   within 24 hours of the representation so the screen reflects the latest
   OFAC / BIS / SAM Exclusions designations.
2. **W.W2 screen has been run** for the current build:
   `--prohibited-vendor-screen` emits `out/prohibited-vendors-screen-result.json`.
3. **Operator config is complete** (see §2). Missing mandatory fields cause the
   emitter to throw a `requires_operator_input:<field>` diagnostic and write
   nothing — a representation with a missing UEI or unsigned officer block is
   legally void.
4. **Methodology document** exists at
   `docs/section889/reasonable-inquiry-methodology.md` (or the path configured in
   `section_889.annual_representation.reasonable_inquiry_methodology_path`).

## 2. Configuration (`config.yaml`)

```yaml
section_889:
  offeror:
    legal_name: "FedPy Cloud Services, Inc."
    unique_entity_id: "JKL5678MNOP9"   # SAM UEI — 12 chars [A-Z0-9]
    cage_code: "9ABC1"                  # optional — 5 chars [A-Z0-9]
    physical_address:
      street1: "123 Main Street"
      city: "Reston"
      state: "VA"
      zip: "20190"
      country: "US"
  authorized_officer:
    full_name: "Jane Q. Operator"
    title: "Chief Information Security Officer"
    email: "ciso@example.com"
    signing_key_id: "operator-officer-2026Q3"
  annual_representation:
    reasonable_inquiry_methodology_path: "docs/section889/reasonable-inquiry-methodology.md"
    include_kaspersky_attachment: true  # NDAA §1634 / BOD 17-01 supplement annex
    valid_until_days: 365               # FAR 52.204-8(d) — 1..730
```

See `section889-annual-rep.example.yaml` for a fully-annotated template.

## 3. Emit

```bash
npm run collect -- --prohibited-vendors-catalog --prohibited-vendor-screen \
                   --prohibited-vendor-1bd-report --section889-annual-rep
# or set CLOUD_EVIDENCE_SECTION889_ANNUAL_REP=1
```

Outputs (under `out/`):

| File | Purpose |
|---|---|
| `section889-annual-rep.json` | Signed canonical-JSON envelope (the authoritative record). |
| `section889-annual-rep.json.sig` | Detached Ed25519 signature sidecar. |
| `section889-annual-rep.docx` | Printable representation for officer signature + SAM submission. |
| `section889-annual-reps.jsonl` | Append-only ledger (delta + continuity index). |
| `marketplace-section889-badge.json` | LOOP-Q.Q1 "Section 889 Compliant" badge feed. |

The console prints the two `does / does not` answers, the count of linked W.W3
1-business-day incidents, the count of representation flips vs the prior
representation, and whether the Marketplace badge is enabled.

## 4. The two representation answers

- **(c)(1) provides** — "does" iff a non-suppressed match was found on the
  subprocessor sheet or an inventory provider-tag / SKU surface (equipment or
  services the offeror provides to the Government).
- **(c)(2) uses** — "does" iff ANY non-suppressed match was found (the offeror's
  own SBOM + OCI dependencies count as "use" regardless of contract
  performance).

The `.docx` marks the screen-driven box (■) and leaves the alternative
unmarked (□); the rationale under each citation lists every driving match.

## 5. Sign + submit (officer ceremony)

1. The authorized officer reviews the `.docx`, confirms the marked boxes match
   the CSP's understanding, and wet-signs the signature region (or applies the
   organization's e-signature).
2. The officer logs in to SAM.gov and enters the two representation answers in
   the entity's annual representations and certifications.
3. Record the SAM submission receipt id alongside the filing for the audit
   trail (the tracker-resident paste-back form is a deferred follow-up — see
   LOOP-W-RISKS W.W4-EXT-1; until then, retain the receipt with the signed
   `.docx`).

## 6. Cadence + expiry

- The envelope's `valid_until` = `signed_at + valid_until_days` (default 365).
- Re-issue at SAM registration renewal, whenever a representation answer flips
  from "does not" to "does", and at each solicitation response that incorporates
  FAR 52.204-26.
- A representation flip ("does not" → "does") is logged
  (`event=w.w4.representation_flip`) and surfaced in the console summary — it is
  high-signal for the AO and may require a contemporaneous SAM update.

## 7. Confidentiality

The `.docx` discloses the offeror identity, UEI, CAGE, and (when matches exist)
the covered vendors and linked incidents. Treat it as sensitive: store `out/`
with restrictive ACLs and submit to SAM.gov over the authenticated session, not
plaintext email.

## 8. Scope reminder

LOOP-W covers FAR §889 + NDAA §1634 + OFAC + BIS + SAM Exclusions. It does NOT
cover ITAR or EAR export-control screening, FAR 52.204-24 solicitation-level
representations, or FAR 52.212-3 commercial-item reps and certs — the operator
transcribes the two W.W4 answers into those forms manually when bidding.
