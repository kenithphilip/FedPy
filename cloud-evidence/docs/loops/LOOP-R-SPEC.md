# LOOP-R — Post-Quantum Cryptography Inventory + Migration Plan

> Comprehensive implementation specification for the three slices in LOOP-R.
> Authored as a stand-alone artifact: any future Claude / human session can
> execute LOOP-R end-to-end by reading ONLY this file + the three supporting
> files cited in Section 2 ("Dependencies"). No prior conversation history
> required.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard) governs
> every slice below. Every byte emitted must trace back to real evidence or
> operator-supplied configuration. Slices ship under the Real Slice Contract
> in CLAUDE.md Rule 2.

---

## 1. Why this loop exists

### The gap LOOP-A through LOOP-Q left open

FedPy today collects FIPS-validated cryptographic-module evidence per provider
via `providers/{aws,gcp,azure}/crypto.ts` — the KSI-AFR-UCM "Using
Cryptographic Modules" hybrid collector. Those collectors satisfy the *current*
Phase Two Moderate obligation: FIPS 140-2 / 140-3 validated modules with CMVP
certificate references in the SSP. That obligation is sized for the world
where every asymmetric algorithm in use is RSA, ECDSA, ECDH, or DH and where
"FIPS-validated" is a sufficient signal of cryptographic strength.

That world is ending. NIST released the principal three Post-Quantum
Cryptography (PQC) standards in August 2024 — FIPS 203 (ML-KEM), FIPS 204
(ML-DSA), and FIPS 205 (SLH-DSA). NIST IR 8547 (initial public draft, Nov
2024) sets the deprecation timeline: NIST will deprecate and ultimately
remove quantum-vulnerable algorithms from its standards by 2035, with
high-risk systems transitioning earlier. OMB M-23-02 (Nov 2022, "Migrating
to Post-Quantum Cryptography") obligates every federal agency — and, by
extension, every CSP serving federal customers — to inventory cryptographic
systems containing quantum-vulnerable algorithms and submit an *annual report*
through 2035 documenting migration progress. CNSA 2.0 (Sep 2022) mandates
PQC for National Security Systems on an accelerated schedule (2025-2033 per
asset class). NSM-10 (May 2022) anchors the executive direction.

FedPy emits exactly zero of the artifacts these obligations call for:

1. There is no **asymmetric-cryptography inventory** that enumerates every
   instance of RSA, ECDSA, ECDH, DH, EdDSA across TLS endpoints, KMS keys,
   signing keys, code-signing keys, IPsec VPN endpoints, mTLS service
   meshes, SSH host keys, CA-issued certificates, JWT signing keys, OIDC
   discovery keys, IMDS signatures, Resource Manager / EventGrid event
   signatures, and HSM-backed key stores. The existing AFR-UCM collectors
   verify that the *module* is FIPS-validated; they do not enumerate the
   *algorithm* the module is configured to use.

2. There is no **per-asset migration plan** that records: target algorithm
   (one of ML-KEM-512 / -768 / -1024 / ML-DSA-44 / -65 / -87 /
   SLH-DSA-SHA2-128s / etc.), target completion date, ownership, blockers
   (cloud-provider PQC roadmap), and inheritance from upstream cloud-vendor
   roadmaps (AWS KMS, GCP Cloud KMS, Azure Key Vault each publish their
   own PQC rollouts).

3. There is no **annual report emitter** that aggregates inventory +
   plan + delta from prior year into the OMB M-23-02 §V format federal
   agency customers will demand by 2027 and that OMB itself collects
   through 2035.

LOOP-R closes all three gaps with three slices that EXTEND (do not replace)
the existing AFR-UCM collectors, reuse the OSCAL POA&M emitter pattern for
unplanned migrations, and reuse the LOOP-C OOXML `.docx` rendering helpers
for the annual report. The result is a CSP-side cryptographic posture
artifact that maps 1:1 to OMB M-23-02's required submission format and
that puts FedPy on the leading edge of the 2026 Consolidated Rules window.

### Artifacts LOOP-R delivers

| # | Artifact | Source | Consumer |
|---|---|---|---|
| 1 | `core/pqc-inventory.ts` — pure aggregator over provider crypto collectors | R.R1 | Migration plan emitter, annual report, KSI-AFR-UCM evidence pack |
| 2 | `out/crypto-inventory.json` — per-asset × per-algorithm enumeration | R.R1 | Submission bundle, 3PAO review, OMB report |
| 3 | `out/crypto-inventory.xlsx` — operator-readable workbook keyed on quantum-vulnerable class | R.R1 | Internal review, AO sign-off |
| 4 | `core/pqc-migration-plan.ts` — per-asset migration plan emitter | R.R2 | OMB submission, AO review |
| 5 | `out/pqc-migration-plan.docx` — OMB M-23-02 §IV-shape per-asset migration plan | R.R2 | Federal agency customer review |
| 6 | `out/pqc-migration-plan.json` — structured twin of the .docx | R.R2 | Annual report, delta computation |
| 7 | POA&M items for un-planned migrations | R.R2 | OSCAL POA&M chain |
| 8 | `core/pqc-annual-report.ts` — annual report emitter per OMB M-23-02 §V | R.R3 | OMB submission, agency customer review |
| 9 | `out/pqc-annual-report.docx` + `.json` | R.R3 | OMB submission |
| 10 | Tracker review/sign-off UI for annual report | R.R3 | Internal review |

### Authorization-package gaps closed

| Package gap | Slice | Authoritative source |
|---|---|---|
| No enumeration of asymmetric algorithm × asset × purpose × rotation in use | R.R1 | OMB M-23-02 §III "Cryptographic Inventory"; NIST IR 8547 §3 quantum-vulnerable classification table |
| No per-asset migration roadmap citing FIPS 203 / 204 / 205 targets and dates | R.R2 | OMB M-23-02 §IV "Migration Planning"; NIST IR 8547 §4.2 timeline |
| No annual OMB-format report on PQC migration progress | R.R3 | OMB M-23-02 §V "Reporting Requirements"; through 2035 |
| AFR-SCG Secure Configuration Guide lacks PQC algorithm-policy section | R.R1 → LOOP-G.G5 | CISA Post-Quantum Cryptography Initiative; NSM-10 |
| FedRAMP authorization package has no "PQC readiness" attestation | R.R3 | OMB M-23-02 obligation cascading to CSPs serving federal customers |

---

## 2. Dependencies

### Loops / slices that MUST complete first

| Dep | Why |
|---|---|
| `providers/aws/crypto.ts` (existing AFR-UCM collector) | R.R1 extends to enumerate algorithm × key-size × purpose per KMS key, ACM cert, IAM signing cert |
| `providers/gcp/crypto.ts` (existing AFR-UCM collector) | R.R1 extends to enumerate Cloud KMS algorithm purpose, Certificate Manager cert SAN, Cloud HSM key types |
| `providers/azure/crypto.ts` (existing AFR-UCM collector) | R.R1 extends to enumerate Key Vault key `kty` + `crv` + `keyOps`, App Gateway SSL policy ciphersuites, AKV-backed certificate algorithms |
| INV-P1..S6 (`inventory.json`) | R.R1 keys inventory entries by `asset_id` so the report can be per-asset; reuses `inventory.assets[].identifier` |
| `core/vdr-scan.ts` (existing VDR pipeline) | R.R1 cross-references VDR-discovered TLS endpoints for algorithm + key-size signals (e.g. nmap-style cipher enumeration via Inspector / Security Command Center) |
| `core/oscal-poam.ts` (LOOP-A.A1) | R.R2 emits one POA&M item per *un-planned* migration so unplanned quantum-vulnerable usage flows into the existing risk pipeline (and thus picks up LOOP-B risk scores) |
| `core/oscal.ts` (LOOP-A.A3 chain) | R.R2/R.R3 cross-link to SSP component-uuid and AP/AR back-references where applicable |
| `core/submission-bundle.ts` (LOOP-A.A4) | R.R1/R.R2/R.R3 add new roles to the well-known catalogue: `crypto-inventory-json`, `crypto-inventory-xlsx`, `pqc-migration-plan-docx`, `pqc-migration-plan-json`, `pqc-annual-report-docx`, `pqc-annual-report-json` |
| `core/sign.ts` (existing Ed25519 + RFC 3161 manifest) | R.R1/R.R2/R.R3 outputs flow through the existing signing pipeline |
| LOOP-G.G5 (`core/afr-scg.ts` Secure Configuration Guide, if shipped) | R.R1 emits a PQC-algorithm-policy section the AFR-SCG `.docx` consumes; soft dependency (R.R1 ships without it; LOOP-G.G5 reads R.R1 when both exist) |
| LOOP-B.B1 (`core/risk-score.ts`) | R.R2 reads `risk_score` blocks on unplanned-migration POA&M items so the migration plan is sortable by composite score |

### Existing files this loop EXTENDS

| File | Modification |
|---|---|
| `providers/aws/crypto.ts` | (R.R1) Add `enumerateAwsAsymmetricCrypto()` that walks KMS asymmetric keys, ACM certificates, IAM signing certificates, IAM server certificates, ELB/ALB listener cipher suites, EKS control-plane cipher policy, RDS TLS endpoints, and emits structured records (algorithm, key_size, purpose, rotation_cadence, quantum_vulnerable_class). Keep the existing `collectUcm()` function untouched. |
| `providers/gcp/crypto.ts` | (R.R1) Add `enumerateGcpAsymmetricCrypto()` walking Cloud KMS asymmetric keys (`purpose: ASYMMETRIC_SIGN`, `ASYMMETRIC_DECRYPT`), Certificate Manager certs, Compute Engine SSL policies, Load Balancer target HTTPS proxies. |
| `providers/azure/crypto.ts` | (R.R1) Add `enumerateAzureAsymmetricCrypto()` walking Key Vault keys (kty=RSA / EC, crv=P-256 / P-384 / P-521), App Gateway SSL policies (cipher suite enumeration), App Service minimum TLS, Front Door cipher suites. |
| `core/envelope.ts` | (R.R1) Add optional `crypto_inventory_entries?: CryptoInventoryEntry[]` to the `ProviderBlock` interface (REO-safe additive). |
| `core/orchestrator.ts` | (R.R1/R.R2/R.R3) New flags: `--pqc-inventory`, `--pqc-migration-plan`, `--pqc-annual-report`, `--pqc-config <path>`, `--strict-pqc` plus env equivalents `CLOUD_EVIDENCE_PQC_INVENTORY`, `CLOUD_EVIDENCE_PQC_PLAN`, `CLOUD_EVIDENCE_PQC_REPORT`, `CLOUD_EVIDENCE_PQC_CONFIG`. |
| `core/submission-bundle.ts` | Add 6 new roles to `WELL_KNOWN` (see slice docs). |
| `core/oscal-poam.ts` | (R.R2) Accept `pqc_unplanned_migrations[]` input; emit one OSCAL `poam-item` per entry with severity derived from the IR 8547 deadline (entries past 2030 → high; past 2035 → critical). |
| `core/afr-scg.ts` (LOOP-G.G5) | (R.R1, soft dep) Read `out/crypto-inventory.json` and emit a "Cryptographic Algorithm Policy" section listing every algorithm + its quantum-vulnerable class. |
| `tracker/server/schema.sql` | (R.R3) Tables `pqc_annual_report_reviews`, `pqc_algorithm_overrides`, `pqc_migration_owners`. |
| `tracker/server/index.ts` | (R.R3) Mount `routes/pqc-annual-report.ts`, `routes/pqc-migration-owners.ts`. |
| `tracker/client/src/App.tsx` | (R.R3) Add routes `/pqc-annual-report`, `/pqc-migration-owners`. |
| `cloud-evidence/CHANGELOG.md` | Unreleased entry per slice. |
| `cloud-evidence/docs/STATUS.md` | Per-slice status line updated when slice ships. |

### Loops UNBLOCKED when LOOP-R is complete

| Unblocked loop | Reason |
|---|---|
| LOOP-G.G5 (AFR-SCG) | R.R1 feeds the "Cryptographic Algorithm Policy" section of the Secure Configuration Guide |
| LOOP-Q.Q1 (Marketplace metadata) | R.R3 emits the "PQC Readiness" attestation Marketplace listings will surface from 2027 |
| LOOP-E.E1 (Monthly ConMon analysis) | R.R2 unplanned-migration POA&M items flow into the ConMon delta report |
| LOOP-C.C7 (Risk Management Strategy doc) | R.R3 annual report feeds the RMS "Quantum-Vulnerable Risk" appendix |
| LOOP-N.N1 (Threat modeling — adversarial validation) | R.R1 algorithm enumeration is an input to "harvest-now-decrypt-later" threat scenarios |
| LOOP-J.J3 (Supply-chain attestations) | R.R2 cross-references upstream-vendor PQC roadmaps as inheritance signals |

---

## 3. Authoritative sources

Every URL + spec referenced in any LOOP-R slice. All quotes are verbatim
where retrievable. Where the source PDF returns HTTP 403 to anonymous
fetches (CNSA 2.0, OMB M-23-02, FIPS 203/204/205 full PDFs), the
implementer downloads the PDF into `cloud-evidence/docs/sources/` and
re-quotes verbatim in the relevant slice docstring.

### NIST FIPS PQC standards (finalized 13 August 2024)

- **FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard
  (ML-KEM)** — https://csrc.nist.gov/pubs/fips/203/final  
  PDF: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
  - Full title: "Module-Lattice-Based Key-Encapsulation Mechanism
    Standard" (NIST CSRC, August 13, 2024).
  - Parameter sets specified: ML-KEM-512, ML-KEM-768, ML-KEM-1024,
    "listed in order of increasing security strength and decreasing
    performance" (CSRC publication page).
  - Replaces / is the PQC counterpart to: RSA-OAEP, RSA-KEM, ECDH key
    establishment.
  - Security strength categories (NIST PQC submission categories): cat 1
    for ML-KEM-512, cat 3 for ML-KEM-768, cat 5 for ML-KEM-1024.
  - Algorithm name token used in `crypto-inventory.json`:
    `ml-kem-512` / `ml-kem-768` / `ml-kem-1024`.

- **FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)** —
  https://csrc.nist.gov/pubs/fips/204/final  
  PDF: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
  - Full title: "Module-Lattice-Based Digital Signature Standard" (NIST
    CSRC, August 13, 2024).
  - Parameter sets specified: ML-DSA-44, ML-DSA-65, ML-DSA-87.
  - Replaces / is the PQC counterpart to: RSA-PSS, RSA-PKCS1-v1_5,
    ECDSA, EdDSA signature primitives.
  - Algorithm name token: `ml-dsa-44` / `ml-dsa-65` / `ml-dsa-87`.

- **FIPS 205 — Stateless Hash-Based Digital Signature Standard
  (SLH-DSA)** — https://csrc.nist.gov/pubs/fips/205/final  
  PDF: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
  - Full title: "Stateless Hash-Based Digital Signature Standard" (NIST
    CSRC, August 13, 2024).
  - Parameter sets (12 variants): `SLH-DSA-SHA2-128s`,
    `SLH-DSA-SHA2-128f`, `SLH-DSA-SHA2-192s`, `SLH-DSA-SHA2-192f`,
    `SLH-DSA-SHA2-256s`, `SLH-DSA-SHA2-256f`, plus the corresponding
    SHAKE variants `SLH-DSA-SHAKE-128s` etc. ("s" = small signature,
    "f" = fast).
  - Intended use cases: firmware / code signing where signature size is
    tolerable in exchange for hash-based (conservative cryptanalytic
    assumption) security.

### NIST IR 8547 — Transition to Post-Quantum Cryptography Standards

- **NIST IR 8547 (Initial Public Draft, Nov 12 2024)** —
  https://csrc.nist.gov/pubs/ir/8547/ipd  
  PDF: https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf
  - NIST CSRC PQC project page (https://csrc.nist.gov/projects/post-quantum-cryptography)
    summarises IR 8547 verbatim:
    > "Under the transition timeline in NIST IR 8547, NIST will deprecate
    > and ultimately remove quantum-vulnerable algorithms from its
    > standards by 2035, with high-risk systems transitioning much
    > earlier."
  - The IR 8547 IPD enumerates the quantum-vulnerable asymmetric
    primitives that will be deprecated and disallowed; the canonical list
    used by R.R1's `quantum_vulnerable_class` enum is:
    - **RSA** (all key sizes, including RSA-2048, RSA-3072, RSA-4096)
    - **ECDSA** (P-224 / P-256 / P-384 / P-521)
    - **EdDSA** (Ed25519 / Ed448)
    - **ECDH** (P-256 / P-384 / P-521 / X25519 / X448)
    - **DH** (finite-field Diffie-Hellman, all moduli)
  - Quantum-resistant symmetric primitives that continue to satisfy the
    standard (Grover's algorithm halves the effective bit strength, so
    AES-128 is borderline; AES-256 retains 128-bit post-quantum security):
    - AES-256 (preferred); AES-128 ("transitional" — acceptable but
      monitor)
    - SHA-256 / SHA-384 / SHA-512
    - SHA3-256 / SHA3-384 / SHA3-512
    - HMAC + AES-GCM + AES-CCM (when keyed with AES-256)
  - **Timeline anchor**: 2030 (target deprecation; high-risk systems);
    2035 (disallowed in NIST standards). R.R2 uses these as default
    target dates when no operator override is provided.
  - **REO note**: until the implementer downloads the IR 8547 IPD PDF
    and pastes the exact deprecation/disallow table into
    `core/pqc-classification.ts` as a string constant, the constants
    carry a `REQUIRES-OPERATOR-INPUT: confirm-against-ir-8547` marker
    on the docstring (visible to `check:reo`).

### OMB Memorandum M-23-02 — Migrating to Post-Quantum Cryptography

- **OMB M-23-02 (Nov 18 2022)** —
  https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf
  - The PDF returns HTTP 403 / encoded binary to anonymous fetches. The
    implementer downloads the PDF into
    `cloud-evidence/docs/sources/omb-m-23-02.pdf` before R.R1, R.R2, or
    R.R3 ship. Verbatim quotes from the memo's structure
    (publicly-known section titles; full text held by the operator):
    - §III "Cryptographic Inventory" — agencies must maintain a current
      inventory of information systems and assets containing certain
      cryptographic systems.
    - §IV "Migration Planning" — agencies must develop and maintain
      a plan for migrating prioritized information systems to PQC.
    - §V "Reporting Requirements" — agencies must submit annual reports
      through 2035 documenting inventory + migration status.
  - **Scope as it applies to a CSP**: federal agency customers will
    pass-through M-23-02's obligations to their CSPs via contract +
    FedRAMP authorization conditions. A CSP whose authorization package
    includes a current crypto inventory + migration plan + annual report
    is meeting the *customer-facing* PQC obligation pre-emptively.
  - **OMB reporting cadence**: annual, every fiscal year, starting FY
    2023, through FY 2035. R.R3 emits the report on demand
    (`--pqc-annual-report` flag); operator generates one per FY at
    submission time.

### NSM-10 — National Security Memorandum on Quantum Cryptography

- **NSM-10 (May 4 2022)** —
  https://www.whitehouse.gov/briefing-room/statements-releases/2022/05/04/national-security-memorandum-on-promoting-united-states-leadership-in-quantum-computing-while-mitigating-risks-to-vulnerable-cryptographic-systems/
  - URL currently returns HTTP 404 on direct anonymous fetch; the
    memorandum is widely mirrored. Operator downloads the official text
    into `cloud-evidence/docs/sources/nsm-10.pdf`.
  - Anchors the executive-branch direction: mitigation of risks from
    quantum computers to cryptographic systems by 2035; National
    Security Systems on the accelerated CNSA 2.0 schedule.
  - LOOP-R cites NSM-10 in the annual report's "Authority" section
    (R.R3) — not used to drive algorithm timing (that comes from IR
    8547 + OMB M-23-02 directly).

### NSA CNSA 2.0 — Commercial National Security Algorithm Suite 2.0

- **CNSA 2.0 (Sep 2022)** —
  https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
  - PDF returns HTTP 403 to anonymous fetches. Operator downloads into
    `cloud-evidence/docs/sources/cnsa-2.0.pdf`.
  - CNSA 2.0 mandates ML-KEM, ML-DSA (or LMS / XMSS hash-based for
    firmware) for National Security Systems. Timeline tokens used by
    R.R2 when the operator declares the CSP serves NSS-adjacent
    customers: 2025 (begin transition), 2030 (preference), 2033 (NSS
    mandate). For a non-NSS CSP, default to OMB M-23-02 / IR 8547
    timeline (2030 / 2035).
  - **REO note**: same as IR 8547 — `REQUIRES-OPERATOR-INPUT:
    confirm-against-cnsa-2.0` marker on the constant docstring until
    the PDF is local.

### CISA Post-Quantum Cryptography Initiative

- **CISA Quantum page** — https://www.cisa.gov/quantum (currently 403
  to anonymous fetch; operator downloads / quotes the public text into
  `cloud-evidence/docs/sources/cisa-quantum.md`)
  - Anchors federal civilian agency (and by extension CSP) operational
    guidance. R.R3 cites the CISA initiative in the annual report
    "References" section.

### NIST Cybersecurity Framework v2.0 + OLIR

- **NIST CSF v2.0** — https://csrc.nist.gov/projects/cybersecurity-framework
  - GOVERN function GV.OC-02 / GV.RM-04 implicate cryptographic-asset
    management. LOOP-R is a partial implementation of those CSF
    outcomes; cited in the annual report.

### NIST SP 800-53 Rev 5 — relevant controls

- **NIST SP 800-53 Rev 5** —
  https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
  - **SC-12 (Cryptographic Key Establishment and Management)** — R.R1
    inventories the keys; R.R2 plans migration; R.R3 reports progress.
  - **SC-13 (Cryptographic Protection)** — R.R1 inventories the
    algorithms used "for protecting information that requires the
    application of cryptographic mechanisms".
  - **SA-9 (External System Services)** — R.R2 captures inherited
    PQC roadmaps from upstream cloud providers (AWS / GCP / Azure).
  - **PM-15 (Security and Privacy Groups and Associations)** — R.R3's
    annual report submission cadence overlaps with PM-15's external
    reporting expectations.

### Cloud-provider PQC roadmap signals (inheritance)

- **AWS KMS PQC** — https://aws.amazon.com/security/post-quantum-cryptography/
  - AWS publishes which AWS services have integrated PQC for TLS / KMS
    key wrap; R.R2 reads operator-supplied `pqc-config.yaml` entries
    capturing inheritance state per service.
- **GCP Cloud KMS PQC** — https://cloud.google.com/kms/docs (operator
  records inheritance state).
- **Azure Key Vault PQC** — https://learn.microsoft.com/azure/key-vault/
  (operator records inheritance state).
- For all three: R.R2's "inheritance" entry records the upstream
  provider's published target date + the asset's dependency on it; the
  CSP's own target date can be later if it inherits, earlier if the CSP
  ships its own PQC-capable abstraction.

### Inventory + asset model (existing FedPy)

- **`inventory.json` schema** — `core/inventory.ts` produces the per-asset
  inventory used as the join key in R.R1. Every crypto-inventory entry
  must reference an `asset_id` that exists in inventory.json, OR be
  emitted with `asset_source: 'cross-cloud-discovery'` and a manual
  note for the 3PAO.

### OSCAL v1.1.2 (consumer)

- **OSCAL POA&M v1.1.2 schema** — committed at
  `cloud-evidence/docs/oscal/oscal_poam_schema.v1.1.2.json`. R.R2 emits
  `poam-item` for un-planned migrations using the same `props[]`
  extension namespace `CE_NS` (`https://cloud-evidence.example/oscal-ns`)
  as LOOP-B.

---

## 4. Per-slice implementation specs

### Slice R.R1 — Cryptographic inventory collector

**Why this slice**: FedPy's existing AFR-UCM collectors verify the
*module* is FIPS-validated; OMB M-23-02 §III requires enumeration of the
*algorithm* in use per asset. This slice walks every asymmetric crypto
surface on AWS / GCP / Azure and produces `out/crypto-inventory.json`
keyed by `(asset_id, algorithm, key_size, purpose, rotation_cadence,
quantum_vulnerable_class)`.

**Files to create**:
- `cloud-evidence/core/pqc-inventory.ts` — pure aggregator:
  type definitions (`CryptoInventoryEntry`, `QuantumVulnerableClass`,
  `CryptoPurpose`), classification table, asset-join helpers.
- `cloud-evidence/core/pqc-classification.ts` — typed constant table
  mapping algorithm name → quantum-vulnerable class (per IR 8547
  §3 + CNSA 2.0).
- `cloud-evidence/core/pqc-inventory-emit.ts` — disk emitter: walks
  provider crypto blocks, normalises entries, joins to inventory,
  writes `out/crypto-inventory.json` + `out/crypto-inventory.xlsx`.
- `cloud-evidence/core/pqc-inventory-xlsx.ts` — pure-JS xlsx renderer
  reusing the `core/inventory-workbook.ts` pattern.
- `cloud-evidence/pqc-config.example.yaml` — committed example for the
  operator's PQC configuration (inheritance flags, deadline overrides,
  algorithm tokens for in-house systems).
- Tests: `tests/core/pqc-inventory.test.ts`,
  `tests/core/pqc-classification.test.ts`,
  `tests/core/pqc-inventory-emit.test.ts`,
  `tests/core/pqc-inventory-xlsx.test.ts`.
- Fixtures: `tests/fixtures/pqc/` — provider block samples.

**Files to extend**:
- `providers/aws/crypto.ts` — add `enumerateAwsAsymmetricCrypto()`
  returning `CryptoInventoryEntry[]` keyed by:
  - KMS asymmetric customer-managed keys (KeySpec=RSA_2048 / RSA_3072 /
    RSA_4096 / ECC_NIST_P256 / ECC_NIST_P384 / ECC_NIST_P521 /
    ECC_SECG_P256K1 / SM2; KeyUsage=SIGN_VERIFY / ENCRYPT_DECRYPT /
    KEY_AGREEMENT).
  - ACM-issued certificates (KeyAlgorithm + InUseBy).
  - IAM signing certificates + server certificates.
  - ELB / ALB / NLB listener `ssl_policy` ciphersuites
    (TLS_AES_256_GCM_SHA384 = AES-256+SHA-384 = quantum-resistant
    symmetric; TLS_ECDHE_RSA_* = RSA+ECDH = quantum-vulnerable).
  - EKS control-plane cipher suite.
  - RDS TLS endpoint algorithm + minimum TLS version.
- `providers/gcp/crypto.ts` — `enumerateGcpAsymmetricCrypto()` over:
  - Cloud KMS asymmetric keys (`purpose: ASYMMETRIC_SIGN /
    ASYMMETRIC_DECRYPT`, algorithm enum
    `RSA_SIGN_PSS_2048_SHA256` etc.).
  - Certificate Manager managed certificates.
  - Compute Engine SSL policies (`min_tls_version`, `profile`,
    `custom_features[]`).
  - Load Balancer target HTTPS proxies (ssl_certificates, ssl_policy).
- `providers/azure/crypto.ts` — `enumerateAzureAsymmetricCrypto()` over:
  - Key Vault keys (`kty=RSA`/`EC`, `crv=P-256`/`P-384`/`P-521`,
    `key_size`, `keyOps`).
  - App Gateway SSL policies (existing query already pulls
    `policyName` + `minProto`; extend with ciphersuite enumeration
    via `properties.sslPolicy.cipherSuites[]`).
  - App Service / Front Door TLS configuration.
- `core/envelope.ts` — extend `ProviderBlock` interface with optional
  `crypto_inventory_entries?: CryptoInventoryEntry[]` field.
- `core/orchestrator.ts` — `--pqc-inventory` flag invokes
  `emitPqcInventory()`; runs AFTER provider collection.
- `core/submission-bundle.ts` — `WELL_KNOWN` adds:
  - `{ role: 'crypto-inventory-json', filename: 'crypto-inventory.json' }`
  - `{ role: 'crypto-inventory-xlsx', filename: 'crypto-inventory.xlsx' }`

**Schemas / standards**:
- **Quantum-vulnerable class enum** (per NIST IR 8547 §3 +
  CNSA 2.0):
  ```ts
  export type QuantumVulnerableClass =
    | 'quantum-vulnerable-asymmetric'    // RSA, ECDSA, ECDH, DH, EdDSA
    | 'quantum-resistant-symmetric'      // AES-256, SHA-384, SHA3
    | 'quantum-resistant-pqc'            // ML-KEM, ML-DSA, SLH-DSA, LMS, XMSS
    | 'transitional-symmetric'           // AES-128, SHA-256 (Grover-halved)
    | 'unknown'                          // unclassified algorithm token
    | 'REQUIRES-OPERATOR-INPUT';         // collector returned algo string we can't classify
  ```
- **Algorithm token canonicalisation**: lowercase, hyphen-separated.
  Examples: `rsa-2048`, `rsa-3072`, `rsa-4096`, `ecdsa-p256`,
  `ecdsa-p384`, `ecdsa-p521`, `ecdh-p256`, `ecdh-x25519`, `dh-2048`,
  `eddsa-ed25519`, `ml-kem-768`, `ml-dsa-65`, `slh-dsa-sha2-128s`,
  `aes-256-gcm`, `aes-128-gcm`, `sha-384`.
- **Purpose enum**:
  ```ts
  export type CryptoPurpose =
    | 'tls-server'         // ALB/ELB/CloudFront/Front Door cert
    | 'tls-client'         // mTLS client auth
    | 'kms-key-wrap'       // KMS key encryption
    | 'kms-signing'        // KMS asymmetric sign
    | 'code-signing'       // signtool / cosign / notary
    | 'jwt-signing'        // OIDC / IdP signing key
    | 'vpn-ipsec'          // IPsec IKE/ESP
    | 'ssh-host-key'       // SSH host identity
    | 'ca-issuance'        // CA-issued cert chain
    | 'message-signing'    // EventGrid / SNS signing
    | 'hsm-backed'         // HSM-resident key (purpose may be opaque)
    | 'other';
  ```

**Build steps**:

1. Define types in `core/pqc-inventory.ts`:
   ```ts
   export interface CryptoInventoryEntry {
     asset_id: string;                         // joins to inventory.json identifier
     provider: 'aws' | 'gcp' | 'azure';
     resource_arn?: string;                    // AWS only
     resource_id?: string;                     // GCP / Azure
     algorithm: string;                        // canonicalised token
     key_size?: number;                        // bits (e.g. 2048, 3072)
     curve?: string;                           // P-256 / P-384 / P-521 / X25519
     purpose: CryptoPurpose;
     rotation_cadence_days?: number;           // null when not rotated
     last_rotated_at?: string;                 // ISO datetime if known
     fips_module_certificate?: string;         // CMVP cert id when reachable
     quantum_vulnerable_class: QuantumVulnerableClass;
     inheritance_source?: 'aws-kms' | 'gcp-cloud-kms' | 'azure-key-vault' | 'in-house' | 'third-party';
     /** Whence the entry came (per-field traceability). */
     sources: {
       algorithm_source: 'sdk-keyspec' | 'sdk-cert-public-key' | 'sdk-ssl-policy-cipher' | 'tag-override' | 'operator-config' | 'REQUIRES-OPERATOR-INPUT';
       purpose_source: 'sdk-keyusage' | 'sdk-cert-extkey-usage' | 'operator-config' | 'REQUIRES-OPERATOR-INPUT';
       classification_source: 'ir-8547-table' | 'cnsa-2.0-table' | 'operator-override' | 'REQUIRES-OPERATOR-INPUT';
     };
     discovered_at: string;                    // ISO datetime
   }
   ```
2. Define classification table in `core/pqc-classification.ts`:
   ```ts
   export const QUANTUM_CLASSIFICATION: Record<string, QuantumVulnerableClass> = {
     // Vulnerable asymmetric
     'rsa-1024': 'quantum-vulnerable-asymmetric',
     'rsa-2048': 'quantum-vulnerable-asymmetric',
     'rsa-3072': 'quantum-vulnerable-asymmetric',
     'rsa-4096': 'quantum-vulnerable-asymmetric',
     'ecdsa-p256': 'quantum-vulnerable-asymmetric',
     'ecdsa-p384': 'quantum-vulnerable-asymmetric',
     'ecdsa-p521': 'quantum-vulnerable-asymmetric',
     'eddsa-ed25519': 'quantum-vulnerable-asymmetric',
     'eddsa-ed448': 'quantum-vulnerable-asymmetric',
     'ecdh-p256': 'quantum-vulnerable-asymmetric',
     'ecdh-p384': 'quantum-vulnerable-asymmetric',
     'ecdh-x25519': 'quantum-vulnerable-asymmetric',
     'ecdh-x448': 'quantum-vulnerable-asymmetric',
     'dh-2048': 'quantum-vulnerable-asymmetric',
     'dh-3072': 'quantum-vulnerable-asymmetric',
     // Resistant symmetric
     'aes-256-gcm': 'quantum-resistant-symmetric',
     'aes-256-cbc': 'quantum-resistant-symmetric',
     'aes-256-ccm': 'quantum-resistant-symmetric',
     'sha-384': 'quantum-resistant-symmetric',
     'sha-512': 'quantum-resistant-symmetric',
     'sha3-256': 'quantum-resistant-symmetric',
     'sha3-384': 'quantum-resistant-symmetric',
     'sha3-512': 'quantum-resistant-symmetric',
     // Resistant PQC
     'ml-kem-512':  'quantum-resistant-pqc',
     'ml-kem-768':  'quantum-resistant-pqc',
     'ml-kem-1024': 'quantum-resistant-pqc',
     'ml-dsa-44':   'quantum-resistant-pqc',
     'ml-dsa-65':   'quantum-resistant-pqc',
     'ml-dsa-87':   'quantum-resistant-pqc',
     // SLH-DSA full 12-variant enumeration
     'slh-dsa-sha2-128s': 'quantum-resistant-pqc',
     'slh-dsa-sha2-128f': 'quantum-resistant-pqc',
     'slh-dsa-sha2-192s': 'quantum-resistant-pqc',
     'slh-dsa-sha2-192f': 'quantum-resistant-pqc',
     'slh-dsa-sha2-256s': 'quantum-resistant-pqc',
     'slh-dsa-sha2-256f': 'quantum-resistant-pqc',
     'slh-dsa-shake-128s':'quantum-resistant-pqc',
     'slh-dsa-shake-128f':'quantum-resistant-pqc',
     'slh-dsa-shake-192s':'quantum-resistant-pqc',
     'slh-dsa-shake-192f':'quantum-resistant-pqc',
     'slh-dsa-shake-256s':'quantum-resistant-pqc',
     'slh-dsa-shake-256f':'quantum-resistant-pqc',
     // Hash-based legacy
     'lms-sha256': 'quantum-resistant-pqc',
     'xmss-sha256':'quantum-resistant-pqc',
     // Transitional symmetric
     'aes-128-gcm': 'transitional-symmetric',
     'aes-128-cbc': 'transitional-symmetric',
     'sha-256':     'transitional-symmetric',
   };
   ```
   Docstring cites IR 8547 §3 + CNSA 2.0 §2 verbatim (post-PDF
   download).

3. Provider crypto extensions: each provider's
   `enumerate*AsymmetricCrypto()` returns `CryptoInventoryEntry[]` with
   the per-resource SDK call recorded in `raw_evidence` (so the
   provenance pipeline picks it up). No mocked SDK responses; mock only
   at the wire transport layer in tests.

4. Aggregator `aggregatePqcInventory(providers, inventory, opts) → CryptoInventoryEntry[]`:
   - Walks every `ProviderBlock`'s `crypto_inventory_entries`.
   - Joins each entry to `inventory.assets[]` by `asset_id`.
   - When no inventory match: records the entry with `asset_source:
     'cross-cloud-discovery'`, surfaces it in the coverage report.
   - Applies `pqc-config.yaml` algorithm overrides (operator can declare
     `rsa-2048-as-cnsa-1.0` → quantum-vulnerable but with shorter
     deadline).
   - De-duplicates exact (asset_id, algorithm, purpose) triples.

5. Disk emitter `core/pqc-inventory-emit.ts`:
   ```ts
   export interface PqcInventoryEmitOptions {
     outDir: string;
     inventoryPath?: string;
     pqcConfigPath?: string;
     runId: string;
   }
   export interface PqcInventoryEmitResult {
     jsonPath: string;
     xlsxPath: string;
     total_entries: number;
     quantum_vulnerable_count: number;
     quantum_resistant_count: number;
     requires_operator_input_count: number;
     unknown_count: number;
   }
   export function emitPqcInventory(opts: PqcInventoryEmitOptions): Promise<PqcInventoryEmitResult>;
   ```
   The emitter writes:
   - `out/crypto-inventory.json` with top-level `provenance` block
     (per REO Rule 2.6) + `entries[]`.
   - `out/crypto-inventory.xlsx` with one sheet "Crypto Inventory"
     (columns A–N listed below).

6. XLSX columns (reuses `inventory-workbook.ts` pattern):
   - A: Asset ID
   - B: Provider
   - C: Resource ARN / ID
   - D: Algorithm
   - E: Key Size / Curve
   - F: Purpose
   - G: Quantum-Vulnerable Class
   - H: Rotation Cadence (days)
   - I: Last Rotated At
   - J: FIPS Module Cert
   - K: Inheritance Source
   - L: Algorithm Source (REQUIRES-OPERATOR-INPUT visibility)
   - M: Classification Source
   - N: Discovered At

7. Coverage contract: extend `core/inventory-coverage.ts` with
   `crypto_inventory_fill_rate` per provider × purpose. Coverage
   regression check fires if fill rate drops between runs.

8. Wire orchestrator: `--pqc-inventory` flag runs the emitter after
   provider collection. Outputs flow through `core/sign.ts` glob.

9. Update `core/oscal-ssp.ts` (existing): when `crypto-inventory.json`
   exists, the SSP "Hardware Inventory" section gains a per-component
   `crypto-algorithm` link via existing `links[]` infrastructure.

10. Validation pass:
    - `npm run check:provenance` — verifies the `provenance` block.
    - `npm run lint:no-stubs` — verifies no TODO/stub markers.

**REQUIRES-OPERATOR-INPUT fields**:
- `algorithm_source = 'REQUIRES-OPERATOR-INPUT'` — when the SDK returns
  a key algorithm string outside the classification table (e.g. a
  custom KMS key type from a partner integration). Operator updates
  `pqc-config.yaml` to map the string to a canonical token.
- `purpose_source = 'REQUIRES-OPERATOR-INPUT'` — when SDK does not
  expose `keyUsage` / `extKeyUsage` (e.g. some HSM-backed keys).
  Operator declares via `pqc-config.yaml`.
- `classification_source = 'REQUIRES-OPERATOR-INPUT'` — when the
  algorithm token is `unknown` (classification table missing the
  entry). Operator declares override.
- `inheritance_source` — operator-supplied via `pqc-config.yaml`
  (which AWS / GCP / Azure services the CSP delegates crypto to).
- `pqc-config.yaml` itself — operator-supplied, similar to LOOP-B's
  `risk-config.yaml`. Defaults work without it.

**Test specifications** (≥12 tests):

1. `it('classifies rsa-2048 as quantum-vulnerable-asymmetric per IR 8547', ...)`.
2. `it('classifies ml-kem-768 as quantum-resistant-pqc per FIPS 203', ...)`.
3. `it('classifies aes-256-gcm as quantum-resistant-symmetric (Grover 128-bit)', ...)`.
4. `it('classifies aes-128-gcm as transitional-symmetric', ...)`.
5. `it('classifies unknown algorithm tokens as REQUIRES-OPERATOR-INPUT', ...)`.
6. `it('canonicalises AWS KMS KeySpec RSA_2048 → rsa-2048', ...)`.
7. `it('canonicalises GCP Cloud KMS RSA_SIGN_PSS_2048_SHA256 → rsa-2048', ...)`.
8. `it('canonicalises Azure Key Vault kty=RSA + key_size=3072 → rsa-3072', ...)`.
9. `it('enumerates ALB listener ssl_policy ciphersuites', ...)`.
10. `it('joins entries to inventory.json by asset_id', ...)`.
11. `it('marks cross-cloud-discovery when asset_id not in inventory', ...)`.
12. `it('emits crypto-inventory.json with provenance block', ...)`.
13. `it('emits crypto-inventory.xlsx with 14 columns + one row per entry', ...)`.
14. `it('honours pqc-config.yaml algorithm overrides', ...)`.
15. `it('coverage report includes crypto_inventory_fill_rate per provider', ...)`.
16. `it('SLH-DSA-SHA2-128s classifies as quantum-resistant-pqc', ...)`.

**REO compliance checks specific to this slice**:
- Algorithm tokens come from SDK responses (real KMS / Key Vault /
  Cloud KMS calls) or operator-supplied config — never invented.
- Classification table cites IR 8547 §3 verbatim in docstring (with
  PDF page reference once downloaded).
- Provider extensions reuse existing read-only Proxy SDK clients.
- Inventory joins go through real `inventory.json` reads.
- No silent fallbacks: when classification fails, the entry's
  `classification_source` carries `REQUIRES-OPERATOR-INPUT` and the
  entry appears in the coverage gap report.

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/pqc-inventory.test.ts tests/core/pqc-classification.test.ts tests/core/pqc-inventory-emit.test.ts tests/core/pqc-inventory-xlsx.test.ts
npm run check:reo
npm run check:provenance
npm run lint:no-stubs
```

**Estimated effort**: 5–6 working days for a single implementer.

---

### Slice R.R2 — PQC migration plan emitter

**Why this slice**: OMB M-23-02 §IV obligates a per-asset migration
plan. R.R1 enumerates the inventory; R.R2 produces the plan — target
algorithm, target date, owner, blockers, inheritance, OSCAL POA&M
items for un-planned migrations.

**Files to create**:
- `cloud-evidence/core/pqc-migration-plan.ts` — pure builder over
  R.R1 inventory + `pqc-config.yaml` + tracker `pqc_migration_owners`.
- `cloud-evidence/core/pqc-migration-plan-docx.ts` — OOXML renderer
  reusing `core/oscal-ssp-docx.ts` infrastructure.
- `cloud-evidence/core/pqc-migration-plan-emit.ts` — orchestrates the
  pure builder + writers, emits `.docx` + `.json`.
- Tests: `tests/core/pqc-migration-plan.test.ts`,
  `tests/core/pqc-migration-plan-docx.test.ts`,
  `tests/core/pqc-migration-plan-emit.test.ts`.
- Fixtures: `tests/fixtures/pqc/migration-plan/`.

**Files to extend**:
- `core/oscal-poam.ts` — accept `pqc_unplanned_migrations[]` input;
  for each unplanned entry, emit a POA&M item with `props`:
  - `name: 'pqc-asset-id'`
  - `name: 'pqc-current-algorithm'`
  - `name: 'pqc-target-algorithm'`
  - `name: 'pqc-target-date'`
  - `name: 'pqc-deadline-source'` (one of `omb-m-23-02` /
    `ir-8547-deprecate-2030` / `ir-8547-disallow-2035` /
    `cnsa-2.0` / `operator-override`)
- `core/orchestrator.ts` — `--pqc-migration-plan` flag.
- `core/submission-bundle.ts` — `WELL_KNOWN` adds:
  - `{ role: 'pqc-migration-plan-docx', filename: 'pqc-migration-plan.docx' }`
  - `{ role: 'pqc-migration-plan-json', filename: 'pqc-migration-plan.json' }`

**Schemas / standards**:
- **OMB M-23-02 §IV migration-plan fields** (verbatim from
  publicly-known structure; full PDF held by operator):
  - System name + identifier
  - Cryptographic system + current algorithm
  - Target PQC algorithm + parameter set
  - Target migration date
  - Owner / responsible party
  - Dependencies + blockers
  - Inheritance from upstream
  - Status (planned / in-progress / complete)
- **NIST IR 8547 timeline anchors**:
  - 2030 — target deprecation for high-risk systems.
  - 2035 — disallowed in NIST standards.
- **CNSA 2.0 timeline** (for NSS-adjacent CSPs only):
  - 2025 — begin
  - 2030 — preferred
  - 2033 — mandate

**Build steps**:

1. Define `PqcMigrationPlanEntry`:
   ```ts
   export interface PqcMigrationPlanEntry {
     uuid: string;                              // deterministic from (asset_id, algorithm, purpose)
     asset_id: string;
     provider: 'aws' | 'gcp' | 'azure';
     resource_id: string;
     current_algorithm: string;                 // from R.R1
     current_quantum_vulnerable_class: QuantumVulnerableClass;
     target_algorithm: string;                  // ml-kem-768 / ml-dsa-65 / slh-dsa-sha2-128s / aes-256-gcm
     target_fips_standard: 'FIPS 203' | 'FIPS 204' | 'FIPS 205' | 'FIPS 197' | 'not-applicable';
     target_date: string;                        // ISO date YYYY-MM-DD
     target_date_source: 'operator-override' | 'omb-m-23-02' | 'ir-8547-deprecate-2030' | 'ir-8547-disallow-2035' | 'cnsa-2.0';
     owner_user_id?: number;                    // tracker user id
     owner_email?: string;                      // operator-supplied
     blockers: string[];                        // free text per blocker
     inheritance: {
       upstream_provider: 'aws-kms' | 'gcp-cloud-kms' | 'azure-key-vault' | 'in-house' | 'third-party' | 'none';
       upstream_target_date?: string;           // from operator config or upstream public roadmap
       blocked_by_upstream: boolean;            // if true, target_date inherits from upstream
     };
     status: 'unplanned' | 'planned' | 'in-progress' | 'pilot' | 'complete';
     last_updated_at: string;
     /** Provenance */
     sources: {
       target_algorithm_source: 'pqc-config' | 'default-mapping' | 'operator-override' | 'REQUIRES-OPERATOR-INPUT';
       target_date_source_field: 'pqc-config' | 'default-omb' | 'operator-override' | 'REQUIRES-OPERATOR-INPUT';
       owner_source: 'tracker' | 'pqc-config' | 'REQUIRES-OPERATOR-INPUT';
     };
   }
   ```

2. **Default algorithm-mapping table** (operator-overridable via
   `pqc-config.yaml`):
   ```
   rsa-2048   → ml-kem-768 (TLS / KMS wrap) OR ml-dsa-65 (signing)
   rsa-3072   → ml-kem-768 OR ml-dsa-65
   rsa-4096   → ml-kem-1024 OR ml-dsa-87
   ecdsa-p256 → ml-dsa-44
   ecdsa-p384 → ml-dsa-65
   ecdsa-p521 → ml-dsa-87
   ecdh-p256  → ml-kem-512
   ecdh-p384  → ml-kem-768
   ecdh-x25519→ ml-kem-768
   dh-*       → ml-kem-768
   eddsa-ed25519 → ml-dsa-44
   ```
   For code-signing / firmware: prefer SLH-DSA when stateless signing
   without state management is required (per FIPS 205 §1).

3. **Default target date**:
   - Quantum-vulnerable + tls/kms purpose → 2030-12-31 (IR 8547
     deprecate).
   - Quantum-vulnerable + ca-issuance / code-signing → 2030-06-30
     (high-risk).
   - Quantum-vulnerable + hsm-backed → 2032-12-31 (intermediate).
   - Operator override via `pqc-config.yaml` always wins.

4. Pure builder `buildPqcMigrationPlan(inventory, opts) → PqcMigrationPlanEntry[]`:
   - One entry per quantum-vulnerable inventory entry.
   - Reads owner from tracker `pqc_migration_owners` table (R.R3
     schema) when reachable; otherwise from `pqc-config.yaml`;
     otherwise marks `owner_source: 'REQUIRES-OPERATOR-INPUT'`.
   - Reads inheritance from `pqc-config.yaml` (operator declares
     "I inherit TLS termination from AWS ALB; AWS publishes target
     date 2028-12-31").

5. **Status derivation**:
   - `complete` when inventory shows the target_algorithm already in
     use (replacement entry exists for same asset_id + purpose).
   - `pilot` when inventory shows BOTH the legacy + target algorithm
     in use for the same asset (dual-key TLS, hybrid mode).
   - `planned` when operator config has a planned entry.
   - `unplanned` otherwise.

6. **`unplanned` POA&M emission**:
   - Each `unplanned` entry → one OSCAL `poam-item` via
     `core/oscal-poam.ts`.
   - Severity derived from target date:
     - target_date < now() → `critical`
     - target_date < now() + 1y → `high`
     - target_date < now() + 3y → `medium`
     - target_date < 2035 → `low`
     - else → `info`
   - LOOP-B.B1 risk scoring picks up the resulting items normally.
   - LOOP-B.B2 deadline engine reads `pqc-target-date` prop and
     respects it (new `deadline-source = 'pqc-target-date'`).

7. **DOCX emitter** in `core/pqc-migration-plan-docx.ts`:
   - Reuses `core/oscal-ssp-docx.ts` OOXML helpers.
   - Sections (per OMB M-23-02 §IV publicly-known structure):
     1. Cover page — CSP name, system identifier, fiscal year.
     2. Authority — OMB M-23-02 + NSM-10 + NIST IR 8547 + CNSA 2.0
        citations.
     3. Scope — inventory summary (count of quantum-vulnerable
        entries by purpose).
     4. Algorithm migration matrix — table mapping current → target.
     5. Per-asset migration plan — one row per entry with owner,
        target date, blockers, inheritance.
     6. Inheritance summary — table of upstream provider × target
        date × CSP-side dependency.
     7. POA&M cross-reference — list of unplanned-migration POA&M
        UUIDs.
     8. Sign-off block — operator name + date + tracker audit-log
        reference.

8. **JSON twin** `out/pqc-migration-plan.json`:
   ```ts
   {
     plan_id: string,
     fiscal_year: string,
     csp_name: string,
     system_id: string,
     generated_at: string,
     entries: PqcMigrationPlanEntry[],
     unplanned_poam_items: string[],            // uuids
     provenance: { emitter, emittedAt, sourceCalls, signingKeyId }
   }
   ```

9. **Strict mode**: `--strict-pqc` exits non-zero when any
   `unplanned` entry has `target_date < now()`.

10. **Submission bundle**: both files included via new roles.

**REQUIRES-OPERATOR-INPUT fields**:
- `owner_user_id` / `owner_email` — operator assigns via tracker
  (R.R3) or `pqc-config.yaml`.
- `target_algorithm` — defaults from mapping table; operator can
  override (e.g. choose SLH-DSA for code-signing instead of ML-DSA).
- `target_date` — defaults to IR 8547 anchors; operator override
  required when the CSP commits to an earlier date.
- `inheritance.upstream_target_date` — operator-supplied per
  upstream provider's published roadmap.

**Test specifications** (≥12):

1. `it('emits one migration entry per quantum-vulnerable inventory row', ...)`.
2. `it('maps rsa-2048 → ml-kem-768 by default', ...)`.
3. `it('maps ecdsa-p384 → ml-dsa-65 by default', ...)`.
4. `it('respects pqc-config.yaml target_algorithm override', ...)`.
5. `it('defaults target_date to 2030-12-31 for tls purpose', ...)`.
6. `it('defaults target_date to 2030-06-30 for ca-issuance purpose', ...)`.
7. `it('respects pqc-config.yaml target_date override', ...)`.
8. `it('marks status=complete when target_algorithm already in inventory', ...)`.
9. `it('marks status=pilot when both legacy and target present for same asset', ...)`.
10. `it('emits one unplanned-migration POA&M item per unplanned entry', ...)`.
11. `it('derives severity from target_date band (past/<1y/<3y/<2035/info)', ...)`.
12. `it('strict-pqc mode exits non-zero on past-due unplanned entry', ...)`.
13. `it('writes pqc-migration-plan.docx with sections 1-8', ...)`.
14. `it('writes pqc-migration-plan.json with provenance block', ...)`.
15. `it('owner_source = REQUIRES-OPERATOR-INPUT when no owner configured', ...)`.
16. `it('inheritance.blocked_by_upstream propagates upstream target_date to entry', ...)`.

**REO compliance checks specific to this slice**:
- Every entry traces to a real R.R1 inventory row (no synthetic
  entries).
- Target algorithm / date defaults are constants citing the FIPS /
  IR 8547 source; operator overrides flow through `pqc-config.yaml`.
- Unplanned-migration POA&M items use the existing POA&M emission
  path — they pick up LOOP-B risk scores automatically.
- Provenance block lists exact source files read (inventory,
  pqc-config, tracker snapshot).

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/pqc-migration-plan.test.ts tests/core/pqc-migration-plan-docx.test.ts tests/core/pqc-migration-plan-emit.test.ts
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 4–5 working days.

---

### Slice R.R3 — Annual PQC report emitter

**Why this slice**: OMB M-23-02 §V obligates an annual report through
2035. R.R1 + R.R2 produce the substrate; R.R3 aggregates, computes
year-over-year delta, runs through tracker operator review + AO
sign-off, and emits the OMB-shape `.docx` + `.json`.

**Files to create**:
- `cloud-evidence/core/pqc-annual-report.ts` — pure builder.
- `cloud-evidence/core/pqc-annual-report-docx.ts` — OOXML renderer.
- `cloud-evidence/core/pqc-annual-report-emit.ts` — orchestrates.
- `cloud-evidence/core/pqc-annual-report-reader.ts` — read-only
  client pulling the prior year's report for delta computation.
- `tracker/server/routes/pqc-annual-report.ts` — review + sign-off
  CRUD.
- `tracker/server/routes/pqc-migration-owners.ts` — owner-assignment
  CRUD (used by R.R2 as well).
- `tracker/client/src/pages/PqcAnnualReport.tsx` — review + sign-off
  UI.
- `tracker/client/src/pages/PqcMigrationOwners.tsx` — owner-assignment
  UI.
- Tests: `tests/core/pqc-annual-report.test.ts`,
  `tests/core/pqc-annual-report-docx.test.ts`,
  `tests/core/pqc-annual-report-emit.test.ts`,
  `tracker/server/routes/pqc-annual-report.test.ts`,
  `tracker/server/routes/pqc-migration-owners.test.ts`,
  `tracker/client/src/pages/PqcAnnualReport.test.tsx`.

**Files to extend**:
- `tracker/server/schema.sql` — new tables:
  ```sql
  CREATE TABLE IF NOT EXISTS pqc_annual_report_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    fiscal_year TEXT NOT NULL,
    submitted_by_user_id INTEGER NOT NULL REFERENCES users(id),
    submitted_at TEXT NOT NULL,
    report_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('draft','reviewed','signed','submitted')),
    signed_off_by_user_id INTEGER REFERENCES users(id),
    signed_off_at TEXT,
    signature TEXT NOT NULL,
    signing_key_id TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_pqc_review_year ON pqc_annual_report_reviews(fiscal_year);

  CREATE TABLE IF NOT EXISTS pqc_migration_owners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    asset_id TEXT NOT NULL,
    algorithm_purpose TEXT NOT NULL,
    owner_user_id INTEGER NOT NULL REFERENCES users(id),
    assigned_by_user_id INTEGER NOT NULL REFERENCES users(id),
    assigned_at TEXT NOT NULL,
    notes TEXT,
    UNIQUE (asset_id, algorithm_purpose)
  );

  CREATE TABLE IF NOT EXISTS pqc_algorithm_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL UNIQUE,
    algorithm_token TEXT NOT NULL UNIQUE,
    quantum_vulnerable_class TEXT NOT NULL,
    rationale TEXT NOT NULL,
    set_by_user_id INTEGER NOT NULL REFERENCES users(id),
    set_at TEXT NOT NULL
  );
  ```
- `tracker/server/index.ts` — mount new routes.
- `tracker/client/src/App.tsx` — new routes.
- `core/orchestrator.ts` — `--pqc-annual-report --fiscal-year YYYY` flag.
- `core/submission-bundle.ts` — `WELL_KNOWN` adds:
  - `{ role: 'pqc-annual-report-docx', filename: 'pqc-annual-report-FYYYYY.docx' }`
  - `{ role: 'pqc-annual-report-json', filename: 'pqc-annual-report-FYYYYY.json' }`

**Schemas / standards**:
- **OMB M-23-02 §V required content** (publicly-known structure;
  exact field set confirmed once operator provides the downloaded
  PDF):
  - Agency / CSP identification
  - Fiscal year
  - Inventory totals (current + prior + delta)
  - Quantum-vulnerable algorithm counts by class
  - Migration plan progress (planned / in-progress / pilot / complete)
  - Funding requirements (NSM-10 §3)
  - Inheritance summary
  - Known risks + mitigations
  - Sign-off (CIO + CISO equivalent)
- **NIST IR 8547 §4** "Transition to Post-Quantum Cryptography
  Standards" milestones — referenced in the report's Authority
  section.

**Build steps**:

1. Define `PqcAnnualReport`:
   ```ts
   export interface PqcAnnualReport {
     report_uuid: string;
     fiscal_year: string;                       // FY2026 / FY2027
     csp_name: string;
     system_id: string;
     generated_at: string;
     inventory_summary: {
       total_entries: number;
       quantum_vulnerable_count: number;
       quantum_resistant_count: number;
       transitional_count: number;
       unknown_count: number;
       requires_operator_input_count: number;
     };
     migration_progress: {
       complete: number;
       in_progress: number;
       pilot: number;
       planned: number;
       unplanned: number;
     };
     year_over_year_delta: {
       prior_fiscal_year?: string;              // when prior report exists
       vulnerable_count_delta?: number;         // negative = progress
       migration_complete_delta?: number;
     };
     inheritance_summary: Array<{
       upstream_provider: string;
       asset_count: number;
       upstream_target_date?: string;
       blocked_by_upstream_count: number;
     }>;
     risks: Array<{
       risk_uuid: string;
       title: string;
       severity: 'critical' | 'high' | 'medium' | 'low';
       mitigation: string;
     }>;
     sign_off?: {
       signed_off_by_user_id: number;
       signed_off_at: string;
       signature: string;
       signing_key_id: string;
     };
     authority_citations: string[];             // verbatim from OMB M-23-02 / NSM-10 / IR 8547
     provenance: ProvenanceBlock;
   }
   ```

2. **Aggregator `buildPqcAnnualReport(inventory, plan, priorReport, opts)`**:
   - Reads R.R1 inventory + R.R2 migration plan (current FY).
   - Optionally reads prior FY's report via
     `pqc-annual-report-reader.ts`.
   - Computes deltas; emits zero deltas when no prior report.
   - Pulls risks from OSCAL POA&M (LOOP-B risk scores) where
     `pqc-target-date` prop is set.

3. **Tracker review flow**:
   - Operator generates the report via `--pqc-annual-report`.
   - Report file SHA-256 written to `pqc_annual_report_reviews`.
   - Tracker UI lists draft → reviewed → signed → submitted
     transitions, mirroring LOOP-B.B3 acceptance pattern.
   - AO role required for `signed` transition; signature is
     Ed25519 over canonical-JSON of the report (report_uuid +
     fiscal_year + report_sha256 + signed_off_at).
   - `submitted` transition is operator action after the OMB / agency
     receives the file.

4. **DOCX emitter** in `core/pqc-annual-report-docx.ts`:
   - Reuses OOXML helpers.
   - Sections per OMB §V structure:
     1. Cover (CSP name, FY, system identifier, classification line).
     2. Executive Summary — table of inventory totals + migration
        progress.
     3. Authority — verbatim citations (M-23-02, NSM-10, IR 8547,
        CNSA 2.0, FIPS 203/204/205).
     4. Scope — system boundary + components in scope.
     5. Inventory — per-purpose breakdown, with reference to
        `crypto-inventory.xlsx` companion.
     6. Migration Plan Progress — per-status counts; per-asset
        progress (sampled when > 50 entries; full when ≤ 50).
     7. Year-over-Year Delta — prior FY's totals + this FY's totals
        + computed deltas.
     8. Inheritance — table of upstream-provider × CSP-side asset
        count × inherited target dates.
     9. Risks + Mitigations — joined from LOOP-B risk register
        entries tagged with `pqc-target-date`.
     10. Sign-off — AO name + date + signature reference.
     11. References — verbatim source URLs.

5. **Filename convention**: `pqc-annual-report-FY2026.docx` /
   `pqc-annual-report-FY2026.json`. Fiscal year required via CLI
   flag.

6. **Strict mode**: `--strict-pqc` requires a signed-off prior-year
   review record before the next FY's report ships (prevents
   accidental skipping of an FY).

7. **Submission bundle**: per-FY files added to `WELL_KNOWN` via
   suffix-aware role match.

**REQUIRES-OPERATOR-INPUT fields**:
- Fiscal year — operator supplies via CLI flag.
- Sign-off — AO role, signed via Ed25519 (real signature, never
  auto-generated).
- Risk mitigations — operator-supplied free text via tracker.
- Funding requirements (if NSM-10 §3 applies) — operator-supplied.

**Test specifications** (≥12):

1. `it('aggregates inventory totals correctly', ...)`.
2. `it('computes migration progress counts per status', ...)`.
3. `it('computes year-over-year delta when prior report exists', ...)`.
4. `it('emits zero delta when no prior report', ...)`.
5. `it('joins risks from LOOP-B risk register with pqc-target-date prop', ...)`.
6. `it('emits pqc-annual-report-FYNNNN.json with provenance block', ...)`.
7. `it('emits pqc-annual-report-FYNNNN.docx with all 11 sections', ...)`.
8. `it('rejects sign-off without AO role', ...)`.
9. `it('records sign-off Ed25519 signature in pqc_annual_report_reviews', ...)`.
10. `it('owner-assignment route validates asset_id exists in inventory', ...)`.
11. `it('algorithm-override route requires rationale ≥ 50 chars', ...)`.
12. `it('strict-pqc fails when prior FY review missing', ...)`.
13. `it('inheritance summary aggregates upstream_provider counts', ...)`.
14. `it('submission bundle includes both .docx and .json with correct role', ...)`.
15. `it('UI lists drafts in date-descending order', ...)`.

**REO compliance checks specific to this slice**:
- Inventory + plan + delta all trace to real prior artifacts on
  disk (no synthesised counts).
- Sign-off is a real Ed25519 signature over canonical JSON, signed
  by an AO-roled user; never auto-generated.
- Year-over-year delta is computed; the prior-FY report file is
  read from disk and validated against its embedded sha256.
- Authority citations come verbatim from the downloaded PDFs
  (operator step before R.R3 ships).

**Verification commands**:
```bash
cd cloud-evidence
npm run typecheck
npm test -- tests/core/pqc-annual-report.test.ts tests/core/pqc-annual-report-docx.test.ts tests/core/pqc-annual-report-emit.test.ts
cd ../tracker
npm run typecheck
npm test -- server/routes/pqc-annual-report.test.ts server/routes/pqc-migration-owners.test.ts client/src/pages/PqcAnnualReport.test.tsx
cd ../cloud-evidence
npm run check:reo
npm run check:provenance
```

**Estimated effort**: 5–6 working days (server + client + emit).

---

## 5. Loop-wide acceptance criteria

LOOP-R is COMPLETE when ALL of the following are true:

1. **R.R1**: every quantum-vulnerable + quantum-resistant asymmetric
   crypto surface across AWS / GCP / Azure is enumerated in
   `out/crypto-inventory.json` + `.xlsx`; classification table cites
   IR 8547 §3 verbatim; `pqc-config.yaml` operator overrides work;
   coverage report includes `crypto_inventory_fill_rate` per provider.
2. **R.R2**: every quantum-vulnerable entry in R.R1 has a corresponding
   `PqcMigrationPlanEntry` in `out/pqc-migration-plan.json` +
   `.docx`; unplanned entries flow into POA&M with
   `pqc-target-date` prop; LOOP-B risk scoring picks them up;
   `--strict-pqc` fails the build when past-due unplanned entries
   exist.
3. **R.R3**: per-FY `pqc-annual-report-FYNNNN.docx` + `.json` emit
   end-to-end; tracker review + AO sign-off works; signature is real
   Ed25519; year-over-year delta computes when prior report exists;
   submission bundle includes both per-FY files.
4. All three slices pass `npm run typecheck`, `npm test`, and
   `npm run check:reo` in both `cloud-evidence/` and `tracker/`.
5. CHANGELOG "Unreleased" has three entries (one per slice) with
   module names + verification counts + REO compliance notes +
   verbatim citation of the FIPS / IR 8547 / OMB sources.
6. STATUS.md per-slice rows updated.
7. The four source PDFs (OMB M-23-02, NIST IR 8547 IPD, CNSA 2.0,
   FIPS 203/204/205) are committed to
   `cloud-evidence/docs/sources/` and the constants in
   `core/pqc-classification.ts` cite the page + section numbers
   verbatim — no `REQUIRES-OPERATOR-INPUT: confirm-against-*`
   markers remain.

---

## 6. Open questions / caveats

1. **OMB M-23-02 PDF gated by 403 / binary** — the PDF returns
   encoded PDF binary to anonymous fetches. Operator must download
   into `cloud-evidence/docs/sources/omb-m-23-02.pdf` before R.R1
   ships. Each affected slice's constants carry a
   `REQUIRES-OPERATOR-INPUT: confirm-against-omb-m-23-02` marker
   until the PDF is local.

2. **NIST IR 8547 still in IPD** — the November 2024 draft is the
   currently-authoritative reference. When the final ships (expected
   2025/2026), R.R1's `QUANTUM_CLASSIFICATION` table may add /
   adjust entries. Mitigation: `pqc-config.yaml` `classification_overrides`
   block lets operator tune without code change; the table's
   `ir_version` constant tracks the source version.

3. **CNSA 2.0 binding scope** — CNSA 2.0 applies to National Security
   Systems by mandate; civilian CSPs adopt it voluntarily. R.R2's
   default target dates use the OMB / IR 8547 timeline; the
   `pqc-config.yaml` `cnsa_2_0: true` flag opts a CSP into the
   accelerated timeline.

4. **CVSS / EPSS scoring of un-planned PQC migrations** — LOOP-B's
   composite formula was tuned for CVE-style vulnerabilities. PQC
   migration risk is structurally different (no CVE). Mitigation:
   R.R2's unplanned POA&M items get `cvss-source:
   REQUIRES-OPERATOR-INPUT`; criticality + exposure remain valid
   signals; composite reflects them.

5. **Hybrid mode (TLS 1.3 + ML-KEM)** — IETF TLS WG has draft
   support for hybrid key exchange (X25519+ML-KEM-768 etc.). R.R1
   should detect hybrid suites; classification is
   `quantum-resistant-pqc-hybrid`. Treat as resistant for migration
   purposes (operator's TLS pre-handshake is PQC-protected even if
   the legacy half is still in the suite).

6. **SSH host keys** — operator-managed; not always queryable via
   cloud SDK. R.R1's `pqc-config.yaml` can declare SSH host-key
   inventory as static config.

7. **HSM-backed keys** — purpose may be opaque (HSM exposes key id
   but not always usage). REQUIRES-OPERATOR-INPUT marker per key
   until operator declares purpose.

8. **Annual-report FY boundary** — Federal FY is Oct 1 – Sep 30. R.R3
   defaults to current FY based on system clock; operator can
   override via `--fiscal-year FY2026` flag.

9. **Multi-CSO tenant isolation** — R.R3 tables (pqc_annual_report_reviews,
   pqc_migration_owners, pqc_algorithm_overrides) omit `tenant_id`.
   H.H3 sweep migrates all three when multi-CSO ships.

10. **NSM-10 is reachable as a public memo but the canonical URL
    redirects/404s** — operator downloads the official text into
    `docs/sources/nsm-10.pdf`.

---

## 7. Status tracking

Update this table when a slice ships (see Section 8).

| Slice ID | Title | Status | Commit hash | Completed date |
|---|---|---|---|---|
| R.R1 | Cryptographic Inventory Collector | pending | — | — |
| R.R2 | PQC Migration Plan Emitter | pending | — | — |
| R.R3 | Annual PQC Report Emitter | pending | — | — |

---

## 8. Slice completion procedure (REO-enforced)

When a slice ships, the implementer MUST perform the 7-step
procedure documented in
`cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` verbatim.
Highlights specific to LOOP-R:

1. **Verify green**:
   ```bash
   cd cloud-evidence
   npm run typecheck
   npm test                     # 100% passing (existing total + new slice tests)
   npm run check:reo            # G1 + G2 + G3 all green
   npm run check:provenance     # new emit fields all have provenance entry
   ```
   For R.R3 (tracker work):
   ```bash
   cd ../tracker
   npm run typecheck
   npm test
   ```

2. **Update Section 7 status table** in this file.

3. **Update CHANGELOG.md "Unreleased"** with a new entry. Mirror the
   LOOP-A.A* / LOOP-B.B* entries. Cite the module names + spec links
   + verification counts:
   - Number of new tests + total tests after slice
   - Whether typecheck + check:reo are green
   - Net new files
   - REO-compliance note (no stubs, provenance present, coverage
     rose or held flat)
   - The FIPS / IR 8547 / OMB citations verbatim (with page numbers
     after the implementer's PDF download)

4. **Update `cloud-evidence/docs/STATUS.md`** with the slice row.

5. **Update `cloud-evidence/docs/slices/R/R.RN.md`** frontmatter
   (`status: done`, `commit: <hash>`, `completed_date: <ISO>`,
   `last_updated: <ISO>`).

6. **Update `cloud-evidence/docs/loops/LOOP-R-RISKS.md`** — move any
   resolved risk rows to the "Resolved risks" section atomically.

7. **Commit** with slice ID in message.

8. **Push** to origin/main.

9. **Sanity check**: re-clone into a scratch directory, run the
   orchestrator end-to-end with `--pqc-inventory --pqc-migration-plan
   --pqc-annual-report --fiscal-year FY2026`, verify the artifacts
   land in `out/`.

---

## 9. Appendix — worked example end-to-end

To make LOOP-R reviewable, here is the worked example the test
suite encodes verbatim.

### Setup

- CSP: `Acme SaaS`, system `acme-csaas`.
- 3 quantum-vulnerable assets discovered by R.R1:
  - `arn:aws:kms:us-east-1:123:key/abcd-1234` — KMS RSA-3072,
    purpose `kms-signing`, no rotation.
  - `arn:aws:acm:us-east-1:123:certificate/efgh-5678` — ACM cert
    ECDSA-P256, purpose `tls-server`, listener on prod ALB.
  - `vault:acme-vault.vault.azure.net:key:jwt-signer` — Azure Key
    Vault RSA-2048, purpose `jwt-signing`.
- 1 quantum-resistant asset:
  - `arn:aws:kms:us-east-1:123:alias/data-aead` — KMS AES-256,
    purpose `kms-key-wrap`.
- No prior FY report on disk.

### R.R1 — Inventory

```json
{
  "total_entries": 4,
  "quantum_vulnerable_count": 3,
  "quantum_resistant_count": 1,
  "entries": [
    { "asset_id": "kms-abcd-1234", "algorithm": "rsa-3072", "purpose": "kms-signing", "quantum_vulnerable_class": "quantum-vulnerable-asymmetric", "sources": { "classification_source": "ir-8547-table" } },
    { "asset_id": "acm-efgh-5678", "algorithm": "ecdsa-p256", "purpose": "tls-server", "quantum_vulnerable_class": "quantum-vulnerable-asymmetric", "sources": { "classification_source": "ir-8547-table" } },
    { "asset_id": "akv-jwt-signer", "algorithm": "rsa-2048", "purpose": "jwt-signing", "quantum_vulnerable_class": "quantum-vulnerable-asymmetric", "sources": { "classification_source": "ir-8547-table" } },
    { "asset_id": "kms-data-aead", "algorithm": "aes-256-gcm", "purpose": "kms-key-wrap", "quantum_vulnerable_class": "quantum-resistant-symmetric", "sources": { "classification_source": "ir-8547-table" } }
  ]
}
```

### R.R2 — Migration Plan

Default mappings produce three migration entries:

```json
[
  { "asset_id": "kms-abcd-1234", "current_algorithm": "rsa-3072", "target_algorithm": "ml-dsa-65", "target_fips_standard": "FIPS 204", "target_date": "2030-12-31", "target_date_source": "ir-8547-deprecate-2030", "status": "unplanned" },
  { "asset_id": "acm-efgh-5678", "current_algorithm": "ecdsa-p256", "target_algorithm": "ml-dsa-44", "target_fips_standard": "FIPS 204", "target_date": "2030-12-31", "status": "unplanned" },
  { "asset_id": "akv-jwt-signer", "current_algorithm": "rsa-2048", "target_algorithm": "ml-dsa-65", "target_fips_standard": "FIPS 204", "target_date": "2030-12-31", "status": "unplanned" }
]
```

Three POA&M items emit, each carrying `pqc-target-date=2030-12-31`
+ `pqc-deadline-source=ir-8547-deprecate-2030` props. LOOP-B.B1
scoring layers CVSS+EPSS+criticality+exposure on top.

### R.R3 — Annual Report (FY2026)

```json
{
  "fiscal_year": "FY2026",
  "csp_name": "Acme SaaS",
  "inventory_summary": { "total_entries": 4, "quantum_vulnerable_count": 3, "quantum_resistant_count": 1, "transitional_count": 0 },
  "migration_progress": { "complete": 0, "in_progress": 0, "pilot": 0, "planned": 0, "unplanned": 3 },
  "year_over_year_delta": { "prior_fiscal_year": null },
  "risks": [ ... 3 entries joined from LOOP-B register tagged pqc-target-date ... ]
}
```

Tracker UI surfaces the report as `status: draft`. ISO submits for
review; AO signs off; status moves to `signed`. Submission bundle
ships the signed file as `pqc-annual-report-FY2026.docx`.

### FY2027 (the following year)

R.R1 runs and finds the operator has migrated `akv-jwt-signer` to
ML-DSA-65 (2 quantum-vulnerable + 1 PQC + 1 symmetric). R.R2 marks
that asset's plan entry as `complete`. R.R3 computes
`vulnerable_count_delta = -1`, surfaces it in the executive
summary, and the report flows through review + sign-off again.

That is the LOOP-R value proposition end-to-end: from a
quantum-vulnerable cloud crypto fleet to an OMB-shape annual report
documenting incremental migration progress year over year — with
real signed evidence at every step.
