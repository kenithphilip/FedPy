---
slice_id: R.R1
title: Cryptographic Inventory Collector (asymmetric algorithm × asset × purpose)
loop: R
status: pending
commit: —
completed_date: —
depends_on: [INV-P1, INV-P2, INV-P3, INV-P4, INV-P5, INV-S1, AFR-UCM-AWS, AFR-UCM-GCP, AFR-UCM-AZURE]
blocks: [R.R2, R.R3, G.G5, Q.Q1, N.N1]
estimated_effort: 5-6 working days
last_updated: 2026-06-07
---

# R.R1 — Cryptographic Inventory Collector

## TL;DR
Walk every asymmetric-crypto surface on AWS, GCP, and Azure — KMS asymmetric keys, ACM / Certificate Manager / Key Vault certificates, ALB / Cloud Load Balancer / Application Gateway listener cipher suites, IAM signing certificates, IPsec / VPN endpoint policies — and produce `out/crypto-inventory.json` + `out/crypto-inventory.xlsx` keyed by `(asset_id, algorithm, key_size, purpose, rotation_cadence, quantum_vulnerable_class)`. The classification table cites NIST IR 8547 §3 verbatim; quantum-vulnerable instances of RSA / ECDSA / ECDH / DH / EdDSA are flagged in the enum the downstream R.R2 migration plan reads. The existing AFR-UCM collectors (which verify the *module* is FIPS-validated) are untouched; this slice adds *algorithm enumeration* alongside them.

## Status
- Status: pending
- Commit: — (filled when shipped, per SLICE-COMPLETION-PROCEDURE.md)
- Date: —
- Verification: typecheck=—, tests=—, check:reo=—

## Connection to FedPy mission
FedPy is read-only, evidence-grade automation for FedRAMP 20x + Rev5. The existing `providers/{aws,gcp,azure}/crypto.ts` collectors satisfy KSI-AFR-UCM ("Using Cryptographic Modules") by verifying that crypto runs on FIPS-validated modules. That is sufficient for the *current* Phase Two obligation. It is insufficient for OMB M-23-02 §III, which obligates a *per-algorithm* inventory of every quantum-vulnerable cryptographic system. R.R1 closes the gap by adding algorithm enumeration on top of the existing module-validity collectors — preserving the AFR-UCM evidence path, extending it with a new disk output and a new XLSX workbook, and feeding R.R2 + R.R3 the per-asset substrate they need.

## Why this slice exists
- **OMB M-23-02 §III** requires every federal agency (and by extension every CSP serving federal customers) to maintain a current inventory of information systems and assets containing cryptographic systems vulnerable to a future cryptographically-relevant quantum computer. FedPy emits zero such inventory today.
- **NIST IR 8547 §3** enumerates the quantum-vulnerable asymmetric primitives that will be deprecated by 2030 and disallowed by 2035. The list — RSA, ECDSA, ECDH, DH, EdDSA — is the canonical taxonomy the inventory must surface against.
- **CNSA 2.0** mandates ML-KEM and ML-DSA for National Security Systems on an accelerated 2025–2033 schedule. For CSPs serving NSS-adjacent customers, the inventory must also classify against CNSA 2.0 thresholds.
- **FedRAMP 20x Phase Two** does not yet hard-gate PQC inventory; the Consolidated Rules 2026 window is widely expected to start surfacing it. Federal agency customers and 3PAOs will start asking inside 2026–2028; CSPs that pre-ship this artifact win every authorization conversation that touches the question.
- **R.R2 + R.R3 cannot ship without R.R1**: the migration plan needs the per-asset enumeration; the annual report aggregates inventory totals + year-over-year deltas.

## Authoritative sources (with verbatim quotes)
- https://csrc.nist.gov/pubs/ir/8547/ipd — **NIST IR 8547 IPD, Transition to Post-Quantum Cryptography Standards (Nov 12 2024)**:
  > "Under the transition timeline in NIST IR 8547, NIST will deprecate and ultimately remove quantum-vulnerable algorithms from its standards by 2035, with high-risk systems transitioning much earlier."
  > (Citation via NIST CSRC PQC project page: https://csrc.nist.gov/projects/post-quantum-cryptography .)
  The quantum-vulnerable asymmetric primitives enumerated in §3 (per the IPD; final ship pending) are RSA (all sizes), ECDSA (all NIST curves), ECDH (all NIST + X-curves), DH (finite-field), and EdDSA (Ed25519 / Ed448). The implementer downloads the IPD PDF into `cloud-evidence/docs/sources/nist-ir-8547-ipd.pdf` and pastes §3's exact table into `core/pqc-classification.ts`'s docstring before ship.

- https://csrc.nist.gov/pubs/fips/203/final — **FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM), Aug 13 2024**:
  > "The standard specifies three parameter sets: ML-KEM-512, ML-KEM-768, and ML-KEM-1024, listed in order of increasing security strength and decreasing performance." (CSRC publication page abstract.)
  R.R1's `QUANTUM_CLASSIFICATION` table classifies all three as `quantum-resistant-pqc`.

- https://csrc.nist.gov/pubs/fips/204/final — **FIPS 204, Module-Lattice-Based Digital Signature Standard (ML-DSA), Aug 13 2024**:
  Title: "Module-Lattice-Based Digital Signature Standard". Three parameter sets: ML-DSA-44, ML-DSA-65, ML-DSA-87. R.R1 classifies as `quantum-resistant-pqc`.

- https://csrc.nist.gov/pubs/fips/205/final — **FIPS 205, Stateless Hash-Based Digital Signature Standard (SLH-DSA), Aug 13 2024**:
  Title: "Stateless Hash-Based Digital Signature Standard". Twelve parameter sets (SHA2 + SHAKE × 128 / 192 / 256 × s/f). R.R1 classifies all as `quantum-resistant-pqc`. Intended use cases include firmware / code-signing where stateless signature without key-state management is required.

- https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf — **OMB M-23-02, Migrating to Post-Quantum Cryptography (Nov 18 2022)**:
  PDF returns HTTP 403 / binary to anonymous fetches; implementer downloads to `cloud-evidence/docs/sources/omb-m-23-02.pdf`. §III "Cryptographic Inventory" obligates a current per-asset inventory of quantum-vulnerable cryptography. §V obligates an annual report through 2035 (consumed by R.R3).

- https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF — **NSA CNSA 2.0 (Sep 2022)**:
  PDF returns HTTP 403 to anonymous fetches; implementer downloads to `cloud-evidence/docs/sources/cnsa-2.0.pdf`. Mandates ML-KEM + ML-DSA for NSS by 2033. R.R1 honours an opt-in `pqc-config.yaml` `cnsa_2_0: true` flag that swaps the classification timeline.

- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf — **NIST SP 800-53 Rev 5, SC-12 + SC-13**:
  > "SC-12 (Cryptographic Key Establishment and Management) … Establish and manage cryptographic keys when cryptography is employed within the system."
  > "SC-13 (Cryptographic Protection) … Implement [the following types of cryptography] required for protecting information that requires the application of cryptographic mechanisms."
  R.R1 surfaces the *what* and *where* SC-12/SC-13 leave to the operator.

## Files to create (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pqc-inventory.ts` — pure aggregator + types (`CryptoInventoryEntry`, `QuantumVulnerableClass`, `CryptoPurpose`). ~500 lines.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pqc-classification.ts` — typed constant table `QUANTUM_CLASSIFICATION` mapping algorithm tokens to classes; docstring cites IR 8547 §3 + CNSA 2.0 verbatim post-PDF-download.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pqc-inventory-emit.ts` — disk emitter that walks provider blocks, joins to inventory, writes `out/crypto-inventory.json` (+ provenance) + `out/crypto-inventory.xlsx`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pqc-inventory-xlsx.ts` — pure-JS xlsx renderer reusing the `core/inventory-workbook.ts` pattern. 14 columns.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/pqc-config.ts` — typed loader for `pqc-config.yaml`. Validates `classification_overrides{}`, `algorithm_purpose_overrides{}`, `inheritance{}` keys.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/pqc-config.example.yaml` — committed example.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pqc-inventory.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pqc-classification.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pqc-inventory-emit.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pqc-inventory-xlsx.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/core/pqc-config.test.ts`
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tests/fixtures/pqc/` — sample provider blocks (AWS KMS, GCP Cloud KMS, Azure Key Vault) + sample inventory.json.

## Files to extend (exact paths)
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/aws/crypto.ts` — add `enumerateAwsAsymmetricCrypto(ctx) → CryptoInventoryEntry[]` that walks:
  - **KMS** customer-managed asymmetric keys via `ListKeys` + `DescribeKey` (KeySpec ∈ RSA_2048, RSA_3072, RSA_4096, ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521, ECC_SECG_P256K1, SM2; KeyUsage ∈ SIGN_VERIFY, ENCRYPT_DECRYPT, KEY_AGREEMENT).
  - **ACM** issued certificates via `ListCertificates` + `DescribeCertificate` (KeyAlgorithm, InUseBy[]).
  - **IAM** signing certificates (`ListSigningCertificates`) + server certificates (`ListServerCertificates` + `GetServerCertificate`).
  - **ELBv2** listener `ssl_policy` cipher suite enumeration via `DescribeListeners` + `DescribeSSLPolicies`.
  - **CloudFront** distribution viewer-certificate algorithm via `ListDistributions`.
  - **RDS** instance TLS endpoint algorithm via `DescribeDBInstances` (TLS minimum version + Certificate Authority).
  Keep existing `collectUcm()` untouched.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/gcp/crypto.ts` — add `enumerateGcpAsymmetricCrypto(ctx) → CryptoInventoryEntry[]` over:
  - **Cloud KMS** asymmetric keys (`purpose: ASYMMETRIC_SIGN | ASYMMETRIC_DECRYPT`, algorithm enum e.g. `RSA_SIGN_PSS_2048_SHA256`, `EC_SIGN_P256_SHA256`).
  - **Certificate Manager** managed certificates (`Certificate.managed.dns_authorizations` + `pem_certificate`).
  - **Compute Engine** SSL policies (`min_tls_version`, `profile`, `custom_features[]`).
  - **Load Balancer** target HTTPS proxies (`ssl_certificates[]`, `ssl_policy`).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/azure/crypto.ts` — add `enumerateAzureAsymmetricCrypto(ctx) → CryptoInventoryEntry[]` over:
  - **Key Vault** keys (kty=RSA / EC, crv=P-256 / P-384 / P-521, key_size, keyOps) via the existing Resource Graph query path; extend the projection to include `kty`, `crv`, `key_size`, `keyOps[]`.
  - **App Gateway** SSL policies (extend existing query to project `properties.sslPolicy.cipherSuites[]` + `disabledSslProtocols[]`).
  - **App Service** minimum TLS version + ciphers.
  - **Front Door** custom domain cipher suite + min TLS version.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/envelope.ts` — extend `ProviderBlock` interface with optional `crypto_inventory_entries?: CryptoInventoryEntry[]` field (additive, backward-compatible).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — new `--pqc-inventory` flag + env `CLOUD_EVIDENCE_PQC_INVENTORY`; runs AFTER provider collection.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — `WELL_KNOWN` adds:
  ```ts
  { role: 'crypto-inventory-json', filename: 'crypto-inventory.json', description: 'Asymmetric crypto inventory per OMB M-23-02 §III (LOOP-R.R1)' },
  { role: 'crypto-inventory-xlsx', filename: 'crypto-inventory.xlsx', description: 'Operator-readable PQC inventory workbook (LOOP-R.R1)' },
  ```
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts` — extend to track `crypto_inventory_fill_rate` per provider × purpose.

## Schemas / standards
- **`CryptoInventoryEntry`** schema (see LOOP-R-SPEC.md §4.R1 for full definition):
  ```ts
  interface CryptoInventoryEntry {
    asset_id: string;
    provider: 'aws' | 'gcp' | 'azure';
    resource_arn?: string;
    resource_id?: string;
    algorithm: string;                    // canonicalised lowercase token
    key_size?: number;
    curve?: string;
    purpose: CryptoPurpose;
    rotation_cadence_days?: number;
    last_rotated_at?: string;
    fips_module_certificate?: string;
    quantum_vulnerable_class: QuantumVulnerableClass;
    inheritance_source?: 'aws-kms' | 'gcp-cloud-kms' | 'azure-key-vault' | 'in-house' | 'third-party';
    sources: {
      algorithm_source: 'sdk-keyspec' | 'sdk-cert-public-key' | 'sdk-ssl-policy-cipher' | 'tag-override' | 'operator-config' | 'REQUIRES-OPERATOR-INPUT';
      purpose_source:    'sdk-keyusage' | 'sdk-cert-extkey-usage' | 'operator-config' | 'REQUIRES-OPERATOR-INPUT';
      classification_source: 'ir-8547-table' | 'cnsa-2.0-table' | 'operator-override' | 'REQUIRES-OPERATOR-INPUT';
    };
    discovered_at: string;
  }
  ```
- **`QuantumVulnerableClass`** — `quantum-vulnerable-asymmetric` | `quantum-resistant-symmetric` | `quantum-resistant-pqc` | `transitional-symmetric` | `unknown` | `REQUIRES-OPERATOR-INPUT`.
- **`CryptoPurpose`** — `tls-server` | `tls-client` | `kms-key-wrap` | `kms-signing` | `code-signing` | `jwt-signing` | `vpn-ipsec` | `ssh-host-key` | `ca-issuance` | `message-signing` | `hsm-backed` | `other`.
- **Algorithm token canonicalisation rules**: lowercase, hyphen-separated. AWS KMS `RSA_3072` → `rsa-3072`. GCP Cloud KMS `RSA_SIGN_PSS_2048_SHA256` → `rsa-2048` (drops the padding + hash suffix into a separate `padding` / `hash` field on the entry — to be added if needed by R.R2). Azure Key Vault `kty=RSA, key_size=4096` → `rsa-4096`. ECC: AWS `ECC_NIST_P384` → `ecdsa-p384` when KeyUsage=SIGN_VERIFY; `ecdh-p384` when KeyUsage=KEY_AGREEMENT.
- **`QUANTUM_CLASSIFICATION`** typed constant table — see LOOP-R-SPEC.md §4.R1 step 2 for the full table. Cites IR 8547 §3 in docstring (post-PDF-download); falls back to `REQUIRES-OPERATOR-INPUT: confirm-against-ir-8547` until then.
- **Coverage contract**: `core/inventory-coverage.ts` gains `crypto_inventory_fill_rate` per (provider, purpose). Initial fill rate baselined the run after R.R1 ships. CI G2 (`check:coverage-regression`) fails on subsequent drops.
- **`inventory.json` join key**: every `CryptoInventoryEntry.asset_id` must match an `inventory.assets[].identifier`. When no match, `asset_source: 'cross-cloud-discovery'` and the entry surfaces in the gap report.

## Build steps (concrete, numbered)
1. Define `QuantumVulnerableClass`, `CryptoPurpose`, `CryptoInventoryEntry` types in `core/pqc-inventory.ts`.
2. Define `QUANTUM_CLASSIFICATION` constant in `core/pqc-classification.ts` with every algorithm token in the LOOP-R-SPEC.md §4.R1 step 2 table. Add docstring block citing IR 8547 §3 + FIPS 203/204/205 page numbers (verbatim, after PDF download).
3. Implement `canonicaliseAlgorithm(raw, provider, key_size?, curve?) → string` — pure function that converts provider-specific tokens to canonical lowercase. Cases: AWS `KeySpec`, GCP `CryptoKeyVersion.algorithm`, Azure `(kty, crv, key_size)` triple.
4. Implement `classify(algoToken) → QuantumVulnerableClass` — reads `QUANTUM_CLASSIFICATION`; unknown → `unknown`; `unknown` joined with operator override map → final class.
5. Implement `derivePurpose(provider, keyUsage / keyOps / extKeyUsage / SSL-policy-cipher) → CryptoPurpose`.
6. In `providers/aws/crypto.ts` — add `enumerateAwsAsymmetricCrypto(ctx)`. Reuses existing `aws.kms()` / `aws.acm()` / `aws.iam()` / `aws.elbv2()` / `aws.cloudfront()` / `aws.rds()` clients (read-only). Each SDK call is recorded in `raw_evidence` for provenance.
7. In `providers/gcp/crypto.ts` — add `enumerateGcpAsymmetricCrypto(ctx)`. Reuses existing `gcp.cloudKms()` / `gcp.certificateManager()` / `gcp.compute()` clients.
8. In `providers/azure/crypto.ts` — add `enumerateAzureAsymmetricCrypto(ctx)`. Extend existing Resource Graph queries to project the additional fields (`kty`, `crv`, `key_size`, `keyOps`, `cipherSuites`).
9. Aggregator `aggregatePqcInventory(providerBlocks, inventory, opts) → CryptoInventoryEntry[]` in `core/pqc-inventory.ts`:
   - Walks each provider block's `crypto_inventory_entries`.
   - Joins to `inventory.assets[]` by `asset_id`.
   - Applies `pqc-config.yaml` overrides (algorithm-overrides, classification-overrides).
   - De-duplicates exact `(asset_id, algorithm, purpose)` triples.
   - Returns sorted (by `quantum_vulnerable_class` desc, then `asset_id`).
10. Disk emitter `emitPqcInventory(opts) → PqcInventoryEmitResult` in `core/pqc-inventory-emit.ts`:
    - Reads provider blocks from `out/KSI-*.json` (the same envelopes the rest of the pipeline reads).
    - Reads inventory from `out/inventory.json`.
    - Reads `pqc-config.yaml` (optional).
    - Calls aggregator.
    - Writes `out/crypto-inventory.json` with top-level provenance block (per REO Rule 2.6): emitter name, emittedAt, sourceCalls (envelope paths, inventory path, pqc-config path), signingKeyId.
    - Writes `out/crypto-inventory.xlsx` via `core/pqc-inventory-xlsx.ts`.
    - Updates `out/inventory-coverage.json` with new `crypto_inventory_fill_rate` per provider × purpose.
11. XLSX renderer (`core/pqc-inventory-xlsx.ts`) — reuse the OOXML compose pattern from `core/inventory-workbook.ts`. 14 columns:
    A: Asset ID — B: Provider — C: Resource ARN/ID — D: Algorithm — E: Key Size / Curve — F: Purpose — G: Quantum-Vulnerable Class — H: Rotation Cadence (days) — I: Last Rotated At — J: FIPS Module Cert — K: Inheritance Source — L: Algorithm Source — M: Classification Source — N: Discovered At. Conditional formatting: `quantum-vulnerable-asymmetric` rows tinted red; `REQUIRES-OPERATOR-INPUT` rows tinted amber.
12. `pqc-config.example.yaml` — committed example with documented schema:
    ```yaml
    # pqc-config.example.yaml — operator copies to pqc-config.yaml and customises.
    classification_overrides:
      "custom-rsa-cnsa": quantum-vulnerable-asymmetric
    algorithm_purpose_overrides:
      "akv-jwt-signer": jwt-signing
    inheritance:
      aws-kms:
        upstream_target_date: 2028-12-31
      azure-key-vault:
        upstream_target_date: 2029-06-30
    cnsa_2_0: false   # set true for NSS-adjacent CSPs
    ```
13. Wire orchestrator: `--pqc-inventory` flag invokes `emitPqcInventory()` AFTER provider collection (so envelopes have `crypto_inventory_entries`). Documented order in `core/orchestrator.ts`: collect → score → POA&M → AR → bundle → sign → **PQC inventory** → migration plan → annual report.
14. Sign + timestamp: `crypto-inventory.json` and `.xlsx` flow through the existing `core/sign.ts` glob + RFC 3161 manifest.
15. Validation:
    - `npm run check:provenance` — must list the `provenance` block on `crypto-inventory.json`.
    - `npm run lint:no-stubs` — no TODO/stub markers.
    - `npm run check:coverage-regression` — initial baseline; subsequent runs must not drop fill rate.

## REQUIRES-OPERATOR-INPUT fields
Per REO Rule 4 (`cloud-evidence/CLAUDE.md`):

| Field | Source | Behavior when missing |
|---|---|---|
| `algorithm_source` | Provider SDK (KMS KeySpec / Cloud KMS algorithm / Azure KV kty+crv+size) | Unknown SDK token → `REQUIRES-OPERATOR-INPUT`; operator maps via `pqc-config.yaml` `algorithm_overrides{}` |
| `purpose_source` | SDK keyUsage / keyOps / extKeyUsage | Opaque (HSM-backed) → `REQUIRES-OPERATOR-INPUT`; operator declares via `pqc-config.yaml` `algorithm_purpose_overrides{}` |
| `classification_source` | `QUANTUM_CLASSIFICATION` table lookup | Algorithm token not in table → `REQUIRES-OPERATOR-INPUT`; operator declares via `pqc-config.yaml` `classification_overrides{}` |
| `inheritance_source` | Operator-supplied via `pqc-config.yaml` `inheritance{}` | Default `none`; surfaces in entry |
| `asset_id` join | `inventory.json` lookup | When no match: `asset_source: 'cross-cloud-discovery'`, entry retained, gap reported in coverage |
| `cnsa_2_0` opt-in | `pqc-config.yaml` | Defaults to `false` (OMB / IR 8547 timeline); operator opts in for NSS adjacency |

## Test specifications (≥12 tests)
1. `it('classifies rsa-2048 as quantum-vulnerable-asymmetric per IR 8547 §3')` — canonical token in the table; assertion against `QUANTUM_CLASSIFICATION['rsa-2048']`.
2. `it('classifies ml-kem-768 as quantum-resistant-pqc per FIPS 203')` — verifies ML-KEM parameter set.
3. `it('classifies aes-256-gcm as quantum-resistant-symmetric (Grover 128-bit effective)')`.
4. `it('classifies aes-128-gcm as transitional-symmetric')` — verifies the Grover-halved bucket.
5. `it('classifies unknown algorithm tokens as REQUIRES-OPERATOR-INPUT')` — asserts the gap surfaces, doesn't silently default.
6. `it('canonicalises AWS KMS KeySpec RSA_2048 → rsa-2048')` — algorithm-token normalisation.
7. `it('canonicalises AWS KMS ECC_NIST_P384 + KeyUsage=SIGN_VERIFY → ecdsa-p384')` — same token, different purpose disambiguates curve usage.
8. `it('canonicalises AWS KMS ECC_NIST_P384 + KeyUsage=KEY_AGREEMENT → ecdh-p384')`.
9. `it('canonicalises GCP Cloud KMS RSA_SIGN_PSS_2048_SHA256 → rsa-2048')`.
10. `it('canonicalises Azure Key Vault kty=RSA + key_size=3072 → rsa-3072')`.
11. `it('canonicalises Azure Key Vault kty=EC + crv=P-256 → ecdsa-p256 when keyOps=[sign,verify]')`.
12. `it('derives purpose=tls-server from ACM cert InUseBy ALB listener')`.
13. `it('derives purpose=kms-signing from KMS KeyUsage=SIGN_VERIFY')`.
14. `it('enumerates ALB listener ssl_policy ciphersuites including TLS_AES_256_GCM_SHA384')` — checks symmetric-suite classification path.
15. `it('joins entries to inventory.json by asset_id')` — sample inventory + sample provider block, asserts the matched join.
16. `it('marks asset_source=cross-cloud-discovery when asset_id not in inventory')`.
17. `it('emits crypto-inventory.json with provenance.emitter + sourceCalls')` — `check:provenance` script run against the emitted file exits 0.
18. `it('emits crypto-inventory.xlsx with 14 columns and one row per entry')` — SheetJS round-trip.
19. `it('honours pqc-config.yaml classification_overrides for custom tokens')`.
20. `it('honours pqc-config.yaml algorithm_purpose_overrides')`.
21. `it('coverage report includes crypto_inventory_fill_rate per (provider, purpose)')`.
22. `it('SLH-DSA-SHAKE-128f classifies as quantum-resistant-pqc')` — full SLH-DSA enumeration.
23. `it('cnsa_2_0: true flag swaps the classification timeline reference')`.
24. `it('rejects pqc-config.yaml when classification_override value is invalid enum')` — config loader throws typed error.

## REO compliance
Per `cloud-evidence/CLAUDE.md`:
- **Rule 1.1** — every algorithm token traces to a real SDK response or operator config; no placeholder returns.
- **Rule 1.3** — algorithm strings come from cloud SDK responses (`KeySpec`, `algorithm`, `kty`) or `pqc-config.yaml`; never hardcoded sample data.
- **Rule 1.4** — provider SDK clients are the existing read-only Proxy clients (`aws.kms()`, `gcp.cloudKms()`, `azure.resourceGraph()`); no mocked clients in production paths.
- **Rule 1.5** — when classification fails, the entry's `classification_source = 'REQUIRES-OPERATOR-INPUT'` and `inventory-coverage.json` flags it; never silently classified as `quantum-resistant-symmetric` to inflate the fill rate.
- **Rule 1.8** — no `if (process.env.NODE_ENV === 'test')` branches; tests inject HTTP / SDK seams via dependency injection.
- **Rule 1.9** — every emit field (algorithm, purpose, class, sources block) has end-to-end implementation; schema does not exceed implementation.
- **Rule 2.1** — end-to-end flow is real cloud SDK call → real envelope read → real disk write.
- **Rule 2.2** — signed + timestamped via existing `core/sign.ts` (Ed25519 + RFC 3161).
- **Rule 2.3** — coverage report `inventory-coverage.json` gains `crypto_inventory_fill_rate`; baseline established on first run; subsequent runs must not drop.
- **Rule 2.4** — parsers / classifiers / xlsx renderer never mocked; only SDK transport mocked in tests.
- **Rule 2.5** — `npm run lint:no-stubs` green.
- **Rule 2.6** — `provenance` block on `crypto-inventory.json`; `check:provenance` green.

## Verification commands
```bash
cd /Users/kenith.philip/FedRAMP\ 20x/cloud-evidence
npm run typecheck
npm test -- tests/core/pqc-inventory.test.ts tests/core/pqc-classification.test.ts tests/core/pqc-inventory-emit.test.ts tests/core/pqc-inventory-xlsx.test.ts tests/core/pqc-config.test.ts
npm run check:reo
npm run check:provenance
npm run check:coverage-regression
npm run lint:no-stubs
```

## Known risks / issues
- **Risk 1: NIST IR 8547 is in IPD; final ship may adjust the enumerated quantum-vulnerable list.** Mitigation: classification table sourced from a pinned `ir_version = "8547-ipd-2024-11"` constant; when the final lands, bump the constant + adjust entries; operator override via `pqc-config.yaml` lets early adopters opt in pre-final.
- **Risk 2: Provider SDK algorithm enums change between SDK versions (e.g. AWS KMS adds a new `KeySpec` enum entry).** Mitigation: `canonicaliseAlgorithm()` returns `unknown` for unrecognised tokens; the entry surfaces via `algorithm_source: 'REQUIRES-OPERATOR-INPUT'`; never silently misclassified.
- **Risk 3: HSM-backed keys have opaque purpose.** Mitigation: `purpose_source: 'REQUIRES-OPERATOR-INPUT'` on the entry; operator declares via `pqc-config.yaml`; gap visible in coverage report.
- **Risk 4: Same logical asset surfaces multiple algorithm entries (e.g. ACM cert with RSA + ECDSA SAN entries).** Mitigation: de-dup key is `(asset_id, algorithm, purpose)` triple; multi-algo certs produce multiple entries by design (each must migrate independently).
- **Risk 5: Cross-cloud-discovered keys (asset not in inventory).** Mitigation: `asset_source: 'cross-cloud-discovery'` and gap surfaces; operator follow-up: either tag the asset for INV inclusion or declare exclusion via `pqc-config.yaml`.
- **Risk 6: SSL policy + cipher suite enumeration is expensive on large fleets.** Mitigation: existing AFR-UCM collectors already pull policies; we extend the projection, not the query count. Total runtime ≤ +15% over baseline; benchmarked in CI.
- **Risk 7: Azure Resource Graph queries truncate at 1000 rows + `$skipToken` pagination.** Mitigation: existing `runKql()` in `providers/azure/crypto.ts` already paginates up to 50 pages = 50k rows; large CSPs above that need additional partitioning by subscription.
- **Risk 8: `pqc-config.yaml` conflict with `risk-config.yaml` semantics.** Mitigation: distinct file names + namespaces; loader-level schema validation prevents accidental cross-pollination.

## Open questions (for implementation session to resolve)
- **Q1**: Should hybrid TLS suites (e.g. `X25519MLKEM768`) classify as `quantum-resistant-pqc` or a new `quantum-resistant-pqc-hybrid` class? Recommend: new class `quantum-resistant-pqc-hybrid` so the inventory can distinguish (R.R2 may treat them as migration-complete or migration-in-progress depending on operator policy).
- **Q2**: When an ACM certificate is `InUseBy: []` (orphaned), should it still appear in the inventory? Recommend: yes, with `purpose: 'other'` + a note; operator may want to clean up orphans during PQC migration anyway.
- **Q3**: AWS KMS asymmetric keys with `KeyManager = AWS` (AWS-managed CMKs) — include or exclude? Recommend: exclude from the inventory but include in inheritance reporting (R.R2 reads them).
- **Q4**: Should ELBv2 listener cipher-suite enumeration walk each ciphersuite as a separate inventory entry, or aggregate at listener level? Recommend: aggregate per listener with `algorithm` = the strongest enumerated suite + a `cipher_suites_aggregated[]` extension array.
- **Q5**: GCP Cloud KMS supports import via `ImportJob`; should we record import provenance per key? Recommend: yes, add an optional `import_job_id` field to the entry for completeness.
- **Q6**: When `pqc-config.yaml` is missing entirely (operator did not opt in), do we fail loud or run with defaults? Recommend: run with defaults, log `pqc:config-missing` info; CHANGELOG documents.

## Implementation log (running journal — implementing session updates)
```
(empty — implementing session fills this in as work progresses)
```

## Completion checklist (from SLICE-COMPLETION-PROCEDURE.md)
The implementing session MUST check every box:
- [ ] typecheck clean (`npm run typecheck`)
- [ ] tests passing 100% (count increased by ≥24 for this slice's new tests)
- [ ] check:reo green (G1+G2+G3)
- [ ] check:provenance green for `crypto-inventory.json`
- [ ] STATUS.md updated (slice row + Overall section)
- [ ] LOOP-R-SPEC.md status table updated
- [ ] This file's frontmatter updated (status=done, commit=<hash>, completed_date=<ISO>, last_updated=<ISO>)
- [ ] CHANGELOG.md "Unreleased" entry added (cites FIPS 203/204/205 + IR 8547 + OMB M-23-02 §III)
- [ ] Commit with slice ID `R.R1` in message
- [ ] Pushed to origin/main

## Resume-from-fresh-session checklist
If a session opens with ONLY this file as context:
1. Read `cloud-evidence/CLAUDE.md` (auto-loaded; REO standard).
2. This file gives you: source obligations + files to create + build steps + tests + risks + completion checklist.
3. Read `cloud-evidence/docs/loops/LOOP-R-SPEC.md` §2 (Dependencies) + §3 (Authoritative sources) for cross-loop context.
4. Read `cloud-evidence/docs/loops/LOOP-R-RISKS.md` cross-cutting section for risks affecting all R slices.
5. Read `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` for the mandatory 7-step commit pattern.
6. Read `cloud-evidence/providers/azure/crypto.ts` end-to-end — it's the existing AFR-UCM collector pattern your extension mirrors.
7. Read `cloud-evidence/providers/aws/crypto.ts` + `providers/gcp/crypto.ts` for the same pattern in their providers.
8. Read `cloud-evidence/core/envelope.ts` — you'll add `crypto_inventory_entries?: CryptoInventoryEntry[]` to `ProviderBlock`.
9. Read `cloud-evidence/core/inventory-workbook.ts` for the OOXML xlsx renderer pattern your new `pqc-inventory-xlsx.ts` mirrors.
10. Read `cloud-evidence/core/inventory-coverage.ts` for the coverage-contract pattern.
11. Read `cloud-evidence/core/submission-bundle.ts` `WELL_KNOWN` array — add two new entries.
12. Download the four source PDFs (OMB M-23-02, NIST IR 8547 IPD, CNSA 2.0, FIPS 203/204/205) into `cloud-evidence/docs/sources/`; paste verbatim §3 quantum-vulnerable table into `core/pqc-classification.ts` docstring.
13. Begin implementation; update Implementation log section as you go.

---
