# Dependency Graph — every slice across LOOP-A through LOOP-W (+ CIRCIA + SEC 8-K overlays)

> Single source of truth for slice ordering. Derived from the `depends_on`
> and `blocks` frontmatter in every per-slice doc under `docs/slices/X/X.XN.md`.
> Read this when planning what to work on next, what can be parallelised,
> and what cannot start yet.
>
> **Scope:** 92 enumerated slices (LOOP-A complete; LOOP-B through LOOP-W
> pending) + 3 overlay slices (G.G2.CIRCIA, M.M4.CIRCIA, G.G2-SEC-8K).
> LOOP-L through LOOP-Q were ratified 2026-06-07 (see
> `ADDITIONAL-LOOPS-AUDIT.md` + `SECOND-PASS-AUDIT.md`). LOOP-R + LOOP-S +
> CIRCIA extensions were ratified 2026-06-07 (see `THIRD-PASS-AUDIT.md`).
> LOOP-T (Continuous Authorization Telemetry) and LOOP-W (Supply Chain
> Transparency / SBOM Attestation) were ratified 2026-06-07 (see
> `FOURTH-PASS-AUDIT.md`). The SEC 8-K Item 1.05 overlay on G.G2 was
> ratified 2026-06-07 (publicly-traded CSPs only).
> LOOP-M (Privacy/SORN/DPIA) and LOOP-O (AI/ML Governance) are confirmed
> applicable. LOOP-R (PQC) is mandatory for all CSPs (federal mandate);
> LOOP-S (DFARS 7012) is conditional on DoD-prime customers; CIRCIA
> extensions are HIGH PRIORITY (May 2026 effective date); LOOP-T is
> recommended for any CSP pursuing 20x Phase Two; LOOP-W is mandatory
> per EO 14028 + OMB M-22-18 + M-23-16; SEC 8-K overlay is conditional
> on publicly-traded CSP status.

---

## 1. Mermaid graph — full dependency map

```mermaid
graph TD
  %% =========================================================
  %% Pre-flight (DONE)
  %% =========================================================
  REO0[REO-0 REO standard + CI guardrails]
  R1[R1 AFR family classification]
  R2[R2 Monthly POA&M delta research]
  R3[R3 Phase Two pilot output format]
  R4[R4 Sample selection methodology]

  %% Inventory chain (DONE)
  INVCHAIN[INV-P1..S6 Inventory chain]
  SSP1[SSP-1 OSCAL SSP emitter]
  SCN1[SCN-1 SCN classifier]
  SUBSHEET[subprocessors-sheet]
  IAMAAM[IAM-AAM AWS/GCP/AZ]
  IAMELP[IAM-ELP AWS/GCP/AZ]
  INRRIR[INR-RIR collector]
  RPLCHAIN[RPL-ABO/TRC/RRO/ARP collectors]
  VDRSCAN[VDR-* scanner collectors]
  E2SBOM[E.2 SBOM depth]
  REFARCH[providers/*/reference-arch.ts]
  KSIMAP[ksi-map.ts]
  DOCXPRIM[Pre-slice docx-primitives]

  %% =========================================================
  %% LOOP-A (DONE)
  %% =========================================================
  REO0 --> A.A1[A.A1 OSCAL POA&M emitter]
  A.A1 --> A.A2[A.A2 OSCAL Assessment Plan]
  A.A2 --> A.A3[A.A3 AR import-AP chain]
  A.A3 --> A.A4[A.A4 Submission package bundler]
  A.A4 --> A.A5[A.A5 Rules of Engagement template]

  %% =========================================================
  %% LOOP-B Risk + Remediation Engine
  %% =========================================================
  A.A1 --> B.B1[B.B1 CVSS+EPSS scoring]
  INVCHAIN --> B.B1
  B.B1 --> B.B2[B.B2 Remediation deadline math]
  A.A1 --> B.B2
  B.B1 --> B.B3[B.B3 Risk acceptance workflow]
  B.B2 --> B.B3
  A.A1 --> B.B3
  A.A3 --> B.B3
  B.B3 --> B.B4[B.B4 Compensating-controls registry]
  A.A1 --> B.B4
  B.B1 --> B.B5[B.B5 Central Risk Register RA-3]
  B.B2 --> B.B5
  B.B3 --> B.B5
  B.B4 --> B.B5
  A.A1 --> B.B5
  A.A4 --> B.B5

  %% =========================================================
  %% LOOP-C Document Template Pack
  %% =========================================================
  DOCXPRIM --> C.C1[C.C1 CMP CM-9]
  A.A4 --> C.C1
  INVCHAIN --> C.C1
  SSP1 --> C.C1
  DOCXPRIM --> C.C2[C.C2 ISCP + AAR CP-2]
  RPLCHAIN --> C.C2
  INVCHAIN --> C.C2
  SSP1 --> C.C2
  DOCXPRIM --> C.C3[C.C3 IRP + AAR IR-8]
  INRRIR --> C.C3
  INVCHAIN --> C.C3
  SSP1 --> C.C3
  DOCXPRIM --> C.C4[C.C4 PTA + PIA]
  INVCHAIN --> C.C4
  SSP1 --> C.C4
  DOCXPRIM --> C.C5[C.C5 FIPS 199]
  SSP1 --> C.C5
  DOCXPRIM --> C.C6[C.C6 ConMon Strategy CA-7]
  A.A1 --> C.C6
  INVCHAIN --> C.C6
  VDRSCAN --> C.C6
  KSIMAP --> C.C6
  DOCXPRIM --> C.C7[C.C7 RMS PM-9]
  A.A1 --> C.C7
  B.B3 --> C.C7
  B.B4 --> C.C7
  B.B5 --> C.C7
  J.J1 --> C.C7
  J.J2 --> C.C7
  J.J3 --> C.C7
  I.I4 --> C.C7
  DOCXPRIM --> C.C8[C.C8 Cover letter]
  A.A4 --> C.C8
  A.A2 --> C.C8
  C.C5 --> C.C8
  DOCXPRIM --> C.C9[C.C9 Baseline Config CM-2]
  INVCHAIN --> C.C9
  REFARCH --> C.C9
  D.D1 --> C.C9
  D.D2 --> C.C9
  D.D3 --> C.C9
  I.I4 --> C.C1
  I.I4 --> C.C2
  I.I4 --> C.C3
  I.I4 --> C.C5
  I.I4 --> C.C6
  I.I4 --> C.C8
  I.I4 --> C.C9

  %% =========================================================
  %% LOOP-D Diagrams
  %% =========================================================
  INVCHAIN --> D.D1[D.D1 Boundary diagram]
  A.A4 --> D.D1
  REO0 --> D.D1
  D.D1 --> D.D2[D.D2 Network diagram]
  INVCHAIN --> D.D2
  A.A4 --> D.D2
  D.D2 --> D.D3[D.D3 Data flow diagram]
  D.D1 --> D.D3
  INVCHAIN --> D.D3
  A.A4 --> D.D3

  %% =========================================================
  %% LOOP-E ConMon agent
  %% =========================================================
  A.A1 --> E.E1[E.E1 Monthly ConMon report]
  A.A4 --> E.E1
  B.B1 --> E.E1
  B.B2 --> E.E1
  B.B5 --> E.E1
  E.E5 --> E.E1
  E.E6 --> E.E1
  G.G6 --> E.E1
  I.I3 --> E.E1
  K.K1 --> E.E1
  E.E1 --> E.E2[E.E2 Monthly POA&M delta]
  A.A1 --> E.E2
  B.B2 --> E.E2
  E.E1 --> E.E3[E.E3 Annual assessment package]
  E.E2 --> E.E3
  E.E4 --> E.E3
  E.E5 --> E.E3
  E.E6 --> E.E3
  E.E7 --> E.E3
  A.A2 --> E.E3
  A.A3 --> E.E3
  A.A4 --> E.E3
  A.A1 --> E.E3
  K.K2 --> E.E3
  H.H1 --> E.E3
  H.H2 --> E.E3
  A.A2 --> E.E4[E.E4 Annual SSP review]
  E.E3 --> E.E4
  A.A1 --> E.E5[E.E5 Deviation Request emitter]
  A.A5 --> E.E5
  B.B3 --> E.E5
  A.A5 --> E.E6[E.E6 Formal SCN doc]
  SCN1 --> E.E6
  D.D1 --> E.E6
  D.D2 --> E.E6
  D.D3 --> E.E6
  A.A5 --> E.E7[E.E7 Annual IRP/ISCP test cadence]
  E.E3 --> E.E7
  C.C2 --> E.E7
  C.C3 --> E.E7

  %% =========================================================
  %% LOOP-F 3PAO Assessor UX
  %% =========================================================
  A.A2 --> F.F1[F.F1 3PAO sign-off UI]
  A.A3 --> F.F1
  B.B3 --> F.F1
  B.B4 --> F.F1
  E.E5 --> F.F1
  K.K1 --> F.F1
  K.K2 --> F.F1
  F.F1 --> F.F2[F.F2 Comment threads]
  A.A1 --> F.F2
  A.A2 --> F.F3[F.F3 Sample selection auto-derive]
  R4 --> F.F3
  K.K2 --> F.F3
  A.A3 --> F.F4[F.F4 Evidence walk-through artifacts]
  F.F1 --> F.F4
  D.D1 --> F.F4
  E.E7 --> F.F4
  K.K1 --> F.F4
  G.G1 --> F.F4
  G.G2 --> F.F4
  G.G5 --> F.F4
  G.G6 --> F.F4
  A.A1 --> F.F5[F.F5 3PAO recommendation letter]
  A.A3 --> F.F5
  A.A4 --> F.F5
  A.A5 --> F.F5
  F.F3 --> F.F5
  G.G5 --> F.F5
  I.I1 --> F.F5
  F.F6 --> F.F5
  A.A4 --> F.F6[F.F6 Full ATO workflow]
  F.F1 --> F.F6
  F.F5 --> F.F6
  C.C8 --> F.F6
  A.A1 --> F.F7[F.F7 SAR draft generator]
  A.A2 --> F.F7
  A.A3 --> F.F7
  A.A4 --> F.F7
  A.A5 --> F.F7
  F.F1 --> F.F7
  F.F2 --> F.F7
  F.F3 --> F.F7
  F.F4 --> F.F7
  F.F5 --> F.F7
  F.F6 --> F.F7
  C.C2 --> F.F7
  C.C3 --> F.F7
  C.C5 --> F.F7
  C.C7 --> F.F7
  E.E3 --> F.F7
  E.E4 --> F.F7
  G.G3 --> F.F7
  G.G4 --> F.F7
  J.J3 --> F.F7
  K.K1 --> F.F7
  K.K2 --> F.F7

  %% =========================================================
  %% LOOP-G AFR family
  %% =========================================================
  A.A1 --> G.G1[G.G1 AFR-FSI]
  A.A2 --> G.G1
  A.A3 --> G.G1
  A.A4 --> G.G1
  REO0 --> G.G1
  A.A1 --> G.G2[G.G2 AFR-ICP]
  A.A2 --> G.G2
  A.A3 --> G.G2
  A.A4 --> G.G2
  REO0 --> G.G2
  C.C3 --> G.G2
  A.A1 --> G.G3[G.G3 AFR-ADS]
  A.A2 --> G.G3
  A.A3 --> G.G3
  A.A4 --> G.G3
  REO0 --> G.G3
  I.I1 --> G.G3
  H.H2 --> G.G3
  A.A1 --> G.G4[G.G4 AFR-MAS]
  A.A2 --> G.G4
  A.A4 --> G.G4
  A.A5 --> G.G4
  REO0 --> G.G4
  R1 --> G.G4
  INVCHAIN --> G.G4
  J.J1 --> G.G4
  J.J2 --> G.G4
  D.D3 --> G.G4
  A.A1 --> G.G5[G.G5 AFR-SCG]
  A.A2 --> G.G5
  A.A4 --> G.G5
  A.A5 --> G.G5
  REO0 --> G.G5
  R1 --> G.G5
  REFARCH --> G.G5
  A.A1 --> G.G6[G.G6 AFR-CCM]
  A.A2 --> G.G6
  A.A4 --> G.G6
  REO0 --> G.G6
  R1 --> G.G6
  R2 --> G.G6
  R3 --> G.G6
  E.E1 --> G.G6
  I.I2 --> G.G6
  I.I3 --> G.G6

  %% =========================================================
  %% LOOP-H storage
  %% =========================================================
  A.A4 --> H.H1[H.H1 Immutable evidence archive]
  H.H1 --> H.H2[H.H2 AU-11 retention enforcement]
  H.H2 --> H.H3[H.H3 Multi-CSO support]

  %% =========================================================
  %% LOOP-I dashboards
  %% =========================================================
  A.A1 --> I.I1[I.I1 Executive posture dashboard]
  A.A4 --> I.I1
  B.B1 --> I.I1
  B.B2 --> I.I1
  B.B5 --> I.I1
  F.F1 --> I.I1
  F.F4 --> I.I1
  F.F5 --> I.I1
  F.F6 --> I.I1
  F.F7 --> I.I1
  G.G1 --> I.I1
  G.G2 --> I.I1
  G.G3 --> I.I1
  G.G4 --> I.I1
  G.G5 --> I.I1
  G.G6 --> I.I1
  J.J1 --> I.I1
  J.J3 --> I.I1
  K.K1 --> I.I1
  H.H3 --> I.I1
  A.A1 --> I.I2[I.I2 Finding burndown]
  A.A4 --> I.I2
  B.B2 --> I.I2
  E.E2 --> I.I2
  F.F6 --> I.I2
  H.H3 --> I.I2
  A.A1 --> I.I3[I.I3 Longitudinal trend analysis]
  B.B1 --> I.I3
  H.H3 --> I.I3
  SSP1 --> I.I4[I.I4 SSP narrative library]
  H.H3 --> I.I4

  %% =========================================================
  %% LOOP-J supply chain
  %% =========================================================
  A.A4 --> J.J1[J.J1 Roles & privileges matrix]
  SSP1 --> J.J1
  IAMAAM --> J.J1
  IAMELP --> J.J1
  A.A4 --> J.J2[J.J2 Subprocessor inventory]
  SUBSHEET --> J.J2
  A.A1 --> J.J3[J.J3 Supply chain risk + SBOM]
  A.A4 --> J.J3
  J.J2 --> J.J3
  SSP1 --> J.J3
  E2SBOM --> J.J3
  INVCHAIN --> J.J3

  %% =========================================================
  %% LOOP-K test artifact ingestion
  %% =========================================================
  A.A1 --> K.K1[K.K1 PenTest report ingest]
  A.A3 --> K.K1
  A.A4 --> K.K1
  A.A1 --> K.K2[K.K2 AR test-result-objects]
  A.A2 --> K.K2
  A.A3 --> K.K2
  A.A4 --> K.K2
  K.K1 --> K.K2

  %% =========================================================
  %% LOOP-L CRM + Leveraged-Authorization Inheritance
  %% =========================================================
  A.A1 --> L.L1[L.L1 CRM Workbook generator]
  D.D1 --> L.L1
  REFARCH --> L.L1
  SSP1 --> L.L1
  L.L1 --> L.L2[L.L2 Inherited-controls tracker]
  J.J2 --> L.L2
  L.L1 --> L.L3[L.L3 CRM Gap Report]
  L.L2 --> L.L3
  L.L1 --> L.L4[L.L4 Per-control responsibility split]
  L.L2 --> L.L4

  %% =========================================================
  %% LOOP-M Privacy Package Extension (SORN + DPIA)
  %% =========================================================
  C.C4 --> M.M1[M.M1 SORN emitter]
  J.J2 --> M.M1
  M.M1 --> M.M2[M.M2 DPIA cross-border/agency-partner]
  C.C4 --> M.M2
  J.J2 --> M.M2
  C.C4 --> M.M3[M.M3 PT-family inventory PT-1..PT-8]
  M.M3 --> M.M4[M.M4 Privacy incident response PT-7]
  C.C3 --> M.M4

  %% =========================================================
  %% LOOP-N Threat Modeling + Adversarial Validation
  %% =========================================================
  D.D3 --> N.N1[N.N1 STRIDE threat model per-component]
  INVCHAIN --> N.N1
  D.D1 --> N.N2[N.N2 Attack surface enumeration]
  REFARCH --> N.N2
  B.B1 --> N.N3[N.N3 PASTA red-team adversarial framework]
  N.N1 --> N.N3
  N.N2 --> N.N3
  N.N1 --> N.N4[N.N4 MITRE ATT&CK technique mapping]
  N.N2 --> N.N4

  %% =========================================================
  %% LOOP-O AI/ML Governance per NIST AI RMF + OMB M-24-10
  %% =========================================================
  INVCHAIN --> O.O1[O.O1 AI/ML asset inventory]
  O.O1 --> O.O2[O.O2 NIST AI RMF GOVERN/MAP/MEASURE/MANAGE]
  C.C4 --> O.O2
  O.O1 --> O.O3[O.O3 AI risk register]
  B.B1 --> O.O3
  O.O2 --> O.O3
  O.O1 --> O.O4[O.O4 AI evaluation per OMB M-24-10]
  O.O2 --> O.O4
  O.O3 --> O.O4
  O.O1 --> O.O5[O.O5 Model card + datasheet emitter]
  O.O2 --> O.O5

  %% =========================================================
  %% LOOP-P Insider Threat + PS-family
  %% =========================================================
  J.J1 --> P.P1[P.P1 Insider Threat Program]
  P.P1 --> P.P2[P.P2 Position risk designation PS-2/PS-3]
  J.J1 --> P.P2
  P.P2 --> P.P3[P.P3 Transfer + termination PS-4/PS-5]
  J.J1 --> P.P3
  P.P1 --> P.P4[P.P4 Access agreements + NDA PS-6]
  J.J1 --> P.P4
  P.P1 --> P.P5[P.P5 Continuous workforce monitoring]
  P.P3 --> P.P5

  %% =========================================================
  %% LOOP-Q Marketplace + Post-ATO Publication
  %% =========================================================
  A.A4 --> Q.Q1[Q.Q1 FedRAMP Marketplace listing RFC-0021]
  F.F6 --> Q.Q1
  E.E1 --> Q.Q2[Q.Q2 Post-ATO ConMon publication]
  A.A4 --> Q.Q2
  Q.Q1 --> Q.Q3[Q.Q3 Agency authorization tracking]
  F.F6 --> Q.Q3

  %% =========================================================
  %% LOOP-R Post-Quantum Cryptography Migration
  %% =========================================================
  AFRUCM[AFR-UCM crypto.ts AWS/GCP/AZ]
  AFRUCM --> R.R1[R.R1 Cryptographic Inventory Collector]
  CTRLBENCH[control-benchmark.ts]
  CTRLBENCH --> R.R1
  G.G5 --> R.R1
  R.R1 --> R.R2[R.R2 Migration Plan Emitter]
  B.B1 --> R.R2
  B.B2 --> R.R2
  A.A1 --> R.R2
  R.R2 --> R.R3[R.R3 Annual PQC Report Emitter]
  R.R1 --> R.R3
  E.E3 --> R.R3
  A.A4 --> R.R3

  %% =========================================================
  %% LOOP-S DFARS 252.204-7012 Cloud Equivalency (conditional)
  %% =========================================================
  CTRLBENCH --> S.S1[S.S1 NIST 800-171 Rev3 Moderate crosswalk]
  S.S1 --> S.S2[S.S2 DFARS 252.204-7012(c) incident reporting]
  G.G2 --> S.S2
  M.M4 --> S.S2
  C.C3 --> S.S2
  S.S1 --> S.S3[S.S3 Cloud Equivalency Attestation Package]
  S.S2 --> S.S3
  A.A4 --> S.S3
  L.L1 --> S.S3

  %% =========================================================
  %% CIRCIA extensions (overlays on G.G2 + M.M4)
  %% =========================================================
  G.G2 -.-> G.G2.CIRCIA[G.G2.CIRCIA 72-hour incident reporting]
  C.C3 -.-> G.G2.CIRCIA
  M.M4 -.-> M.M4.CIRCIA[M.M4.CIRCIA CIRCIA + Privacy Act harmonization]
  G.G2.CIRCIA -.-> M.M4.CIRCIA

  %% =========================================================
  %% SEC 8-K Item 1.05 extension (overlay on G.G2; publicly-traded CSPs)
  %% =========================================================
  G.G2 -.-> G.G2.SEC8K[G.G2-SEC-8K Item 1.05 four-business-day disclosure]
  G.G2.CIRCIA -.-> G.G2.SEC8K

  %% =========================================================
  %% LOOP-W Supply Chain Transparency / SBOM Attestation
  %% =========================================================
  W.W1[W.W1 SBOM attestation foundation]
  W.W1 --> W.W2[W.W2 SBOM ingest + subprocessor cross-walk]
  E2SBOM --> W.W2
  J.J3 --> W.W2
  SUBSHEET --> W.W2
  W.W2 --> W.W3[W.W3 Vendor attestation registry]
  A.A4 --> W.W3
  A.A5 --> W.W3
  W.W2 --> W.W4[W.W4 Signed SBOM publication envelope]
  A.A5 --> W.W4

  %% =========================================================
  %% LOOP-T Continuous Authorization Telemetry
  %% =========================================================
  T.T1[T.T1 Telemetry foundation]
  T.T1 --> T.T2[T.T2 KSI-envelope telemetry pipeline]
  B.B1 -.-> T.T2
  B.B2 -.-> T.T2
  B.B3 -.-> T.T2
  B.B4 -.-> T.T2
  B.B5 -.-> T.T2
  C.C1 -.-> T.T2
  C.C2 -.-> T.T2
  C.C3 -.-> T.T2
  C.C4 -.-> T.T2
  C.C5 -.-> T.T2
  C.C6 -.-> T.T2
  C.C7 -.-> T.T2
  C.C8 -.-> T.T2
  C.C9 -.-> T.T2
  D.D1 -.-> T.T2
  D.D2 -.-> T.T2
  D.D3 -.-> T.T2
  E.E1 -.-> T.T2
  E.E2 -.-> T.T2
  E.E3 -.-> T.T2
  E.E4 -.-> T.T2
  E.E5 -.-> T.T2
  E.E6 -.-> T.T2
  E.E7 -.-> T.T2
  F.F1 -.-> T.T2
  F.F2 -.-> T.T2
  F.F3 -.-> T.T2
  F.F4 -.-> T.T2
  F.F5 -.-> T.T2
  F.F6 -.-> T.T2
  F.F7 -.-> T.T2
  G.G1 -.-> T.T2
  G.G2 -.-> T.T2
  G.G3 -.-> T.T2
  G.G4 -.-> T.T2
  G.G5 -.-> T.T2
  G.G6 -.-> T.T2
  H.H1 -.-> T.T2
  H.H2 -.-> T.T2
  H.H3 -.-> T.T2
  I.I1 -.-> T.T2
  I.I2 -.-> T.T2
  I.I3 -.-> T.T2
  I.I4 -.-> T.T2
  J.J1 -.-> T.T2
  J.J2 -.-> T.T2
  J.J3 -.-> T.T2
  K.K1 -.-> T.T2
  K.K2 -.-> T.T2
  T.T1 --> T.T3[T.T3 Posture-delta aggregator]
  T.T2 --> T.T3
  T.T3 --> T.T4[T.T4 Continuous-ATO event log + tracker integration]
  A.A4 --> T.T4
  T.T1 --> T.T5[T.T5 Telemetry consumer + AI-eval feedback]
  T.T2 --> T.T5
  O.O5 --> T.T5

  %% =========================================================
  %% Pre-flight wiring
  %% =========================================================
  REO0 --> A.A1
  R1 --> G.G1
  R1 --> G.G2
  R1 --> G.G3
  R1 --> G.G4
  R1 --> G.G5
  R1 --> G.G6
  R2 --> E.E2
  R2 --> G.G6
  R3 --> G.G6
  R4 --> F.F3
```

---

## 2. Tabular dependencies

The canonical `depends_on` / `blocks` lists below are extracted verbatim
from each per-slice doc's frontmatter. "External" deps mean dependencies
on already-shipped LOOP-A slices, pre-flight (REO-0, R1–R4), or
infrastructure chains (INV-P1..S6, SSP-1, SCN-1, IAM collectors, etc.).
Where an external dep is collapsed below (e.g. "INV-chain") the
underlying expansion is documented in the corresponding per-slice doc.

| Slice | Depends on | Blocks |
|---|---|---|
| **A.A1** | REO-0 | A.A2, A.A3, A.A4, A.A5, B.B1, B.B2, B.B3, B.B4, B.B5, C.C6, C.C7, E.E1, E.E2, E.E3, E.E5, F.F2, F.F5, F.F7, G.G1, G.G2, G.G3, G.G4, G.G5, G.G6, I.I1, I.I2, I.I3, J.J3, K.K1, K.K2 |
| **A.A2** | A.A1 | A.A3, C.C8, E.E3, E.E4, F.F1, F.F3, F.F7, G.G1, G.G2, G.G3, G.G4, G.G5, G.G6, K.K2 |
| **A.A3** | A.A2 | A.A4, B.B3, E.E3, F.F1, F.F4, F.F5, F.F7, G.G1, G.G2, G.G3, K.K1, K.K2 |
| **A.A4** | A.A3 | A.A5, B.B5, C.C1, C.C8, D.D1, D.D2, D.D3, E.E1, E.E3, F.F5, F.F6, F.F7, G.G1, G.G2, G.G3, G.G4, G.G5, G.G6, H.H1, I.I1, I.I2, J.J1, J.J2, J.J3, K.K1, K.K2 |
| **A.A5** | A.A4 | E.E5, E.E6, E.E7, F.F5, F.F7, G.G4, G.G5 |
| **B.B1** | A.A1, INV-P1..P5, INV-S1..S6 | B.B2, B.B5, I.I1, I.I3, E.E1, C.C7 |
| **B.B2** | A.A1, B.B1 | B.B3, E.E1, E.E2, I.I1, I.I2 |
| **B.B3** | A.A1, A.A3, B.B1, B.B2 | B.B4, B.B5, E.E5, F.F1, C.C7 |
| **B.B4** | A.A1, B.B3 | B.B5, C.C7, F.F1 |
| **B.B5** | A.A1, A.A4, B.B1, B.B2, B.B3, B.B4 | C.C7, I.I1, E.E1 |
| **C.C1** | docx-prim, A.A4, INV-chain, SSP-1, I.I4 | C.C6, C.C9, E.E2, G.G5 |
| **C.C2** | docx-prim, INV-chain, RPL collectors, SSP-1, I.I4 | E.E7, F.F7 |
| **C.C3** | docx-prim, INR-RIR, INV-chain, SSP-1, I.I4 | E.E7, G.G2, F.F7 |
| **C.C4** | docx-prim, INV-chain (data_classification), SSP-1 | E.E annual, I.I4 narrative library |
| **C.C5** | docx-prim, SSP-1, I.I4 | C.C8, F.F7 |
| **C.C6** | docx-prim, A.A1, INV-S1, VDR collectors, ksi-map, I.I4 | E.E1..E.E7, G.G6 |
| **C.C7** | docx-prim, A.A1, B.B3, B.B4, B.B5, J.J1, J.J2, J.J3, I.I4 | I.I1 ref, F.F7 ref |
| **C.C8** | docx-prim, A.A4, A.A2, C.C5, I.I4 | F.F6 |
| **C.C9** | docx-prim, INV-chain, reference-arch, D.D1, D.D2, D.D3, I.I4 | C.C1, E.E ConMon drift |
| **D.D1** | INV-chain, REO-0, A.A4 | D.D2, D.D3, C.C9, E.E6, G.G4, F.F4 |
| **D.D2** | INV-chain, REO-0, A.A4, D.D1 | D.D3, C.C9, E.E6, G.G4, F.F4 |
| **D.D3** | INV-chain, REO-0, A.A4, D.D1, D.D2 | C.C9, E.E6, G.G4 (AFR-MAS info-flow), F.F4 |
| **E.E1** | A.A1, A.A4, B.B1, B.B2, B.B5, E.E5, E.E6, G.G6, I.I3, K.K1 | E.E2, E.E3, G.G6 |
| **E.E2** | A.A1, E.E1, B.B2, R2 | E.E3, I.I2 |
| **E.E3** | A.A1, A.A2, A.A3, A.A4, E.E1, E.E2, E.E4, E.E7, E.E5, E.E6, K.K2, H.H1, H.H2 | F.F1, F.F7, H.H1 |
| **E.E4** | A.A2, E.E3 | E.E3, F.F7 |
| **E.E5** | A.A1, A.A5, B.B3 | E.E1, E.E3, F.F1 |
| **E.E6** | A.A5, SCN-1, D.D1, D.D2, D.D3 | E.E1, E.E3 |
| **E.E7** | A.A5, E.E3, C.C2, C.C3 | E.E3, F.F4 |
| **F.F1** | A.A2, A.A3, B.B3, B.B4, E.E5, K.K1, K.K2 | F.F2, F.F4, F.F6, F.F7, I.I1, K.K2 |
| **F.F2** | F.F1, A.A1 | F.F4, F.F7 |
| **F.F3** | A.A2, R4, K.K2, INV-P1 | F.F5, F.F7 |
| **F.F4** | A.A3, F.F1, D.D1, E.E7, K.K1, G.G1, G.G2, G.G5, G.G6 | F.F7, K.K1, I.I1 |
| **F.F5** | A.A1, A.A3, A.A4, A.A5, F.F3, G.G5, I.I1, F.F6 | F.F7, I.I1 |
| **F.F6** | A.A4, F.F1, F.F5, C.C8 | F.F5, F.F7, I.I1, I.I2 |
| **F.F7** | A.A1, A.A2, A.A3, A.A4, A.A5, F.F1, F.F2, F.F3, F.F4, F.F5, F.F6, C.C2, C.C3, C.C5, C.C7, E.E3, E.E4, G.G3, G.G4, J.J3, K.K1, K.K2 | I.I1, K.K1 |
| **G.G1** | A.A1, A.A2, A.A3, A.A4, REO-0, R1 | E.E6, F.F4, I.I1 |
| **G.G2** | A.A1, A.A2, A.A3, A.A4, REO-0, R1, C.C3 | F.F4, I.I1 |
| **G.G3** | A.A1, A.A2, A.A3, A.A4, REO-0, R1, I.I1, H.H2 | F.F7, H.H2, I.I1 |
| **G.G4** | A.A1, A.A2, A.A4, A.A5, REO-0, R1, INV-chain, J.J1, J.J2, D.D3 | F.F7, J.J2, I.I1 |
| **G.G5** | A.A1, A.A2, A.A4, A.A5, REO-0, R1, reference-arch | F.F4, F.F5, I.I1 |
| **G.G6** | A.A1, A.A2, A.A4, REO-0, R1, R2, R3, E.E1, I.I2, I.I3 | E.E1, F.F4, I.I1 |
| **H.H1** | A.A4, B.1 (signing), B.2 (TSA) | H.H2, E.E3 |
| **H.H2** | H.H1 | E.E3, G.G3 |
| **H.H3** | D.4 (RBAC), D.5 (backup), B.B3 | I.I1, I.I2, I.I3, I.I4, F.F6 |
| **I.I1** | A.A1, A.A4, B.B1, B.B2, B.B5, F.F1, F.F4, F.F5, F.F6, F.F7, G.G1..G.G6, J.J1, J.J3, K.K1, H.H3 | F.F5, G.G3 |
| **I.I2** | A.A1, A.A4, B.B2, E.E2, F.F6, H.H3 | G.G6 |
| **I.I3** | A.A1, B.B1, H.H3 | E.E1, G.G6 |
| **I.I4** | SSP-1, H.H3 | C.C1, C.C2, C.C3, C.C5, C.C6, C.C7, C.C8, C.C9 |
| **J.J1** | A.A4, SSP-1, IAM-AAM, IAM-ELP | G.G4, B.B5, C.C7, I.I1 |
| **J.J2** | A.A4, subprocessors-sheet, G.G4 | G.G4, H.H3, J.J3, C.C7 |
| **J.J3** | A.A1, A.A4, J.J2, SSP-1, INV-P4, E.2 SBOM | B.B5, C.C7, I.I1, F.F7 |
| **K.K1** | A.A1, A.A3, A.A4, F.F4 | F.F1, F.F4, F.F7, E.E1, K.K2 |
| **K.K2** | A.A1, A.A2, A.A3, A.A4, K.K1, F.F1 | F.F1, F.F3, F.F7, E.E3 |
| **L.L1** | A.A1, D.D1, reference-arch, SSP-1 | L.L2, L.L3, L.L4 |
| **L.L2** | L.L1, J.J2 | L.L3, L.L4 |
| **L.L3** | L.L1, L.L2 | (terminal — feeds CRM gap closure) |
| **L.L4** | L.L1, L.L2 | (terminal — UI renderer) |
| **M.M1** | C.C4, J.J2 | M.M2 |
| **M.M2** | M.M1, C.C4, J.J2 | (terminal — DPIA artifact) |
| **M.M3** | C.C4 | M.M4 |
| **M.M4** | M.M3, C.C3 | (terminal — privacy incident artifact) |
| **N.N1** | D.D3, INV-chain | N.N3, N.N4 |
| **N.N2** | D.D1, reference-arch | N.N3, N.N4 |
| **N.N3** | B.B1, N.N1, N.N2 | (terminal — adversarial test framework) |
| **N.N4** | N.N1, N.N2 | (terminal — ATT&CK mapping) |
| **O.O1** | INV-chain | O.O2, O.O3, O.O4, O.O5 |
| **O.O2** | O.O1, C.C4 | O.O3, O.O4, O.O5 |
| **O.O3** | O.O1, B.B1, O.O2 | O.O4 |
| **O.O4** | O.O1, O.O2, O.O3 | (terminal — pre-deployment + ongoing AI eval) |
| **O.O5** | O.O1, O.O2 | (terminal — model card + datasheet) |
| **P.P1** | existing tracker (RBAC + audit log), J.J1 | P.P2, P.P3, P.P4, P.P5 |
| **P.P2** | P.P1, J.J1 | P.P3 |
| **P.P3** | P.P2, J.J1 | P.P5 |
| **P.P4** | P.P1, J.J1 | (terminal — access agreements + NDA) |
| **P.P5** | P.P1, P.P3 | (terminal — continuous workforce monitoring) |
| **Q.Q1** | A.A4, F.F6 | Q.Q3 |
| **Q.Q2** | E.E1, A.A4 | (terminal — monthly publication to FedRAMP repo) |
| **Q.Q3** | Q.Q1, F.F6 | (terminal — agency authorization tracking) |
| **R.R1** | AFR-UCM (providers/{aws,gcp,azure}/crypto.ts), control-benchmark.ts, G.G5 | R.R2, R.R3 |
| **R.R2** | R.R1, B.B1, B.B2, A.A1 | R.R3 |
| **R.R3** | R.R1, R.R2, E.E3, A.A4 | (terminal — annual PQC report to OMB / agency) |
| **S.S1** | control-benchmark.ts | S.S2, S.S3 |
| **S.S2** | S.S1, G.G2, M.M4, C.C3 | S.S3 |
| **S.S3** | S.S1, S.S2, A.A4, L.L1 | (terminal — DFARS 7012 attestation package) |
| **G.G2.CIRCIA** *(overlay)* | G.G2, C.C3 | M.M4.CIRCIA |
| **M.M4.CIRCIA** *(overlay)* | M.M4, G.G2.CIRCIA | (terminal — CIRCIA + Privacy Act harmonization) |
| **G.G2-SEC-8K** *(overlay)* | G.G2 *(extends)*, G.G2.CIRCIA *(sibling overlay)* | (terminal — SEC Item 1.05 Form 8-K four-business-day disclosure; conditional on publicly-traded CSP) |
| **W.W1** | (foundation — no enumerated slice predecessors) | W.W2, W.W3, W.W4 |
| **W.W2** | W.W1, E.2 SBOM, J.J3, subprocessors-sheet | W.W3, W.W4 |
| **W.W3** | W.W2, A.A4 (tracker DB), A.A5 (signing) | (terminal — vendor attestation registry) |
| **W.W4** | W.W2, A.A5 (signing) | (terminal — signed SBOM publication envelope) |
| **T.T1** | (foundation — no enumerated slice predecessors) | T.T2, T.T3, T.T5 |
| **T.T2** | T.T1, KSI envelopes (B–K family) | T.T3, T.T5 |
| **T.T3** | T.T1, T.T2 | T.T4 |
| **T.T4** | T.T3, A.A4 | (terminal — continuous-ATO event log + tracker integration) |
| **T.T5** | T.T1, T.T2, O.O5 | (terminal — telemetry consumer + AI-eval feedback) |

Cycle notes (self-referential pairs in the table above):
- **E.E3 ↔ E.E4** — E.E4 depends on E.E3 for the annual harness; E.E3
  consumes E.E4's annual-SSP-diff output. Resolve by shipping E.E3 first
  as a single-shot annual harness, then layering E.E4's diff in as an
  optional input.
- **F.F1 ↔ K.K1 ↔ K.K2** — F.F1 needs K.K* sign-off targets; K.K* needs
  F.F1 sign-off UI. Resolve by shipping F.F1 with stub sign-off targets
  (one per LOOP-A artifact) and adding K.K* targets in a follow-up
  commit when K.K* lands.
- **F.F5 ↔ F.F6** — F.F5 depends on F.F6 ATO state machine but blocks
  F.F6's letter rendering. Resolve by shipping F.F6 first with no letter
  step; F.F5 adds the letter step.
- **G.G3 ↔ H.H2** — G.G3 publishes Trust Center artifacts that consume
  H.H2 retention metadata; H.H2 reports on G.G3's published artifacts.
  Resolve by shipping H.H2 first; G.G3 layers on top.
- **I.I1 ↔ G.G3** — I.I1 dashboard surfaces G.G3 Trust Center status;
  G.G3 publishes I.I1 KPIs. Resolve by shipping I.I1 first with placeholder
  Trust Center widgets.

---

## 3. Critical path

End-to-end longest dependency chain (depth from REO-0 to the final
deliverable, counting only enumerated slices — pre-flight nodes
collapsed):

```
REO-0
 └─→ A.A1 (POA&M)
      └─→ A.A2 (AP)
           └─→ A.A3 (AR import-AP)
                └─→ A.A4 (bundler)
                     └─→ A.A5 (RoE)              [LOOP-A: DONE]
                     └─→ B.B1 (risk scoring)
                          └─→ B.B2 (deadline math)
                               └─→ B.B3 (risk acceptance)
                                    └─→ B.B4 (compensating controls)
                                         └─→ B.B5 (RA-3 register)
                                              └─→ C.C7 (RMS doc)
                                                   └─→ F.F7 (SAR draft)
```

**Critical-path length** (from REO-0 through pre-flight + LOOP-A +
LOOP-B + LOOP-C.C7 + LOOP-F.F7): **12 nodes** post-REO-0.

**Effort estimate along critical path:**
- LOOP-A (5 slices) — DONE.
- B.B1 → B.B5 (5 slices × ~4-5 days) ≈ 22 working days.
- C.C7 ≈ 5 working days.
- F.F7 ≈ 6-8 working days (depends on every other F.F* + multiple G/J slices).
- **Total critical path remaining:** ≈ 7-8 working weeks single-thread
  to reach F.F7 (assumes critical-path slices alone; the SAR draft
  itself is gated by 22 distinct precedents per the F.F7 table row).

**Alternate critical paths (each ≈ same length):**

- `A.A1 → C.C6 → E.E1 → E.E3 → F.F7` (ConMon-driven SAR path)
- `A.A4 → D.D1 → D.D2 → D.D3 → C.C9 → F.F7` (diagrams-driven SAR path)
- `A.A1 → B.B1 → I.I3 → E.E1 → G.G6 → F.F4 → F.F7` (longitudinal-trends
  feedback path; 8 hops post-A.A1)

**LOOP-L through LOOP-Q critical chains (added 2026-06-07):**

- `A.A1 → L.L1 → L.L2 → L.L3` (CRM workbook → inheritance → gap report; 4 hops)
- `C.C4 → M.M1 → M.M2` (PTA/PIA → SORN → DPIA; 3 hops)
- `D.D3 → N.N1 → N.N3` (DFD → STRIDE → adversarial framework; 3 hops)
- `INV-chain → O.O1 → O.O2 → O.O3 → O.O4` (inventory → RMF alignment → risk register → eval; 5 hops)
- `J.J1 → P.P1 → P.P2 → P.P3 → P.P5` (privileges → insider threat → screening → transfer → monitoring; 5 hops)
- `A.A4 → F.F6 → Q.Q1 → Q.Q3` (bundler → ATO state → Marketplace listing → agency tracking; 4 hops)

These chains run **in parallel** with the LOOP-B → LOOP-F.F7 critical path and
do not extend the SAR-completion gate.

**LOOP-R + LOOP-S + CIRCIA-extension critical chains (added 2026-06-07):**

- `AFR-UCM → R.R1 → R.R2 → R.R3` (crypto.ts collectors → PQC inventory → migration plan → annual report; 4 hops)
- `control-benchmark.ts → S.S1 → S.S2 → S.S3` (800-53 benchmark → 800-171 Rev3 crosswalk → DFARS incident reporting → attestation pkg; 4 hops)
- `G.G2 → G.G2.CIRCIA` (incident-comms parent → CIRCIA overlay; co-ship in same commit per CLAUDE.md directive)
- `M.M4 → M.M4.CIRCIA` (privacy-incident parent → CIRCIA + Privacy Act overlay; co-ship in same commit)

R.R3 has a hard dependency on E.E3 (Annual Assessment package), so the
LOOP-R critical chain effectively becomes
`B.B1 → B.B2 → E.E1 → E.E3 → R.R3` for the annual PQC report.
S.S2 has hard dependencies on G.G2 + M.M4 + C.C3 (incident harmonization)
and S.S3 additionally on L.L1 (CRM workbook embedding the equivalency
attestation), so the LOOP-S critical chain effectively becomes
`C.C3 → G.G2 → M.M4 → S.S1 → S.S2 → S.S3` (and S.S3 also waits on L.L1).
CIRCIA overlays do not extend the critical path because they ship in
the same commit as their parent slice (G.G2 / M.M4).

---

## 4. Parallelization opportunities

### 4.1 Independent streams (no cross-stream blocking until merge point)

These streams can be staffed in parallel against the same LOOP-A
baseline:

**Stream 1 — Risk + Dashboards (B + I subset):**
- B.B1 → B.B2 → B.B3 → B.B4 → B.B5
- I.I3 (depends only on B.B1)
- Effort: ~5 weeks single-thread, but I.I3 can shift left once B.B1
  ships.

**Stream 2 — Document Templates (C, except C.C7/C.C8/C.C9):**
- C.C1, C.C2, C.C3, C.C4, C.C5, C.C6 are mutually independent (only
  share the I.I4 narrative-library gate + docx-primitives).
- C.C7 + C.C8 + C.C9 wait for Stream 1 (B.B5) and Stream 3 (D.D*).
- Effort: ~6 weeks if I.I4 + docx-primitives land first; can be
  multi-person.

**Stream 3 — Diagrams (D) + AFR (G) + Storage (H):**
- D.D1 → D.D2 → D.D3 (sequential within stream).
- G.G1, G.G2, G.G3, G.G5 are mutually independent (each depends only
  on LOOP-A + REO-0 + R1; G.G2 additionally on C.C3, G.G3 on I.I1+H.H2,
  G.G5 on reference-arch).
- G.G4 waits for D.D3 + J.J1 + J.J2.
- G.G6 waits for R2 + R3 + E.E1.
- H.H1 → H.H2 → H.H3 (sequential within stream).
- Effort: ~6 weeks; G family parallelisable inside itself.

**Stream 4 — Supply Chain (J):**
- J.J1 + J.J2 mutually independent (different evidence sources).
- J.J3 waits for J.J2.
- Effort: ~3 weeks.

**Stream 5 — Test Ingestion (K):**
- K.K1 → K.K2 (sequential).
- Both gated only by LOOP-A.
- Effort: ~2 weeks.

**Stream 6 — CRM + Inheritance (L):**
- L.L1 gated by A.A1 + D.D1 + reference-arch + SSP-1.
- L.L2 waits for L.L1 + J.J2.
- L.L3 + L.L4 wait for L.L1 + L.L2 (mutually independent of each other).
- Effort: ~4 weeks. Two of four slices parallelisable post-L.L2.

**Stream 7 — Privacy Package (M) — CONFIRMED APPLICABLE:**
- M.M1 + M.M3 mutually independent (both depend only on C.C4).
- M.M2 waits for M.M1.
- M.M4 waits for M.M3 + C.C3.
- Effort: ~4 weeks. Two top-of-stream slices parallelisable.

**Stream 8 — Threat Modeling (N):**
- N.N1 + N.N2 mutually independent.
- N.N3 + N.N4 wait for N.N1 + N.N2.
- N.N3 also depends on B.B1 (risk scoring fuels adversarial test severity).
- Effort: ~4 weeks. Two top-of-stream slices parallelisable.

**Stream 9 — AI/ML Governance (O) — CONFIRMED APPLICABLE:**
- O.O1 leads.
- O.O2 + O.O3 + O.O5 mutually parallelisable post-O.O1+O.O2.
- O.O4 is terminal (depends on O.O1+O.O2+O.O3).
- Effort: ~5 weeks. Three of five slices parallelisable post-O.O2.

**Stream 10 — Insider Threat + PS-family (P):**
- P.P1 leads.
- P.P2 + P.P4 mutually parallel post-P.P1.
- P.P3 waits for P.P2.
- P.P5 waits for P.P1 + P.P3.
- Effort: ~5 weeks.

**Stream 11 — Marketplace + Post-ATO (Q):**
- Q.Q1 + Q.Q2 mutually independent.
- Q.Q3 waits for Q.Q1.
- Q.Q1 + Q.Q3 gated by F.F6 (ATO state machine).
- Effort: ~3 weeks.

### 4.2 Strict-sequential gates (no parallelism possible)

- **A.A1 → A.A2 → A.A3 → A.A4 → A.A5** — DONE.
- **B.B1 → B.B2 → B.B3 → B.B4 → B.B5** — strictly sequential because each
  consumes the prior's schema extensions.
- **E.E1 → E.E2 → E.E3** — strictly sequential ConMon stack.
- **D.D1 → D.D2 → D.D3** — strictly sequential diagram stack.
- **H.H1 → H.H2 → H.H3** — strictly sequential storage stack.
- **F.F1 → F.F4 → F.F7** — assessor flow.

### 4.3 Recommended 3-stream parallel plan

If 3 engineers are available concurrently:

| Stream | Path | Estimated weeks |
|---|---|---|
| Stream A | B.B1 → B.B2 → B.B3 → B.B4 → B.B5 → I.I1 → I.I2 → I.I3 | 11 |
| Stream B | C.C1..C.C6 (parallel docs) → C.C7..C.C9 → E.E1..E.E3 → E.E5..E.E7 | 15 |
| Stream C | D.D1 → D.D2 → D.D3 → G.G1..G.G6 → H.H1..H.H3 → J.J1..J.J3 → K.K1 → K.K2 | 14 |
| Merge | F.F1 → F.F2..F.F6 → F.F7 (after all three streams land) | 4 |

**Total parallel-mode estimate:** ~19 weeks vs ~46 weeks single-thread.

Note: F.F7 SAR draft has 22 precedents and must be last across all
streams. Plan its kickoff for after Streams A+B+C have closed.

### 4.4 LOOP-L through LOOP-Q parallel layer (ratified 2026-06-07)

Loops L–Q add 25 more slices and ~25 weeks of single-thread effort, but
they layer **on top of** the LOOP-B..K streams and do not extend the
LOOP-F.F7 critical path. Recommended overlay (additional engineers /
parallel streams):

| Overlay Stream | Path | Estimated weeks | Gate |
|---|---|---|---|
| Overlay L | L.L1 → L.L2 → (L.L3 ∥ L.L4) | 4 | A.A1 + D.D1 + SSP-1 |
| Overlay M | (M.M1 ∥ M.M3) → (M.M2 ∥ M.M4) | 4 | C.C4 + C.C3 + J.J2 |
| Overlay N | (N.N1 ∥ N.N2) → (N.N3 ∥ N.N4) | 4 | D.D3 + B.B1 |
| Overlay O | O.O1 → O.O2 → (O.O3 ∥ O.O5) → O.O4 | 5 | INV-chain + C.C4 + B.B1 |
| Overlay P | P.P1 → (P.P2 ∥ P.P4) → P.P3 → P.P5 | 5 | tracker (RBAC+audit) + J.J1 |
| Overlay Q | (Q.Q1 ∥ Q.Q2) → Q.Q3 | 3 | A.A4 + F.F6 + E.E1 |

If all overlays staffed concurrently with the base 3-stream plan,
overall delivery extends from ~19 weeks to ~24 weeks (gated by Overlay O
+ Overlay P each at 5 weeks plus the existing 19-week base).

### 4.5 LOOP-R + LOOP-S + CIRCIA overlays (ratified 2026-06-07)

LOOP-R + LOOP-S add 6 more slices and ~6 weeks of single-thread effort.
CIRCIA-extension overlays add 2 overlay slices that ship co-resident with
their parent G.G2 / M.M4 commits. None of these extend the LOOP-F.F7
critical path.

| Overlay Stream | Path | Estimated weeks | Gate | Applicability |
|---|---|---|---|---|
| Overlay R | R.R1 → R.R2 → R.R3 | 3 | AFR-UCM + control-benchmark.ts + G.G5 + B.B1 + B.B2 + A.A1 + E.E3 + A.A4 | Mandatory (federal PQC mandate) |
| Overlay S | S.S1 → S.S2 → S.S3 | 3 | control-benchmark.ts + G.G2 + M.M4 + C.C3 + A.A4 + L.L1 | Conditional on DoD-prime customers |
| CIRCIA G.G2 | G.G2.CIRCIA (overlay) | co-ships with G.G2 | G.G2 + C.C3 | High priority — May 2026 effective |
| CIRCIA M.M4 | M.M4.CIRCIA (overlay) | co-ships with M.M4 | M.M4 + G.G2.CIRCIA | High priority — May 2026 effective |

Overlay R is independent of S and most overlays — it can run in parallel
with B.B1/B.B2 once they ship (R.R2 + R.R3 consume the risk scoring
chain). Overlay S is gated by G.G2 + M.M4 + C.C3 + L.L1, so it cannot
start until the Privacy + AFR + CRM streams have closed those slices.
CIRCIA overlays cost ~0.5 week each (they reuse G.G2 / M.M4
infrastructure) and the cost is folded into the parent slice's estimate
when CIRCIA co-ships.

If all overlays (L through R + S + CIRCIA) staffed concurrently with the
base 3-stream plan, overall delivery extends from ~24 weeks (post-L–Q
overlay) to ~27 weeks (gated by Overlay R + Overlay S layered behind
their respective base-stream gates).

---

## 5. LOOP-L through LOOP-Q — ratified 2026-06-07

LOOP-L through LOOP-Q were proposed by `ADDITIONAL-LOOPS-AUDIT.md`
(2026-06-06) and **ratified by the human on 2026-06-07**. All 25 slices
are now first-class nodes in §1 (Mermaid graph) and §2 (tabular
dependencies) above. M (Privacy/SORN/DPIA) and O (AI/ML Governance) are
confirmed applicable (no longer conditional).

The earlier advisory dependency sketch (initial audit-time guess) has
been superseded by the per-slice frontmatter under
`docs/slices/{L,M,N,O,P,Q}/*.md`, which is the authoritative source for
§1 and §2. A second-pass audit (`docs/SECOND-PASS-AUDIT.md`) confirmed
nothing else is still missing after L-Q specification.

Implementation priority remains LOOP-B.B1 first (risk scoring is a
shared dependency for N.N3 and O.O3). LOOP-L.L1 is queued immediately
behind B.B1.

Per-loop risks: see `docs/loops/LOOP-{L,M,N,O,P,Q}-RISKS.md`.

---

## 5a. LOOP-R + LOOP-S + CIRCIA extensions — ratified 2026-06-07

LOOP-R (Post-Quantum Cryptography Migration), LOOP-S (DFARS 252.204-7012
Cloud Equivalency), and the CIRCIA Final Rule extensions to G.G2 + M.M4
were surfaced by `docs/THIRD-PASS-AUDIT.md` (2026-06-07) and **ratified
by the human on 2026-06-07**. All 6 LOOP-R/S slices + 2 CIRCIA-extension
overlay slices are now first-class nodes in §1 (Mermaid graph) and §2
(tabular dependencies) above.

Applicability:

- **LOOP-R (PQC)** — **mandatory** for all CSPs. NIST IR 8547 +
  OMB M-23-02 + NSM-10 + NSA CNSA 2.0 jointly require federal systems
  to inventory cryptographic algorithms, plan migration to PQC-safe
  algorithms (ML-KEM/ML-DSA/SLH-DSA), and report progress annually.
  The CSP role obliges us to surface this inventory + plan to agency
  consumers.
- **LOOP-S (DFARS 7012 Cloud Equivalency)** — **conditional**. Only
  required when the CSP has or pursues DoD-prime customers running
  Covered Defense Information (CDI) workloads on the CSO. Skipped
  otherwise.
- **CIRCIA extensions** — **HIGH PRIORITY**. CIRCIA Final Rule effective
  date is May 2026. Any CSP processing critical-infrastructure-related
  workloads (PPD-21 sectors) is a Covered Entity and must report
  covered cyber incidents to CISA within 72 hours and ransom payments
  within 24 hours. G.G2.CIRCIA + M.M4.CIRCIA overlays MUST ship in the
  same commit as their parent slice (G.G2 / M.M4) or be explicitly
  tracked as a follow-up in STATUS.md.

Implementation priority: LOOP-B.B1 remains the highest-priority next
slice. LOOP-R, LOOP-S, and CIRCIA extensions queue behind LOOP-L–Q in
the default order. The human may elevate CIRCIA extensions above
LOOP-B.B1 once basic CSP operations need to be CIRCIA-compliant.

Per-loop risks: see `docs/loops/LOOP-R-RISKS.md` and
`docs/loops/LOOP-S-RISKS.md`. CIRCIA-extension risks are folded into
G.G2 and M.M4 per-slice docs.

---

## 6. How to regenerate this graph

Each per-slice doc carries `depends_on:` and `blocks:` in its
frontmatter. To keep this graph in sync:

1. Edit only the per-slice doc's frontmatter.
2. Run a future-deferred `scripts/build-dep-graph.mjs` (planned —
   not yet implemented) to regenerate §1 + §2 from the YAML.
3. The §3 critical path is hand-derived. After any frontmatter change,
   re-walk it.
4. The §4 streams are advisory; re-evaluate when slice estimates change.
