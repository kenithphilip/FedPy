# FedRAMP 20x execution status

> Updated automatically by the slice-completion procedure (see SLICE-COMPLETION-PROCEDURE.md).
> The values below MUST be kept in sync with CHANGELOG.md "Unreleased" entries.
> When a slice completes: update its row + commit + push (atomic with the slice's own commit).

## Scope (READ CLAUDE.md "Scope Guard" block first)

FedPy is FedRAMP 20x + Rev5 evidence automation. Loops in **Core** are
in-scope for implementation. Loops in **Overlay / Out-of-Core** are
parallel compliance regimes preserved as research / roadmap reference
under `docs/roadmap/` — not part of the FedRAMP authorization pipeline
and not on the implementation queue.

## Overall (Core only)
- Total core slices: 102 base + 1 SEC 8-K overlay = 103 counting overlay
  - 5 LOOP-A done
  - 6 LOOP-B–K base done (B.B1, B.B2, E.E1, E.E2, J.J2, J.J3), 44 LOOP-B-K pending
  - 25 LOOP-L-Q pending
  - 6 LOOP-R+S pending
  - 1 LOOP-W done, 3 LOOP-W pending
  - 1 LOOP-T done (T.T1), 4 LOOP-T pending
  - 5 LOOP-X pending
  - 2 CIRCIA-extension slices pending
  - + 4 pre-loop research (R1-R4 done) + REO-0 (done)
- Core loops total: 22 (A through S + T + W + X) + 2 CIRCIA extensions (G.G2.CIRCIA, M.M4.CIRCIA) + 1 SEC 8-K overlay (G.G2-SEC-8K)
- Loops complete: 1 of 22 (LOOP-A); LOOP-W in progress (1 of 4 slices done); LOOP-T in progress (1 of 5 slices done); LOOP-B in progress (2 of 5 slices done — B.B1, B.B2); LOOP-E in progress (2 of 7 slices done — E.E1, E.E2); LOOP-J in progress (2 of 3 slices done — J.J2, J.J3; J.J1 pending)
- Last shipped: LOOP-E.E2 (commit `<TBD-step6>`)
- Next priority: **LOOP-W.W2 (Subprocessor + supplier inventory crosscheck against prohibited-vendor list)** — now fully unblocked: its real dependencies (per per-slice frontmatter `W.W1 ✅, E.E2 ✅, J.J3 ✅, A.A1 ✅, A.A5 ✅, B.B1 ✅`) are all done — E.E2 shipped this session was the last gating ConMon link. W.W2 is the next link in the HIGHEST-PRIORITY LOOP-W chain (FAR 52.204-25 statutorily gates the submission package). So ship **W.W2 → W.W3 → W.W4** to close LOOP-W. **B.B3 (Risk acceptance workflow)** remains an ALSO-unblocked alternative (`depends_on: [A.A1 ✅, A.A3 ✅, B.B1 ✅, B.B2 ✅]`) — B.B2 shipped the `acceptanceOverride` hook for B.B3 to plug into; it unblocks B.B4/B.B5/E.E5/F.F1/C.C7. Then **LOOP-T.T2-T.T5** (CISA SSDF Common Form; T.T2 is closer — J.J2 ✅ + J.J3 ✅ cleared two of its deps, though it still needs broad B-K KSI envelopes). LOOP-L through LOOP-Q queued behind the above. LOOP-R (PQC), LOOP-S (DFARS, conditional), LOOP-X (Zero Trust), G.G2-SEC-8K, and CIRCIA extensions queued behind LOOP-L–Q.
  - **Dependency-metadata note (discovered 2026-06-10; still open):** the W.W2 row's `Dependencies` column below reads `W.W1, J.J2`, which is inconsistent with the W.W2 per-slice-doc frontmatter (`W.W1, E.E2, J.J3, A.A1, A.A5, B.B1`). All of the frontmatter deps are now `done`, so W.W2 is genuinely shippable — but the next session MUST reconcile the W.W2 row's `Dependencies` column to match the frontmatter as its first Phase −1 step. See `docs/loops/LOOP-B-RISKS.md` risk B.B1-EXT-1.

## Out-of-Core / Roadmap (NOT on the implementation queue)
Parallel compliance regimes; preserved as research material under
`docs/roadmap/`. See `docs/roadmap/README.md` for the scope-fence
rationale.

| Out-of-core loop | What it is | Roadmap doc |
|---|---|---|
| LOOP-U Privacy frameworks | FERPA / COPPA / GLBA / CCPA / CPRA / GDPR / UK GDPR / NY SHIELD / 50-state breach matrix / Schrems II | `docs/roadmap/loops/LOOP-U-{SPEC,RISKS}.md` + `docs/roadmap/slices/U/` |
| LOOP-V Healthcare overlay | HIPAA Security Rule + Breach Notification + BAA + NIST SP 800-66 R2 + HITRUST CSF v11.2.0 | `docs/roadmap/loops/LOOP-V-{SPEC,RISKS}.md` + `docs/roadmap/slices/V/` |
| LOOP-Y Sector overlays | CJIS Security Policy v5.9.5 + IRS Publication 1075 | `docs/roadmap/loops/LOOP-Y-{SPEC,RISKS}.md` + `docs/roadmap/slices/Y/` |
| LOOP-Z International | ISO/IEC 27001:2022 + 27017 + 27018 + 27701 + ENISA EUCS | `docs/roadmap/loops/LOOP-Z-{SPEC,RISKS}.md` + `docs/roadmap/slices/Z/` |
| FIFTH-PASS-AUDIT candidates | PCI-DSS, CMMC, FedRAMP Tailored, TIC 3.0, SOC 2, ISMAP/IRAP/TISAX, StateRAMP, NSM-22, AI EOs, Section 508, FIPS 140-3, CISA CPGs, etc. | `docs/roadmap/FIFTH-PASS-AUDIT.md` |

> **Note on LOOP-L through LOOP-Q (2026-06-07):** `ADDITIONAL-LOOPS-AUDIT.md`
> (2026-06-06) surfaced 6 net-new loops (L–Q). The human has ratified the
> audit and all six are now fully specified (`docs/loops/LOOP-{L,M,N,O,P,Q}-SPEC.md`
> + 25 per-slice docs under `docs/slices/{L,M,N,O,P,Q}/` + 6 risks registers).
> LOOP-M (Privacy/SORN/DPIA) and LOOP-O (AI/ML Governance) are now
> **confirmed applicable** (no longer conditional on operator decisions).
> Next-priority remains LOOP-B.B1 — risk scoring is still the highest-priority
> enabling slice for I, F, E, and (now) N + O. LOOP-L.L1 is queued
> immediately behind B.B1. A second-pass audit (`docs/SECOND-PASS-AUDIT.md`)
> ran after L-Q specification to confirm nothing else is still missing.

> **Note on LOOP-R, LOOP-S, CIRCIA extensions (2026-06-07):** A third-pass
> audit (`docs/THIRD-PASS-AUDIT.md`) surfaced three additional bodies of
> work that the second-pass audit missed: (a) Post-Quantum Cryptography
> migration per NIST IR 8547 + OMB M-23-02 + NSM-10 + NSA CNSA 2.0
> (LOOP-R, 3 slices, applicable to all CSPs because PQC migration is
> federally mandated), (b) DFARS 252.204-7012 Cloud Equivalency for
> DoD-prime customers (LOOP-S, 3 slices, **conditional** — only required
> when the CSP has or pursues DoD-prime customers running Covered Defense
> Information workloads on the CSO), and (c) **CIRCIA Final Rule 72-hour
> incident reporting** extensions to G.G2 (Incident Communications
> Procedures) and M.M4 (Privacy incident response) — these are
> **HIGH-PRIORITY** because CIRCIA's effective date is May 2026 and any
> CSP processing critical-infrastructure-related workloads is a Covered
> Entity. CIRCIA extensions are tracked as overlay slices that MUST ship
> in the same commit as the parent slice (G.G2 / M.M4) or be explicitly
> tracked as a follow-up. The human may elevate CIRCIA extensions above
> LOOP-B.B1 once basic CSP operations need to be CIRCIA-compliant.

## Pre-flight
| ID | Title | Status | Commit | Date |
|---|---|---|---|---|
| REO-0 | Real-Evidence-Only standard + CI guardrails | done | `794457b` | (per CHANGELOG) |
| R1 | FRMR walk for AFR family classification | done | `794457b` | (per CHANGELOG) |
| R2 | Monthly POA&M delta format research | done | `7a95221` | (per CHANGELOG) |
| R3 | Phase Two pilot output format check | done | `7a95221` | (per CHANGELOG) |
| R4 | Sample selection methodology research | done | `7a95221` | (per CHANGELOG) |

## LOOP-A — OSCAL Package Completeness (COMPLETE)
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| A.A1 | OSCAL POA&M emitter | done | `7a95221` | — | (in EXECUTION-PLAN.md) | — |
| A.A2 | OSCAL Assessment Plan emitter | done | `4f2170b` | — | (in EXECUTION-PLAN.md) | — |
| A.A3 | AR import-AP chain wiring | done | `553637c` | — | (in EXECUTION-PLAN.md) | — |
| A.A4 | Submission package bundler | done | `ecf1525` | — | (in EXECUTION-PLAN.md) | — |
| A.A5 | Rules of Engagement template seed | done | `469049f` | — | (in EXECUTION-PLAN.md) | — |

## LOOP-B — Risk + Remediation Engine
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| B.B1 | Per-finding CVSS+EPSS+criticality+exposure scoring | done | `22b6590` | 2026-06-10 | `docs/loops/LOOP-B-SPEC.md` | `docs/slices/B/B.B1.md` |
| B.B2 | Remediation deadline math (KEV/PAIN/IRV/LEV) | done | `f25255d` | 2026-06-11 | `docs/loops/LOOP-B-SPEC.md` | `docs/slices/B/B.B2.md` |
| B.B3 | Risk acceptance workflow in tracker | pending | — | — | `docs/loops/LOOP-B-SPEC.md` | `docs/slices/B/B.B3.md` |
| B.B4 | Compensating-controls registry | pending | — | — | `docs/loops/LOOP-B-SPEC.md` | `docs/slices/B/B.B4.md` |
| B.B5 | Central Risk Register (RA-3) | pending | — | — | `docs/loops/LOOP-B-SPEC.md` | `docs/slices/B/B.B5.md` |

## LOOP-C — Document Template Pack
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| C.C1 | Configuration Management Plan (CMP) | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C1.md` |
| C.C2 | Information System Contingency Plan (ISCP) + Test AAR | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C2.md` |
| C.C3 | Incident Response Plan (IRP) + Test AAR | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C3.md` |
| C.C4 | Privacy Threshold Analysis (PTA) + PIA | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C4.md` |
| C.C5 | FIPS 199 categorization worksheet | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C5.md` |
| C.C6 | Continuous Monitoring Strategy + Plan | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C6.md` |
| C.C7 | Risk Management Strategy (RMS) | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C7.md` |
| C.C8 | Authorization request cover letter | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C8.md` |
| C.C9 | Baseline Configuration document (CM-2) | pending | — | — | `docs/loops/LOOP-C-SPEC.md` | `docs/slices/C/C.C9.md` |

## LOOP-D — Diagram Auto-Generation
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| D.D1 | Authorization Boundary Diagram | pending | — | — | `docs/loops/LOOP-D-SPEC.md` | `docs/slices/D/D.D1.md` |
| D.D2 | Network Diagram | pending | — | — | `docs/loops/LOOP-D-SPEC.md` | `docs/slices/D/D.D2.md` |
| D.D3 | Data Flow Diagram | pending | — | — | `docs/loops/LOOP-D-SPEC.md` | `docs/slices/D/D.D3.md` |

## LOOP-E — Continuous Monitoring Agent
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| E.E1 | Monthly ConMon analysis report | done | `ddfa499` | 2026-06-11 | `docs/loops/LOOP-E-SPEC.md` | `docs/slices/E/E.E1.md` |
| E.E2 | Monthly POA&M delta workflow | done | `<TBD-step6>` | 2026-06-11 | `docs/loops/LOOP-E-SPEC.md` | `docs/slices/E/E.E2.md` |
| E.E3 | Annual Assessment package generator | pending | — | — | `docs/loops/LOOP-E-SPEC.md` | `docs/slices/E/E.E3.md` |
| E.E4 | Annual SSP review/update workflow | pending | — | — | `docs/loops/LOOP-E-SPEC.md` | `docs/slices/E/E.E4.md` |
| E.E5 | Deviation Request (DR) emitter | pending | — | — | `docs/loops/LOOP-E-SPEC.md` | `docs/slices/E/E.E5.md` |
| E.E6 | Formal SCN doc emitter | pending | — | — | `docs/loops/LOOP-E-SPEC.md` | `docs/slices/E/E.E6.md` |
| E.E7 | Annual IRP/ISCP test cadence runner | pending | — | — | `docs/loops/LOOP-E-SPEC.md` | `docs/slices/E/E.E7.md` |

## LOOP-F — 3PAO Assessor Experience
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| F.F1 | 3PAO sign-off UI in tracker | pending | — | — | `docs/loops/LOOP-F-SPEC.md` | `docs/slices/F/F.F1.md` |
| F.F2 | Comment threads on findings | pending | — | — | `docs/loops/LOOP-F-SPEC.md` | `docs/slices/F/F.F2.md` |
| F.F3 | Sample selection methodology auto-derive | pending | — | — | `docs/loops/LOOP-F-SPEC.md` | `docs/slices/F/F.F3.md` |
| F.F4 | Evidence walk-through artifacts | pending | — | — | `docs/loops/LOOP-F-SPEC.md` | `docs/slices/F/F.F4.md` |
| F.F5 | 3PAO recommendation letter template | pending | — | — | `docs/loops/LOOP-F-SPEC.md` | `docs/slices/F/F.F5.md` |
| F.F6 | Full ATO workflow tracker (PM-10) | pending | — | — | `docs/loops/LOOP-F-SPEC.md` | `docs/slices/F/F.F6.md` |
| F.F7 | SAR draft generator | pending | — | — | `docs/loops/LOOP-F-SPEC.md` | `docs/slices/F/F.F7.md` |

## LOOP-G — AFR Family (20x deliverables)
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| G.G1 | AFR-FSI (FedRAMP Security Inbox) | pending | — | — | `docs/loops/LOOP-G-SPEC.md` | `docs/slices/G/G.G1.md` |
| G.G2 | AFR-ICP (Incident Communications Procedures) | pending | — | — | `docs/loops/LOOP-G-SPEC.md` | `docs/slices/G/G.G2.md` |
| G.G3 | AFR-ADS (Authorization Data Sharing) | pending | — | — | `docs/loops/LOOP-G-SPEC.md` | `docs/slices/G/G.G3.md` |
| G.G4 | AFR-MAS (Minimum Assessment Scope) | pending | — | — | `docs/loops/LOOP-G-SPEC.md` | `docs/slices/G/G.G4.md` |
| G.G5 | AFR-SCG (Secure Configuration Guide) | pending | — | — | `docs/loops/LOOP-G-SPEC.md` | `docs/slices/G/G.G5.md` |
| G.G6 | AFR-CCM (Continuous Monitoring per 20x) | pending | — | — | `docs/loops/LOOP-G-SPEC.md` | `docs/slices/G/G.G6.md` |

## LOOP-H — Long-Term Storage + Multi-CSO
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| H.H1 | Immutable evidence archive | pending | — | — | `docs/loops/LOOP-H-SPEC.md` | `docs/slices/H/H.H1.md` |
| H.H2 | Audit retention policy enforcement (AU-11) | pending | — | — | `docs/loops/LOOP-H-SPEC.md` | `docs/slices/H/H.H2.md` |
| H.H3 | Multi-CSO support | pending | — | — | `docs/loops/LOOP-H-SPEC.md` | `docs/slices/H/H.H3.md` |

## LOOP-I — Stakeholder Dashboards
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| I.I1 | Executive posture dashboard | pending | — | — | `docs/loops/LOOP-I-SPEC.md` | `docs/slices/I/I.I1.md` |
| I.I2 | Finding burndown + deadline pipeline | pending | — | — | `docs/loops/LOOP-I-SPEC.md` | `docs/slices/I/I.I2.md` |
| I.I3 | Longitudinal trend analysis | pending | — | — | `docs/loops/LOOP-I-SPEC.md` | `docs/slices/I/I.I3.md` |
| I.I4 | SSP narrative library completion | pending | — | — | `docs/loops/LOOP-I-SPEC.md` | `docs/slices/I/I.I4.md` |

## LOOP-J — Supply Chain + Privileges
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| J.J1 | User Roles & Privileges matrix (AC-2 + AC-6) | pending | — | — | `docs/loops/LOOP-J-SPEC.md` | `docs/slices/J/J.J1.md` |
| J.J2 | Subprocessor inventory expansion (SA-9) | done | `3e3d6c5` | 2026-06-11 | `docs/loops/LOOP-J-SPEC.md` | `docs/slices/J/J.J2.md` |
| J.J3 | Supply chain risk register (SR-3) + SBOM | done | `a635da4` | 2026-06-11 | `docs/loops/LOOP-J-SPEC.md` | `docs/slices/J/J.J3.md` |

## LOOP-K — Test Artifact Ingestion
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| K.K1 | PenTest report ingest schema + tracker display | pending | — | — | `docs/loops/LOOP-K-SPEC.md` | `docs/slices/K/K.K1.md` |
| K.K2 | 3PAO test results matrix → OSCAL AR test-result-objects | pending | — | — | `docs/loops/LOOP-K-SPEC.md` | `docs/slices/K/K.K2.md` |

## LOOP-L — Customer Responsibility Matrix + Leveraged-Authorization Inheritance
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| L.L1 | CRM Workbook generator (SSP Appendix J) | pending | — | — | `docs/loops/LOOP-L-SPEC.md` | `docs/slices/L/L.L1.md` |
| L.L2 | Inherited-controls tracker + Leveraged-Authorization enumeration | pending | — | — | `docs/loops/LOOP-L-SPEC.md` | `docs/slices/L/L.L2.md` |
| L.L3 | CRM Gap Report | pending | — | — | `docs/loops/LOOP-L-SPEC.md` | `docs/slices/L/L.L3.md` |
| L.L4 | Per-control Responsibility Split Renderer | pending | — | — | `docs/loops/LOOP-L-SPEC.md` | `docs/slices/L/L.L4.md` |

## LOOP-M — Privacy Package Extension (SORN + DPIA) — CONFIRMED APPLICABLE
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| M.M1 | System of Records Notice (SORN) emitter — Privacy Act §552a | pending | — | — | `docs/loops/LOOP-M-SPEC.md` | `docs/slices/M/M.M1.md` |
| M.M2 | Data Protection Impact Assessment (DPIA) for cross-border / agency-partner data | pending | — | — | `docs/loops/LOOP-M-SPEC.md` | `docs/slices/M/M.M2.md` |
| M.M3 | PT-family controls inventory (PT-1..PT-8) beyond PTA/PIA scope | pending | — | — | `docs/loops/LOOP-M-SPEC.md` | `docs/slices/M/M.M3.md` |
| M.M4 | Privacy incident response procedures (PT-7 + breach notification per OMB M-17-12) | pending | — | — | `docs/loops/LOOP-M-SPEC.md` | `docs/slices/M/M.M4.md` |

## LOOP-N — Threat Modeling + Adversarial Validation
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| N.N1 | STRIDE threat model generator (per-component, from inventory + DFD) | pending | — | — | `docs/loops/LOOP-N-SPEC.md` | `docs/slices/N/N.N1.md` |
| N.N2 | Attack surface enumeration (boundary entry points + exposed services) | pending | — | — | `docs/loops/LOOP-N-SPEC.md` | `docs/slices/N/N.N2.md` |
| N.N3 | PASTA / red-team adversarial test framework (automated adversarial runs) | pending | — | — | `docs/loops/LOOP-N-SPEC.md` | `docs/slices/N/N.N3.md` |
| N.N4 | MITRE ATT&CK technique mapping (which techniques apply to our boundary) | pending | — | — | `docs/loops/LOOP-N-SPEC.md` | `docs/slices/N/N.N4.md` |

## LOOP-O — AI/ML Governance per NIST AI RMF + OMB M-24-10 — CONFIRMED APPLICABLE
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| O.O1 | AI/ML asset inventory (models, training data, inference endpoints) | pending | — | — | `docs/loops/LOOP-O-SPEC.md` | `docs/slices/O/O.O1.md` |
| O.O2 | NIST AI RMF alignment (GOVERN / MAP / MEASURE / MANAGE) | pending | — | — | `docs/loops/LOOP-O-SPEC.md` | `docs/slices/O/O.O2.md` |
| O.O3 | AI risk register (bias, fairness, robustness, adversarial) | pending | — | — | `docs/loops/LOOP-O-SPEC.md` | `docs/slices/O/O.O3.md` |
| O.O4 | AI evaluation per OMB M-24-10 (pre-deployment + ongoing) | pending | — | — | `docs/loops/LOOP-O-SPEC.md` | `docs/slices/O/O.O4.md` |
| O.O5 | Model card + datasheet emitter | pending | — | — | `docs/loops/LOOP-O-SPEC.md` | `docs/slices/O/O.O5.md` |

## LOOP-P — Insider Threat + PS-family Workforce Security
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| P.P1 | Insider Threat Program documentation + tracker workflow | pending | — | — | `docs/loops/LOOP-P-SPEC.md` | `docs/slices/P/P.P1.md` |
| P.P2 | Position risk designation per role (PS-2 + PS-3 screening) | pending | — | — | `docs/loops/LOOP-P-SPEC.md` | `docs/slices/P/P.P2.md` |
| P.P3 | Personnel transfer + termination procedures (PS-4 + PS-5) | pending | — | — | `docs/loops/LOOP-P-SPEC.md` | `docs/slices/P/P.P3.md` |
| P.P4 | Access agreements + acknowledgments + NDA (PS-6) | pending | — | — | `docs/loops/LOOP-P-SPEC.md` | `docs/slices/P/P.P4.md` |
| P.P5 | Continuous workforce monitoring + behavioral analytics | pending | — | — | `docs/loops/LOOP-P-SPEC.md` | `docs/slices/P/P.P5.md` |

## LOOP-Q — Marketplace + Post-ATO Publication
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| Q.Q1 | FedRAMP Marketplace listing emitter (per RFC-0021 format) | pending | — | — | `docs/loops/LOOP-Q-SPEC.md` | `docs/slices/Q/Q.Q1.md` |
| Q.Q2 | Post-ATO ConMon publication (monthly delivery to FedRAMP secure repository) | pending | — | — | `docs/loops/LOOP-Q-SPEC.md` | `docs/slices/Q/Q.Q2.md` |
| Q.Q3 | Agency authorization tracking (who is using the CSO + their authorization documents) | pending | — | — | `docs/loops/LOOP-Q-SPEC.md` | `docs/slices/Q/Q.Q3.md` |

## LOOP-R — Post-Quantum Cryptography Migration
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| R.R1 | Cryptographic Inventory Collector | pending | — | — | `docs/loops/LOOP-R-SPEC.md` | `docs/slices/R/R.R1.md` |
| R.R2 | Migration Plan Emitter | pending | — | — | `docs/loops/LOOP-R-SPEC.md` | `docs/slices/R/R.R2.md` |
| R.R3 | Annual PQC Report Emitter | pending | — | — | `docs/loops/LOOP-R-SPEC.md` | `docs/slices/R/R.R3.md` |

## LOOP-S — DFARS 252.204-7012 Cloud Equivalency (conditional: DoD-prime customers)
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| S.S1 | NIST 800-171 Rev 3 → FedRAMP Moderate Crosswalk | pending | — | — | `docs/loops/LOOP-S-SPEC.md` | `docs/slices/S/S.S1.md` |
| S.S2 | Cyber Incident Reporting per DFARS 252.204-7012(c) | pending | — | — | `docs/loops/LOOP-S-SPEC.md` | `docs/slices/S/S.S2.md` |
| S.S3 | Cloud Equivalency Attestation Package | pending | — | — | `docs/loops/LOOP-S-SPEC.md` | `docs/slices/S/S.S3.md` |

## LOOP-W — Prohibited Vendors (HIGHEST PRIORITY — statutorily gates submission package)
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc | Dependencies | Last updated |
|---|---|---|---|---|---|---|---|---|
| W.W1 | Prohibited-vendor catalog ingester + canonical-JSON emitter (OFAC SDN + BIS Entity List + SAM Exclusions + FAR 52.204-25 + NDAA §889 + NDAA §1634 + FASCSA) | done | `be78723` | 2026-06-08 | `docs/loops/LOOP-W-SPEC.md` | `docs/slices/W/W.W1.md` | — | 2026-06-08 |
| W.W2 | Subprocessor + supplier inventory crosscheck against prohibited-vendor list | proposed | TBD | — | `docs/loops/LOOP-W-SPEC.md` | `docs/slices/W/W.W2.md` | W.W1, J.J2 | 2026-06-07 |
| W.W3 | SBOM + dependency-graph crosscheck against prohibited-vendor list (transitive supplier check) | proposed | TBD | — | `docs/loops/LOOP-W-SPEC.md` | `docs/slices/W/W.W3.md` | W.W1, J.J3 | 2026-06-07 |
| W.W4 | Prohibited-vendor compliance attestation emitter (signed, blocks submission on hit) | proposed | TBD | — | `docs/loops/LOOP-W-SPEC.md` | `docs/slices/W/W.W4.md` | W.W1, W.W2, W.W3 | 2026-06-07 |

## LOOP-T — NIST SSDF + CISA Secure Software Development Attestation Common Form
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc | Dependencies | Last updated |
|---|---|---|---|---|---|---|---|---|
| T.T1 | NIST SSDF (SP 800-218) practice inventory + control mapping | done | `9bbbcd1` | 2026-06-10 | `docs/loops/LOOP-T-SPEC.md` | `docs/slices/T/T.T1.md` | — | 2026-06-10 |
| T.T2 | SSDF evidence collector (CI/CD pipeline, build provenance, SBOM, signing) | proposed | TBD | — | `docs/loops/LOOP-T-SPEC.md` | `docs/slices/T/T.T2.md` | T.T1, J.J3 | 2026-06-07 |
| T.T3 | CISA Secure Software Development Attestation Common Form emitter (OMB M-22-18 / M-23-16) | proposed | TBD | — | `docs/loops/LOOP-T-SPEC.md` | `docs/slices/T/T.T3.md` | T.T1, T.T2 | 2026-06-07 |
| T.T4 | Third-party software components attestation appendix | proposed | TBD | — | `docs/loops/LOOP-T-SPEC.md` | `docs/slices/T/T.T4.md` | T.T3 | 2026-06-07 |
| T.T5 | CISA RSAA portal submission package + repository signed-envelope | proposed | TBD | — | `docs/loops/LOOP-T-SPEC.md` | `docs/slices/T/T.T5.md` | T.T3, T.T4 | 2026-06-07 |

## LOOP-X — Zero Trust Architecture compliance (OMB M-22-09 + NIST SP 800-207/207A + CISA ZTMM v2.0)
| Slice | Title | Status | Commit | Spec | Doc | Dependencies | Last updated |
|---|---|---|---|---|---|---|---|
| X.X1 | ZT pillar inventory (Identity / Devices / Networks / Apps / Data + cross-cutting capabilities) | proposed | TBD | `docs/loops/LOOP-X-SPEC.md` | `docs/slices/X/X.X1.md` | A.A5 | 2026-06-08 |
| X.X2 | NIST SP 800-207 architecture mapping (PDP/PEP placement + trust algorithm) | proposed | TBD | `docs/loops/LOOP-X-SPEC.md` | `docs/slices/X/X.X2.md` | X.X1, INV-S | 2026-06-08 |
| X.X3 | NIST SP 800-207A cloud-native ZTA (service mesh, sidecar, k8s admission, API gateway) | proposed | TBD | `docs/loops/LOOP-X-SPEC.md` | `docs/slices/X/X.X3.md` | X.X2, E.1, J.J3 | 2026-06-08 |
| X.X4 | CISA ZTMM v2.0 maturity scoring (per-pillar Traditional/Initial/Advanced/Optimal scorecard .docx) | proposed | TBD | `docs/loops/LOOP-X-SPEC.md` | `docs/slices/X/X.X4.md` | X.X1-X.X3, A.A4, A.A5 | 2026-06-08 |
| X.X5 | PDP / PEP integration evidence (k8s NetworkPolicy, AWS VPC SG, GCP firewall, Azure NSG, OPA/Gatekeeper, Istio AuthorizationPolicy) | proposed | TBD | `docs/loops/LOOP-X-SPEC.md` | `docs/slices/X/X.X5.md` | X.X2, X.X3, INV-S | 2026-06-08 |

## Out-of-Core / Overlay loops — see `docs/roadmap/`

LOOP-U (Privacy frameworks), LOOP-V (HIPAA Healthcare), LOOP-Y
(CJIS + IRS Pub 1075), and LOOP-Z (ISO 27001/27017/27018/27701 +
ENISA EUCS) were scope-fenced out of core FedPy and relocated to
`cloud-evidence/docs/roadmap/loops/` + `cloud-evidence/docs/roadmap/slices/`.
They are preserved as research / roadmap reference, not as
implementation work. The FIFTH-PASS-AUDIT.md candidates
(LOOP-AA through LOOP-GG: PCI-DSS / CMMC / FedRAMP Tailored / TIC 3.0
/ SOC 2 / ISMAP/IRAP/TISAX / StateRAMP / NSM-22 / AI EOs / Section 508 /
FIPS 140-3 / CISA CPGs / etc.) are also roadmap-only.

Read `docs/roadmap/README.md` and the **Scope Guard** block in
`cloud-evidence/CLAUDE.md` before referencing anything in that folder.
The scope-fence policy is: do not propose moving these back to core
without an explicit mission re-statement from the user.

## CIRCIA Extensions + Overlays (HIGH PRIORITY — May 2026 effective for CIRCIA; SEC 8-K is in force today)
| Slice | Title | Status | Commit | Date | Spec | Per-slice doc |
|---|---|---|---|---|---|---|
| G.G2.CIRCIA | CIRCIA 72-hour incident reporting extension | pending | — | — | `docs/CIRCIA-WORKFLOW.md` | `docs/slices/G/G.G2-CIRCIA-EXTENSION.md` |
| M.M4.CIRCIA | CIRCIA + Privacy Act incident harmonization | pending | — | — | `docs/CIRCIA-WORKFLOW.md` | `docs/slices/M/M.M4-CIRCIA-EXTENSION.md` |
| G.G2-SEC-8K | SEC Item 1.05 Form 8-K cyber-incident disclosure overlay (four-business-day clock; applies when CSP is an SEC-registrant or subsidiary thereof) | proposed | TBD | — | `docs/loops/LOOP-G-SPEC.md` | `docs/slices/G/G.G2-SEC-8K-EXTENSION.md` |

## Per-loop risks registers
Each loop has a dedicated risks register listing implementation,
schedule, dependency, and external risks discovered during planning +
slice authoring. Update the register every time a slice surfaces a new
risk (per the Strong-Directive in `cloud-evidence/CLAUDE.md`).

| Register | Loop | Path |
|---|---|---|
| LOOP-B risks | Risk + Remediation Engine | `docs/loops/LOOP-B-RISKS.md` |
| LOOP-C risks | Document Template Pack | `docs/loops/LOOP-C-RISKS.md` |
| LOOP-D risks | Diagram Auto-Generation | `docs/loops/LOOP-D-RISKS.md` |
| LOOP-E risks | Continuous Monitoring Agent | `docs/loops/LOOP-E-RISKS.md` |
| LOOP-F risks | 3PAO Assessor Experience | `docs/loops/LOOP-F-RISKS.md` |
| LOOP-G risks | AFR Family | `docs/loops/LOOP-G-RISKS.md` |
| LOOP-H risks | Long-Term Storage + Multi-CSO | `docs/loops/LOOP-H-RISKS.md` |
| LOOP-I risks | Stakeholder Dashboards | `docs/loops/LOOP-I-RISKS.md` |
| LOOP-J risks | Supply Chain + Privileges | `docs/loops/LOOP-J-RISKS.md` |
| LOOP-K risks | Test Artifact Ingestion | `docs/loops/LOOP-K-RISKS.md` |
| LOOP-L risks | CRM + Leveraged-Authorization Inheritance | `docs/loops/LOOP-L-RISKS.md` |
| LOOP-M risks | Privacy Package Extension (SORN + DPIA) | `docs/loops/LOOP-M-RISKS.md` |
| LOOP-N risks | Threat Modeling + Adversarial Validation | `docs/loops/LOOP-N-RISKS.md` |
| LOOP-O risks | AI/ML Governance | `docs/loops/LOOP-O-RISKS.md` |
| LOOP-P risks | Insider Threat + PS-family | `docs/loops/LOOP-P-RISKS.md` |
| LOOP-Q risks | Marketplace + Post-ATO Publication | `docs/loops/LOOP-Q-RISKS.md` |
| LOOP-R risks | Post-Quantum Cryptography Migration | `docs/loops/LOOP-R-RISKS.md` |
| LOOP-S risks | DFARS 252.204-7012 Cloud Equivalency | `docs/loops/LOOP-S-RISKS.md` |

## Cross-cutting references
Reference docs that span every loop. Read these whenever planning
across loops, onboarding a new contributor, or answering a "where
does X term come from" question.

| Doc | Purpose | Path |
|---|---|---|
| Dependency graph | Mermaid + tabular dependency map for every slice; critical path; parallelization streams | `docs/DEPENDENCY-GRAPH.md` |
| Glossary | A–Z of every FedRAMP / NIST / OSCAL / internal term used in the spec corpus (90+ terms) | `docs/GLOSSARY.md` |
| Implementation log template | Format + cadence for the per-slice "Implementation log" running journal | `docs/IMPLEMENTATION-LOG-TEMPLATE.md` |
| Additional loops audit | Audit of FedRAMP/NIST corpus for items missing from the LOOP-A..K roadmap; proposes LOOP-L..Q + §3 extensions | `docs/ADDITIONAL-LOOPS-AUDIT.md` |
| Second-pass audit | Post-LOOP-L..Q audit confirming nothing else is still missing after L-Q specification | `docs/SECOND-PASS-AUDIT.md` |

## Sections (artifact requirements layer)
| Section | Title | Spec doc |
|---|---|---|
| A | Submission package artifacts | `docs/sections/SECTION-A.md` |
| B | 3PAO assessment workflow | `docs/sections/SECTION-B.md` |
| C | Post-authorization ConMon | `docs/sections/SECTION-C.md` |
| D | Audit agent UX | `docs/sections/SECTION-D.md` |
| E | NIST 800-53 Rev5 control mapping | `docs/sections/SECTION-E.md` |
| F | FedRAMP 20x specific deliverables | `docs/sections/SECTION-F.md` |
