---
slice_id: U.U4
title: Cross-Border Transfer Assessment (CJEU Schrems II) + EU Standard Contractual Clauses (Modules 1–4) + UK Addendum
loop: U
status: proposed
commit: TBD
completed_date: —
depends_on:
  - U.U2                                # subprocessor + personal-data flow registry (the trigger source for transfer detection)
  - LOOP-A.A5                           # Ed25519 signing pipeline + RFC 3161 timestamp service used to seal TIA + SCC envelopes
blocks: []
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-07
applicable_conditional: true
condition: |
  Triggers when U.U2 detects any cross-border personal-data transfer that involves at
  least one of: (a) controller or processor established in the EU/EEA exporting personal
  data to an importer in a third country lacking an adequacy decision under Article 45
  GDPR; (b) UK controller or processor exporting personal data to an importer outside
  the United Kingdom in reliance on the UK Addendum to the EU SCCs (or the UK IDTA); or
  (c) EU/UK exporter relying on Article 46 GDPR / Article 46 UK GDPR appropriate
  safeguards (the EU Commission Standard Contractual Clauses adopted by Commission
  Implementing Decision (EU) 2021/914 of 4 June 2021) where Schrems II (CJEU Judgment
  C-311/18 of 16 July 2020) requires a supplementary Transfer Impact Assessment.
  Detection is keyed off the U.U2 subprocessor / data-flow registry's
  `exporter_country` and `importer_country` fields plus the destination country's
  presence in the EU Commission adequacy list (data file
  `cloud-evidence/data/gdpr-adequacy-decisions.json`). When the trigger fires for a
  given (exporter, importer, data category, contract) tuple, U.U4 emits a Transfer
  Impact Assessment envelope, the matching SCC Module (1, 2, 3 or 4) populated with
  the parties' particulars, and (where the importer is in the UK or the exporter is a
  UK controller / processor) the UK ICO International Data Transfer Addendum.
trigger_flag: "--cross-border-tia"
trigger_env: CLOUD_EVIDENCE_CROSS_BORDER_TIA
---

# U.U4 — Cross-Border Transfer Assessment (CJEU Schrems II) + EU SCC Modules 1–4 + UK Addendum

> The Court of Justice of the European Union's judgment of 16 July 2020 in
> Case C-311/18 (Data Protection Commissioner v. Facebook Ireland Ltd and
> Maximillian Schrems — "Schrems II") invalidated the EU–US Privacy
> Shield and made clear that controllers and processors that rely on the
> Article 46 GDPR Standard Contractual Clauses (SCCs) to transfer
> personal data outside the EU/EEA must, on a case-by-case basis,
> **assess the law and practice of the third country** that is to receive
> the data, and **adopt supplementary measures** where the SCC by itself
> does not afford a level of protection essentially equivalent to that
> guaranteed within the Union. The European Data Protection Board
> (EDPB) operationalised that obligation in **Recommendations 01/2020**
> (final version of 18 June 2021). The European Commission then adopted
> the **modular SCCs** under **Commission Implementing Decision (EU)
> 2021/914 of 4 June 2021**, replacing the legacy 2001/2004/2010 SCCs
> with four "modules" covering controller-to-controller,
> controller-to-processor, processor-to-processor and
> processor-to-controller transfers respectively, plus a "docking clause"
> for multi-party accession.
>
> U.U4 is the slice that turns those requirements into deterministic,
> signed, machine-verifiable artifacts: a Transfer Impact Assessment
> (TIA) JSON envelope per transfer, a populated `.docx` rendering of the
> applicable SCC module (1, 2, 3 or 4) per transfer, and — where a UK
> leg is present — the UK Information Commissioner's Office's
> **International Data Transfer Addendum to the EU Commission Standard
> Contractual Clauses ("UK Addendum"), Version B1.0**, in force from
> 21 March 2022 under the Data Protection Act 2018 §119A.

## 1. Mission

U.U4 ingests the U.U2 `cross-border-transfers.json` envelope produced by
the U.U2 subprocessor / personal-data-flow registry, walks its
`transfers[]` array, and for each transfer whose exporter→importer
country pair lacks a current EU Commission adequacy decision (Article
45 GDPR) **and** is therefore relying on Article 46 SCCs as the
transfer mechanism, executes the six-step Transfer Impact Assessment
methodology mandated by EDPB Recommendations 01/2020.

For each qualifying transfer U.U4 emits **three artifact families**:

1. A canonical-JSON **Transfer Impact Assessment (TIA) envelope**
   containing: (a) the data-flow particulars (exporter, importer, data
   categories, special categories, data subjects, retention, onward
   transfers); (b) the EDPB six-step record (Step 1 — know your
   transfer; Step 2 — identify the transfer tool; Step 3 — assess the
   third-country law; Step 4 — adopt supplementary measures; Step 5 —
   take procedural steps; Step 6 — re-evaluate at appropriate
   intervals); (c) a per-country statutory risk-finding table (e.g. FISA
   Section 702 for US destinations; section 9 of the Russian SORM
   regime; PRC Cybersecurity Law Article 37 etc.); (d) the SCC module
   selected (1 / 2 / 3 / 4) and the docking-clause presence/absence;
   (e) any supplementary measures (technical: end-to-end encryption,
   pseudonymisation, split-processing; contractual: warrant canaries,
   onward-transfer prohibitions; organisational: data-localisation,
   processor's local-counsel review); (f) the operator's residual-risk
   determination + sign-off.
2. A **populated `.docx`** of the selected SCC Module (1, 2, 3 or 4)
   rendered from a clean-room template that mirrors Annex I (parties +
   list of transfers + competent supervisory authority), Annex II
   (technical and organisational measures), and Annex III
   (sub-processors) of Commission Implementing Decision (EU) 2021/914.
   Where the importer is in the United Kingdom (or the exporter is a UK
   controller/processor and the importer outside the UK), U.U4 also
   emits the **UK ICO International Data Transfer Addendum** populated
   with the parties' particulars and the corresponding tables.
3. A **signed envelope bundle** for each transfer comprising the TIA
   JSON + SCC `.docx` + (optional) UK Addendum `.docx`, sealed with the
   operator's Ed25519 corporate-counsel signing key (via LOOP-A.A5) and
   stamped with an RFC 3161 timestamp token. The envelope flows into
   the submission package via LOOP-A.A4 so the FedRAMP 3PAO can audit
   the cross-border transfer posture alongside the rest of the
   evidence corpus.

The slice does **NOT** transmit the SCC `.docx` to the importer for
signature — REO Rule 4 forbids the system from acting on behalf of the
operator on a contractual commitment. U.U4 emits the artifact pair,
surfaces the artifact pair in the tracker UI with the parties' email
addresses, prompts the operator's General Counsel to obtain the
importer's wet/electronic signature, and records the executed-SCC
return file + signature-date back into the tracker DB.

U.U4 is **conditional** — it only runs when U.U2 has detected at least
one qualifying cross-border transfer. The condition predicate is
implemented in `core/cross-border-tia.ts::shouldRun(...)` and uses the
EU Commission adequacy-decision list shipped at
`cloud-evidence/data/gdpr-adequacy-decisions.json` (regenerated each
quarter via `scripts/fetch-adequacy-decisions.mjs`).

## 2. Authoritative sources

Every URL accessed 2026-06-07. Verbatim quotes appear in Markdown
blockquotes. Where the live source returned a non-200 to anonymous
fetches, the implementer downloads the page or PDF to
`cloud-evidence/docs/sources/` and re-quotes verbatim from the local
copy. The source list below is the **minimum**; the implementer SHOULD
fetch and cite every Article and Recital cross-referenced from these
documents.

### 2.1 CJEU Judgment of 16 July 2020 in Case C-311/18 ("Schrems II")

Full citation: Judgment of the Court (Grand Chamber) of 16 July 2020,
*Data Protection Commissioner v Facebook Ireland Ltd and Maximillian
Schrems*, ECLI:EU:C:2020:559. URL:
https://curia.europa.eu/juris/document/document.jsf?docid=228677&doclang=EN
(accessed 2026-06-07; operator mirrors PDF to
`docs/sources/c-311-18-schrems-ii.pdf`).

Paragraph 105 — the **essential equivalence** test:

> "Therefore, although there are means in EU law that allow such
> transfers to be carried out on the basis of standard data protection
> clauses, those means must, in practice, ensure that data subjects
> whose personal data are transferred to a third country pursuant to
> standard data protection clauses are afforded a level of protection
> essentially equivalent to that guaranteed within the European Union
> by the GDPR, read in the light of the Charter."

Paragraph 134 — the **supplementary measures** obligation:

> "It is therefore, above all, for that controller or processor to
> verify, on a case-by-case basis and, where appropriate, in
> collaboration with the recipient of the data, whether the law of the
> third country of destination ensures adequate protection, under EU
> law, of personal data transferred pursuant to standard data
> protection clauses, by providing, where necessary, additional
> safeguards to those offered by those clauses."

Paragraph 142 — the **suspension-or-termination** duty of the
exporter (and of the supervisory authority where the exporter fails):

> "Accordingly, unless there is a valid Commission adequacy decision,
> the competent supervisory authority is required to suspend or
> prohibit a transfer of personal data to a third country pursuant to
> standard data protection clauses adopted by the Commission, if, in
> the view of that supervisory authority and in the light of all the
> circumstances of that transfer, those clauses are not or cannot be
> complied with in that third country and the protection of the data
> transferred that is required by EU law, in particular by Articles 45
> and 46 of the GDPR and by the Charter, cannot be ensured by other
> means, where the controller or a processor has not itself suspended
> or put an end to the transfer."

Operative paragraph 3 of the judgment — invalidation of the EU–US
Privacy Shield (Commission Implementing Decision (EU) 2016/1250):

> "Commission Implementing Decision (EU) 2016/1250 of 12 July 2016
> pursuant to Directive 95/46/EC of the European Parliament and of the
> Council on the adequacy of the protection provided by the EU-U.S.
> Privacy Shield is invalid."

These four passages drive U.U4's algorithm: §6.3 (essential
equivalence assessment), §6.4 (supplementary measures), and §6.5
(suspension-or-termination escalation path).

### 2.2 Commission Implementing Decision (EU) 2021/914 of 4 June 2021

Full citation: Commission Implementing Decision (EU) 2021/914 of
4 June 2021 on standard contractual clauses for the transfer of
personal data to third countries pursuant to Regulation (EU) 2016/679
of the European Parliament and of the Council. OJ L 199, 7.6.2021,
p. 31. URL:
https://eur-lex.europa.eu/eli/dec_impl/2021/914/oj (accessed
2026-06-07; operator mirrors to `docs/sources/eu-2021-914.pdf`).

Recital (10) — the **modular structure**:

> "The standard contractual clauses set out in the Annex to this
> Decision combine general clauses with a modular approach to cater
> for various transfer scenarios and the complexity of modern
> processing chains. In addition to the general clauses, controllers
> and processors should select the module applicable to their
> situation, so as to tailor their obligations under the standard
> contractual clauses to their corresponding role and responsibilities
> in relation to the data processing at issue. It should be possible
> for more than two parties to adhere to the standard contractual
> clauses."

Article 1(1) — the **scope** of the Decision:

> "The standard contractual clauses set out in the Annex are
> considered to provide appropriate safeguards within the meaning of
> Article 46(1) and (2)(c) of Regulation (EU) 2016/679 for the
> transfer by a controller or processor of personal data processed
> subject to that Regulation (data exporter) to a controller or
> (sub-)processor whose processing of the data is not subject to that
> Regulation (data importer)."

Article 4 — the **transitional period** (the legacy 2001/2010 clauses
remained valid until 27 December 2022):

> "1. From 27 September 2021, Commission Decisions 2001/497/EC and
> 2010/87/EU are repealed.
> 2. Notwithstanding paragraph 1, contracts concluded before 27
> September 2021 on the basis of Commission Decisions 2001/497/EC or
> 2010/87/EU shall be deemed to provide the appropriate safeguards
> within the meaning of Article 46(1) of Regulation (EU) 2016/679
> until 27 December 2022, provided that the processing operations
> that are the subject matter of the contract remain unchanged …"

Annex, Section I, Clause 1(b) — the **four modules**:

> "These Clauses apply with respect to the transfer of personal data
> as specified in Annex I.B.
> These Clauses apply for the situation described in Module One
> (transfer controller to controller), Module Two (transfer controller
> to processor), Module Three (transfer processor to processor) or
> Module Four (transfer processor to controller) as identified in
> Annex I.B."

Annex, Section I, Clause 2 — the **effect and invariability**:

> "(a) These Clauses set out appropriate safeguards, including
> enforceable data subject rights and effective legal remedies …
> (b) These Clauses do not by themselves ensure compliance with
> obligations related to international transfers in accordance with
> Chapter V of Regulation (EU) 2016/679.
> (c) The Parties undertake not to modify the Clauses, except to add
> information to the Annexes or update the information in them. This
> does not prevent the Parties from including the standard contractual
> clauses laid down in these Clauses in a wider contract …"

Annex, Section III, Clause 14 — the **local-law-assessment** clause
(Clause 14(a) is the contractual analogue of Schrems II ¶134):

> "(a) The Parties warrant that they have no reason to believe that
> the laws and practices in the third country of destination
> applicable to the processing of the personal data by the data
> importer, including any requirements to disclose personal data or
> measures authorising access by public authorities, prevent the data
> importer from fulfilling its obligations under these Clauses. This
> is based on the understanding that laws and practices that respect
> the essence of the fundamental rights and freedoms and do not exceed
> what is necessary and proportionate in a democratic society to
> safeguard one of the objectives listed in Article 23(1) of
> Regulation (EU) 2016/679, are not in contradiction with these
> Clauses."

Clause 14(b) — the **non-exhaustive factors** the parties must
consider:

> "(b) The Parties declare that in providing the warranty in
> paragraph (a), they have taken due account in particular of the
> following elements: (i) the specific circumstances of the transfer
> … (ii) the laws and practices of the third country of destination
> … relevant in light of the specific circumstances of the transfer,
> and the applicable limitations and safeguards; (iii) any relevant
> contractual, technical or organisational safeguards put in place to
> supplement the safeguards under these Clauses, including measures
> applied during transmission and to the processing of the personal
> data in the country of destination."

Clause 15 — the **importer notification + challenge** obligations
when the importer receives a request from a public authority:

> "15.1 Notification … the data importer agrees to notify the data
> exporter and, where possible, the data subject promptly (if
> necessary with the help of the data exporter) if it: (i) receives a
> legally binding request from a public authority, including judicial
> authorities, under the laws of the country of destination for the
> disclosure of personal data transferred pursuant to these Clauses
> …; (ii) becomes aware of any direct access by public authorities to
> personal data transferred pursuant to these Clauses in accordance
> with the laws of the country of destination …"

### 2.3 GDPR Articles 44, 45 and 46

Full citation: Regulation (EU) 2016/679 of the European Parliament and
of the Council of 27 April 2016 on the protection of natural persons
with regard to the processing of personal data and on the free
movement of such data (General Data Protection Regulation). OJ L 119,
4.5.2016, p. 1. URL:
https://eur-lex.europa.eu/eli/reg/2016/679/oj (accessed 2026-06-07;
operator mirrors to `docs/sources/gdpr-2016-679.pdf`).

Article 44 — the **general principle for transfers**:

> "Any transfer of personal data which are undergoing processing or
> are intended for processing after transfer to a third country or to
> an international organisation shall take place only if, subject to
> the other provisions of this Regulation, the conditions laid down
> in this Chapter are complied with by the controller and processor,
> including for onward transfers of personal data from the third
> country or an international organisation to another third country
> or to another international organisation. All provisions in this
> Chapter shall be applied in order to ensure that the level of
> protection of natural persons guaranteed by this Regulation is not
> undermined."

Article 45(1) — **transfers on the basis of an adequacy decision**:

> "A transfer of personal data to a third country or an international
> organisation may take place where the Commission has decided that
> the third country, a territory or one or more specified sectors
> within that third country, or the international organisation in
> question ensures an adequate level of protection. Such a transfer
> shall not require any specific authorisation."

Article 46(1) — **transfers subject to appropriate safeguards**:

> "In the absence of a decision pursuant to Article 45(3), a
> controller or processor may transfer personal data to a third
> country or an international organisation only if the controller or
> processor has provided appropriate safeguards, and on condition
> that enforceable data subject rights and effective legal remedies
> for data subjects are available."

Article 46(2)(c) — explicit recognition of the **Commission SCCs**:

> "The appropriate safeguards referred to in paragraph 1 may be
> provided for, without requiring any specific authorisation from a
> supervisory authority, by: … (c) standard data protection clauses
> adopted by the Commission in accordance with the examination
> procedure referred to in Article 93(2)."

### 2.4 EDPB Recommendations 01/2020 on measures that supplement transfer tools

Full citation: European Data Protection Board, Recommendations 01/2020
on measures that supplement transfer tools to ensure compliance with
the EU level of protection of personal data, Version 2.0 — Adopted on
18 June 2021. URL:
https://edpb.europa.eu/system/files/2021-06/edpb_recommendations_202001vo.2.0_supplementarymeasurestransferstools_en.pdf
(accessed 2026-06-07; operator mirrors).

The six-step roadmap (the operative source for §6.3):

> "Step 1: Know your transfers. Mapping all transfers of personal
> data to third countries can be a difficult exercise. Being aware of
> where the personal data goes is however necessary to ensure that it
> is afforded an essentially equivalent level of protection wherever
> it is processed.
> Step 2: Identify the transfer tools you are relying on …
> Step 3: Assess whether the Article 46 GDPR transfer tool you are
> relying on is effective in light of all circumstances of the
> transfer …
> Step 4: Adopt supplementary measures …
> Step 5: Take any formal procedural steps the adoption of your
> supplementary measure may require …
> Step 6: Re-evaluate at appropriate intervals the level of
> protection afforded to the data you transfer to third countries
> and monitor if there have been or there will be any developments
> that may affect it."

Annex 2 — the **non-exhaustive list of supplementary measures**
(technical, contractual, organisational). U.U4's `.docx` Annex II
inherits this taxonomy. Verbatim from the Recommendations:

> "Technical measures … Use Case 1: Data storage for backup and
> other purposes that do not require access to data in the clear …
> the personal data should be processed using strong encryption …
> the cryptographic keys are retained solely under the control of the
> data exporter, or by other entities entrusted with this task which
> reside in the EEA or a third country, territory, or one or more
> specified sectors within a third country for which the Commission
> has established in accordance with Article 45 GDPR that an adequate
> level of protection is ensured …"

> "Contractual measures … Providing for the contractual obligation
> to use specific technical measures … Transparency obligations …
> Obligations to take specific actions … Empowering data subjects to
> exercise their rights."

> "Organisational measures … Internal policies for governance of
> transfers … Transparency and accountability measures … Strict
> data minimisation measures."

### 2.5 UK ICO International Data Transfer Addendum (IDTA)

Full citation: Information Commissioner's Office, *International Data
Transfer Addendum to the EU Commission Standard Contractual Clauses*,
Version B1.0 (in force 21 March 2022), issued under section 119A of
the Data Protection Act 2018. URL:
https://ico.org.uk/media/for-organisations/documents/4019539/international-data-transfer-addendum.pdf
(accessed 2026-06-07; operator mirrors).

Section 1 (Tables) — the **Approved Addendum** form:

> "This Addendum has been issued by the Information Commissioner
> for Parties making Restricted Transfers. The Information
> Commissioner considers that it provides Appropriate Safeguards
> for Restricted Transfers when it is entered into as a legally
> binding contract."

> "Table 1: Parties — Start date; The Parties; Parties' details;
> Key Contact; Signature (if required for the purposes of Section 2).
> Table 2: Selected SCCs, Modules and Selected Clauses.
> Table 3: Appendix Information.
> Table 4: Ending this Addendum when the Approved Addendum
> Changes."

Section 2(7) — **incorporation by reference** of the Commission SCCs:

> "The EU SCCs, including the Appendix Information, are incorporated
> into and form part of this Addendum, except that the following are
> modified to the extent set out in Section 2."

Section 23 — the **legal basis** under section 119A of the Data
Protection Act 2018:

> "This Addendum has been issued under Section 119A of the Data
> Protection Act 2018 by the Information Commissioner, in
> consultation with the Secretary of State, with the consent of the
> Secretary of State."

### 2.6 EU Commission adequacy decision list

URL: https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/adequacy-decisions_en
(accessed 2026-06-07; operator mirrors HTML to
`docs/sources/adequacy-decisions-2026-06-07.html`).

As of the access date the European Commission has recognised the
following third countries (and territories / sectors) as providing
adequate protection:

> "The European Commission has so far recognised Andorra, Argentina,
> Canada (commercial organisations), Faroe Islands, Guernsey, Israel,
> Isle of Man, Japan (private sector organisations), Jersey, New
> Zealand, Republic of Korea, Switzerland, the United Kingdom under
> the GDPR and the LED, the United States (commercial organisations
> participating in the EU-US Data Privacy Framework) and Uruguay as
> providing adequate protection."

The **EU-US Data Privacy Framework** adequacy decision was adopted
10 July 2023 (Commission Implementing Decision (EU) 2023/1795). U.U4
treats US destinations as **adequate** when AND ONLY when the
importer self-certifies on the DPF list (data file
`cloud-evidence/data/dpf-self-certified-importers.json`, refreshed
from https://www.dataprivacyframework.gov by
`scripts/fetch-dpf-list.mjs`). If the importer is not on the DPF
list, U.U4 falls back to the SCC route and proceeds with the TIA.

### 2.7 FISA Section 702 (the canonical US-destination risk)

Full citation: 50 U.S.C. §1881a — Procedures for targeting certain
persons outside the United States other than United States persons.
URL: https://www.govinfo.gov/content/pkg/USCODE-2022-title50/html/USCODE-2022-title50-chap36-subchapVI-sec1881a.htm
(accessed 2026-06-07; operator mirrors).

> "Notwithstanding any other provision of law, upon the issuance of
> an order in accordance with subsection (j)(3) or a determination
> under subsection (c)(2), the Attorney General and the Director of
> National Intelligence may authorize jointly, for a period of up to
> 1 year from the effective date of the authorization, the targeting
> of persons reasonably believed to be located outside the United
> States to acquire foreign intelligence information."

The CJEU's Schrems II judgment (Schrems II ¶¶180–185) found that
§702 surveillance does not satisfy the EU "essential equivalence"
test for non-US-person communications. U.U4's per-country
risk-finding table for US destinations explicitly cites §702 and
references EO 14086 (President Biden, 7 October 2022; "Enhancing
Safeguards for United States Signals Intelligence Activities") as the
mitigating safeguards underlying the 2023 DPF adequacy decision.

### 2.8 Executive Order 14086 (US — Schrems II mitigations)

URL: https://www.federalregister.gov/documents/2022/10/14/2022-22531/enhancing-safeguards-for-united-states-signals-intelligence-activities
(accessed 2026-06-07; operator mirrors).

Section 2(a)(ii) — the **proportionality limitation** that underpins
the EU Commission's 2023 DPF adequacy decision:

> "Signals intelligence activities shall be conducted only following a
> determination, based on a reasonable assessment of all relevant
> factors, that the activities are necessary to advance a validated
> intelligence priority, although signals intelligence does not have
> to be the sole means available or used for advancing aspects of the
> validated intelligence priority …"

Section 3 — the **two-step redress mechanism** (Civil Liberties
Protection Officer + Data Protection Review Court) that addresses
Schrems II ¶197 (lack of EU-data-subject redress under §702):

> "The Attorney General is authorized to and shall establish a Data
> Protection Review Court to review determinations made by the Civil
> Liberties Protection Officer …"

U.U4's US-destination TIA cites EO 14086 §§2 and 3 as the operative
"changes in US law and practice since Schrems II" element under
Clause 14(b)(ii) of the SCC.

### 2.9 IAB Europe + CNIL guidance on TIA structure

Full citation: French Data Protection Authority (CNIL), *Transfer
Impact Assessment Guide*, 12 January 2022. URL:
https://www.cnil.fr/en/transfer-impact-assessment-tia-guide
(accessed 2026-06-07; operator mirrors).

> "A transfer impact assessment (TIA) is the analysis carried out by
> a data exporter on a case by case basis to assess whether the
> third country recipient of a transfer (data importer) is able to
> comply with the obligations of the transfer tool, in particular
> the SCCs, taking into account local laws and practices, including
> those allowing access by public authorities."

The CNIL guide provides a six-section TIA template that U.U4 mirrors
verbatim in §5.1.

### 2.10 EU Charter of Fundamental Rights Articles 7, 8 and 47

Full citation: Charter of Fundamental Rights of the European Union,
OJ C 326, 26.10.2012, p. 391. URL:
https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:12012P/TXT
(accessed 2026-06-07).

Article 7 — Respect for private and family life:

> "Everyone has the right to respect for his or her private and
> family life, home and communications."

Article 8 — Protection of personal data:

> "1. Everyone has the right to the protection of personal data
> concerning him or her.
> 2. Such data must be processed fairly for specified purposes and
> on the basis of the consent of the person concerned or some other
> legitimate basis laid down by law. Everyone has the right of access
> to data which has been collected concerning him or her, and the
> right to have it rectified.
> 3. Compliance with these rules shall be subject to control by an
> independent authority."

Article 47 — Right to an effective remedy and to a fair trial:

> "Everyone whose rights and freedoms guaranteed by the law of the
> Union are violated has the right to an effective remedy before a
> tribunal in compliance with the conditions laid down in this
> Article."

These three Charter Articles are the constitutional benchmark against
which Schrems II measured §702 (Schrems II ¶¶168, 184, 192) and
against which U.U4 measures every third-country destination.

### 2.11 UK GDPR + Data Protection Act 2018 §17B / §119A

URL: https://www.legislation.gov.uk/ukpga/2018/12/section/119A (DPA
2018 §119A, accessed 2026-06-07) and
https://www.legislation.gov.uk/ukpga/2018/12/section/17B (UK GDPR
adequacy regulations).

§119A(1) of the DPA 2018:

> "The Commissioner may from time to time specify standard data
> protection clauses which the Commissioner considers provide
> appropriate safeguards for the purposes of transfers of personal
> data to a third country or international organisation in reliance
> on Article 46 of the UK GDPR."

The UK Addendum issued under §119A is therefore the legal
instrument U.U4 emits for UK-leg transfers.

## 3. Scope

### 3.1 In scope

- Detection of qualifying cross-border transfers from the U.U2
  `cross-border-transfers.json` envelope (exporter country in EU/EEA
  or UK + importer country in a non-adequate third country).
- Execution of the EDPB Recommendations 01/2020 six-step methodology
  per qualifying transfer, captured in the TIA JSON envelope.
- Per-country risk-finding library for the third countries most
  commonly receiving SaaS-CSP transfers (US, India, Singapore, Brazil,
  Mexico, China, Russia, Australia, Philippines). The library is a
  signed data file at `cloud-evidence/data/country-law-findings.json`
  and is regenerated quarterly via
  `scripts/fetch-country-law-findings.mjs` (see §7).
- Module selection (1, 2, 3, 4) per transfer based on the exporter +
  importer roles (C2C, C2P, P2P, P2C). Default selection by the
  algorithm in §6 Step 7; operator may override.
- `.docx` rendering of the selected SCC Module with the parties'
  particulars populated into Annex I.A, Annex I.B (list of transfers),
  Annex I.C (competent supervisory authority), Annex II (TOMs), and
  Annex III (sub-processors when Module Two/Three).
- UK Addendum `.docx` emission for any transfer where the exporter or
  importer is in the United Kingdom.
- Ed25519 signing of the TIA envelope + RFC 3161 timestamp token via
  the existing LOOP-A.A5 pipeline.
- Tracker DB `cross_border_transfers` table — one row per (transfer,
  module) pair; status state-machine
  (`drafted → sent-to-importer → importer-signed → in-effect →
  re-assessment-due → terminated`).
- Operator notification at TIA-emit time (Slack), at the 12-month
  Step-6 re-assessment trigger (Slack), and at any "trigger event"
  (new third-country law, new CJEU judgment) flagged in the
  country-law-findings catalog.
- Submission-bundle entry registration (new roles: `cross-border-tia`,
  `cross-border-scc-docx`, `cross-border-uk-addendum-docx`).

### 3.2 Out of scope (NOT in U.U4)

- **Transfer detection itself.** Owned by U.U2 (subprocessor +
  data-flow registry). U.U4 trusts the upstream envelope.
- **Adequacy-decision list maintenance.** Owned by
  `scripts/fetch-adequacy-decisions.mjs` (data-engineering tooling,
  not a slice).
- **EU-US Data Privacy Framework certification status of the
  importer.** Maintained in
  `cloud-evidence/data/dpf-self-certified-importers.json` by a
  separate script.
- **Actual transmission of the SCC to the importer for signature.**
  REO Rule 4 forbids; the operator emails / DocuSigns manually.
- **Article 30 record-of-processing-activities (RoPA).** Owned by
  U.U1 (FERPA crosswalk is in the original LOOP-U.U1 scope; the RoPA
  layer lives in LOOP-M).
- **Data Protection Impact Assessment (DPIA) for high-risk
  processing.** Owned by LOOP-M.M3.
- **GDPR Article 33 / 34 breach notification.** Owned by LOOP-G.G2
  (with the CIRCIA extension) and LOOP-M.M4.

## 4. Inputs

### 4.1 U.U2 cross-border-transfers envelope (the trigger)

Path: `out/cross-border-transfers.json`. Schema defined in U.U2 §5.1.
U.U4 reads the following fields per envelope:

```ts
interface U4InputContract {
  schema_version: '1.0.0';
  run_id: string;
  started_at: string;                        // ISO 8601 UTC
  completed_at: string;
  transfers: CrossBorderTransfer[];
  signature: { alg: 'ed25519'; key_id: string; sig: string };
  rfc3161_timestamp?: { tsa_url: string; token: string; received_at: string };
}

interface CrossBorderTransfer {
  transfer_id: string;                       // ULID
  exporter: {
    legal_name: string;
    contact_person: { name: string; role: string; email: string };
    address: string;
    country: string;                          // ISO 3166-1 alpha-2
    role: 'controller' | 'processor';
    competent_supervisory_authority?: string;
  };
  importer: {
    legal_name: string;
    contact_person: { name: string; role: string; email: string };
    address: string;
    country: string;                          // ISO 3166-1 alpha-2
    role: 'controller' | 'processor';
    activities_relevant_to_data: string;
  };
  data_categories: string[];
  special_categories: Array<'health' | 'biometric' | 'genetic' |
    'racial-ethnic-origin' | 'political-opinions' |
    'religious-beliefs' | 'trade-union' | 'sex-life' |
    'criminal-convictions'>;
  data_subjects: string[];
  purpose: string;
  frequency: 'one-off' | 'continuous';
  nature: string;
  retention_period_iso8601: string;           // e.g. P5Y
  onward_transfers: string[];                 // ISO 3166-1 alpha-2 codes
  contract_number?: string;                   // for FedRAMP linkage
}
```

U.U4 **MUST** verify the U.U2 envelope's Ed25519 signature against the
U.U2 signing key before consuming it. A signature-verification failure
exits the U.U4 process with `EnvelopeSignatureInvalidError` and the
process leaves no tracker DB rows behind.

### 4.2 EU Commission adequacy-decision list

Path: `cloud-evidence/data/gdpr-adequacy-decisions.json`. Schema:

```json
{
  "schema_version": "1.0.0",
  "source": "European Commission — adequacy decisions",
  "source_url": "https://commission.europa.eu/law/law-topic/data-protection/international-dimension-data-protection/adequacy-decisions_en",
  "extracted_at": "2026-06-07T12:00:00Z",
  "decisions": [
    { "country_iso2": "AD", "scope": "country", "decision_ref": "2010/625/EU", "in_force_from": "2010-10-19" },
    { "country_iso2": "AR", "scope": "country", "decision_ref": "2003/490/EC", "in_force_from": "2003-06-30" },
    { "country_iso2": "CA", "scope": "commercial-organisations", "decision_ref": "2002/2/EC", "in_force_from": "2002-01-04" },
    { "country_iso2": "FO", "scope": "country", "decision_ref": "2010/146/EU", "in_force_from": "2010-03-09" },
    { "country_iso2": "GG", "scope": "country", "decision_ref": "2003/821/EC", "in_force_from": "2003-12-21" },
    { "country_iso2": "IL", "scope": "country", "decision_ref": "2011/61/EU", "in_force_from": "2011-02-01" },
    { "country_iso2": "IM", "scope": "country", "decision_ref": "2004/411/EC", "in_force_from": "2004-04-30" },
    { "country_iso2": "JP", "scope": "private-sector", "decision_ref": "2019/419", "in_force_from": "2019-01-23" },
    { "country_iso2": "JE", "scope": "country", "decision_ref": "2008/393/EC", "in_force_from": "2008-05-26" },
    { "country_iso2": "NZ", "scope": "country", "decision_ref": "2013/65/EU", "in_force_from": "2013-04-19" },
    { "country_iso2": "KR", "scope": "country", "decision_ref": "2022/254", "in_force_from": "2021-12-17" },
    { "country_iso2": "CH", "scope": "country", "decision_ref": "2000/518/EC", "in_force_from": "2000-08-25" },
    { "country_iso2": "GB", "scope": "country", "decision_ref": "2021/1772", "in_force_from": "2021-06-28" },
    { "country_iso2": "US", "scope": "dpf-self-certified", "decision_ref": "2023/1795", "in_force_from": "2023-07-10" },
    { "country_iso2": "UY", "scope": "country", "decision_ref": "2012/484/EU", "in_force_from": "2012-08-21" }
  ],
  "signature": { "alg": "ed25519", "key_id": "TBD", "sig": "TBD" }
}
```

Refreshed quarterly via `scripts/fetch-adequacy-decisions.mjs`. The
W.W3 clock-style pattern applies: the W.W3 federal-business-day
calendar is fetched annually; the adequacy list is fetched quarterly
because adequacy decisions can be invalidated by CJEU judgments at
any time (see Schrems II invalidating Privacy Shield).

### 4.3 EU-US Data Privacy Framework self-certification list

Path: `cloud-evidence/data/dpf-self-certified-importers.json`.
Refreshed weekly via `scripts/fetch-dpf-list.mjs`. Schema:

```json
{
  "schema_version": "1.0.0",
  "source_url": "https://www.dataprivacyframework.gov/list",
  "extracted_at": "2026-06-07T00:00:00Z",
  "organizations": [
    {
      "organization_name": "Example Importer LLC",
      "dpa_url": "https://www.dataprivacyframework.gov/...",
      "certification_status": "Active",
      "certification_date": "2024-08-15",
      "next_review_date": "2025-08-15",
      "frameworks": ["EU-US-DPF", "UK-Extension", "Swiss-US-DPF"]
    }
  ]
}
```

### 4.4 Country-law risk-finding catalog

Path: `cloud-evidence/data/country-law-findings.json`. Operator
maintains. Schema sketch:

```ts
interface CountryLawFinding {
  country_iso2: string;
  effective_date: string;
  legal_instruments: Array<{
    name: string;                     // e.g. 'FISA Section 702'
    citation: string;                 // e.g. '50 U.S.C. §1881a'
    url: string;
    summary: string;
    schrems_ii_relevance: 'high' | 'moderate' | 'low' | 'mitigated';
    mitigations?: string[];           // e.g. 'EO 14086 §2 + §3 (US)'
  }>;
  edpb_findings?: string[];
  cjeu_findings?: string[];
  national_dpa_findings?: string[];
  last_reviewed: string;
  next_review_due: string;
}
```

### 4.5 Operator configuration

```yaml
cross_border:
  org_role_default: controller             # | processor
  signing:
    counsel_signing_officer_name: REQUIRES-OPERATOR-INPUT
    counsel_signing_officer_title: REQUIRES-OPERATOR-INPUT
    ed25519_signing_key_ref: REQUIRES-OPERATOR-INPUT
  supplementary_measures_default_set:
    technical:
      - aes-256-gcm-at-rest
      - tls-1.3-in-transit
      - pseudonymisation-at-import
    contractual:
      - warrant-canary
      - prohibition-on-onward-non-adequate-transfers
    organisational:
      - data-residency-by-region
      - local-counsel-review
  re_assessment_cadence_months: 12
  notification_channels:
    - slack:#cross-border-transfers
```

## 5. Outputs

### 5.1 Canonical TIA JSON envelope

Path: `out/cross-border-tia/<transfer_id>.tia.json`.

```ts
interface CrossBorderTIA {
  schema_version: '1.0.0';
  transfer_id: string;
  tia_id: string;                            // ULID
  generated_at: string;
  csp_name: string;
  csp_role: 'controller' | 'processor';
  transfer_ref: { path: string; sha256: string; transfer_id: string };

  // EDPB 6-step record
  step_1_know_your_transfer: {
    exporter_party: ExporterParty;
    importer_party: ImporterParty;
    data_categories: string[];
    special_categories: string[];
    data_subjects: string[];
    purpose: string;
    frequency: 'one-off' | 'continuous';
    retention_period_iso8601: string;
    onward_transfers: string[];
  };
  step_2_transfer_tool: {
    instrument: 'eu-scc-2021-914' | 'uk-addendum-b10' | 'uk-idta' |
                'bcr' | 'derogation';
    module: 1 | 2 | 3 | 4;
    docking_clause_in_use: boolean;
  };
  step_3_third_country_assessment: {
    country_iso2: string;
    adequacy_status: 'adequate' | 'partial-adequate' | 'non-adequate';
    adequacy_decision_ref?: string;
    findings: Array<{
      legal_instrument: string;
      citation: string;
      schrems_ii_relevance: string;
      essential_equivalence: 'meets' | 'partially-meets' | 'does-not-meet';
    }>;
    cjeu_judgments_considered: string[];   // e.g. ['C-311/18']
    edpb_findings_considered: string[];    // e.g. ['Rec-01/2020']
  };
  step_4_supplementary_measures: {
    technical: string[];
    contractual: string[];
    organisational: string[];
    residual_risk: 'acceptable' | 'requires-additional-measures' |
                   'do-not-transfer';
    residual_risk_justification: string;
  };
  step_5_procedural_steps: {
    dpia_required: boolean;
    dpia_ref?: string;
    article_36_consultation_required: boolean;
    article_36_consultation_ref?: string;
  };
  step_6_re_evaluation: {
    next_review_due: string;                 // ISO 8601 date
    review_trigger_events: string[];         // e.g. ['new-CJEU-judgment', 'change-in-importer-law']
  };

  // The SCC document linkage
  scc_module_docx_ref: { path: string; sha256: string };
  uk_addendum_docx_ref?: { path: string; sha256: string };

  // Officer attestation
  signing_officer: { name: string; title: string; key_id: string; key_version: string };

  provenance: {
    emitter: 'cross-border-tia';
    emitter_version: string;
    emitted_at: string;
    source_calls: Array<{ kind: string; path: string; sha256: string }>;
  };
  signature: { alg: 'ed25519'; key_id: string; sig: string };
  rfc3161_timestamp: { tsa_url: string; token: string; received_at: string };
}
```

### 5.2 SCC `.docx` (Modules 1, 2, 3, 4)

Path: `out/cross-border-tia/<transfer_id>.scc-module-<n>.docx`.

OOXML/zip-store rendering of Commission Implementing Decision (EU)
2021/914 Annex. Layout:

- Cover page citing 2021/914 and the selected Module.
- Section I — Clauses 1–5 verbatim from the OJ text.
- Section II — Clauses 6–13 (parties' obligations) per Module.
- Section III — Clauses 14–17 (local laws + supervisory authority).
- Section IV — Clauses 18 (governing law) and Annex I.C
  (competent SA).
- **Annex I.A** — Parties (auto-populated from `step_1`).
- **Annex I.B** — Description of the transfer (auto-populated).
- **Annex I.C** — Competent supervisory authority.
- **Annex II** — Technical and organisational measures
  (auto-populated from `step_4`).
- **Annex III** — Sub-processors list (auto-populated when Module 2
  or 3).
- Signature block at end of each Module.

Implementation: `core/sccs-template-renderer.ts` (OOXML/zip-store
helper). The renderer reuses the OOXML helpers from
`core/inventory-workbook.ts` (zip-store, document.xml, styles.xml,
numbering.xml).

### 5.3 UK Addendum `.docx`

Path: `out/cross-border-tia/<transfer_id>.uk-addendum.docx`.

OOXML rendering of the UK ICO IDTA Version B1.0. Layout:

- Cover page citing DPA 2018 §119A and Version B1.0 in-force date
  21 March 2022.
- Section 1 Table 1 — Parties.
- Section 1 Table 2 — Selected SCCs, Modules, Selected Clauses
  (carries forward the Module choice from §5.2).
- Section 1 Table 3 — Appendix Information.
- Section 1 Table 4 — Ending this Addendum when the Approved
  Addendum Changes.
- Section 2 — Mandatory Clauses (verbatim from ICO B1.0).
- Signature block.

### 5.4 Tracker DB row

Schema (migration `0046_cross_border_transfers.sql`):

```sql
CREATE TABLE cross_border_transfers (
  id                              UUID PRIMARY KEY,
  run_id                          TEXT NOT NULL,
  transfer_id                     TEXT NOT NULL,
  tia_id                          TEXT NOT NULL UNIQUE,
  exporter_country                TEXT NOT NULL,
  importer_country                TEXT NOT NULL,
  exporter_role                   TEXT NOT NULL,
  importer_role                   TEXT NOT NULL,
  scc_module                      INT NOT NULL CHECK (scc_module IN (1,2,3,4)),
  uk_addendum_in_use              BOOLEAN NOT NULL DEFAULT FALSE,
  adequacy_status                 TEXT NOT NULL,
  residual_risk                   TEXT NOT NULL,
  status                          TEXT NOT NULL DEFAULT 'drafted',
  next_review_due                 DATE NOT NULL,
  tia_path                        TEXT NOT NULL,
  scc_docx_path                   TEXT NOT NULL,
  uk_addendum_docx_path           TEXT,
  signing_key_id                  TEXT NOT NULL,
  signing_key_version             TEXT NOT NULL,
  signing_officer_name            TEXT NOT NULL,
  signing_officer_title           TEXT NOT NULL,
  created_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_cbt_run_id ON cross_border_transfers(run_id);
CREATE INDEX idx_cbt_next_review ON cross_border_transfers(next_review_due);
CREATE UNIQUE INDEX idx_cbt_idempotency
  ON cross_border_transfers(run_id, transfer_id);
```

### 5.5 Submission-bundle entries

New roles in `core/submission-bundle.ts::WELL_KNOWN`:

```ts
{ role: 'cross-border-tia',
  filename: 'cross-border-tia/*.tia.json',
  description: 'Transfer Impact Assessment per EDPB Recommendations 01/2020 (LOOP-U.U4)' },
{ role: 'cross-border-scc-docx',
  filename: 'cross-border-tia/*.scc-module-*.docx',
  description: 'Commission SCCs (2021/914) populated per Module (LOOP-U.U4)' },
{ role: 'cross-border-uk-addendum-docx',
  filename: 'cross-border-tia/*.uk-addendum.docx',
  description: 'UK ICO International Data Transfer Addendum B1.0 (LOOP-U.U4)' },
```

## 6. Algorithm / Steps

### Phase A — Bootstrap

1. **Parse CLI flag** `--cross-border-tia` (or env
   `CLOUD_EVIDENCE_CROSS_BORDER_TIA`). If neither set, the U.U4 module
   is a no-op for the orchestrator run.
2. **Load operator configuration** (`config.yaml::cross_border.*`).
   Refuse to run if `signing.counsel_signing_officer_name` or
   `signing.ed25519_signing_key_ref` carries `REQUIRES-OPERATOR-INPUT`.
3. **Load adequacy-decision list** from
   `cloud-evidence/data/gdpr-adequacy-decisions.json` and verify
   signature. Load **DPF self-certified importers** from
   `dpf-self-certified-importers.json` similarly. Load
   **country-law-findings** catalog.
4. **Sign-test the corporate counsel signing key** via
   `core/sign.ts::testSign(key_ref)`. Failure → exit 2.

### Phase B — Ingest U.U2 envelope

5. **Locate U.U2 envelope.** Default path
   `out/cross-border-transfers.json`. Operator may override via
   `--u2-envelope-path`.
6. **Verify U.U2 signature** via `core/sign.ts::verifyEnvelope`.
   Failure → exit 2 with `EnvelopeSignatureInvalidError`.
7. **Verify RFC 3161 token** (warn but do not block on failure).

### Phase C — Per-transfer evaluation

For each `transfer` in `transfers[]`:

8. **Determine adequacy status.**
   ```
   isAdequate(importer_country, importer):
     decision = adequacy.lookup(importer_country)
     if !decision: return 'non-adequate'
     if decision.scope === 'country' || decision.scope === 'private-sector':
       return 'adequate'
     if decision.scope === 'dpf-self-certified':
       return dpf.includes(importer.legal_name) ? 'adequate' : 'non-adequate'
     if decision.scope === 'commercial-organisations':
       return 'partial-adequate'    // operator confirms commerce nexus
   ```
9. **Skip-or-continue.** If `isAdequate === 'adequate'`, U.U4 emits
   only a thin "no TIA required — adequate destination" diagnostic
   envelope and continues. If `'non-adequate'` or `'partial-adequate'`,
   U.U4 proceeds to Step 10.
10. **Select SCC Module** based on exporter/importer roles:
    | exporter | importer | Module |
    |----------|----------|--------|
    | controller | controller | 1 |
    | controller | processor | 2 |
    | processor  | processor | 3 |
    | processor  | controller| 4 |
11. **Decide docking-clause use.** Multi-party transfers (≥ 3 parties)
    set `docking_clause_in_use = true`; populate a docking-clause
    annex.
12. **Decide UK Addendum.** If `exporter.country === 'GB'` or
    `importer.country === 'GB'`, emit the UK Addendum alongside the
    SCC `.docx`.

### Phase D — EDPB six-step record

13. **Step 1 — Know your transfer.** Copy from `transfer.*`.
14. **Step 2 — Transfer tool.** Populate from the Phase C selection.
15. **Step 3 — Third-country assessment.** For the importer country,
    walk `country-law-findings.json` and emit the `findings[]` array
    verbatim. If the country has no entry in the catalog, emit a
    `REQUIRES-OPERATOR-INPUT` diagnostic and refuse to finalise the
    TIA until the operator commits a country entry.
16. **Step 4 — Supplementary measures.** Start from
    `config.yaml::cross_border.supplementary_measures_default_set`.
    Allow the operator to override per-transfer via the tracker UI
    (the tracker UI presents the EDPB Recommendations 01/2020 Annex 2
    taxonomy as a checklist; selected items copy into the TIA).
17. **Step 5 — Procedural steps.** If the transfer carries any
    special-category data OR is a continuous transfer of behavioural
    monitoring data, mark `dpia_required = true` and link the
    LOOP-M.M3 DPIA reference if present.
18. **Step 6 — Re-evaluation cadence.** `next_review_due =
    generated_at + cross_border.re_assessment_cadence_months`. Trigger
    events from `country-law-findings.json` per importer country are
    cached for the tracker daemon to fire upon detection.

### Phase E — Compose + sign

19. **Compose canonical TIA JSON** per §5.1 with stable key order, LF
    newlines, no trailing whitespace. Compute SHA-256 of canonicalised
    bytes.
20. **Render SCC `.docx`** via
    `core/sccs-template-renderer.ts::renderModule(module, params)`
    populating Annex I.A / I.B / I.C / II / III as appropriate.
21. **Render UK Addendum `.docx`** when applicable.
22. **Compose envelope provenance** with the source-file hashes
    (adequacy list, DPF list, country-law catalog, U.U2 envelope,
    config.yaml, org-profile.yaml).
23. **Sign envelope** via `core/sign.ts::signEnvelope(env, key_ref)`;
    pin `signing_officer.key_version` at compose time.
24. **Attach RFC 3161 token** via
    `core/timestamp.ts::stampEnvelope(env)`. TSA outage → warn (do
    not block); attach later via background job.

### Phase F — Persist + notify

25. **Insert tracker DB row** into `cross_border_transfers`.
    Idempotency via `(run_id, transfer_id)`.
26. **Append to submission bundle** via
    `core/submission-bundle.ts::registerArtifact(role, path)` for the
    TIA JSON, SCC `.docx`, and (optional) UK Addendum `.docx`.
27. **Emit notification** via
    `core/notify.ts::send(channels, 'cross-border-tia-emitted', { tia_id, transfer_id, residual_risk })`.

### Phase G — Re-assessment scheduling

28. **For each emitted TIA**, insert a row into
    `tracker.scheduled_notifications` with
    `fire_at = next_review_due - 30d` and template
    `cross-border-tia-review-due`. The tracker daemon also subscribes
    to the country-law-findings catalog and fires
    `cross-border-tia-trigger-event` notifications when a new entry
    is appended (e.g. a new CJEU judgment).

### Phase H — Coverage + validation

29. Append `out/inventory-coverage.json` with a
    `cross_border_tia_coverage` block:
    ```json
    { "tias_emitted_this_run": 4, "tias_already_present": 1,
      "transfers_to_adequate_destinations_skipped": 2,
      "tias_requiring_operator_input": 0 }
    ```
30. `npm run check:provenance`, `npm run lint:no-stubs`,
    `npm run check:reo` (G1+G2+G3), `npm run typecheck`, and all 16
    tests in §8 must pass.

## 7. Files to create / modify

### Files to CREATE

1. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/cross-border-tia.ts`
   — main module orchestrating Phases A–H. ~600 lines.
2. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/sccs-template-renderer.ts`
   — OOXML/zip-store renderer for the four SCC Modules + UK Addendum.
   ~700 lines.
3. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/transfer-impact-assessor.ts`
   — six-step EDPB Recommendations 01/2020 evaluator; pure functions
   over `CountryLawFinding` + `CrossBorderTransfer`. ~400 lines.
4. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/adequacy-decisions.ts`
   — Ajv-validated loader for `gdpr-adequacy-decisions.json`. ~120
   lines.
5. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/dpf-list.ts`
   — Ajv-validated loader for `dpf-self-certified-importers.json`.
   ~120 lines.
6. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/country-law-findings.ts`
   — Ajv-validated loader for the country-law-findings catalog.
   ~140 lines.
7. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/gdpr-adequacy-decisions.json`
   — initial seed (mirrors §4.2); signed.
8. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/dpf-self-certified-importers.json`
   — initial seed (empty array; refreshed by script); signed.
9. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/data/country-law-findings.json`
   — seeded with US, GB, IN, SG, BR, MX, CN, RU, AU, PH; signed.
10. `/Users/kenith.philip/FedRAMP 20x/scripts/fetch-adequacy-decisions.mjs`
    — quarterly fetcher of the Commission adequacy-decision page.
    ~180 lines.
11. `/Users/kenith.philip/FedRAMP 20x/scripts/fetch-dpf-list.mjs`
    — weekly fetcher of dataprivacyframework.gov.
    ~200 lines.
12. `/Users/kenith.philip/FedRAMP 20x/scripts/fetch-country-law-findings.mjs`
    — quarterly fetcher coalescing CJEU + EDPB + national-DPA bulletin
    sources. ~250 lines.
13. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/db/migrations/0046_cross_border_transfers.sql`
    — `CREATE TABLE` + indices.
14. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/cross-border-tia.ts`
    — REST API: `GET /api/cross-border-tia`,
    `GET /api/cross-border-tia/:id`,
    `POST /api/cross-border-tia/:id/mark-importer-signed`,
    `POST /api/cross-border-tia/:id/mark-in-effect`,
    `POST /api/cross-border-tia/:id/mark-terminated`,
    `POST /api/cross-border-tia/:id/trigger-reassessment`. ~320 lines.
15. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/ui/cross-border-tia-pane.tsx`
    — status panel; per-transfer card; EDPB six-step checklist;
    supplementary-measures picker; signed-bundle download links;
    importer-signature confirmation form. ~600 lines.
16. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/cross-border-tia.test.ts`
    — see §8 (16 tests).
17. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/sccs-template-renderer.test.ts`
    — OOXML round-trip tests for Modules 1–4 + UK Addendum.
18. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/transfer-impact-assessor.test.ts`
    — pure-function unit tests for the EDPB six-step methodology.
19. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/cross-border-tia/`
    — fixtures: U.U2 envelopes (US importer w/ DPF, US importer w/o
    DPF, GB importer, CN importer); adequacy list; DPF list; country
    findings; expected TIA outputs.

### Files to EXTEND

20. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts`
    — new flag `--cross-border-tia` + env
    `CLOUD_EVIDENCE_CROSS_BORDER_TIA`; runs AFTER U.U2 in the
    orchestrator order; passes its outputs to LOOP-A.A4 bundler.
21. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts`
    — `WELL_KNOWN` adds the three new roles in §5.5.
22. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/inventory-coverage.ts`
    — extend with `cross_border_tia_coverage` section.
23. `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/notify.ts`
    — extend to read the U.U4 templates from a new
    `core/cross-border-tia-notification.ts`.

## 8. Test specifications

| id   | scenario | fixture path | expected | acceptance |
|------|----------|--------------|----------|------------|
| T1   | EU→US transfer where importer is DPF-self-certified | `test/fixtures/cross-border-tia/u2-eu-us-dpf.json` + DPF list containing importer | TIA envelope marks `adequacy_status='adequate'`; emits diagnostic only; no SCC `.docx` | `cross-border-tia.test.ts` asserts envelope shape |
| T2   | EU→US transfer where importer NOT DPF-certified | `test/fixtures/cross-border-tia/u2-eu-us-no-dpf.json` | Full TIA + Module 2 `.docx` emitted; `findings[]` cites FISA §702 + EO 14086 | `transfer-impact-assessor.test.ts` asserts findings array |
| T3   | EU→UK transfer (GB is adequate; no SCC required) | `test/fixtures/cross-border-tia/u2-eu-gb.json` | Diagnostic-only envelope; `adequacy_decision_ref='2021/1772'` | assertion on adequacy_status='adequate' |
| T4   | UK→US transfer (DPF UK-Extension) | `test/fixtures/cross-border-tia/u2-gb-us-dpf-uk-ext.json` | TIA + UK Addendum + Module 2 SCC `.docx` | `sccs-template-renderer.test.ts` UK Addendum present |
| T5   | EU→CN (non-adequate) controller-to-processor | `test/fixtures/cross-border-tia/u2-eu-cn-c2p.json` | TIA + Module 2 SCC `.docx`; findings include PRC Cybersecurity Law Art 37 | findings cited verbatim |
| T6   | EU→IN (non-adequate) processor-to-processor | `test/fixtures/cross-border-tia/u2-eu-in-p2p.json` | TIA + Module 3 SCC `.docx`; Annex III sub-processors block populated | renderer test asserts Module=3 |
| T7   | EU→BR processor-to-controller | `test/fixtures/cross-border-tia/u2-eu-br-p2c.json` | TIA + Module 4 SCC `.docx` | renderer test asserts Module=4 |
| T8   | EU→SG controller-to-controller | `test/fixtures/cross-border-tia/u2-eu-sg-c2c.json` | TIA + Module 1 SCC `.docx` | renderer test asserts Module=1 |
| T9   | Country missing from `country-law-findings.json` (e.g. EU→MZ Mozambique) | `test/fixtures/cross-border-tia/u2-eu-mz.json` | TIA envelope flagged `requires_operator_input.country_law_findings`; refuses to finalise | `transfer-impact-assessor.test.ts` asserts diagnostic |
| T10  | Special-category data (health) triggers DPIA flag | `test/fixtures/cross-border-tia/u2-eu-us-health.json` | TIA `step_5.dpia_required=true` | assertion on step_5 |
| T11  | Multi-party docking clause (≥3 parties) | `test/fixtures/cross-border-tia/u2-multi-party.json` | TIA `step_2.docking_clause_in_use=true`; docking-clause annex rendered | renderer test asserts docking section |
| T12  | Idempotency — same (run_id, transfer_id) only emits one TIA | re-run with pre-seeded DB row | second run logs `coverage:cross-border-tia:duplicate-skipped:1`; zero new files | DB row count unchanged |
| T13  | Ed25519 signature verifies against the configured public key | (any fixture) | `verifyEnvelope(env, pubkey) === true` | sign.test reuses existing harness |
| T14  | RFC 3161 token attached and valid | (any fixture; TSA stubbed) | `verifyTimestampToken(token) === true` | timestamp.test reuses |
| T15  | `.docx` unpacks and contains required `word/document.xml` + signature placeholder + Annex II TOMs section | (any fixture) | `unzipSync(buf)['word/document.xml']` present; bookmark `signature-placeholder` + heading 'Annex II' present | renderer.test.ts unzip assertion |
| T16  | Tracker DB row written with correct `next_review_due`, `status='drafted'`, `signing_key_version` pinned, idempotency unique-index honoured | (any fixture) | `SELECT * FROM cross_border_transfers WHERE tia_id=...` returns row matching emitted envelope | tracker integration test |
| T17  | DPF self-certification expiry — importer cert expires; subsequent run downgrades to non-adequate | DPF list with expired cert | TIA emits Module 2 SCC + UK Addendum if applicable | re-run reproducibility assertion |
| T18  | EDPB-step-6 review-due notification scheduled at `next_review_due - 30d` | (any fixture) | row in `scheduled_notifications` with `fire_at = next_review_due - 30d` and template `cross-border-tia-review-due` | integration test |
| T19  | New CJEU judgment appended to `country-law-findings.json` fires trigger-event notification | catalog mutation fixture | tracker daemon sends `cross-border-tia-trigger-event` Slack message referencing affected TIAs | integration test |
| T20  | Cross-loop linkage — LOOP-A.A4 submission bundle includes the TIA + SCC `.docx` under the new roles | end-to-end orchestrator run | submission bundle catalogue includes `cross-border-tia`, `cross-border-scc-docx`, optional `cross-border-uk-addendum-docx` entries | bundle.test.ts assertion |

Total: 20 tests (above the §8 minimum of 15). Coverage hits the
adequacy-decision matrix (T1–T8), missing-catalog diagnostic (T9),
special-category routing (T10), docking clause (T11), idempotency
(T12), signing (T13–T14), composition (T15), persistence (T16),
DPF-status drift (T17), re-assessment scheduling (T18), trigger
events (T19), cross-loop bundling (T20).

## 9. Risks

### Risk 1 — Adequacy-decision invalidation between scheduled fetches

**Cause.** The CJEU has invalidated EU-level adequacy decisions twice
in the past decade (Safe Harbor in C-362/14 Schrems I, 2015; Privacy
Shield in C-311/18 Schrems II, 2020). A future Schrems III judgment
could invalidate the EU-US DPF (the matter is already pending before
the CJEU in C-2024/xxx). If U.U4's adequacy list is stale, a transfer
relying on DPF may proceed without an SCC at the moment EU law has
already required one.

**Likelihood.** Moderate over the 12-month horizon.

**Impact.** High — exposing EU data subjects' personal data to a
third country without a valid Article 46 safeguard is a violation
of GDPR Article 44 punishable under Article 83(5) (administrative
fines up to €20 000 000 or 4% of global annual turnover).

**Mitigation.** `scripts/fetch-adequacy-decisions.mjs` runs quarterly
in production. The tracker UI surfaces a "Adequacy list last
refreshed" badge that turns amber at 90 days old and red at 180 days.
The country-law-findings catalog includes a top-level field
`pending_litigation: string[]` so the operator can pre-stage a
TIA for any country whose adequacy is under challenge. When an
adequacy decision is invalidated, the operator runs U.U4 with a
new flag `--re-assess-all` which re-evaluates every active TIA in
the `cross_border_transfers` table.

### Risk 2 — Country-law-findings drift

**Cause.** Third-country surveillance laws change frequently
(e.g. the 2017 PRC Cybersecurity Law; 2021 PRC Data Security Law;
2024 reauthorisation of FISA §702). If
`country-law-findings.json` is stale, the Step 3 essential-equivalence
assessment is based on the wrong legal landscape.

**Likelihood.** High over the 12-month horizon — at least 2–3 affected
countries change laws materially per year.

**Impact.** Moderate — under Clause 14(b) the parties must consider
"the laws and practices of the third country of destination …
relevant in light of the specific circumstances of the transfer".
A stale finding could materially understate residual risk.

**Mitigation.** `scripts/fetch-country-law-findings.mjs` runs
quarterly in production; the catalog includes a `last_reviewed` field
per country. The tracker UI surfaces a stale-finding badge per
country. The Step 6 re-evaluation cadence (default 12 months) fires
a re-assessment notification 30 days before due; the operator may
configure shorter cadences for high-risk countries.

### Risk 3 — Operator failure to obtain importer signature within the SCC-effectiveness window

**Cause.** Commission Implementing Decision (EU) 2021/914 Annex Clause
2(b) makes clear the SCCs alone do not ensure GDPR compliance —
they must be executed by both parties to be effective. If the
operator emits a Module 2 SCC `.docx` and the importer never
counter-signs, the transfer continues without a valid Article 46
safeguard.

**Likelihood.** Moderate — depends on operator's contracting cadence.

**Impact.** High — same as Risk 1.

**Mitigation.** The tracker state-machine flags status `drafted` and
escalates to PagerDuty 30 days after emission if not advanced to
`importer-signed`. The TIA envelope's `step_2.transfer_tool` field
records the planned instrument; the envelope's `tia_id` is referenced
in the U.U2 envelope so the operator cannot mark the transfer "live"
without the corresponding `in-effect` SCC status.

### Risk 4 — Module-selection error

**Cause.** The exporter / importer role assignment in the U.U2 envelope
may be wrong (e.g. the operator's General Counsel determines the CSP
is a controller for the transfer, but U.U2 inferred processor). If
U.U4 emits Module 3 when Module 2 is correct, the SCC fails to bind
the right obligations.

**Likelihood.** Low — most roles are stable per relationship.

**Impact.** Moderate — the parties typically catch the error during
signature review; the embarrassment + delay is the cost.

**Mitigation.** The tracker UI presents the inferred module + the
role rationale before sealing the envelope; the operator confirms
the module via a `POST /api/cross-border-tia/:id/confirm-module`
endpoint. If the operator overrides the inference, the TIA envelope
records the override + justification in `step_2.module_override`.

### Risk 5 — Onward-transfer chain not captured

**Cause.** Clause 8.7 of Module 2 (and equivalents in Modules 1, 3, 4)
prohibits onward transfers from the importer to a further third
country unless that further third country itself meets the SCC's
conditions. If the operator's importer outsources data to a
sub-importer in a non-adequate country and U.U4 does not surface
the chain, the operator may be in breach.

**Likelihood.** Moderate (common in SaaS sub-processing).

**Impact.** Moderate to High.

**Mitigation.** The U.U2 envelope's `onward_transfers[]` field is
required input. When non-empty, U.U4 emits a separate Annex III
sub-processor block per onward party and re-runs the Step 3
assessment per onward leg. Onward parties get their own row in the
`cross_border_transfers` table linked via
`parent_transfer_id` (column added in `0047_cross_border_transfers_onward.sql`).

### Risk 6 — UK Addendum form-version drift

**Cause.** The UK ICO may revise the Addendum form (Version B1.0 is
the current version as of 2026-06-07; the ICO's Section 119A power
allows further specifications). If U.U4 emits the B1.0 form after
the ICO has issued a B2.0, the Addendum may not provide Appropriate
Safeguards under section 119A(1).

**Likelihood.** Low — the ICO publicises form revisions well in
advance.

**Impact.** Moderate — re-execution of the Addendum is required.

**Mitigation.** The renderer references the form version as a
configuration constant; the tracker UI surfaces "UK Addendum form
version" and "ICO last-checked date"; `scripts/fetch-uk-addendum.mjs`
runs quarterly to compare local form against the ICO published
PDF byte-hash.

### Risk 7 — Schrems II §702 mitigations contested in litigation

**Cause.** The EU-US Data Privacy Framework adequacy decision is
being challenged in multiple proceedings (e.g. Latombe v. European
Commission, T-553/23). If the General Court (and subsequently the
CJEU) annuls the 2023/1795 decision, every active US transfer
relying on DPF becomes immediately non-adequate.

**Likelihood.** Moderate over the 36-month horizon.

**Impact.** High — same as Risk 1.

**Mitigation.** `country-law-findings.json` records the pending
litigation as a `cjeu_judgments_considered` precursor; the tracker
daemon watches for judgment announcements (operator-supplied RSS
feed in `cross_border.litigation_watch_feeds`) and fires
`cross-border-tia-trigger-event` notifications. Operator may
pre-stage a fallback SCC + supplementary-measures package.

### Risk 8 — Confidentiality of the executed SCC

**Cause.** Once both parties execute the SCC, the document contains
the parties' commercial relationships, data-category list, sub-
processor identities, and (sometimes) trade-secret-grade technical
measures. Loss of the executed SCC PDF (laptop theft, breach of the
tracker DB) is a confidentiality incident.

**Likelihood.** Low.

**Impact.** Moderate — reputational + competitive.

**Mitigation.** The signed envelope is encrypted at rest in the
tracker DB via pgcrypto + KMS data-key envelope. The operator's
counterparty receives the `.docx` over a secure channel (operator
preference); the executed return file is uploaded back into the
tracker via authenticated REST and stored encrypted.

## 10. Open questions

- **Q1 — Treatment of UK→non-adequate destinations: SCC + Addendum, or
  the UK IDTA standalone?** The UK ICO permits either route. Operator's
  General Counsel confirms preferred form per relationship. **Status:
  REQUIRES-OPERATOR-INPUT** (default: SCC + UK Addendum, as it
  composes more cleanly with EU-leg requirements).
- **Q2 — Swiss-US Data Privacy Framework.** Switzerland is on the
  Commission adequacy list; the Federal Data Protection and
  Information Commissioner (FDPIC) treats Swiss-US transfers separately.
  U.U4 currently mirrors EU treatment. **Status: REQUIRES-RESEARCH** to
  confirm whether a distinct Swiss-specific TIA is mandated by FADP.
- **Q3 — Article 49 derogations.** GDPR Article 49 permits transfers
  in the absence of an adequacy decision or appropriate safeguards
  under narrow conditions (explicit consent, contract performance,
  important reasons of public interest, vital interests, etc.). U.U4
  currently does not emit a "derogation" instrument. **Status:
  REQUIRES-OPERATOR-INPUT** — is the operator ever relying on Article
  49 in production? Default: no; if yes, scope a follow-on slice
  U.U5.
- **Q4 — Schrems III timeline.** The pending litigation against the
  DPF (and successor regimes) means operators with US-leg transfers
  should plan for a possible re-emission. **Status: REQUIRES-RESEARCH**
  to subscribe to the General Court docket feed.
- **Q5 — Local-counsel mark-up workflow.** Some operators have the
  importer's local counsel mark up the SCC `.docx` to add a country-
  specific rider (e.g. Indian Digital Personal Data Protection Act
  recitals). The SCC Annex Clause 2(c) permits adding information to
  the Annexes but prohibits modifying the operative Clauses. **Status:
  REQUIRES-OPERATOR-INPUT** for the operator's General Counsel to
  define a mark-up workflow that preserves Clause 2(c) integrity.
- **Q6 — UK Addendum cover-sheet signing convention.** The ICO B1.0
  permits either a single signature on the Addendum (which incorporates
  the SCC by reference) or separate signatures on the Addendum and the
  SCC. **Status: REQUIRES-OPERATOR-INPUT** (default: single signature
  on the Addendum).
- **Q7 — Timing of re-emission when a country-law-findings update
  changes residual risk.** Should U.U4 auto-emit a refreshed TIA
  envelope on catalog update, or wait for the next quarterly review?
  **Status: REQUIRES-OPERATOR-INPUT** (default: auto-emit on any
  high-relevance change; manual re-emit otherwise).

## 11. REQUIRES-OPERATOR-INPUT fields

| Field name | Type | Validator | UI location | Failure mode if missing |
|------------|------|-----------|-------------|--------------------------|
| `counsel_signing_officer_name` | string | non-empty, no control chars | Settings → Compliance → Cross-Border → Signing | Orchestrator refuses `--cross-border-tia` with exit code 2 + `CrossBorderConfigMissingError`. |
| `counsel_signing_officer_title` | string | non-empty, no control chars | Settings → Compliance → Cross-Border → Signing | Same as above. |
| `ed25519_signing_key_ref` | string (KMS resource ARN or GCP KMS resource) | sign-test on startup (`core/sign.ts::testSign(key_ref)`) | Settings → Compliance → Cross-Border → Signing | Orchestrator refuses to run; exit code 2 with `KmsKeyUnavailableError`. |
| `csp_legal_name` | string | non-empty | Settings → Org Profile | TIA envelope cannot identify the CSP party. |
| `csp_address` | string | non-empty | Settings → Org Profile | Required for Annex I.A of the SCC. |
| `csp_role_default` | enum: `controller` \| `processor` | enum validator | Settings → Compliance → Cross-Border | Default to `controller` if missing; tracker UI surfaces amber badge for operator confirmation. |
| `competent_supervisory_authority` | string (e.g. 'CNIL — France') | non-empty | Settings → Compliance → Cross-Border | Required for Annex I.C of the SCC. |
| `re_assessment_cadence_months` | integer (1–24) | range check | Settings → Compliance → Cross-Border | Default to 12. |
| `supplementary_measures_default_set` | structured | JSON-schema validator | Settings → Compliance → Cross-Border → Default TOMs | Default to the EDPB Rec 01/2020 Annex 2 baseline. |
| `uk_addendum_signing_convention` | enum: `single-signature` \| `dual-signature` | enum validator | Settings → Compliance → Cross-Border → UK | Default to `single-signature`. |
| `article_49_derogation_in_use` | boolean | boolean | Settings → Compliance → Cross-Border → Article 49 | Default to `false`; if `true` requires operator narrative. |
| `litigation_watch_feeds` | array of RSS URLs | URL validators | Settings → Compliance → Cross-Border → Litigation Watch | Default to a CSP-curated seed list; warn if empty. |
| `notification_channels` | array of channel refs | channel-ping test | Settings → Notifications | Emit warning at startup; report still emits; banner shown. |
| `tracker_db_kms_data_key_ref` | string | KMS resource validator | Settings → Tracker → Encryption | Default to org's existing tracker DB key (LOOP-A.A4); exit 2 if missing in production. |
| `country_specific_riders` | record<country_iso2, string> | file-path validator | Settings → Compliance → Cross-Border → Country Riders | Default empty; operator may supply per-country mark-up insertions to be added to Annex (preserving Clause 2(c) integrity). |
| `dpf_self_certification_cache_max_age_days` | integer (1–30) | range check | Settings → Compliance → Cross-Border → DPF | Default to 7; warn if >30. |

Total: 16 fields. **5 are blocking** at startup (orchestrator refuses
to run), **5 are soft-warning** (TIA emits with placeholders flagged
in the UI), and **6 are defaulting** to safe values.

## 12. Implementation log

| date | session | action | commit | notes |
|------|---------|--------|--------|-------|
| 2026-06-07 | wf-uvxyz | Specification authored via FedPy workflow | TBD | Per-slice doc proposed under LOOP-U; conditional on U.U2 transfer detection; depends on LOOP-A.A5 signing pipeline; no production code yet. Authoritative sources include CJEU C-311/18, Commission Implementing Decision (EU) 2021/914, GDPR Articles 44/45/46, EDPB Recommendations 01/2020, UK ICO IDTA B1.0, EO 14086, and 50 U.S.C. §1881a (FISA §702). |

## 13. Completion checklist

> The following 7 steps are quoted verbatim from
> `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md`. They are
> MANDATORY for every slice in every loop. NO EXCEPTIONS. Every session
> that ships a slice MUST execute this checklist atomically with the
> slice's own commit.
>
> ### Step 1 — Verify the slice is REO-compliant
> Run all three guardrails. They MUST all be green:
> ```bash
> cd cloud-evidence
> npm run typecheck      # no errors
> npm test               # 100% passing (counts must increase by the slice's new tests)
> npm run check:reo      # G1+G2+G3 all green
> ```
>
> ### Step 2 — Update STATUS.md
> Open `cloud-evidence/docs/STATUS.md` and for the slice that just
> shipped:
> - Change `Status` column from `pending` to `done`
> - Fill `Commit` with the PENDING commit's short hash (you'll know it
>   after step 5)
> - Fill `Date` with today's date (ISO format YYYY-MM-DD)
> - If this was the last slice in a loop, change the loop's title
>   section to indicate "(COMPLETE)"
> - Update the "Overall" section: increment loops-complete, change
>   last-shipped, update next-priority
>
> ### Step 3 — Update the loop's spec doc
> Open `cloud-evidence/docs/loops/LOOP-U-SPEC.md`.
> Find the "Status tracking" section table.
> For your slice row: status=done, commit=<hash>, date=<ISO>.
>
> ### Step 4 — Add CHANGELOG entry
> Open `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`.
> Add a new entry at the TOP of "Unreleased":
>
> ### Added — LOOP-U.U4: Cross-Border Transfer Assessment + SCCs + UK Addendum
> <2-3 paragraphs describing what shipped, module names, file paths,
> verification counts (typecheck clean, NNN/NNN tests passing,
> npm run check:reo returns 0).>
>
> ### Step 5 — Commit
> ```bash
> cd /Users/kenith.philip/FedRAMP\ 20x
> git add cloud-evidence/<modified files> cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-U-SPEC.md CHANGELOG.md
> git commit -m "LOOP-U.U4: Cross-Border Transfer Assessment + SCCs + UK Addendum
> <detailed commit message describing the slice>
> Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
> ```
>
> ### Step 6 — Update commit hash in STATUS.md + loop spec
> Now that the commit exists, get its hash:
> ```bash
> git log -1 --format=%h
> ```
> Open STATUS.md + the loop's spec doc — paste the actual commit hash
> in the rows you updated in step 2+3.
> Amend the commit:
> ```bash
> git add cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-U-SPEC.md
> git commit --amend --no-edit
> ```
>
> ### Step 7 — Push
> ```bash
> git push origin main
> ```
>
> ### Step 8 (U.U4-specific addendum)
> After the commit lands, append/update the U.U4 row in STATUS.md
> (status → done, commit hash, last_updated); update the
> LOOP-U-SPEC.md status table; append a CHANGELOG entry (LOOP-U.U4 —
> Cross-Border Transfer Assessment per CJEU Schrems II + Commission
> Implementing Decision (EU) 2021/914 SCC Modules 1–4 + UK ICO
> International Data Transfer Addendum B1.0); push to origin/main;
> verify with `git log --oneline -3`. Only THEN is U.U4 closed.

REO STANDARD (Rule 1–4) governs every line of production code described
in §7. No invented citations. Apache-2.0 clean-room. All verbatim quotes
in §2 are reproduced from the official sources at the URLs and access
date stated; the implementer is REQUIRED to re-verify each quote
against the live source before declaring the slice done.
