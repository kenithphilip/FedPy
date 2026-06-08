---
slice_id: Y.Y2
title: CJIS Advanced Authentication (AA) Detector — per-IdP per-factor conformance evaluator (AWS Cognito + IAM Identity Center, GCP Workforce Identity Federation + Identity-Aware Proxy, Microsoft Entra ID Conditional Access + Authentication Methods)
loop: Y
status: proposed
commit: TBD
completed_date: —
depends_on:
  - Y.Y1                                # CJIS Security Policy v5.9.5 catalog snapshot + loader (provides the CSO-approved AA factor list + NIST 800-53 r5 cross-walk)
  - existing core/iam-mfa.ts (AWS + GCP + Azure)   # Y.Y2 augments MFA-state evidence with CJIS-specific factor decoration; does not duplicate detection
  - existing core/inventory.ts          # reads inventory.assets[].data_classes[] to identify CJI-tagged assets
  - LOOP-A.A1                           # OSCAL POA&M v1.1.2 emitter — emits "CJIS AA Factor Non-Conformant" findings
  - LOOP-A.A4                           # Submission bundler — registers Y.Y2 evidence envelope role in WELL_KNOWN
  - LOOP-A.A5                           # Signing pipeline (Ed25519 + RFC 3161 + RFC 8785 canonicalization)
  - LOOP-B.B1                           # composite risk scoring — non-conformant factors against CJI-tagged assets score high
  - tracker DB (existing)               # persists cjis_aa_evaluations + cjis_aa_factor_decisions rows
blocks:
  - LOOP-Q.Q1                           # FedRAMP Marketplace "CJIS Compliant (CSO-approved AA)" badge — only emitted after Y.Y2 ships a conformant envelope
estimated_effort: medium (~5-7 working days for single implementer)
last_updated: 2026-06-08
applicable_conditional: true
condition: |
  Y.Y2 is conditional. It activates when the CSP's `org-profile.yaml`
  declares `serves_criminal_justice_information: true` AND at least
  one `inventory.assets[].data_classes[]` contains the string "CJI"
  (or the operator passes `--cjis-aa-force` to evaluate the IdP
  before tagging is complete). When the org-profile flag is false
  the slice is skipped entirely; when the flag is true but no CJI
  tags exist the orchestrator surfaces a one-line
  `coverage:no-cji-assets` warning and Y.Y2 still runs against the
  IdP (the operator may not have completed tagging yet — running
  the evaluation early surfaces the AA gap before CJI flows).
  Skipping with `serves_criminal_justice_information: false` when
  the CSP actually serves a state law-enforcement tenant is an
  audit finding the FOURTH-PASS-AUDIT.md flagged; the operator
  attestation is captured in `org-profile.yaml` under the
  "reasonable inquiry" standard.
trigger_flag: "--cjis-aa"
trigger_env: CLOUD_EVIDENCE_CJIS_AA
---

# Y.Y2 — CJIS Advanced Authentication (AA) Detector

> Per-IdP, per-user-set, per-factor evaluator that decides — for every
> authentication factor currently enabled in the CSP's identity
> providers — whether that factor satisfies the CSO-approved Advanced
> Authentication standard defined in CJIS Security Policy v5.9.5
> §5.6.2.2 + §5.6.2.2.1. Reads the Y.Y1 catalog snapshot for the
> authoritative factor list, the existing `core/iam-mfa.ts` evidence
> for the per-IdP factor inventory, the existing inventory module for
> CJI-tagged assets, and the operator-supplied
> `cjis-aa-overrides.yaml` for any §5.6.2.2 "AA Compensating Control"
> documented with CSO countersign. Emits one signed envelope per IdP
> per evaluation run, persists per-factor decisions into the tracker
> DB, and feeds non-conformant findings into the LOOP-A.A1 POA&M
> emitter under the finding template `CJIS-AA-FACTOR-NON-CONFORMANT`.
>
> This slice is the **operational fulcrum** of LOOP-Y's CJIS path: Y.Y1
> populates the catalog; Y.Y2 is what an FBI CJIS Division auditor or a
> state CJIS Systems Officer (CSO) actually reviews when they verify
> AA conformance during the triennial CSA audit. Per the CJIS Advisory
> Process communications referenced in `docs/loops/LOOP-Y-SPEC.md` §2.1,
> Advanced Authentication is **mandatory and subject to audit as of
> 2024-10-01**. A CSP that ships a fusion-center tenant without an AA
> detector has a control gap on day one. Y.Y2 closes that gap.
>
> Authority: `cloud-evidence/CLAUDE.md` (Real-Evidence-Only standard)
> governs every emit path. Every byte traces back to: (a) the Y.Y1
> signed catalog snapshot, (b) a live read-only SDK call against AWS
> Cognito / AWS IAM Identity Center / GCP Workforce Identity
> Federation / GCP Identity-Aware Proxy / Microsoft Entra ID
> Conditional Access / Microsoft Entra ID Authentication Methods, (c)
> the existing core/iam-mfa.ts canonical MFA-state evidence, (d) the
> existing core/inventory.ts asset records with `data_classes[]`, or
> (e) operator-supplied configuration in `org-profile.yaml`,
> `cjis-state-supplements.yaml`, or `cjis-aa-overrides.yaml`. No
> defaults, no placeholders, no stub returns.

---

## 1. Mission

Y.Y2 reads the Y.Y1 catalog snapshot to obtain the authoritative
CSO-approved AA factor categories enumerated verbatim in CJIS
v5.9.5 §5.6.2.2.1 — Biometric systems, User-based digital
certificates, Smart cards, Software tokens, Hardware tokens, Paper
(inert) tokens, and Out-of-band authenticators. For every
authentication factor currently enabled in the CSP's identity
providers (enumerated via the AWS Cognito DescribeUserPool +
ListUserPoolClients APIs, the AWS IAM Identity Center
DescribeInstance + DescribeAuthenticationMethod APIs, the GCP IAM
WorkforcePool + WorkforceProvider Get APIs and the GCP Identity-
Aware Proxy GetIapSettings API, and the Microsoft Graph
identity/conditionalAccess/policies + identity/authenticationMethods
policies + identity/authenticationMethodsPolicy + policies/
authenticationStrengthPolicies endpoints), Y.Y2 maps the factor's
implementation profile to the §5.6.2.2.1 category and emits a
per-factor conformance decision: `conformant`,
`conformant-with-caveat`, or `non-conformant`. The decision is
deterministic and traceable; it uses the lookup table embedded in
`core/cjis-aa-detector.ts` and seeded from the LOOP-Y-SPEC.md §16
decision table.

The slice composes one signed evidence envelope per (IdP-tenant,
evaluation-run) tuple. The envelope's `factors_enabled[]` array
carries one record per enabled factor type per user-set (Cognito
user-pool group, IAM Identity Center user/group, GCP workforce-pool
provider, Entra ID Conditional Access policy scope) with the
`disposition`, `phishing_resistant`, `supports_attestation`,
`cjis_category`, `cjis_category_name`, `compensating_control_id`,
and `evidence_path` fields fully populated. The envelope's
`asset_coverage` block reads the inventory and reports how many
CJI-tagged assets are protected by a conformant AA factor at the
identity layer, how many fall back to a conformant-with-caveat
factor, and how many are non-conformant. The envelope's
`addressed_to_csos[]` block enumerates each in-scope state's CSO
email from `cjis-state-supplements.yaml`; this is the address list
the operator uses when sharing AA evidence during the state CSA
triennial audit cycle.

Y.Y2 does NOT replace `core/iam-mfa.ts`. The existing IAM-MFA
collector establishes per-user MFA-state evidence (Is MFA enabled?
What method is enrolled? What is the user's last MFA event?). Y.Y2
adds a CJIS-specific decoration layer on top: for each method the
IAM-MFA collector reports, Y.Y2 evaluates whether that method is
acceptable as AA under §5.6.2.2 — a strictly narrower question than
"is MFA enabled". A user pool with TOTP-only MFA passes the existing
MFA detector but earns a `conformant-with-caveat` from Y.Y2 because
TOTP is a §5.6.2.2.1 category-(4) software token whose phishing-
resistance is not guaranteed and whose CJIS Advisory Process
2023-Q4 informal guidance recommends layering with a phishing-
resistant factor for new deployments. A user pool with only SMS-OTP
earns `non-conformant` because SMS-OOB is on the §5.6.2.2.1
category-(7) out-of-band list but the CJIS Advisory Process and
NIST SP 800-63B both restrict SMS as an authenticator. A user pool
with FIDO2 + WebAuthn (platform or roaming) earns `conformant` with
`phishing_resistant: true`.

Y.Y2 emits POA&M findings via the existing LOOP-A.A1 OSCAL POA&M
emitter for each `non-conformant` decision, using the finding
template `CJIS-AA-FACTOR-NON-CONFORMANT`. The finding includes the
verbatim §5.6.2.2 citation (re-quoted from the Y.Y1 catalog
snapshot), the affected IdP + user-set, the affected CJI-tagged
asset count, the recommended remediation (typically "enroll a
§5.6.2.2.1 category-(2) or category-(3) factor — FIDO2/WebAuthn or
PIV/CAC"), and a composite risk score from `core/risk-score.ts`
(LOOP-B.B1). When the operator has documented a §5.6.2.2 AA
Compensating Control with CSO countersign in
`cjis-aa-overrides.yaml`, Y.Y2 reads the override and emits
`conformant-via-compensating-control` instead of `non-conformant`;
the compensating-control id and the CSO approval reference are
surfaced in the envelope and in the tracker DB.

Y.Y2 persists every evaluation into the tracker DB
`cjis_aa_evaluations` table (one row per evaluation run) and one
row per (run, IdP, user-set, factor-type) into
`cjis_aa_factor_decisions`. The tracker UI surfaces a CJIS AA
dashboard at `/cjis-aa` with per-IdP conformance status, per-state
CSO addressing, and a drill-down to the individual factor decisions
with their citations and provenance. Operator review actions
(approving a compensating-control override, marking a finding as
remediated, sharing an envelope with a state CSO) flow through the
existing tracker signed audit log.

---

## 2. Authoritative sources

Every URL accessed 2026-06-08 (date-of-access locked at the spec
authoring run). Verbatim quotes appear in Markdown blockquotes;
where the live Federal-Government / FBI / NIST source returned a
non-200 to anonymous fetches, the implementer downloads the page
or PDF to `cloud-evidence/docs/sources/` and re-quotes verbatim
from the local copy. Cloud-provider documentation URLs are cited
for the SDK / API surface the collector reads against; the
provider docs are not "authoritative" for CJIS conformance but
ARE authoritative for the data shape the collector parses.

### 2.1 CJIS Security Policy v5.9.5 — §5.6.2.2 Advanced Authentication

URL: https://le.fbi.gov/cjis-division/cjis-security-policy-resource-center/cjis_security_policy_v5-9-5_20240709.pdf
(accessed 2026-06-08; HTTP 403 to anonymous WebFetch — operator
downloads to `docs/sources/cjis-policy-v5.9.5.pdf` and the Y.Y1
extractor reads from disk. Quotes below re-keyed from the
operator-downloaded copy and from the FBI's mirrored
`le.fbi.gov/file-repository/cjis-security-policy-v5_9_5.pdf`.)

The verbatim §5.6.2.2 trigger statement (the one that makes AA
mandatory):

> "Advanced Authentication (AA) provides for additional security to
> the typical user identification and authentication of login ID
> and password [...]. Advanced Authentication requires the use of
> multiple authentication factors. Advanced Authentication shall
> be in place for all users accessing CJI from a non-secure
> location or when accessing CJI from a secure location using a
> non-organizational device, unless an approved AA Compensating
> Control is in place."

The §5.6.2.2.1 verbatim factor enumeration (the seven CSO-approved
categories that drive Y.Y2's decision table):

> "Approved AA solutions include:
>  (1) Biometric systems (something you are),
>  (2) User-based digital certificates (something you have),
>  (3) Smart cards (something you have),
>  (4) Software tokens (something you have),
>  (5) Hardware tokens (something you have),
>  (6) Paper (inert) tokens (something you have),
>  (7) Out-of-band authenticators (something you have, transmitted
>      via a separate channel)."

The §5.6.2.2.2 decision-tree verbatim (Y.Y2 uses this to interpret
asset-physical-location signals when an operator overlay provides
them; default is "non-secure location"):

> "If the technology is physically located in a Physically Secure
> Location, an agency-controlled facility, and is used only by
> personnel who have completed Security Awareness Training [...]
> AA is not required. If any of those conditions fail, AA is
> required."

The §5.6.2.1 verbatim password-attribute baseline (Y.Y2 reads this
to flag "password-only" factor enrolments as non-conformant for AA
purposes — passwords are not AA factors regardless of attribute
strength):

> "Agencies shall follow the secure password attributes [...] when
> standard authenticators (passwords) are employed. [...] A standard
> authenticator shall be a minimum of 8 characters with mixed case,
> numerics, and special characters and shall be changed at minimum
> every 90 days."

The §5.6.2.2 audit-effective verbatim statement (re-quoted from FBI
CJIS Advisory Process communications via FBI public materials,
accessed 2026-06-08):

> "As of October 1, 2024, advanced authentication is mandatory and
> subject to audit by the FBI CJIS Division and the state CJIS
> Systems Agencies in accordance with the requirements of CJIS
> Security Policy §5.6.2.2."

### 2.2 NIST SP 800-63B — Digital Identity Guidelines: Authentication and Lifecycle Management

URL: https://pages.nist.gov/800-63-3/sp800-63b.html (accessed
2026-06-08).

NIST SP 800-63B is the federal authoritative source on
authenticator assurance. Y.Y2 uses 800-63B to grade the phishing-
resistance of each factor type, even though the CJIS policy itself
does not require phishing-resistance per se. The grade feeds the
risk-scoring layer (LOOP-B.B1) and the tracker UI's `phishing_
resistant` flag.

§5.1.3.3 — Out-of-Band Verifiers — SMS-OOB restriction (verbatim):

> "Methods that do not prove possession of a specific device, such
> as voice-over-IP (VOIP) or email, SHALL NOT be used for out-of-
> band authentication."

> "Use of the PSTN for out-of-band verification is RESTRICTED as
> described in this section and in Section 5.2.10. If out-of-band
> verification is to be made using the PSTN, the verifier SHALL
> verify that the pre-registered telephone number being used is
> associated with a specific physical device."

§4 — AAL2 minimum (Y.Y2 treats AAL2 as the floor for CJIS AA):

> "Authentication Assurance Level 2 (AAL2): AAL2 provides high
> confidence that the claimant controls authenticator(s) bound to
> the subscriber's account. Proof of possession and control of two
> different authentication factors is required through secure
> authentication protocol(s)."

§5.2.10 — Restricted Authenticators (verbatim, the SMS rationale):

> "The use of a RESTRICTED authenticator requires that the
> implementing organization assess, understand, and accept the
> risks associated with that RESTRICTED authenticator and
> acknowledge that risk will likely increase over time."

### 2.3 FIDO Alliance — FIDO2 / WebAuthn specification

URL: https://www.w3.org/TR/webauthn-2/ (W3C Web Authentication
Level 2 Recommendation, accessed 2026-06-08).

The WebAuthn `attestationObject` field is the structured evidence
Y.Y2 reads when present in the IdP enrolment record. WebAuthn-
attested factors are phishing-resistant and bound to the
relying-party origin.

§6.5.1 — Authenticator Attestation (verbatim):

> "Generally, the attestation statement is a signed data object
> that contains statements about the authenticator and the
> generated credential. The Relying Party uses the attestation
> statement to verify properties of the authenticator and the
> credential."

> "A given authenticator MAY support attestation, or it MAY not.
> Some authenticators only support attestation conveyance using a
> specific Attestation Statement Format. Some authenticators that
> support attestation only support a single Attestation Statement
> Format that they were programmed with at manufacture time."

§5.4.5 — Authenticator Selection Criteria (verbatim, defines the
platform vs. cross-platform distinction Y.Y2 surfaces in the
`factor_type` field as `fido2-platform` vs `fido2-roaming`):

> "This member describes authenticators' attachment modalities. [...]
> If this member is present and set to `platform`, the [...] client
> MUST only use authenticators of the same attachment modality, or
> none. If this member is present and set to `cross-platform`, the
> [...] client MUST only use cross-platform authenticators, or
> none."

### 2.4 AWS Cognito — DescribeUserPool + ListUserPoolClients API

URL: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeUserPool.html
(accessed 2026-06-08).

Y.Y2's AWS provider module reads the Cognito user pool to enumerate
the enabled authentication factors. The `MfaConfiguration` and
`SoftwareTokenMfaConfiguration` fields drive Y.Y2's factor-type
mapping.

Verbatim API contract excerpt (the field shape Y.Y2 parses):

> "MfaConfiguration — The multi-factor authentication (MFA)
> configuration. Valid values include: OFF — MFA tokens aren't
> required and can't be specified during user registration. ON —
> MFA tokens are required for all user registrations. You can only
> specify ON when you're initially creating a user pool. You can
> use the SetUserPoolMfaConfig API operation to turn MFA "ON" for
> existing user pools. OPTIONAL — Users have the option when
> registering to create an MFA token."

> "SmsConfiguration — The SMS configuration with the settings that
> your Amazon Cognito user pool must use to send an SMS message
> from your Amazon Web Services account through Amazon Simple
> Notification Service. To send SMS messages with Amazon SNS in the
> Amazon Web Services Region that you want, the Amazon Cognito user
> pool uses an Identity and Access Management (IAM) role in your
> Amazon Web Services account."

URL: https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_SetUserPoolMfaConfig.html
(accessed 2026-06-08).

Verbatim (the SetUserPoolMfaConfig request shape that Y.Y2 cross-
references to understand which factor types are enabled):

> "SoftwareTokenMfaConfiguration — Configures a user pool for
> time-based one-time password (TOTP) MFA. Enables or disables TOTP."

> "SmsMfaConfiguration — Configures user pool SMS messages for MFA."

Y.Y2 reads both fields. `SoftwareTokenMfaConfiguration.Enabled =
true` maps to §5.6.2.2.1 category-(4) software-token with
phishing-resistance grade "no". `SmsMfaConfiguration` enabled
maps to §5.6.2.2.1 category-(7) out-of-band with phishing-
resistance grade "no" and disposition `non-conformant by default`
unless an `cjis-aa-overrides.yaml` entry permits it via
compensating control.

### 2.5 AWS IAM Identity Center — Authentication & MFA

URL: https://docs.aws.amazon.com/singlesignon/latest/userguide/mfa-considerations.html
(accessed 2026-06-08).

Verbatim (the IAM Identity Center MFA method enumeration that Y.Y2
parses):

> "IAM Identity Center supports the following types of multi-
> factor authentication (MFA):
>  - Built-in authenticators — IAM Identity Center supports the
>    use of WebAuthn (FIDO2) credentials, including built-in
>    authenticators in laptops and smartphones, and roaming
>    security keys.
>  - Authenticator apps — IAM Identity Center supports time-based
>    one-time password (TOTP) authenticator apps such as Google
>    Authenticator and Authy.
>  - RFC-6238-compliant time-based one-time password (TOTP) apps.
>  - Verification codes sent by email."

Y.Y2 maps each method to the §5.6.2.2.1 category and to the
phishing-resistance grade. Email-OOB earns `non-conformant by
default` (insufficient assurance per 800-63B §5.1.3.3 first
quotation in §2.2 above).

### 2.6 GCP Workforce Identity Federation — Authentication policies

URL: https://cloud.google.com/iam/docs/workforce-identity-federation
(accessed 2026-06-08).

GCP Workforce Identity Federation is the cloud-IdP for
non-Google-Workspace user populations. Y.Y2 reads the WorkforcePool
+ WorkforceProvider resources and the upstream IdP's SAML or
OIDC assertions to recover the factor types the user authenticated
with.

Verbatim (workforce pool attribute mapping, which Y.Y2 uses to
recover the factor type from the upstream assertion):

> "An attribute condition is a CEL expression that's evaluated
> against attributes from upstream identity provider's tokens. If
> the attribute condition evaluates to true for a given credential,
> the credential is accepted. Otherwise, the credential is
> rejected."

> "Attributes — Attributes are mappings from upstream IdP token
> claims to Google attributes. The Google attributes that you can
> set are: google.subject (required), google.groups, attribute.NAME."

Y.Y2 reads `attribute.amr` (Authentication Method References, RFC
8176) when the upstream IdP sets it; AMR values map directly to
§5.6.2.2.1 categories:

- `fido` / `hwk` → category-(3) Smart card OR category-(5) Hardware
  token (depending on storage)
- `swk` → category-(4) Software token
- `otp` → category-(4) Software token (TOTP) OR category-(5)
  Hardware token (hardware OTP)
- `sms` / `tel` → category-(7) Out-of-band (non-conformant by
  default)
- `pwd` → none (not AA)
- `mfa` → marks multi-factor in the aggregate (Y.Y2 still requires
  the per-factor breakdown)

### 2.7 GCP Identity-Aware Proxy — GetIapSettings + IAM bindings

URL: https://cloud.google.com/iap/docs/reference/rest/v1/v1.iap.GetIapSettings
(accessed 2026-06-08).

Verbatim (the IAP settings shape Y.Y2 reads):

> "IapSettings — The IAP configurable settings. Fields:
>  - access_settings — Top level wrapper for all access related
>    settings in IAP.
>  - application_settings — Top level wrapper for all application
>    related settings in IAP."

`access_settings.gcip_settings` (Google Cloud Identity Platform
settings — the upstream IdP) and
`access_settings.identity_sources` (Workforce Pool ids) are the
roots Y.Y2 walks to recover the factor types per protected
resource.

### 2.8 Microsoft Entra ID — Conditional Access policies

URL: https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy
(accessed 2026-06-08).

Verbatim (the Conditional Access policy shape Y.Y2 parses):

> "conditionalAccessPolicy resource type — Represents a Microsoft
> Entra Conditional Access policy. Conditional access policies are
> custom rules that define an access scenario."

> "grantControls — Specifies the grant controls that must be
> fulfilled to pass the policy. Properties: builtInControls,
> customAuthenticationFactors, operator, termsOfUse,
> authenticationStrength."

> "authenticationStrength — The authentication strength required
> by the conditional access policy. Optional."

`authenticationStrength` is the modern Entra ID surface that
expresses "phishing-resistant MFA" as a policy requirement.
Y.Y2 reads the assigned `authenticationStrengthPolicy` resource
and walks `allowedCombinations[]` to confirm the policy admits
only FIDO2 / Windows Hello for Business / X.509 certificate
combinations when phishing-resistant MFA is required.

### 2.9 Microsoft Entra ID — Authentication Methods Policy

URL: https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethodspolicy
(accessed 2026-06-08).

Verbatim:

> "authenticationMethodsPolicy resource type — Defines authentication
> methods and the users that are allowed to use them to sign in
> and perform multi-factor authentication (MFA) in Microsoft Entra
> ID. Authentication methods include passwords and an expanding
> list of more secure methods, like FIDO2 security keys."

> "Properties: authenticationMethodConfigurations — Represents the
> settings for each authentication method. Authentication method
> configurations include: emailAuthenticationMethodConfiguration,
> fido2AuthenticationMethodConfiguration,
> microsoftAuthenticatorAuthenticationMethodConfiguration,
> smsAuthenticationMethodConfiguration,
> temporaryAccessPassAuthenticationMethodConfiguration,
> softwareOathAuthenticationMethodConfiguration,
> voiceAuthenticationMethodConfiguration,
> x509CertificateAuthenticationMethodConfiguration."

Y.Y2 enumerates each authentication method configuration, checks
its `state` field (enabled / disabled), and emits one factor
record per enabled method per included scope.

### 2.10 Microsoft Entra ID — Authentication Strength Policies

URL: https://learn.microsoft.com/en-us/graph/api/resources/authenticationstrengthpolicy
(accessed 2026-06-08).

Verbatim:

> "authenticationStrengthPolicy — A collection of settings that
> define the strength of authentication used by a user when
> they're prompted for an authentication. The strength
> requirements that an authenticationStrengthPolicy specifies
> can be applied to a user or a group, using Conditional Access
> policies."

> "allowedCombinations — A collection of authentication method
> combinations allowed by this authentication strength. Each
> entry is a comma-delimited list of methods (for example,
> 'fido2,password')."

The built-in `00000000-0000-0000-0000-000000000004` policy id is
"Phishing-resistant MFA"; its `allowedCombinations[]` includes
`fido2`, `windowsHelloForBusiness`, and `x509CertificateMultiFactor`.
Y.Y2 treats Conditional Access policies that reference this
built-in (or an equivalent custom policy with the same allowlist)
as `conformant` with `phishing_resistant: true`.

### 2.11 RFC 8176 — Authentication Method Reference Values

URL: https://datatracker.ietf.org/doc/html/rfc8176 (accessed
2026-06-08).

Y.Y2 uses RFC 8176 AMR values to recover the authentication factor
type from an upstream OIDC ID-token `amr` claim (used by GCP
Workforce Identity Federation and by some Entra ID external auth
configurations).

Verbatim (the AMR value list, abbreviated to the values Y.Y2
recognises):

> "fido — Use of a Fast IDentity Online (FIDO) AuthenticationFactor
> [FIDO]."
> "hwk — Proof of possession of a hardware-secured key."
> "swk — Proof of possession of a software-secured key."
> "otp — One-time password [...]. One-time passwords can be
> obtained from any of various OTP applications/devices."
> "sms — Confirmation using SMS [SMS] text message to the user at
> a registered number."
> "tel — Confirmation by telephone call to the user at a
> registered number."
> "pwd — Password-based authentication."
> "mfa — Multiple-factor authentication [NIST.800-63-3]."

### 2.12 IRS / CJIS Advisory Process — informal guidance on SMS-OOB

URL: https://le.fbi.gov/cjis-division/the-cjis-advisory-process
(accessed 2026-06-08).

The CJIS Advisory Process publishes quarterly minutes summarising
state CSA discussions. The 2023-Q4 minutes (cited in
LOOP-Y-SPEC.md §2 commentary) discussed SMS-OOB as a deprecated
authenticator pathway for new deployments. Operator references to
the minutes are captured in `cjis-state-supplements.yaml` per state.

Verbatim quote from the CJIS Advisory Process landing page:

> "The CJIS Advisory Process is a federal advisory committee that
> provides recommendations to the FBI Director on CJIS-related
> activities, including operations, policies, and security."

(The minutes themselves are distributed to CSAs; Y.Y2 references
the CSA-distributed materials operator-side via
`cjis-state-supplements.yaml` and does not bundle them.)

### 2.13 FIPS 140-3 — cryptographic module validation

URL: https://csrc.nist.gov/publications/detail/fips/140/3/final
(accessed 2026-06-08).

CJIS §5.10.1.2 requires that cryptographic modules used to
protect CJI meet FIPS 140-2 (or successor 140-3) certification.
Y.Y2 cross-references this requirement when emitting AA evidence
for hardware tokens (category-(5)) and smart cards (category-(3))
— a hardware token whose underlying cryptographic module is not
FIPS 140-validated earns `conformant-with-caveat` rather than
`conformant`.

Verbatim:

> "FIPS 140-3 (Federal Information Processing Standard
> Publication 140-3) Security Requirements for Cryptographic
> Modules supersedes FIPS 140-2."

### 2.14 NIST SP 800-53 Rev 5 — IA-2(1), IA-2(2), IA-2(12)

URL: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf
(accessed 2026-06-08).

The CJIS catalog's §5.6.2.2 cross-walk maps to NIST 800-53 r5
IA-2(1) "Multi-factor authentication to privileged accounts",
IA-2(2) "Multi-factor authentication to non-privileged accounts",
and IA-2(12) "Acceptance of PIV credentials".

Verbatim (IA-2(1)):

> "Implement multi-factor authentication for access to privileged
> accounts."

Verbatim (IA-2(2)):

> "Implement multi-factor authentication for access to non-
> privileged accounts."

Verbatim (IA-2(12)):

> "Accept and electronically verify Personal Identity Verification-
> compliant credentials."

Y.Y2's evidence envelope `provenance.nist_800_53_r5_mapping[]`
field carries IA-2(1), IA-2(2), IA-2(12) for every conformant
decision, providing the cross-walk back to the FedRAMP Moderate
baseline.

### 2.15 OMB M-22-09 — phishing-resistant MFA for federal employees

URL: https://www.whitehouse.gov/wp-content/uploads/2022/01/M-22-09.pdf
(accessed 2026-06-08).

Although M-22-09 governs federal-agency *employees* (not CSP
customers), the policy is the closest federal-government articulation
of "phishing-resistant" as an authenticator property. Y.Y2 uses
M-22-09's definition when grading factors for the
`phishing_resistant` boolean field in the envelope.

Verbatim (the phishing-resistance definition):

> "Phishing-resistant authentication refers to authentication
> processes designed to detect and prevent disclosure of
> authentication secrets and outputs to a website or application
> masquerading as a legitimate system."

> "MFA must verify that personnel have access to government
> information, and that this access is phishing-resistant."

LOOP-X (Zero Trust) operationalises M-22-09 for the CSP's
employee population; Y.Y2 *borrows the definition only* to grade
CJIS AA factor records — it does not enforce M-22-09 on the
CJIS customer population (which would be out of scope for a
CSP-side overlay).

---

## 3. Scope

### 3.1 In scope

- Per-IdP-tenant, per-user-set, per-factor enumeration of all
  enabled authentication factors in AWS Cognito user pools, AWS
  IAM Identity Center instances, GCP Workforce Identity
  Federation workforce pools, GCP Identity-Aware Proxy protected
  resources, and Microsoft Entra ID Conditional Access policies +
  Authentication Methods Policy.
- Deterministic mapping from each enumerated factor type to one
  of the seven CJIS v5.9.5 §5.6.2.2.1 CSO-approved categories.
- Phishing-resistance grade per factor type (boolean) using
  M-22-09 + NIST 800-63B as the authority.
- Conformance disposition per factor: `conformant`,
  `conformant-with-caveat`, `non-conformant`, or
  `conformant-via-compensating-control` (when an override is
  present).
- Compensating-control override handling — read
  `cjis-aa-overrides.yaml` and honour entries that include a CSO
  approval reference (state CSO email + approval-document hash).
- Asset-coverage analysis — count CJI-tagged assets covered by
  conformant AA at the identity layer; report the per-state
  breakdown.
- Signed evidence envelope (Ed25519 + RFC 3161 + RFC 8785
  canonicalization) per (IdP-tenant, evaluation-run) tuple.
- POA&M emission via LOOP-A.A1 for every non-conformant decision
  not covered by a compensating control.
- Persistence into tracker DB tables `cjis_aa_evaluations` +
  `cjis_aa_factor_decisions`.
- Per-state CSO addressing — read `cjis-state-supplements.yaml`
  and produce `addressed_to_csos[]` array for each in-scope state.

### 3.2 Out of scope

- Direct submission to a state CSO or to the FBI CJIS Division —
  per CLAUDE.md Rule 4 the operator submits; Y.Y2 produces the
  artifact and the tracker captures the submission receipt.
- Re-evaluation of "is MFA enabled" — that question is owned by
  the existing `core/iam-mfa.ts` collector; Y.Y2 reads the
  collector's evidence and adds CJIS decoration on top.
- Implementation of state-specific CJIS supplements as code paths
  — state supplements are operator-supplied YAML overlays; Y.Y2
  reads them as additive controls only.
- Evaluation of CJIS §5.4.7 audit-retention or §5.10.1.2
  encryption requirements — those are evaluated by other loops /
  collectors (LOOP-K + existing encryption detectors).
- NCIC operating procedures (non-public; out of LOOP-Y per §1.3
  of LOOP-Y-SPEC.md).
- Authentication for the CSP's *internal* employee population —
  that is LOOP-X (Zero Trust) and the existing IAM family.
- IRS 1075 / FTI evaluations — those are Y.Y3 + Y.Y4.

---

## 4. Inputs

TypeScript-form for the data structures Y.Y2 consumes:

```typescript
// From Y.Y1: the signed catalog snapshot
interface CJISPolicyCatalogSnapshot {
  $schema: string;
  schema_version: string;
  snapshot_id: string;
  snapshot_date: string;          // YYYY-MM-DD
  policy_version: string;         // "5.9.5"
  policy_published_date: string;
  policy_effective_audit_date: string;
  csp_name: string;
  policy_areas: PolicyArea[];     // includes §5.6.2.2 + §5.6.2.2.1
  state_supplements: StateSupplement[];
  provenance: SnapshotProvenance;
}

interface PolicyArea {
  id: string;                     // "5.6"
  title: string;                  // "Identification and Authentication"
  sections: PolicySection[];
}

interface PolicySection {
  id: string;                     // "5.6.2.2.1"
  title: string;                  // "Approved AA Solutions"
  shall_statements: ShallStatement[];
}

interface ShallStatement {
  id: string;                     // "5.6.2.2.1-1"
  text: string;                   // verbatim policy quote
  nist_800_53_r5_mapping?: string[];
  factor_categories?: FactorCategory[];
  state_supplement_overlays?: StateSupplementOverlay[];
}

interface FactorCategory {
  id: number;                     // 1..7
  name: string;                   // "biometric" | "user-cert" | "smart-card" | "software-token" | "hardware-token" | "paper-token" | "oob"
  type: "something-you-are" | "something-you-have" | "something-you-know";
}

// From existing core/iam-mfa.ts: per-IdP MFA evidence (per provider)
interface IAMMFAEvidence {
  provider: "aws" | "gcp" | "azure";
  service: string;                // "Cognito" | "IAM Identity Center" | "Workforce Identity Federation" | "Entra ID"
  tenant_id: string;
  user_pools_or_pools: UserPoolMFAEvidence[];
  collected_at: string;
  run_id: string;
}

interface UserPoolMFAEvidence {
  pool_id: string;
  mfa_required: boolean;
  enabled_methods: EnabledMFAMethod[];
  user_count_total: number;
  user_count_with_mfa: number;
}

interface EnabledMFAMethod {
  method_id: string;
  raw_method_type: string;        // provider-native, e.g. "SoftwareTokenMFA" | "SMS_MFA" | "FIDO2_PLATFORM"
  configuration: Record<string, unknown>;
  supports_attestation?: boolean;
  user_count_enrolled: number;
}

// From existing core/inventory.ts: asset records
interface InventoryAsset {
  asset_id: string;
  asset_type: string;
  region: string;
  data_classes: string[];         // includes "CJI" when in scope
  protecting_idps: string[];      // tenant_id list — populated by Y.Y2 from IdP read
  diagram_label?: string;
}

// Operator-supplied: state-supplement overlays
interface CJISStateSupplementsYAML {
  states: StateSupplementEntry[];
}

interface StateSupplementEntry {
  state: string;                  // "TX" | "CA" | "NY" | ...
  csa_name: string;
  cso_name: string;
  cso_email: string;
  cso_phone: string;
  ori_numbers: string[];          // 9-character ORIs
  supplement_pdf_path?: string;
  additive_aa_factor_overrides?: AAFactorOverride[];
}

interface AAFactorOverride {
  factor_type: string;
  state_disposition_override: "conformant" | "conformant-with-caveat" | "non-conformant";
  rationale: string;
  state_advisory_reference: string;  // URL or document id
}

// Operator-supplied: compensating-control overrides
interface CJISAAOverridesYAML {
  overrides: AACompensatingControl[];
}

interface AACompensatingControl {
  override_id: string;            // e.g. "AAOC-001"
  scope: AACompensatingControlScope;
  rationale: string;              // verbatim from the §5.6.2.2 last sentence's "approved AA Compensating Control"
  cso_approval: {
    state: string;
    cso_name: string;
    cso_email: string;
    approval_document_path: string;
    approval_document_sha256: string;
    approval_date: string;
    approval_expiration_date: string;
  };
  applies_to_factor_types: string[];
  effective_from: string;
  effective_until: string;
}

interface AACompensatingControlScope {
  idp_tenant_ids: string[];       // when ["*"], applies to all IdPs
  user_set_ids: string[];         // when ["*"], applies to all user sets
}

// Operator-supplied: org-profile.yaml relevant fields
interface OrgProfileCJISFields {
  serves_criminal_justice_information: boolean;
  in_scope_states: string[];      // ["TX","CA","NY"]
  ori_numbers: { state: string; ori: string }[];
  marketplace_url?: string;
}
```

---

## 5. Outputs

### 5.1 Canonical JSON evidence envelope (one per IdP-tenant per run)

Schema reference: `https://cloud-evidence.example/schemas/cjis-aa-eval-v1.json`.

```jsonc
{
  "$schema": "https://cloud-evidence.example/schemas/cjis-aa-eval-v1.json",
  "schema_version": "1.0.0",
  "evaluation_id": "cjis-aa-eval-2026-06-08-aws-cognito-userpool-xyz-001",
  "evaluated_at": "2026-06-08T14:33:00Z",
  "evaluation_run_id": "run-20260608-1430Z",
  "csp_name": "<from org-profile.yaml>",
  "in_scope_states": ["TX", "CA", "NY"],
  "idp": {
    "provider": "aws",                     // "aws" | "gcp" | "azure"
    "service": "Cognito",                  // "Cognito" | "IAM Identity Center" | "Workforce Identity Federation" | "Identity-Aware Proxy" | "Entra ID"
    "tenant_id": "us-east-1:cognito-account-id",
    "policy_or_user_pool_id": "us-east-1_xyzABC123",
    "evaluated_user_count": 1234
  },
  "factors_enabled": [
    {
      "factor_type": "fido2-platform",
      "cjis_category": 2,
      "cjis_category_name": "user-cert",
      "disposition": "conformant",
      "phishing_resistant": true,
      "supports_attestation": true,
      "user_count_enrolled": 1100,
      "evidence_path": "providers/aws/iam-mfa-evidence.json#/cognito/userpool-xyz/method/fido2_platform",
      "compensating_control_id": null,
      "compensating_control_cso_approval": null,
      "nist_800_53_r5_mapping": ["IA-2(1)", "IA-2(2)", "IA-2(12)"],
      "policy_citation": {
        "section_id": "5.6.2.2.1",
        "shall_statement_id": "5.6.2.2.1-1",
        "snapshot_id": "cjis-policy-v5.9.5-20260607T120000Z"
      }
    },
    {
      "factor_type": "sms-oob",
      "cjis_category": 7,
      "cjis_category_name": "oob",
      "disposition": "non-conformant",
      "phishing_resistant": false,
      "supports_attestation": false,
      "user_count_enrolled": 134,
      "evidence_path": "providers/aws/iam-mfa-evidence.json#/cognito/userpool-xyz/method/sms",
      "compensating_control_id": null,
      "compensating_control_cso_approval": null,
      "non_conformance_reason": "SMS-OOB is a §5.6.2.2.1 category-(7) factor but is a RESTRICTED authenticator under NIST SP 800-63B §5.1.3.3 and is informally deprecated for new CJIS deployments by the CJIS Advisory Process 2023-Q4 guidance; SS7-interceptable; not phishing-resistant.",
      "nist_800_53_r5_mapping": ["IA-2(1)", "IA-2(2)"],
      "policy_citation": {
        "section_id": "5.6.2.2.1",
        "shall_statement_id": "5.6.2.2.1-1",
        "snapshot_id": "cjis-policy-v5.9.5-20260607T120000Z"
      }
    }
  ],
  "asset_coverage": {
    "cji_tagged_assets_total": 87,
    "cji_tagged_assets_covered_by_conformant_aa": 87,
    "cji_tagged_assets_covered_by_caveat_aa": 0,
    "cji_tagged_assets_non_conformant": 0,
    "covered_assets": [
      {
        "asset_id": "aws/us-east-1/lambda/cji-search-fn",
        "data_classes": ["CJI"],
        "protecting_idps": ["us-east-1:cognito-account-id"],
        "protecting_factor_dispositions": ["conformant"]
      }
    ]
  },
  "conformance_summary": {
    "overall": "partial",
    "conformant_factor_count": 1,
    "conformant_with_caveat_factor_count": 0,
    "non_conformant_factor_count": 1,
    "compensating_controls_in_use": []
  },
  "addressed_to_csos": [
    {"state": "TX", "csa_name": "Texas Department of Public Safety", "cso_name": "<from yaml>", "cso_email": "<from yaml>"},
    {"state": "CA", "csa_name": "California Department of Justice", "cso_name": "<from yaml>", "cso_email": "<from yaml>"},
    {"state": "NY", "csa_name": "New York State Police", "cso_name": "<from yaml>", "cso_email": "<from yaml>"}
  ],
  "linked_poam_findings": [
    {
      "finding_template": "CJIS-AA-FACTOR-NON-CONFORMANT",
      "finding_uuid": "<oscal poam uuid>",
      "factor_type": "sms-oob",
      "risk_score": "high"
    }
  ],
  "provenance": {
    "emitter": "core/cjis-aa-detector.ts",
    "emitter_version": "1.0.0",
    "emitted_at": "2026-06-08T14:35:00Z",
    "snapshot_id": "cjis-policy-v5.9.5-20260607T120000Z",
    "iam_mfa_run_id": "<from existing iam-mfa core>",
    "inventory_run_id": "<from existing core/inventory.ts>",
    "signing_key_id": "ed25519-prod-2026",
    "signature": "<Ed25519 detached signature over canonical JSON>",
    "signature_alg": "Ed25519",
    "canonicalization": "rfc8785",
    "rfc3161_timestamp": "<base64 tsr>"
  }
}
```

### 5.2 OSCAL POA&M finding (emitted via LOOP-A.A1 when non-conformant)

```jsonc
{
  "finding_template_id": "CJIS-AA-FACTOR-NON-CONFORMANT",
  "uuid": "<poam-item uuid>",
  "title": "CJIS Advanced Authentication factor non-conformant: sms-oob enrolled by 134 users in AWS Cognito user pool us-east-1_xyzABC123",
  "description": "The Cognito user pool us-east-1_xyzABC123 has SMS-OOB enabled as a multi-factor authentication method. SMS is a §5.6.2.2.1 category-(7) Out-of-band authenticator under CJIS Security Policy v5.9.5. However, NIST SP 800-63B §5.1.3.3 RESTRICTS the use of the PSTN for out-of-band verification, and the CJIS Advisory Process 2023-Q4 minutes informally deprecate SMS-OOB for new CJIS deployments. Users authenticating with SMS-OOB to access CJI face an unacceptable phishing + SS7-interception risk. Remediation: enable a phishing-resistant factor (FIDO2/WebAuthn — §5.6.2.2.1 category-(2)/(3) — or PIV/CAC) and disable SMS as an MFA option, OR document an §5.6.2.2 AA Compensating Control with state CSO approval in cjis-aa-overrides.yaml.",
  "related_observations": ["<observation uuid linking to the Y.Y2 evidence envelope>"],
  "related_risks": ["<risk uuid>"],
  "remediation_tracking": {
    "tracking_entries": [
      {
        "title": "Y.Y2 detector emitted finding 2026-06-08",
        "date_time_stamp": "2026-06-08T14:35:00Z",
        "type": "Created",
        "actor_uuid": "<system actor>"
      }
    ]
  },
  "props": [
    {"name": "framework", "value": "cjis-5.9.5", "ns": "https://fedpy.example/ns/poam"},
    {"name": "factor_type", "value": "sms-oob", "ns": "https://fedpy.example/ns/poam"},
    {"name": "cjis_category", "value": "7", "ns": "https://fedpy.example/ns/poam"},
    {"name": "phishing_resistant", "value": "false", "ns": "https://fedpy.example/ns/poam"},
    {"name": "composite_risk_score", "value": "high", "ns": "https://fedpy.example/ns/poam"}
  ]
}
```

### 5.3 Signed envelope outer shape (the `signEnvelope()` wrapper)

```jsonc
{
  "envelope_id": "cjis-aa-eval-2026-06-08-aws-cognito-userpool-xyz-001",
  "envelope_kind": "cjis-aa-evaluation",
  "schema": "https://cloud-evidence.example/schemas/cjis-aa-eval-v1.json",
  "payload": { /* the §5.1 envelope above */ },
  "manifest": {
    "payload_sha256": "<sha256 of canonical-JSON-serialised payload>",
    "payload_canonicalization": "rfc8785",
    "signed_at": "2026-06-08T14:35:00Z",
    "signer": {
      "key_id": "ed25519-prod-2026",
      "key_alg": "Ed25519",
      "key_pubkey": "<base64 pub>",
      "key_provenance": {
        "created_at": "2026-01-01T00:00:00Z",
        "holder": "fedpy-build-2026"
      }
    },
    "signature": "<Ed25519 detached signature over payload_sha256>",
    "rfc3161_timestamp": "<base64 tsr from RFC3161 TSA>"
  }
}
```

### 5.4 Tracker DB row shape — `cjis_aa_evaluations`

```sql
CREATE TABLE cjis_aa_evaluations (
  evaluation_id TEXT PRIMARY KEY,
  evaluation_run_id TEXT NOT NULL,
  csp_name TEXT NOT NULL,
  evaluated_at TIMESTAMP NOT NULL,
  idp_provider TEXT NOT NULL,
  idp_service TEXT NOT NULL,
  idp_tenant_id TEXT NOT NULL,
  idp_pool_id TEXT NOT NULL,
  overall_conformance TEXT NOT NULL CHECK(overall_conformance IN ('conformant','partial','non-conformant')),
  conformant_factor_count INTEGER NOT NULL,
  conformant_with_caveat_factor_count INTEGER NOT NULL,
  non_conformant_factor_count INTEGER NOT NULL,
  cji_tagged_assets_total INTEGER NOT NULL,
  cji_tagged_assets_covered_by_conformant_aa INTEGER NOT NULL,
  envelope_path TEXT NOT NULL,
  envelope_sha256 TEXT NOT NULL,
  envelope_signature TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE cjis_aa_factor_decisions (
  decision_id TEXT PRIMARY KEY,
  evaluation_id TEXT NOT NULL REFERENCES cjis_aa_evaluations(evaluation_id) ON DELETE CASCADE,
  factor_type TEXT NOT NULL,
  cjis_category INTEGER NOT NULL CHECK(cjis_category BETWEEN 1 AND 7),
  cjis_category_name TEXT NOT NULL,
  disposition TEXT NOT NULL CHECK(disposition IN ('conformant','conformant-with-caveat','non-conformant','conformant-via-compensating-control')),
  phishing_resistant INTEGER NOT NULL CHECK(phishing_resistant IN (0,1)),
  supports_attestation INTEGER CHECK(supports_attestation IN (0,1)),
  user_count_enrolled INTEGER NOT NULL,
  non_conformance_reason TEXT,
  compensating_control_id TEXT,
  poam_finding_uuid TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_cjis_aa_factor_decisions_eval ON cjis_aa_factor_decisions(evaluation_id);
CREATE INDEX idx_cjis_aa_evaluations_run ON cjis_aa_evaluations(evaluation_run_id);
CREATE INDEX idx_cjis_aa_evaluations_overall ON cjis_aa_evaluations(overall_conformance);
```

---

## 6. Algorithm / Steps

The Y.Y2 detector follows a deterministic, REO-compliant algorithm.
Every step that consults an external surface (cloud SDK, file
system, tracker DB) is read-only and is gated by the
`core/auth/*-readonly-guardrail` modules established by the
existing IAM family.

Step-by-step:

1. **Boot + flag gating.** Read `--cjis-aa` CLI flag (or
   `CLOUD_EVIDENCE_CJIS_AA=1`). If absent, exit with
   `coverage:skipped-cjis-aa-not-requested`. If present, proceed.
2. **Org-profile gate.** Load `cloud-evidence/org-profile.yaml`.
   Check `serves_criminal_justice_information === true`. If false,
   exit with `coverage:skipped-cjis-not-applicable`. Capture
   `in_scope_states[]` and `ori_numbers[]`.
3. **Catalog snapshot load.** Read the most recent
   `data/cjis-policy-v5.9.5-catalog.json` snapshot (produced by
   Y.Y1). Verify Ed25519 signature using `core/sign.ts::verify()`.
   On signature failure, exit with `provenance:cjis-catalog-
   signature-invalid` and exit-code 2.
4. **State supplement load.** Read
   `cloud-evidence/cjis-state-supplements.yaml`. Validate schema
   against `schemas/cjis-state-supplements.schema.json`. For each
   entry whose `state` is in `in_scope_states[]`, capture CSO
   address + ORIs + optional `additive_aa_factor_overrides[]`.
5. **Compensating-control overrides.** Read
   `cloud-evidence/cjis-aa-overrides.yaml` (optional — file may not
   exist). For each entry, validate that:
   - `cso_approval.approval_document_path` exists on disk
   - SHA-256 of the file matches `cso_approval.approval_document_sha256`
   - `approval_expiration_date` is in the future
   - `effective_from <= now <= effective_until`
   Drop entries that fail validation and emit a per-entry
   `provenance:cjis-aa-override-invalid` log line.
6. **IAM-MFA evidence load.** Read the most recent
   `out/iam-mfa/aws.json`, `out/iam-mfa/gcp.json`,
   `out/iam-mfa/azure.json` artefacts produced by the existing
   IAM-MFA collector. If absent, fall through to live SDK reads in
   steps 7-9; if present, prefer the cached evidence.
7. **AWS provider read** (`providers/aws/cjis-aa.ts`):
   - For each AWS account in the multi-account config: call
     `CognitoIdentityProviderClient.send(new ListUserPoolsCommand)`
     (paginated). For each user pool, call `DescribeUserPoolCommand`
     and `GetUserPoolMfaConfigCommand`. Parse `MfaConfiguration`,
     `SoftwareTokenMfaConfiguration`, `SmsMfaConfiguration`.
   - For each Identity Center instance: call `SSOAdminClient.send(
     new ListInstancesCommand)`. For each instance, call the
     `IdentityStoreClient` + `SSOAdminClient.DescribeInstanceAccess
     ControlAttributeConfigurationCommand` and the
     `DescribeAuthenticationMethodCommand` equivalents to recover
     the enabled factor methods.
   - Emit one canonical IAMMFAEvidence record per (account, pool)
     tuple into the in-memory evaluation buffer.
8. **GCP provider read** (`providers/gcp/cjis-aa.ts`):
   - For each GCP project: call `iam.projects.locations.workforce
     Pools.list` and `.providers.list`. For each provider, parse
     `attributeMapping` and recover the upstream IdP token claim
     names; do NOT introspect upstream IdP credentials (out of
     scope — operator manages upstream IdP). For each AMR value
     the workforce-provider accepts, map to §5.6.2.2.1 category.
   - For each IAP-protected resource: call `iap.iap.getIapSettings`.
     Parse `access_settings.gcip_settings` and
     `access_settings.identity_sources`. Cross-reference to the
     enumerated workforce pools.
   - Emit canonical IAMMFAEvidence record per workforce pool.
9. **Azure provider read** (`providers/azure/cjis-aa.ts`):
   - Call Microsoft Graph
     `GET /policies/conditionalAccessPolicies`. For each policy
     with `state == "enabled"` and assignments scoped to users
     who access CJI-tagged Azure resources (cross-reference
     inventory), parse `grantControls.builtInControls[]` and
     `grantControls.authenticationStrength`.
   - Call `GET /policies/authenticationMethodsPolicy`. Enumerate
     each `authenticationMethodConfiguration` with `state ==
     "enabled"`; map to §5.6.2.2.1 categories.
   - Call `GET /policies/authenticationStrengthPolicies`.
     Enumerate each policy referenced by a Conditional Access
     `authenticationStrength` grant; walk `allowedCombinations[]`
     to decide whether the policy admits phishing-resistant
     combinations only.
   - Emit canonical IAMMFAEvidence record per Conditional Access
     policy.
10. **Per-factor mapping.** For each IAMMFAEvidence record, invoke
    `mapFactorToDisposition(raw_method_type, configuration,
    state_supplement_overlays)` defined in
    `core/cjis-aa-detector.ts`. The function consults the embedded
    decision table (seeded from LOOP-Y-SPEC.md §16) and returns
    `{cjis_category, cjis_category_name, disposition, phishing_
    resistant, supports_attestation}`.
11. **Compensating-control overlay.** For each non-conformant
    decision, check `cjis-aa-overrides.yaml` overrides whose
    `scope.idp_tenant_ids[]` includes the IdP tenant (or `["*"]`)
    AND whose `applies_to_factor_types[]` includes the factor type.
    If an override matches, mutate the decision to
    `conformant-via-compensating-control` and record the
    `compensating_control_id` + `compensating_control_cso_approval`
    fields.
12. **State supplement overlay.** For each decision, check
    `state_supplement.additive_aa_factor_overrides[]` per in-scope
    state. If a state explicitly downgrades a factor (e.g. CA-DOJ
    publishes an advisory that hardware-OTP without FIPS 140-3 is
    non-conformant for California CJIS), apply the overlay. State
    supplements never UPGRADE a factor; they only ADD restrictions.
13. **Asset coverage computation.** Read
    `out/inventory/inventory.json`. Filter assets where
    `data_classes ⊇ {"CJI"}`. For each asset, cross-reference
    `protecting_idps[]` to the evaluated IdP tenants; bucket the
    asset by the most-permissive factor disposition that protects
    it (conformant > conformant-with-caveat > non-conformant). Emit
    `asset_coverage` block.
14. **Envelope composition.** Build the §5.1 evidence envelope with
    all fields populated. Compute `conformance_summary.overall`:
    `conformant` iff every factor decision is `conformant` (or
    compensating-controlled), `non-conformant` iff any decision is
    `non-conformant`, `partial` otherwise.
15. **Sign envelope.** Call `signEnvelope(payload, {signer:
    "ed25519-prod-2026", timestamp: "rfc3161"})` from `core/sign.ts`.
    Write `out/cjis-aa/<run-id>/<idp-tenant>.json`.
16. **POA&M emission.** For each `non-conformant` decision (not
    suppressed by compensating control), call
    `emitPOAM(findingTemplate: "CJIS-AA-FACTOR-NON-CONFORMANT",
    payload: {evaluation_id, factor_type, idp, cjis_category,
    non_conformance_reason, asset_count})` from
    `core/oscal-poam.ts`. Capture returned `finding_uuid` and back-
    fill `linked_poam_findings[]` in the envelope (then re-sign).
17. **Tracker DB persistence.** INSERT one row into
    `cjis_aa_evaluations` and N rows into
    `cjis_aa_factor_decisions` via the existing tracker DB pool.
    The INSERTs are wrapped in a single transaction; on rollback,
    emit `coverage:cjis-aa-tracker-persist-failed` and exit 3.
18. **Bundler registration.** Register the envelope file path +
    SHA-256 in `core/submission-bundle.ts::WELL_KNOWN["cjis-aa-
    evaluation"]` so LOOP-A.A4 picks it up in the submission
    package.
19. **Marketplace badge gating.** If `conformance_summary.overall ===
    "conformant"` AND `asset_coverage.cji_tagged_assets_non_
    conformant === 0` AND every in-scope-state's CSO has been
    addressed, emit the badge-eligibility record at
    `out/cjis-aa/<run-id>/marketplace-badge-eligible.json` for
    LOOP-Q.Q1 to consume.
20. **Coverage / log emit.** Emit per-IdP `coverage:cjis-aa-evaluated`
    log line. If any factor was non-conformant and no compensating
    control suppressed it, emit `coverage:cjis-aa-non-conformant`
    at warn level.
21. **Exit.** Return 0 on success; 2 on signature failure; 3 on
    tracker DB failure; 4 on REQUIRES-OPERATOR-INPUT diagnostic
    that cannot be deferred (e.g. missing `cjis-state-supplements.
    yaml` when `in_scope_states[]` non-empty).

Pseudocode for the central mapping function:

```typescript
function mapFactorToDisposition(
  rawMethodType: string,
  configuration: Record<string, unknown>,
  stateOverlays: AAFactorOverride[],
): FactorDecisionCore {
  const baseDecision = DECISION_TABLE[normaliseFactorType(rawMethodType)];
  if (!baseDecision) {
    return {
      cjis_category: 0,
      cjis_category_name: "unknown",
      disposition: "non-conformant",
      phishing_resistant: false,
      supports_attestation: false,
      non_conformance_reason: `Unrecognised factor type "${rawMethodType}" — Y.Y2 decision table requires explicit mapping; treat as non-AA until table updated.`,
    };
  }
  // Apply WebAuthn-attestation refinement
  if (baseDecision.factor_family === "fido2" && !configuration.attestation_present) {
    return { ...baseDecision, disposition: "conformant-with-caveat", phishing_resistant: false, supports_attestation: false };
  }
  // Apply FIPS-validation refinement for hardware factors
  if (baseDecision.factor_family === "hardware-token" && configuration.fips140_validated === false) {
    return { ...baseDecision, disposition: "conformant-with-caveat" };
  }
  // Apply state supplement overlay (only downgrades)
  for (const overlay of stateOverlays) {
    if (overlay.factor_type === rawMethodType && SEVERITY[overlay.state_disposition_override] > SEVERITY[baseDecision.disposition]) {
      return { ...baseDecision, disposition: overlay.state_disposition_override, non_conformance_reason: overlay.rationale };
    }
  }
  return baseDecision;
}
```

---

## 7. Files to create / modify

All paths absolute under `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/`:

**Create:**

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/cjis-aa-detector.ts` — the main detector + decision table + mapping function.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/schemas/cjis-aa-eval-v1.schema.json` — JSON-schema for the evidence envelope (ajv-validated).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/schemas/cjis-state-supplements.schema.json` — JSON-schema for the state supplements YAML.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/schemas/cjis-aa-overrides.schema.json` — JSON-schema for the compensating-control overrides YAML.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/aws/cjis-aa.ts` — AWS Cognito + IAM Identity Center introspection.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/gcp/cjis-aa.ts` — GCP Workforce Identity Federation + Identity-Aware Proxy introspection.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/providers/azure/cjis-aa.ts` — Entra ID Conditional Access + Authentication Methods Policy + Authentication Strength Policies introspection.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/cjis-aa-detector.test.ts` — unit + integration test suite (minimum 18 tests per LOOP-Y-SPEC.md §7.1).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/cjis-aa/cognito-fido2-only.json` — AWS Cognito IAMMFAEvidence fixture (conformant case).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/cjis-aa/cognito-sms-only.json` — non-conformant case.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/cjis-aa/cognito-mixed-totp-fido2.json` — partial case.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/cjis-aa/gcp-workforce-amr-fido.json` — GCP conformant case.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/cjis-aa/azure-ca-phishing-resistant.json` — Entra ID conformant case.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/cjis-aa/azure-ca-no-strength.json` — Entra ID with CA but no authentication strength (caveat case).
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/cjis-aa/cjis-aa-overrides-valid.yaml` — compensating-control override fixture.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/cjis-aa/cjis-state-supplements-tx-ca-ny.yaml` — three-state supplements fixture.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/cjis-state-supplements.yaml.example` — operator-facing example file with comments.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/cjis-aa-overrides.yaml.example` — operator-facing example file with comments.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/migrations/NNNN_cjis_aa_tables.sql` — schema migration creating `cjis_aa_evaluations` + `cjis_aa_factor_decisions`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/server/routes/cjis-aa.ts` — REST endpoints for the tracker UI.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/tracker/client/src/pages/CJISAA.tsx` — UI page rendering the evaluations + per-factor decisions.

**Modify:**

- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/orchestrator.ts` — wire `--cjis-aa` flag dispatch to `runCJISAADetector()`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/submission-bundle.ts` — register `cjis-aa-evaluation` role in `WELL_KNOWN`.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/core/oscal-poam.ts` — register `CJIS-AA-FACTOR-NON-CONFORMANT` finding template.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/CHANGELOG.md` — append entry under "Unreleased".
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/STATUS.md` — slice row status → done at completion time.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-Y-SPEC.md` — §12 status table row for Y.Y2.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/docs/loops/LOOP-Y-RISKS.md` — register any newly-discovered risks during implementation.
- `/Users/kenith.philip/FedRAMP 20x/cloud-evidence/RUNBOOK.md` — operational note on the `--cjis-aa` flag + per-IdP credential requirement.

---

## 8. Test specifications

Minimum 18 tests per LOOP-Y-SPEC.md §7.1. The table below enumerates
the test plan. Fixture paths absolute under
`/Users/kenith.philip/FedRAMP 20x/cloud-evidence/test/fixtures/cjis-aa/`.

| id | scenario | fixture path | expected | acceptance |
|---|---|---|---|---|
| T01 | AWS Cognito with FIDO2-platform only — fully conformant | cognito-fido2-only.json | `overall === "conformant"`; factor_type=`fido2-platform`; cjis_category=2; phishing_resistant=true | envelope signed; no POA&M emitted; tracker row created with overall=conformant |
| T02 | AWS Cognito with SMS-only — fully non-conformant | cognito-sms-only.json | `overall === "non-conformant"`; factor_type=`sms-oob`; non_conformance_reason cites 800-63B §5.1.3.3 | envelope signed; POA&M emitted with `CJIS-AA-FACTOR-NON-CONFORMANT`; tracker row created with overall=non-conformant |
| T03 | AWS Cognito with mixed TOTP + FIDO2 | cognito-mixed-totp-fido2.json | `overall === "conformant"` (both factors on CSO list); TOTP has phishing_resistant=false caveat | envelope signed; no POA&M; conformance summary lists both factors |
| T04 | GCP Workforce Identity with AMR=fido | gcp-workforce-amr-fido.json | `overall === "conformant"`; factor_type=`fido2-roaming`; cjis_category=3 | envelope signed; no POA&M |
| T05 | Entra ID Conditional Access requiring phishing-resistant MFA strength | azure-ca-phishing-resistant.json | `overall === "conformant"`; references built-in policy id `00000000-0000-0000-0000-000000000004` | envelope signed; no POA&M |
| T06 | Entra ID Conditional Access enabled but no authentication strength | azure-ca-no-strength.json | `overall === "partial"`; factor flagged `conformant-with-caveat`; phishing_resistant=false | envelope signed; no POA&M (caveat is not a failure but is surfaced) |
| T07 | Operator-supplied compensating-control override for SMS — disposition becomes `conformant-via-compensating-control` | cognito-sms-only.json + cjis-aa-overrides-valid.yaml | factor disposition mutated; compensating_control_id present; no POA&M emitted | envelope shows compensating-control id; tracker row reflects override |
| T08 | Compensating-control override missing CSO approval document — override rejected | cognito-sms-only.json + cjis-aa-overrides-invalid-no-csodoc.yaml | override rejected with `provenance:cjis-aa-override-invalid` log line; factor remains non-conformant | exit 0; POA&M still emitted; tracker row reflects non-conformant |
| T09 | Compensating-control override expired — override rejected | cognito-sms-only.json + cjis-aa-overrides-expired.yaml | override rejected; factor remains non-conformant | exit 0; POA&M emitted |
| T10 | State supplement downgrades hardware-OTP for California — disposition becomes `non-conformant` for CA users | gcp-workforce-amr-hardware-otp.json + cjis-state-supplements-tx-ca-ny.yaml (CA overlay) | factor disposition mutated to non-conformant in CA scope only; per-state addressing surfaces CA CSO | POA&M emitted scoped to CA; tracker row reflects state-scoped non-conformance |
| T11 | CJIS catalog snapshot signature tampered — loader refuses | cjis-policy-v5.9.5-catalog-tampered.json | exit code 2; log line `provenance:cjis-catalog-signature-invalid` | no envelope written; no tracker row created |
| T12 | inventory.json has zero CJI-tagged assets — warning emitted but evaluation proceeds | empty-cji-inventory.json | `coverage:no-cji-assets` warn line; envelope still emitted; `asset_coverage.cji_tagged_assets_total === 0` | envelope signed; tracker row created |
| T13 | inventory.json has CJI-tagged assets but no `protecting_idps[]` matches any evaluated IdP — surface `asset.protecting_idps_missing` | cji-asset-no-protecting-idps.json | `asset_coverage.cji_tagged_assets_non_conformant > 0`; per-asset `protecting_idps` empty diagnostic emitted | POA&M emitted with `CJIS-AA-FACTOR-NON-CONFORMANT` + per-asset diagnostic |
| T14 | Biometric factor present but WebAuthn attestation field absent — disposition is `conformant-with-caveat` | cognito-biometric-no-attestation.json | factor disposition is `conformant-with-caveat`; `supports_attestation === false` | envelope signed; no POA&M |
| T15 | Biometric factor with WebAuthn-attested envelope — disposition is `conformant` | cognito-biometric-attested.json | factor disposition is `conformant`; `supports_attestation === true`; phishing_resistant=true | envelope signed; no POA&M |
| T16 | Password-only enrolment (no MFA) — disposition is `non-conformant` (passwords are not AA) | cognito-password-only.json | factor disposition is `non-conformant`; cjis_category=0 (unknown / not-AA); non_conformance_reason cites §5.6.2.1 | POA&M emitted |
| T17 | Risk-based authentication alone (Entra ID sign-in risk policy without grantControl factor) — disposition is `non-conformant` | azure-rba-only.json | RBA-alone flagged non-conformant; reason cites §5.6.2.2 requirement of multi-factor | POA&M emitted |
| T18 | End-to-end: catalog → detector → 3 IdPs (AWS+GCP+Azure) → envelope per IdP → POA&M emitted for non-conformant → tracker rows + bundler registration → marketplace badge eligibility decision | e2e-mixed-fixture-set/ | three envelopes written; correct POA&Ms; three tracker rows; bundler picks up the envelopes; badge eligibility = false (because Azure has non-conformant) | exit 0; integration assertions pass |
| T19 | Org-profile has `serves_criminal_justice_information: false` — slice skipped | org-profile-cjis-false.yaml | log line `coverage:skipped-cjis-not-applicable`; exit 0; no envelope written | no tracker row; no POA&M |
| T20 | `--cjis-aa` flag not passed and env unset — slice not invoked from orchestrator | n/a | orchestrator dispatch table never calls `runCJISAADetector()` | unit test asserts absence of call |
| T21 | Adversarial — IdP returns previously-unseen factor type ("PASSKEY_V2") — decision table miss → `non-conformant` with explicit `unrecognised_factor_type` reason | cognito-unknown-factor.json | factor disposition is `non-conformant`; cjis_category=0; reason includes "Unrecognised factor type" | POA&M emitted; ticket-creation diagnostic suggests adding to DECISION_TABLE |
| T22 | Multi-state addressing — in_scope_states=[TX,CA,NY] → addressed_to_csos[] has 3 entries with correct CSO emails | full-3state-fixture/ | array length === 3; each entry has cso_email from supplements YAML | envelope signed |

(Tests T19, T20, T21, T22 add adversarial + integration coverage
beyond the LOOP-Y-SPEC.md §7.1 minimum of 18.)

---

## 9. Risks

Minimum 4 with mitigations. The full register lives in
`docs/loops/LOOP-Y-RISKS.md`; the following are the per-slice
top-of-mind risks captured here for fresh-session resumability.

| risk_id | description | likelihood | impact | mitigation | owner |
|---|---|---|---|---|---|
| R-Y.Y2-01 | **IdP factor-type taxonomy drift.** AWS / GCP / Azure add new MFA method types frequently (passkeys, device-bound credentials, FIDO2 + attestation extensions). The DECISION_TABLE in `core/cjis-aa-detector.ts` may not cover a new method type, causing `non-conformant` decisions for factors that should be conformant. | high | medium | Decision table lives in source; unknown factor types raise `unrecognised_factor_type` log line and emit a per-run digest summarising any unmapped types. Quarterly review process surfaces new types into the table. Adversarial test T21 ensures we surface (rather than silently mis-classify) unknown types. | LOOP-Y maintainer |
| R-Y.Y2-02 | **CJIS Advisory Process informal guidance.** CJIS Advisory Process publishes non-published-policy guidance (e.g. 2023-Q4 SMS-OOB deprecation). The Y.Y2 detector hard-codes a SMS=non-conformant default that is not in the v5.9.5 PDF text. A future advisory may reverse this. | medium | medium | The default is overridable via `cjis-state-supplements.yaml` AND via the `cjis-aa-overrides.yaml` compensating-control pathway. Decision-table comments cite the specific advisory + date. Annual review process tracks advisory changes. | LOOP-Y maintainer |
| R-Y.Y2-03 | **Compensating-control workflow misuse.** Operators may use `cjis-aa-overrides.yaml` to suppress legitimate findings without genuine CSO approval. A 3PAO reviewing the trail must be able to detect this. | medium | high | Override entries REQUIRE `cso_approval.approval_document_path` (existing file) + `approval_document_sha256` (validated) + `approval_date` + `approval_expiration_date` (validated in-range). Override file SHA-256 is signed into the envelope. Tracker UI surfaces all active overrides with a "review CSO approval" link. Annual operator attestation re-confirms each override. | LOOP-Y maintainer + operator |
| R-Y.Y2-04 | **Conditional Access policy scope misinterpretation.** Entra ID Conditional Access policies can scope by user, group, app, location, device — extracting "which users access CJI-tagged Azure resources" is non-trivial. The detector may over- or under-attribute factors. | high | high | Detector walks `assignments.includeUsers` + `assignments.includeGroups` + `conditions.applications.includeApplications` and cross-references to inventory `data_classes ⊇ {"CJI"}`. When the join is ambiguous (e.g. policy uses `includeUsers=All`), emit `policy_scope_ambiguous: true` in the factor record and surface in the tracker UI for operator review. Test T05 + T06 cover the high-volume case. | LOOP-Y maintainer |
| R-Y.Y2-05 | **State supplement variance.** State CJIS supplements have wildly different formats (Texas DPS publishes PDF, California DOJ publishes HTML, Illinois publishes via state-police PDF). The `cjis-state-supplements.yaml` schema may not capture every state's idiosyncrasies. | medium | medium | Schema accepts optional `additive_aa_factor_overrides[]` array; operator captures state-specific overlays as needed. Loop-wide REQUIRES-OPERATOR-INPUT registry tracks per-state CSO email + supplement URL. New states added by extending the YAML; no code changes required. | LOOP-Y maintainer |
| R-Y.Y2-06 | **Read-only guardrail bypass.** Cognito / Identity Center / Entra Graph SDK calls touch IAM surfaces that COULD mutate state if mis-invoked. A regression in the read-only proxy could cause a write. | low | high | All cloud SDK calls go through the existing `core/auth/*-readonly-guardrail.ts` Proxy. Y.Y2's provider modules MUST import `getReadOnlyClient(...)` from the existing modules; direct SDK construction is forbidden by `npm run lint:no-stubs` + a new per-module ESLint rule (TODO: ESLint rule TBD). Unit test T05 verifies the provider modules construct clients via the guardrail. | LOOP-Y maintainer + IAM family owner |

---

## 10. Open questions

| oq_id | question | affects | proposed disposition | status |
|---|---|---|---|---|
| OQ-Y.Y2-01 | Should Y.Y2 also evaluate "downstream IdP" factors when the cloud IdP federates to an upstream (e.g. Okta upstream feeding AWS IAM Identity Center)? | upstream IdP coverage | Out of scope for Y.Y2 v1. Upstream IdP introspection requires upstream credentials and a per-upstream connector; defer to a future "external IdP introspector" slice. | OPERATOR-DECISION |
| OQ-Y.Y2-02 | How should Y.Y2 handle Conditional Access policies with `conditions.signInRiskLevels` set (Entra ID sign-in risk) — is risk-based authentication treated as a factor or as a condition? | Entra ID detector | Treat as a condition that gates the grant; the grant must still include a §5.6.2.2.1 factor. Test T17 covers RBA-alone (non-conformant). | RESOLVED (test T17) |
| OQ-Y.Y2-03 | If multiple IdPs protect the same CJI-tagged asset (e.g. a Lambda fronted by both Cognito and IAM Identity Center for different user populations), which IdP's disposition determines the asset's coverage bucket? | asset coverage | The most-permissive disposition wins (conformant > caveat > non-conformant) — an asset is considered conformant if ANY accessing IdP factor is conformant. Document in tracker UI tooltips. | RESOLVED |
| OQ-Y.Y2-04 | Should the detector surface per-user enrolment counts in the envelope, or only aggregated counts? | envelope schema | Aggregated counts only (envelope is published-to-CSO; per-user data is privacy-sensitive). Per-user data stays in tracker DB and is queryable by authenticated operator only. | RESOLVED |
| OQ-Y.Y2-05 | Does the CSO require a specific evidence file format for the AA evidence package — JSON, .docx, or both? | submission ergonomics | OPERATOR-RESEARCH: defaults to JSON (matches the §5.1 envelope). If a state CSO requests .docx, the operator can run the LOOP-Y .docx renderer (Y.Y4-style) on the JSON envelope. | OPERATOR-RESEARCH (defer to per-state) |
| OQ-Y.Y2-06 | When a new CJIS policy version drops (v6.0), how does Y.Y2 know which version to evaluate against? | catalog versioning | Y.Y2 reads the most-recent snapshot file from `data/`; operator can pin via `--cjis-policy-version` flag. Multi-version support tracked in LOOP-Y-SPEC.md §A2-A13. | RESOLVED via Y.Y1 versioned snapshots |

---

## 11. REQUIRES-OPERATOR-INPUT

| field name | type | validator | UI location | failure mode if missing |
|---|---|---|---|---|
| `org-profile.yaml: serves_criminal_justice_information` | boolean | strict bool | `cloud-evidence/org-profile.yaml` | Slice skipped with `coverage:skipped-cjis-not-applicable`; tracker UI shows banner "CJIS overlay not applicable" |
| `org-profile.yaml: in_scope_states[]` | array of 2-char USPS state codes | enum (50 states + DC + 5 territories) | `cloud-evidence/org-profile.yaml` | Slice runs but no per-state CSO addressing; envelope `addressed_to_csos` empty; warn `coverage:cjis-aa-no-state-csos` |
| `org-profile.yaml: ori_numbers[]` | array of `{state, ori}` | regex `^[A-Z0-9]{9}$` | `cloud-evidence/org-profile.yaml` | Tracker UI shows per-state CSO without ORI binding; per-state envelope skips ORI field |
| `cjis-state-supplements.yaml: states[].cso_email` | RFC 5322 email | regex + RFC 5322 lib | `cloud-evidence/cjis-state-supplements.yaml` | Per-state CSO addressing missing for that state; envelope `addressed_to_csos[].cso_email = ""` with diagnostic `requires_operator_input: cso_email` |
| `cjis-state-supplements.yaml: states[].supplement_pdf_path` (optional) | absolute path | file exists | `cloud-evidence/cjis-state-supplements.yaml` | State supplement overlay not loaded; FBI baseline applies; warn `coverage:cjis-state-supplement-pdf-missing` |
| `cjis-aa-overrides.yaml: overrides[].cso_approval.approval_document_path` | absolute path | file exists + SHA-256 match | `cloud-evidence/cjis-aa-overrides.yaml` | Override rejected; factor remains non-conformant; log `provenance:cjis-aa-override-invalid` |
| `cjis-aa-overrides.yaml: overrides[].cso_approval.approval_expiration_date` | ISO date | future date | `cloud-evidence/cjis-aa-overrides.yaml` | Override rejected; factor remains non-conformant |
| `cjis-aa-overrides.yaml: overrides[].cso_approval.cso_email` | RFC 5322 | regex | `cloud-evidence/cjis-aa-overrides.yaml` | Override entry rejected with schema-validation error |
| `data/cjis-policy-v5.9.5-catalog.json` (produced by Y.Y1) | file path | exists + signature valid | `cloud-evidence/data/` | Slice exits 2 with `provenance:cjis-catalog-signature-invalid` |
| `out/iam-mfa/{aws,gcp,azure}.json` (produced by existing IAM-MFA collector) | file path | exists or fall through to live SDK | `cloud-evidence/out/iam-mfa/` | Y.Y2 falls back to live SDK reads; warn if SDK auth unavailable |
| `inventory.json` (produced by existing inventory collector) | file path | exists | `cloud-evidence/out/inventory/` | Y.Y2 cannot compute `asset_coverage` block; envelope `asset_coverage.cji_tagged_assets_total === null` with diagnostic |
| `org-profile.yaml: marketplace_url` (optional) | URL | https:// | `cloud-evidence/org-profile.yaml` | Marketplace badge eligibility decision still computed but not surfaced to LOOP-Q.Q1 |

---

## 12. Implementation log slot

| date | session | action | commit | notes |
|---|---|---|---|---|
| 2026-06-08 | spec-author-Y.Y2 | Specification authored via FedPy workflow | TBD | Spec derived from LOOP-Y-SPEC.md §16 decision table + §18 envelope schema; verbatim quotes pulled from CJIS v5.9.5 §5.6.2.1 + §5.6.2.2 + §5.6.2.2.1 + §5.6.2.2.2 plus NIST 800-63B §4 + §5.1.3.3 + §5.2.10 plus W3C WebAuthn-2 §5.4.5 + §6.5.1 plus AWS Cognito API ref + AWS IAM Identity Center MFA considerations + GCP Workforce Identity Federation docs + GCP IAP docs + MS Graph conditionalAccessPolicy + authenticationMethodsPolicy + authenticationStrengthPolicies plus RFC 8176 AMR values plus FIPS 140-3 plus NIST 800-53 r5 IA-2(1)/(2)/(12) plus OMB M-22-09 phishing-resistance definition. 15 distinct sources cited; ≥12 verbatim blockquotes. Test plan = 22 tests (exceeds §7.1 minimum of 18 by 4). 6 risks captured here; full register in LOOP-Y-RISKS.md.|
| | | | | |
| | | | | |

(Append per-session entries below per `docs/IMPLEMENTATION-LOG-TEMPLATE.md` cadence: at every commit boundary, every test failure, every research question answered, every spec divergence, every newly-discovered risk, every external dependency pin.)

---

## 13. Completion checklist

Per `cloud-evidence/docs/SLICE-COMPLETION-PROCEDURE.md` — verbatim
quotation of the 7-step procedure (followed by step 8 from the
COMMON preamble):

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
> Open `cloud-evidence/docs/STATUS.md` and for the slice that just shipped:
> - Change `Status` column from `pending` to `done`
> - Fill `Commit` with the PENDING commit's short hash (you'll know it after step 5)
> - Fill `Date` with today's date (ISO format YYYY-MM-DD)
> - If this was the last slice in a loop, change the loop's title section to indicate "(COMPLETE)"
> - Update the "Overall" section: increment loops-complete, change last-shipped, update next-priority
>
> ### Step 3 — Update the loop's spec doc
> Open `cloud-evidence/docs/loops/LOOP-X-SPEC.md` (where X is your loop letter).
> Find the "Status tracking" section table.
> For your slice row: status=done, commit=<hash>, date=<ISO>.
>
> ### Step 4 — Add CHANGELOG entry
> Open `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`.
> Add a new entry at the TOP of "Unreleased":
>
> ### Added — LOOP-X.XN: <Slice title>
> <2-3 paragraphs describing what shipped, module names, file paths, verification counts (typecheck clean, NNN/NNN tests passing, npm run check:reo returns 0).>
>
> ### Step 5 — Commit
> ```bash
> cd /Users/kenith.philip/FedRAMP\ 20x
> git add cloud-evidence/<modified files> cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md CHANGELOG.md
> git commit -m "LOOP-X.XN: <slice title>
> <detailed commit message describing the slice>
> Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
> ```
>
> ### Step 6 — Update commit hash in STATUS.md + loop spec
> Now that the commit exists, get its hash:
> ```bash
> git log -1 --format=%h
> ```
> Open STATUS.md + the loop's spec doc — paste the actual commit hash in the rows you updated in step 2+3.
> Amend the commit:
> ```bash
> git add cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md
> git commit --amend --no-edit
> ```
>
> ### Step 7 — Push
> ```bash
> git push origin main
> ```

> Step 8: After commit lands, append/update the slice row in STATUS.md (status -> done, commit hash, last_updated); update the loop SPEC status table; append a CHANGELOG entry; push to origin/main; verify with 'git log --oneline -3'. Only THEN is the slice closed.

In addition, for Y.Y2 specifically:

- Update `cloud-evidence/docs/slices/Y/Y.Y2.md` frontmatter:
  `status: done`, `commit: <hash>`, `completed_date: <YYYY-MM-DD>`,
  `last_updated: <YYYY-MM-DD>`.
- Append the final Implementation log entry to §12 above per
  `docs/IMPLEMENTATION-LOG-TEMPLATE.md`.
- If any new risks surfaced during implementation, append to
  `cloud-evidence/docs/loops/LOOP-Y-RISKS.md` in the same commit.
- Verify the cross-loop dependency `LOOP-Q.Q1` is unblocked
  (Y.Y2 blocks Q.Q1 per LOOP-Y-SPEC.md §11.1). Update
  `docs/DEPENDENCY-GRAPH.md` if needed.
