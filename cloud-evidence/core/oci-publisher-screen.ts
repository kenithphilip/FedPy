/**
 * OCI image publisher prohibited-vendor screener (LOOP-W.W2, surface 3).
 *
 * Reads the cosign-verified / Rekor-logged publisher attestations for the
 * CSP's container images and screens the publishing identity against the W.W1
 * prohibited-vendor catalog. The publisher signal is whatever most reliably
 * identifies who signed the image: the cosign key fingerprint (unambiguous when
 * the operator has registered it on a catalog row), the keyless-OIDC issuer's
 * registrable domain, or the keyless subject / Rekor subject identity.
 *
 * Attestation files live under `out/oci-attestations/*.json` in the shape the
 * upstream signer emits (see docs/slices/W/W.W2.md §4.4). When that directory is
 * absent the screener returns zero matches and the caller records a coverage
 * note — it NEVER fabricates a publisher (REO Rule 1.5: no silent fallback that
 * masks missing data).
 *
 * Confidence (W.W2 §6 step 10): fingerprint = 1.0; subject identity = 0.95;
 * registrable-domain = 0.85; substring-on-subject = 0.7.
 */
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { resolve, basename } from 'node:path';
import { log } from './log.ts';
import type {
  ProhibitedVendorIndex,
  ProhibitedVendorMatch,
} from './prohibited-vendors-screen.ts';
import { buildMatch } from './prohibited-vendors-screen.ts';

export interface OciAttestation {
  image?: string;
  publisher_provenance?: {
    cosign_keyless_oidc_issuer?: string;
    cosign_keyless_subject?: string;
    cosign_key_fingerprint?: string;
    rekor_uuid?: string;
    rekor_subject?: string;
    builder_id?: string;
  };
}

export interface OciScreenResult {
  matches: ProhibitedVendorMatch[];
  images_screened: number;
  files_screened: number;
}

export interface OciScreenOptions {
  attestationDir?: string;
  attestations?: Array<{ path: string; doc: OciAttestation }>;
  index: ProhibitedVendorIndex;
  discoveredAt: string;
}

/** Extract the host of a URL or the domain of an email; returns "" if neither. */
function hostOf(raw: string | undefined): string {
  if (!raw) return '';
  const at = raw.indexOf('@');
  if (at >= 0 && !raw.includes('://')) return raw.slice(at + 1).toLowerCase().trim();
  try {
    return new URL(raw).host.toLowerCase();
  } catch {
    const m = /^([a-z0-9.-]+\.[a-z]{2,})/i.exec(raw);
    return m ? m[1]!.toLowerCase() : '';
  }
}

/** registrable domain = last two labels (best-effort; good enough for brand matching). */
function registrableDomain(host: string): string {
  const labels = host.split('.').filter(Boolean);
  return labels.length >= 2 ? labels.slice(-2).join('.') : host;
}

/** Extract the `<owner>` from a GitHub-Actions keyless identity (Q4 heuristic). */
function githubOwner(raw: string | undefined): string {
  if (!raw) return '';
  const m = /github\.com\/([^/]+)\//i.exec(raw);
  return m ? m[1]!.toLowerCase() : '';
}

function loadAttestations(dir: string): Array<{ path: string; doc: OciAttestation }> {
  if (!existsSync(dir)) return [];
  const out: Array<{ path: string; doc: OciAttestation }> = [];
  for (const f of readdirSync(dir)) {
    if (!f.endsWith('.json')) continue;
    const p = resolve(dir, f);
    try {
      if (!statSync(p).isFile()) continue;
      out.push({ path: p, doc: JSON.parse(readFileSync(p, 'utf8')) as OciAttestation });
    } catch (e) {
      log.warn({ event: 'w.w2.oci_attest_parse_failed', file: basename(p), err: String((e as Error)?.message ?? e) });
    }
  }
  return out;
}

/** Screen every OCI publisher attestation against the catalog. */
export function screenOciPublishers(opts: OciScreenOptions): OciScreenResult {
  const atts = opts.attestations
    ?? (opts.attestationDir ? loadAttestations(opts.attestationDir) : []);
  const fpIndex = opts.index.fingerprintIndex();
  const matches: ProhibitedVendorMatch[] = [];
  let imagesScreened = 0;

  for (const { doc } of atts) {
    const prov = doc.publisher_provenance;
    if (!prov) continue;
    imagesScreened += 1;
    const image = doc.image ?? '(unknown-image)';
    const digest = /(sha256:[0-9a-f]+)/i.exec(image)?.[1];
    const emitted = new Set<string>();

    const push = (
      em: { entry: { catalog_uid: string; entity_name: string }; matched_by: any; confidence: number },
      matchedName: string,
      matchedBy: ProhibitedVendorMatch['matched_by'],
      confidence: number,
      evidence: string,
    ): void => {
      const key = `${em.entry.catalog_uid}|${matchedBy}`;
      if (emitted.has(key)) return;
      emitted.add(key);
      matches.push(buildMatch({
        entryMatch: em as any,
        surface: 'oci-publisher',
        matchedName,
        matchPath: [image, matchedName],
        discoveredAt: opts.discoveredAt,
        confidence,
        matchedBy,
        sources: { surface_evidence: `oci-attestation:${evidence}`, oci_image_digest: digest },
      }));
    };

    // 1. Fingerprint — unambiguous when the operator has registered it.
    const fp = prov.cosign_key_fingerprint?.toLowerCase().trim();
    if (fp) {
      const entry = fpIndex.get(fp);
      if (entry) {
        push({ entry, matched_by: 'fingerprint', confidence: 1.0 }, fp, 'fingerprint', 1.0, `fingerprint:${fp}`);
      }
    }

    // 2. OIDC issuer registrable domain.
    const issuerDomain = registrableDomain(hostOf(prov.cosign_keyless_oidc_issuer));
    if (issuerDomain) {
      for (const em of opts.index.match(issuerDomain)) {
        push(em, issuerDomain, 'domain-registrable', Math.min(em.confidence, 0.85), `oidc-issuer:${issuerDomain}`);
      }
    }

    // 3. Keyless subject + Rekor subject identities (email/URI domains).
    for (const subj of [prov.cosign_keyless_subject, prov.rekor_subject]) {
      const domain = registrableDomain(hostOf(subj));
      if (!domain) continue;
      for (const em of opts.index.match(domain)) {
        push(em, domain, 'domain-registrable', Math.min(em.confidence, 0.85), `subject:${domain}`);
      }
    }

    // 4. GitHub-Actions OIDC owner (Q4 low-confidence heuristic).
    const owner = githubOwner(prov.cosign_keyless_subject) || githubOwner(prov.builder_id);
    if (owner) {
      for (const em of opts.index.match(owner)) {
        push(em, owner, 'domain-registrable', Math.min(em.confidence, 0.7), `github-owner:${owner}`);
      }
    }
  }

  return { matches, images_screened: imagesScreened, files_screened: atts.length };
}
