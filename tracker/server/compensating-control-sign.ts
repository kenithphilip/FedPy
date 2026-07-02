/**
 * LOOP-B.B4 — Compensating-control signing (Ed25519 over RFC-8785-style canonical
 * JSON).
 *
 * A compensating control (NIST 800-53A §2.4) is only trustworthy as assessment
 * evidence if the operator can prove the title / description / referenced controls
 * were not altered after the AO signed off. Every record is signed at create time
 * with the tracker's resident Ed25519 key; activation writes a SECOND signature so
 * the AO sign-off is non-repudiable (a 3PAO can verify both against the published
 * public key).
 *
 * Key material + canonicalisation are REUSED from the B.B3 signing subsystem
 * (server/risk-acceptance-sign.ts) — the same resident key in the signing_keys
 * table signs acceptances and compensating controls, and canonicalize() is
 * byte-identical to cloud-evidence/core/sign.ts so the cloud-evidence reader
 * (core/compensating-control-reader.ts) verifies these signatures without a shared
 * library. This module only adds the two payload shapes.
 */
import {
  canonicalize,
  getPublicKeyPem,
  listPublicKeys,
  publicKeyFingerprint,
  signPayload,
  verifyPayload,
} from './risk-acceptance-sign.ts';

// Re-export the shared signing primitives so route code imports everything CC-related from here.
export { canonicalize, getPublicKeyPem, listPublicKeys, publicKeyFingerprint, signPayload, verifyPayload };

/**
 * The exact object signed at create time. MUST stay byte-for-byte compatible with
 * the cloud-evidence reader's compensatingControlSignedPayload()
 * (cloud-evidence/core/compensating-control-reader.ts). nist_control_ids is sorted
 * so signing + verification are order-stable regardless of the operator's input
 * order.
 */
export interface CompensatingControlPayloadInput {
  title: string;
  description: string;
  nist_control_ids: string[];
  implemented_by_user_id: number;
  implemented_at: string;
  evidence_url: string | null;
  evidence_sha256: string | null;
}

export function compensatingControlPayload(c: CompensatingControlPayloadInput): Record<string, unknown> {
  return {
    title: c.title,
    description: c.description,
    nist_control_ids: [...c.nist_control_ids].sort(),
    implemented_by_user_id: c.implemented_by_user_id,
    implemented_at: c.implemented_at,
    evidence_url: c.evidence_url,
    evidence_sha256: c.evidence_sha256,
  };
}

/** The activation event signed when an AO transitions draft → active. */
export function activationPayload(uuid: string, signedOffByUserId: number, signedOffAt: string): Record<string, unknown> {
  return { compensating_control_uuid: uuid, signed_off_by_user_id: signedOffByUserId, signed_off_at: signedOffAt };
}
