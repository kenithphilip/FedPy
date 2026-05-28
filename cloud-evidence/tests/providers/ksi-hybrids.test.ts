/**
 * Offline tests for the 7 KSI hybrid collectors (P4a).
 * Asserts both providers export all 7 collectors and that each is registered in
 * the KSI map. Does NOT make live cloud calls.
 */
import { describe, it, expect } from 'vitest';
import * as awsHybrids from '../../providers/aws/ksi-hybrids.ts';
import * as gcpHybrids from '../../providers/gcp/ksi-hybrids.ts';
import { KSI_MAP } from '../../core/ksi-map.ts';

const COLLECTORS = ['collectCmtRvp', 'collectInrAar', 'collectInrRpi', 'collectRplArp', 'collectRplRro', 'collectScrMit', 'collectSvcPrr'] as const;
const KSI_IDS = ['KSI-CMT-RVP', 'KSI-INR-AAR', 'KSI-INR-RPI', 'KSI-RPL-ARP', 'KSI-RPL-RRO', 'KSI-SCR-MIT', 'KSI-SVC-PRR'] as const;

describe('KSI hybrid collectors — exports', () => {
  for (const name of COLLECTORS) {
    it(`AWS exports ${name}`, () => {
      expect(typeof (awsHybrids as any)[name]).toBe('function');
    });
    it(`GCP exports ${name}`, () => {
      expect(typeof (gcpHybrids as any)[name]).toBe('function');
    });
  }
});

describe('KSI hybrid collectors — registered in KSI_MAP', () => {
  for (const id of KSI_IDS) {
    it(`${id} is registered with aws + gcp collectors`, () => {
      const entry = KSI_MAP[id];
      expect(entry, `${id} missing from KSI_MAP`).toBeTruthy();
      expect(typeof entry!.aws).toBe('function');
      expect(typeof entry!.gcp).toBe('function');
      expect(entry!.scope).toBe('HYBRID');
      expect(entry!.nist_controls?.length ?? 0).toBeGreaterThan(0);
      expect((entry!.process_artifacts_required?.length ?? 0)).toBeGreaterThan(0);
    });
  }
});
