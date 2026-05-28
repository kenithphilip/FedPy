/**
 * cloud-evidence verifier CLI.
 *
 * Use this to independently confirm that an `out/` directory of evidence
 * matches its signed manifest and that no files have been tampered with.
 *
 * Usage:
 *   tsx core/verify-cli.ts <out-dir> [--expected-public-key <pem>]
 *
 * Exit codes:
 *   0  All files match the manifest and signature verifies.
 *   1  Bad arguments.
 *   2  Verification failed (file changed, missing, extra, or bad signature).
 */
import { verifyRun } from './sign.ts';
import { verifyTimestamp } from './timestamp.ts';
import { resolve } from 'node:path';
import { existsSync } from 'node:fs';

function main(): void {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    console.log(`cloud-evidence verifier

Usage:
  tsx core/verify-cli.ts <out-dir> [--expected-public-key <pem>]

Args:
  <out-dir>                    Directory containing manifest.json, manifest.sig, and the *.json evidence files
  --expected-public-key <pem>  PEM file path; assert the manifest's embedded public key matches this one
`);
    process.exit(argv.length === 0 ? 1 : 0);
  }

  const outDir = resolve(argv[0]!);  // guarded by the empty-args check above
  let expectedPub: string | undefined;
  for (let i = 1; i < argv.length; i++) {
    if (argv[i] === '--expected-public-key') {
      expectedPub = resolve(argv[++i] ?? '');
    }
  }

  const v = verifyRun(outDir, expectedPub);

  console.log(`Directory: ${outDir}`);
  console.log(`Signature: ${v.signature_valid ? '✓ valid' : '✗ INVALID'}`);
  const matched = v.file_results.filter((f) => f.matched).length;
  const mismatched = v.file_results.filter((f) => !f.matched);
  console.log(`Files:     ${matched}/${v.file_results.length} match`);

  if (mismatched.length > 0) {
    console.log('\nMismatched files:');
    for (const f of mismatched) {
      if (f.missing) console.log(`  ✗ ${f.name} (MISSING)`);
      else console.log(`  ✗ ${f.name}`);
    }
  }
  if (v.extra_files.length > 0) {
    console.log('\nExtra (unsigned) files:');
    for (const n of v.extra_files) console.log(`  ! ${n}`);
  }
  if (v.errors.length > 0) {
    console.log('\nErrors:');
    for (const e of v.errors) console.log(`  - ${e}`);
  }

  // RFC 3161 timestamp (best-effort: only if a manifest.tsr is present)
  if (existsSync(resolve(outDir, 'manifest.tsr'))) {
    const tsa = verifyTimestamp(outDir);
    console.log(`\nTSR:       ${tsa.valid ? '✓ valid' : '✗ INVALID'}${tsa.tsa_url ? `  (from ${tsa.tsa_url})` : ''}`);
    if (!tsa.valid) {
      console.log(`  reason: ${tsa.reason ?? '(unknown)'}`);
    }
    if (!tsa.valid && v.valid) {
      // Manifest is good, but the trusted timestamp didn't verify — that's
      // still a verification failure for audit purposes.
      console.log('\n✗ Verification FAILED (TSR did not verify)');
      process.exit(2);
    }
  } else {
    console.log('\nTSR:       (not present — run un-timestamped)');
  }

  if (v.valid) {
    console.log('\n✓ Verification PASSED');
    process.exit(0);
  } else {
    console.log('\n✗ Verification FAILED');
    process.exit(2);
  }
}

main();
