# Slice completion procedure (MANDATORY)

> This procedure is MANDATORY for every slice in every loop. NO EXCEPTIONS.
> Every session that ships a slice MUST execute this checklist atomically with the slice's own commit.
> Failure to follow this procedure breaks the REO standard (CLAUDE.md) and the slice MUST be reverted.

## The 7-step procedure

### Step 1 — Verify the slice is REO-compliant
Run all three guardrails. They MUST all be green:
```bash
cd cloud-evidence
npm run typecheck      # no errors
npm test               # 100% passing (counts must increase by the slice's new tests)
npm run check:reo      # G1+G2+G3 all green
```

### Step 2 — Update STATUS.md
Open `cloud-evidence/docs/STATUS.md` and for the slice that just shipped:
- Change `Status` column from `pending` to `done`
- Fill `Commit` with the PENDING commit's short hash (you'll know it after step 5)
- Fill `Date` with today's date (ISO format YYYY-MM-DD)
- If this was the last slice in a loop, change the loop's title section to indicate "(COMPLETE)"
- Update the "Overall" section: increment loops-complete, change last-shipped, update next-priority

### Step 3 — Update the loop's spec doc
Open `cloud-evidence/docs/loops/LOOP-X-SPEC.md` (where X is your loop letter).
Find the "Status tracking" section table.
For your slice row: status=done, commit=<hash>, date=<ISO>.

### Step 4 — Add CHANGELOG entry
Open `/Users/kenith.philip/FedRAMP 20x/CHANGELOG.md`.
Add a new entry at the TOP of "Unreleased":

### Added — LOOP-X.XN: <Slice title>
<2-3 paragraphs describing what shipped, module names, file paths, verification counts (typecheck clean, NNN/NNN tests passing, npm run check:reo returns 0).>

### Step 5 — Commit
```bash
cd /Users/kenith.philip/FedRAMP\ 20x
git add cloud-evidence/<modified files> cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md CHANGELOG.md
git commit -m "LOOP-X.XN: <slice title>
<detailed commit message describing the slice>
Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Step 6 — Update commit hash in STATUS.md + loop spec
Now that the commit exists, get its hash:
```bash
git log -1 --format=%h
```
Open STATUS.md + the loop's spec doc — paste the actual commit hash in the rows you updated in step 2+3.
Amend the commit:
```bash
git add cloud-evidence/docs/STATUS.md cloud-evidence/docs/loops/LOOP-X-SPEC.md
git commit --amend --no-edit
```

### Step 7 — Push
```bash
git push origin main
```

## Failure handling

If ANY step fails:
- Step 1 (REO guardrails red): fix the issue. DO NOT proceed. DO NOT mark the slice done.
- Step 5 (signing/commit hook failure): unlock 1Password and retry signing. Do not use --no-gpg-sign without explicit user approval.
- Step 7 (push rejected): fetch + rebase, then re-push. NEVER force-push to main.

## REO directive

The CI guardrails (REO-0) will REJECT any slice that:
- Has stub/placeholder/TODO/FIXME markers in production paths (lint:no-stubs)
- Drops inventory-coverage.json fill rates (check:coverage-regression)
- Emits artifacts without provenance (check:provenance)

If your CI fails on any of these, the slice is NOT done. Fix and re-run from step 1.
