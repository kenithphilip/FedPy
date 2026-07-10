# Public-repo safety: no account ids, credentials, or scan outputs

This is a **public** repository. Nothing that identifies which cloud accounts are
scanned — account ids, run configs, evidence/inventory outputs, audit reports —
may ever be committed. Three layers enforce that:

## 1. `.gitignore` (prevention)

Real per-account run configs and every tool's output/report/reference directory
are ignored, so `git add` can't stage them. Committed configs are limited to
sanitized `*.example.yaml` templates. See the "Account-specific data" section of
the root `.gitignore`.

## 2. Pre-commit hook (local enforcement)

`.githooks/pre-commit` runs `scan-account-data.sh --staged` on every commit and
aborts if it finds a real account id, an AWS access key, or PEM private-key
material in the staged changes. **Enable it once per clone:**

```bash
git config core.hooksPath .githooks
```

Verify: `git config core.hooksPath` should print `.githooks`.

## 3. CI (backstop)

`.github/workflows/scan-account-data.yml` runs `scan-account-data.sh --all` on
every push and PR, scanning all tracked files — so a commit made with
`--no-verify` or on a clone that never enabled the hook still gets caught before
merge.

## The scanner

`scan-account-data.sh` blocks:

- any 12-digit token whose **SHA-256** is in **`blocked-account-id-hashes.txt`**
  (known real accounts — matched by hash, so the account numbers themselves are
  never written into this repo);
- any **other** standalone 12-digit account id that is not a documented AWS
  example in **`allowed-account-ids.txt`** (default-deny — this is what catches a
  brand-new real account id nobody remembered to add to the denylist);
- AWS access key ids (`AKIA…`, `ASIA…`) and PEM private keys;
- any match for a pattern in **`blocked-terms.local`** — an OPTIONAL, git-ignored
  file of environment/company identifiers (account nicknames, SSO role names,
  internal cluster/product names). Because it is never committed, the sensitive
  terms are never published; the pre-commit hook enforces it locally (CI can't,
  since it never sees the file). Copy `blocked-terms.example` to get started.

12-digit substrings of longer hashes / terraform ids / digit runs are **not**
flagged (boundary detection excludes alphanumeric neighbors).

**Maintenance:**
- New real account touched by your tooling → add its hash:
  `printf '%s' 123456789012 | shasum -a 256` → paste into `blocked-account-id-hashes.txt`.
- New legitimate AWS example id in a test/fixture → add it to
  `allowed-account-ids.txt` in the same commit (otherwise the scanner blocks it).
- New environment/company term to guard → add a precise regex to your local
  `blocked-terms.local` (keep it out of git).

Run manually any time:

```bash
bash scripts/scan-account-data.sh --all       # whole tree
bash scripts/scan-account-data.sh path/to/file
```
