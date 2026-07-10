#!/usr/bin/env bash
#
# scan-account-data.sh — prevent real cloud account identifiers, credentials,
# environment names, and scan outputs from ever being committed to this PUBLIC
# repository.
#
# It fails (exit 1) when it finds, in the scanned content, any of:
#   * a 12-digit token whose SHA-256 is in scripts/blocked-account-id-hashes.txt
#     (known real accounts — matched by hash so the numbers aren't published here)
#   * any OTHER standalone 12-digit AWS account id not listed in
#     scripts/allowed-account-ids.txt (default-deny — catches unknown real ids)
#   * an AWS access key id (AKIA…/ASIA…) or PEM private-key material
#   * a match for any pattern in scripts/blocked-terms.local — an OPTIONAL,
#     git-ignored file of environment/company identifiers (e.g. account nicknames,
#     SSO role names). Kept local + un-committed so the terms themselves are never
#     published; the pre-commit hook enforces it. Copy blocked-terms.example.
#
# Modes:
#   scan-account-data.sh --staged        scan the git index (added lines) — pre-commit hook
#   scan-account-data.sh --all           scan every tracked file — CI
#   scan-account-data.sh <file> [file…]  scan specific files
#
# Word-boundary detection uses [^0-9A-Za-z] so 12-digit substrings of longer
# hex hashes / terraform ids / digit runs do NOT false-positive.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null || (cd "$HERE/.." && pwd))"
ALLOW_FILE="$HERE/allowed-account-ids.txt"
HASH_FILE="$HERE/blocked-account-id-hashes.txt"
TERMS_FILE="$HERE/blocked-terms.local"

sha256() { if command -v sha256sum >/dev/null 2>&1; then printf '%s' "$1" | sha256sum | cut -d' ' -f1; else printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1; fi; }

ALLOW_IDS="$([ -f "$ALLOW_FILE" ] && grep -oE '^[0-9]{12}' "$ALLOW_FILE" | paste -sd'|' - || true)"
BLOCK_HASHES="$([ -f "$HASH_FILE" ] && grep -oiE '^[0-9a-f]{64}' "$HASH_FILE" | tr 'A-F' 'a-f' | paste -sd'|' - || true)"
TERMS="$([ -f "$TERMS_FILE" ] && grep -vE '^[[:space:]]*(#|$)' "$TERMS_FILE" | paste -sd'|' - || true)"

BOUND='(^|[^0-9A-Za-z])[0-9]{12}([^0-9A-Za-z]|$)'
SECRET='AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'
MASTER="$SECRET|$BOUND"
[ -n "$TERMS" ] && MASTER="$MASTER|$TERMS"

ARGS=("$@")
mode="${1:---staged}"
cd "$REPO"

gather() {
  case "$mode" in
    --staged)
      git diff --cached --name-only --diff-filter=ACM -z |
        while IFS= read -r -d '' f; do
          git show ":$f" 2>/dev/null | grep -nIiE "$MASTER" |
            while IFS= read -r m; do printf '%s:%s\n' "$f" "$m"; done
        done ;;
    --all)
      git ls-files -z |
        while IFS= read -r -d '' f; do grep -HnIiE "$MASTER" -- "$f" 2>/dev/null; done ;;
    *)
      for f in "${ARGS[@]}"; do grep -HnIiE "$MASTER" -- "$f" 2>/dev/null; done ;;
  esac
}

violations=0
report() { printf '  \033[31m✗\033[0m %s\n' "$1" >&2; violations=$((violations + 1)); }

while IFS= read -r rec; do
  [ -n "$rec" ] || continue
  path="${rec%%:*}"; rest="${rec#*:}"; ln="${rest%%:*}"; content="${rest#*:}"
  # Skip the scanner's own config files (they legitimately describe what to block).
  case "${path##*/}" in
    allowed-account-ids.txt | blocked-account-id-hashes.txt | blocked-terms.local | blocked-terms.example) continue ;;
  esac
  if printf '%s' "$content" | grep -qiE "$SECRET"; then
    report "$path:$ln  cloud credential / private-key material"
  fi
  if [ -n "$TERMS" ] && printf '%s' "$content" | grep -qiE "$TERMS"; then
    report "$path:$ln  blocked environment/company term (see scripts/blocked-terms.local)"
  fi
  for tok in $(printf '%s' "$content" | grep -oE "$BOUND" | grep -oE '[0-9]{12}' | sort -u); do
    if [ -n "$BLOCK_HASHES" ] && printf '%s' "$(sha256 "$tok")" | grep -qxE "$BLOCK_HASHES"; then
      report "$path:$ln  BLOCKED real account id (hash match)"
    elif [ -n "$ALLOW_IDS" ] && printf '%s' "$tok" | grep -qxE "$ALLOW_IDS"; then
      : # public AWS example id — allowed
    else
      report "$path:$ln  unrecognized 12-digit account id $tok — if it is a public AWS example add it to scripts/allowed-account-ids.txt, otherwise remove it"
    fi
  done
done < <(gather)

if [ "$violations" -gt 0 ]; then
  printf '\n\033[31mBLOCKED:\033[0m %s account-identifier / secret / env-term finding(s) above must not reach a public repo.\n' "$violations" >&2
  printf 'See scripts/README.md. Real configs & scan outputs belong in .gitignore, not in git history.\n' >&2
  exit 1
fi
printf '\033[32m✓\033[0m scan-account-data: no real account ids, secrets, or blocked terms found.\n'
exit 0
