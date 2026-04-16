#!/usr/bin/env bash
# sast_scan.sh — orchestrate multi-tool SAST in parallel, emit SARIF.
# Usage: sast_scan.sh <repo-path> [output-dir]

set -u

REPO="${1:-.}"
OUT="${2:-./sast-results}"
mkdir -p "$OUT"

# Resolve to absolute paths so per-tool branches that `cd` into $REPO (e.g.
# eslint) still write outputs under the original $OUT.
REPO="$(cd "$REPO" && pwd)"
OUT="$(cd "$OUT" && pwd)"

echo "[*] SAST orchestration: repo=$REPO out=$OUT"

# Always-on, language-agnostic
(
  command -v semgrep >/dev/null && {
    echo "[*] semgrep"
    semgrep --config=auto --config=p/security-audit --config=p/secrets \
            --sarif -o "$OUT/semgrep.sarif" "$REPO" 2>"$OUT/semgrep.err" \
      && echo "[+] semgrep done" || echo "[!] semgrep failed (see $OUT/semgrep.err)"
  }
) &

(
  command -v gitleaks >/dev/null && {
    echo "[*] gitleaks"
    gitleaks detect --source="$REPO" \
                    --report-path="$OUT/gitleaks.sarif" \
                    --report-format=sarif 2>"$OUT/gitleaks.err" \
      && echo "[+] gitleaks done" || echo "[!] gitleaks non-zero (findings or error)"
  }
) &

# Per-language (fire all; tools no-op on empty codebases)
(
  command -v bandit >/dev/null && {
    echo "[*] bandit (python)"
    bandit -r "$REPO" -f sarif -o "$OUT/bandit.sarif" -ll -ii 2>"$OUT/bandit.err" \
      && echo "[+] bandit done" || echo "[!] bandit non-zero"
  }
) &

(
  command -v gosec >/dev/null && {
    echo "[*] gosec (go)"
    gosec -fmt=sarif -out="$OUT/gosec.sarif" "$REPO/..." 2>"$OUT/gosec.err" \
      && echo "[+] gosec done" || echo "[!] gosec non-zero"
  }
) &

(
  command -v brakeman >/dev/null && [ -f "$REPO/Gemfile" ] && {
    echo "[*] brakeman (rails)"
    brakeman "$REPO" -f sarif -o "$OUT/brakeman.sarif" 2>"$OUT/brakeman.err" \
      && echo "[+] brakeman done" || echo "[!] brakeman non-zero"
  }
) &

(
  if command -v npx >/dev/null && [ -f "$REPO/package.json" ]; then
    echo "[*] eslint (js/ts)"
    (cd "$REPO" && npx --no eslint --format @microsoft/eslint-formatter-sarif \
                       --output-file "$OUT/eslint.sarif" . 2>"$OUT/eslint.err") \
      && echo "[+] eslint done" || echo "[!] eslint non-zero"
  fi
) &

# CodeQL: one DB per language, analyze after create per language
if command -v codeql >/dev/null; then
  for lang in python javascript java go ruby; do
    (
      echo "[*] codeql/$lang create"
      codeql database create "$OUT/codeql-$lang" \
            --language="$lang" --source-root="$REPO" \
            --overwrite 2>"$OUT/codeql-$lang.err" || { echo "[!] codeql $lang DB failed"; exit 0; }
      echo "[*] codeql/$lang analyze"
      codeql database analyze "$OUT/codeql-$lang" \
            "codeql/${lang}-queries:codeql-suites/${lang}-security-extended.qls" \
            --format=sarif-latest \
            --output="$OUT/codeql-$lang.sarif" 2>>"$OUT/codeql-$lang.err" \
        && echo "[+] codeql/$lang done" || echo "[!] codeql/$lang analyze failed"
    ) &
  done
fi

wait
echo "[+] all scans complete; SARIF in $OUT"
