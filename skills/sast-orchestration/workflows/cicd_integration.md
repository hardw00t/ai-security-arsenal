# Workflow: SAST in CI/CD

Embed SAST in the pipeline so every PR is scanned, SARIF is aggregated, and gates fail on high-severity findings only.

## Reasoning budget: LOW

This is mostly configuration. Extended thinking only needed for:
- Choosing the gating policy (which severities fail the build).
- Designing incremental scan modes for PRs vs. full scans on main.

## Gating policy (recommended)

| Trigger | Tools | Gate on |
|---------|-------|---------|
| PR to main | Semgrep (diff mode), Gitleaks | New ERROR-level findings only |
| Push to main | Full Semgrep + language-specific | Any critical/high |
| Nightly | Full Semgrep + CodeQL + all tools | Reporting (no gate) |
| Release tag | Full + SBOM + SCA | Any critical |

Never gate on total finding count (incentivizes suppression spam). Gate on new-in-PR findings.

## GitHub Actions

```yaml
name: SAST
on:
  pull_request: { branches: [main] }
  push:         { branches: [main, develop] }
  schedule:     [ { cron: '0 2 * * *' } ]

permissions:
  contents: read
  security-events: write   # required for SARIF upload

jobs:
  semgrep:
    runs-on: ubuntu-latest
    container: returntocorp/semgrep
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - name: Semgrep (diff for PR, full for push)
        run: |
          if [ "${{ github.event_name }}" = "pull_request" ]; then
            semgrep ci --sarif -o semgrep.sarif
          else
            semgrep --config=auto --config=p/security-audit --config=p/secrets \
                    --sarif -o semgrep.sarif .
          fi
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: semgrep.sarif, category: semgrep }

  codeql:
    runs-on: ubuntu-latest
    strategy:
      matrix: { language: [python, javascript, java] }
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with: { languages: ${{ matrix.language }}, queries: security-extended }
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
        with: { category: "/language:${{ matrix.language }}" }

  bandit:
    runs-on: ubuntu-latest
    if: contains(github.event.repository.language, 'Python')
    steps:
      - uses: actions/checkout@v4
      - run: pip install 'bandit[sarif]' && bandit -r . -f sarif -o bandit.sarif -ll -ii || true
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: bandit.sarif, category: bandit }

  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}   # org-only
```

## GitLab CI

```yaml
stages: [sast]

semgrep:
  stage: sast
  image: returntocorp/semgrep
  script:
    - semgrep ci --sarif -o semgrep.sarif
  artifacts:
    reports:
      sast: semgrep.sarif
    when: always
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'

bandit:
  stage: sast
  image: python:3.12
  script:
    - pip install 'bandit[sarif]'
    - bandit -r . -f sarif -o bandit.sarif -ll -ii || true
  artifacts:
    reports:
      sast: bandit.sarif

codeql:
  stage: sast
  image: mcr.microsoft.com/cstsectools/codeql-container:latest
  script:
    - codeql database create db --language=python --source-root=.
    - codeql database analyze db codeql/python-queries:codeql-suites/python-security-extended.qls
                                --format=sarif-latest --output=codeql.sarif
  artifacts: { reports: { sast: codeql.sarif } }
  rules:
    - if: '$CI_COMMIT_BRANCH == "main"'
```

## Bitbucket Pipelines

```yaml
image: python:3.12
pipelines:
  pull-requests:
    '**':
      - step:
          name: SAST
          script:
            - pip install semgrep 'bandit[sarif]'
            - semgrep ci --sarif -o semgrep.sarif
            - bandit -r . -f sarif -o bandit.sarif -ll -ii || true
          artifacts:
            - semgrep.sarif
            - bandit.sarif
  branches:
    main:
      - step:
          name: Full SAST
          size: 2x
          script:
            - pip install semgrep 'bandit[sarif]'
            - semgrep --config=auto --config=p/security-audit --sarif -o semgrep.sarif .
            - bandit -r . -f sarif -o bandit.sarif -ll -ii || true
```

## Jenkins (declarative)

```groovy
pipeline {
  agent any
  stages {
    stage('SAST') {
      parallel {
        stage('Semgrep') {
          steps {
            sh 'pip install semgrep && semgrep --config=auto --sarif -o semgrep.sarif .'
            archiveArtifacts 'semgrep.sarif'
          }
        }
        stage('Bandit') {
          when { expression { fileExists('requirements.txt') } }
          steps {
            sh "pip install 'bandit[sarif]' && bandit -r . -f sarif -o bandit.sarif -ll -ii || true"
            archiveArtifacts 'bandit.sarif'
          }
        }
      }
    }
  }
}
```

## Pre-commit hooks (developer-local)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.60.0
    hooks:
      - id: semgrep
        args: ['--config', 'p/secrets', '--error']
  - repo: https://github.com/PyCQA/bandit
    rev: 1.8.0
    hooks:
      - id: bandit
        args: ['-ll', '-ii']
        exclude: ^tests/
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.20.0
    hooks:
      - id: gitleaks
```

## Incremental (diff) mode

Diff-only scans are much faster for PRs:
- Semgrep: `semgrep ci` auto-detects baseline vs. HEAD on PRs.
- CodeQL: incremental DB analysis via `--no-download` + cached DB.
- Bandit: `bandit $(git diff --name-only origin/main...HEAD)`.
- gosec: not native; use `git diff` filter.

## PR comment automation

GitHub code scanning renders SARIF inline on PR diffs automatically once uploaded via `upload-sarif`. For other providers:
- Reviewdog integrates Semgrep/Bandit output as PR comments: `reviewdog -f=sarif`.
- GitLab SAST reports render in MR diff natively when the job emits a `reports.sast` artifact.

## Baseline management

For existing codebases with many pre-existing findings:
1. Run full scan, commit the SARIF as the baseline.
2. Gate only on findings NOT in the baseline.
3. Expire the baseline (e.g., quarterly) to force cleanup.

```bash
# Semgrep baseline
semgrep --baseline-ref=origin/main --config=auto --sarif -o diff.sarif .
```
