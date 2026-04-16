# CodeQL Reference

Deep, semantic, inter-procedural SAST with a declarative query language (QL). Best for taint-tracking chains, complex dataflow, and authoritative detection where FP cost is high.

## Install

```bash
# Download CLI: https://github.com/github/codeql-cli-binaries/releases
# Clone standard libraries:
git clone https://github.com/github/codeql.git ~/codeql-home/codeql-repo
export PATH="$HOME/codeql-home/codeql:$PATH"
codeql resolve qlpacks  # verify
```

Supported languages (2026-04): C/C++, C#, Go, Java/Kotlin, JavaScript/TypeScript, Python, Ruby, Swift.

## Workflow

```
1. Create database   ──►  2. Run queries/suites   ──►  3. Emit SARIF
   (codeql database       (codeql database             (upload or triage)
    create)                 analyze)
```

### Step 1: database creation (must complete before any query runs)

```bash
# Interpreted languages (Python, JS, Ruby): source-only
codeql database create ./db --language=python --source-root=./src

# Compiled (Java, Go, C/C++): needs build command
codeql database create ./db --language=java \
  --command='mvn clean install -DskipTests' \
  --source-root=.

# Multi-language repo: one DB per language, run in parallel
```

### Step 2: analyze with built-in suites

```bash
# Security + maintainability (extended)
codeql database analyze ./db \
  codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest --output=results.sarif

# Security only (lower FP)
codeql database analyze ./db \
  codeql/python-queries:codeql-suites/python-security-and-quality.qls \
  --format=sarif-latest --output=results.sarif

# Single custom query
codeql database analyze ./db ./custom/sql-injection.ql \
  --format=csv --output=results.csv
```

Suites by language (pattern: `codeql/<lang>-queries:codeql-suites/<lang>-security-extended.qls`):
`python`, `javascript`, `java`, `go`, `ruby`, `csharp`, `cpp`, `swift`.

## Query pack structure

```
my-pack/
  qlpack.yml         # name, version, dependencies
  src/
    MyQuery.ql       # query with metadata
    MyQuery.qlref    # optional: reference form
```

`qlpack.yml`:
```yaml
name: my-org/my-security-queries
version: 0.0.1
dependencies:
  codeql/python-all: "*"
```

## Query metadata (required for analyze to pick it up)

```ql
/**
 * @name SQL injection
 * @description User input flows to SQL query without sanitization
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/sql-injection-custom
 * @tags security
 *       external/cwe/cwe-089
 */
```

`@kind`: `problem` (single location) or `path-problem` (source→sink path, renders in SARIF).

## Taint-tracking skeleton (modern API)

```ql
import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    src = API::moduleImport("flask").getMember("request").getMember(_).getACall()
  }
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode c |
      c = API::moduleImport("subprocess").getMember(_).getACall() and
      sink = c.getArg(0)
    )
  }
  predicate isBarrier(DataFlow::Node n) {
    n = API::moduleImport("shlex").getMember("quote").getACall()
  }
}

module MyFlow = TaintTracking::Global<MyConfig>;
import MyFlow::PathGraph

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Command injection from $@.",
       source.getNode(), "user input"
```

## Starter queries

See `examples/codeql_queries/`:
- `taint_template.ql` — generic taint-tracking skeleton
- `hardcoded_credential.ql` — single-location problem query

## Query development loop

1. `codeql database create` once per codebase change.
2. Open VS Code + CodeQL extension, point at DB.
3. Iterate query; use `codeql test run` with `.expected` fixtures.
4. `codeql database analyze` for final SARIF.

## Performance

- DB creation is the expensive step (minutes to hours). Cache per-commit.
- Large codebases: `--ram=<MB> --threads=<n>`.
- `--fast-compilation` for iteration (lower precision).

## When to prefer CodeQL over Semgrep

- Need true inter-procedural, inter-file taint.
- Custom sanitizer / source modeling.
- Publishing to GitHub code scanning (native SARIF integration).
- Low-FP requirement on a narrow, high-value vulnerability class.

Prefer Semgrep for: rapid iteration, non-build-able source, pattern-match rules, broad language coverage (PHP, HCL, Dockerfile, YAML).
