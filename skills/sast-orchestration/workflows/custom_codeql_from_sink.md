# Workflow: CodeQL Taint-Tracking Query from a Sink

Given a new dangerous API (sink) — e.g., `myorm.raw_query(sql)`, `internal.exec(cmd)` — write a taint-tracking query that flags user input reaching it.

## Reasoning budget: HIGH

CodeQL query design requires:
- Knowing the right standard-library module for sources (`flask`, `express`, `servlet`).
- Modeling the sink shape in QL (method? constructor? argument index?).
- Choosing sanitizers to silence known-safe paths.
- Deciding between `problem` and `path-problem` (`path-problem` is almost always right for taint).

Budget: expect multiple iterations. Use the CodeQL extension in VS Code to iterate.

## Inputs

- Sink API: fully-qualified name, argument that takes the dangerous value, sanitizer names (if any).
- Language.
- Existing CodeQL database (or create one — see `references/codeql.md`).

## Template (Python)

Use `examples/codeql_queries/taint_template.ql` as the starting point. Adapt the three predicates: `isSource`, `isSink`, `isBarrier`.

```ql
/**
 * @name Custom taint to myorm.raw_query
 * @description Untrusted input reaches myorm.raw_query
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision medium
 * @id py/custom-taint-myorm-raw
 * @tags security external/cwe/cwe-089
 */

import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

module CustomConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    // HTTP inputs — Flask, Django, FastAPI shapes
    src = API::moduleImport("flask").getMember("request").getMember(_).getACall()
    or
    src = API::moduleImport("django").getMember("http").getMember("HttpRequest").getInstance().getMember(_).getACall()
    or
    exists(API::Node fastapi |
      fastapi = API::moduleImport("fastapi") and
      src = fastapi.getMember("Request").getInstance().getMember(_).getACall()
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode c |
      c = API::moduleImport("myorm").getMember("raw_query").getACall() and
      sink = c.getArg(0)
    )
  }

  predicate isBarrier(DataFlow::Node n) {
    // Known safe: parameterized wrapper
    n = API::moduleImport("myorm").getMember("quote_literal").getACall()
  }
}

module CustomFlow = TaintTracking::Global<CustomConfig>;
import CustomFlow::PathGraph

from CustomFlow::PathNode source, CustomFlow::PathNode sink
where CustomFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
       "User input from $@ flows to myorm.raw_query.",
       source.getNode(), "HTTP request"
```

## Language variants

### JavaScript / TypeScript

```ql
import javascript
import semmle.javascript.security.dataflow.TaintTracking

module CustomConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    src instanceof RemoteFlowSource  // built-in: req params, body, headers
  }
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode c |
      c = API::moduleImport("myorm").getMember("rawQuery").getACall() and
      sink = c.getArgument(0)
    )
  }
}
module CustomFlow = TaintTracking::Global<CustomConfig>;
```

### Java

```ql
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking

module CustomConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    src instanceof RemoteFlowSource
  }
  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall mc |
      mc.getMethod().hasQualifiedName("com.acme.myorm", "MyOrm", "rawQuery") and
      sink.asExpr() = mc.getArgument(0)
    )
  }
}
module CustomFlow = TaintTracking::Global<CustomConfig>;
```

### Go

```ql
import go
import semmle.go.dataflow.TaintTracking

module CustomConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) { src instanceof UntrustedFlowSource::Range }
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode c |
      c.getTarget().hasQualifiedName("github.com/acme/myorm", "RawQuery") and
      sink = c.getArgument(0)
    )
  }
}
module CustomFlow = TaintTracking::Global<CustomConfig>;
```

## Sink-shape reference

| Sink shape | QL snippet |
|-----------|------------|
| Function top-level | `API::moduleImport("pkg").getMember("fn").getACall()` |
| Method on class instance | `API::moduleImport("pkg").getMember("Cls").getInstance().getMember("m").getACall()` |
| Constructor argument | `API::moduleImport("pkg").getMember("Cls").getACall()` (the call itself is the instance) |
| Nth positional arg | `.getArg(n)` (Py) / `.getArgument(n)` (JS/Java) |
| Keyword arg | `.getArgByName("key")` |

## Sources cheat sheet

| Language | Built-in "untrusted" source |
|----------|----------------------------|
| Python | Manual: `flask.request.*`, `django.http.HttpRequest.*`, `fastapi.Request.*` |
| JavaScript | `RemoteFlowSource` |
| Java | `RemoteFlowSource` |
| Go | `UntrustedFlowSource::Range` |
| Ruby | `Http::ActiveRecordSqlExecutionRange` et al — check `codeql/ruby-queries` |
| C/C++ | `FlowSource` (manual modeling required) |

## Iteration loop

1. Write minimal `isSource` + `isSink` with an empty `isBarrier`.
2. Run against a test DB seeded with a known TP and a known TN.
3. If FN on TP: check sink shape (usually argument index wrong).
4. If FP on TN: add `isBarrier` for the sanitizer used there.
5. Raise `@precision` once FP rate stabilizes <10%.

## Test harness

Place a `.ql` file next to a `.expected` file with expected results. Use `codeql test run <path>`.

## When to use CodeQL vs Semgrep for custom rules

- If inter-procedural flow across >2 files is required → CodeQL.
- If the sink is one well-defined API and codebase already has a CodeQL DB → CodeQL.
- If rule must run in every PR on every language → Semgrep (faster iteration).
- If you need high precision for a single vulnerability family → CodeQL.
