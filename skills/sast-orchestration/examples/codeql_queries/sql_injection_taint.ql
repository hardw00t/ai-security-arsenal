/**
 * @name SQL injection via cursor.execute
 * @description User input flows into cursor.execute as the SQL string.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/sql-injection-custom
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

module SqliConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    // Flask
    src = API::moduleImport("flask").getMember("request").getMember(_).getACall()
    or
    // Django HttpRequest
    exists(DataFlow::AttrRead a |
      a.getAttributeName() in ["GET", "POST", "COOKIES", "META"] and
      src = a
    )
    or
    // FastAPI
    src = API::moduleImport("fastapi").getMember("Request").getInstance().getMember(_).getACall()
  }

  predicate isSink(DataFlow::Node sink) {
    // Any *.execute / *.executemany first arg
    exists(DataFlow::MethodCallNode c |
      c.getMethodName() in ["execute", "executemany"] and
      sink = c.getArg(0)
    )
  }

  predicate isBarrier(DataFlow::Node n) {
    // int() / float() coercion sanitizes for SQL number contexts
    exists(DataFlow::CallCfgNode c |
      c = API::builtin("int").getACall() or
      c = API::builtin("float").getACall() |
      n = c
    )
    or
    // sqlalchemy.text wraps a literal safely
    n = API::moduleImport("sqlalchemy").getMember("text").getACall()
  }
}

module SqliFlow = TaintTracking::Global<SqliConfig>;
import SqliFlow::PathGraph

from SqliFlow::PathNode source, SqliFlow::PathNode sink
where SqliFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection: untrusted input from $@ reaches cursor.execute.",
  source.getNode(), "user input"
