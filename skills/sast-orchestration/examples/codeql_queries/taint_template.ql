/**
 * @name Custom taint tracking template
 * @description Edit isSource, isSink, isBarrier for the vulnerability class you're modeling.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision medium
 * @id py/custom-taint-template
 * @tags security
 */

import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

module CustomConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    // HTTP untrusted sources — Flask, Django, FastAPI
    src = API::moduleImport("flask").getMember("request").getMember(_).getACall()
    or
    src = API::moduleImport("fastapi").getMember("Request").getInstance().getMember(_).getACall()
    or
    exists(DataFlow::CallCfgNode c |
      c = API::moduleImport("django").getMember("http").getMember("HttpRequest").getInstance().getMember("GET").getACall() and
      src = c
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // REPLACE with your target sink
    exists(DataFlow::CallCfgNode c |
      c = API::moduleImport("os").getMember("system").getACall() and
      sink = c.getArg(0)
    )
  }

  predicate isBarrier(DataFlow::Node n) {
    // Sanitizers: recognized safe wrappers
    n = API::moduleImport("shlex").getMember("quote").getACall()
  }
}

module CustomFlow = TaintTracking::Global<CustomConfig>;
import CustomFlow::PathGraph

from CustomFlow::PathNode source, CustomFlow::PathNode sink
where CustomFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted input from $@ reaches dangerous sink.",
  source.getNode(), "here"
