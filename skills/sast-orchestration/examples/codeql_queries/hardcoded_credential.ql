/**
 * @name Hardcoded credential
 * @description Variable with credential-like name is assigned a string literal in source.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id py/hardcoded-credential-custom
 * @tags security
 *       external/cwe/cwe-798
 */

import python

from Assign a, StringLiteral lit, Name target
where
  a.getATarget() = target and
  a.getValue() = lit and
  target.getId().regexpMatch("(?i).*(password|passwd|secret|token|api[_-]?key|apikey|credential).*") and
  lit.getText().length() > 5 and
  // Exclude empty / placeholder strings
  not lit.getText().regexpMatch("^(changeme|xxx+|\\*+|<[^>]+>|your[_-].*|example.*)$") and
  // Exclude test files
  not a.getLocation().getFile().getRelativePath().matches("%test%")
select a,
  "Hardcoded credential in variable '" + target.getId() + "'. " +
  "Load from environment or secrets manager instead."
