# SpotBugs + Find Security Bugs Reference (Java/JVM)

Bytecode-level analysis — works on compiled `.class` / `.jar`, not source. Find Security Bugs (FSB) is the security plugin for SpotBugs.

## Install / invoke

### Maven

```xml
<plugin>
  <groupId>com.github.spotbugs</groupId>
  <artifactId>spotbugs-maven-plugin</artifactId>
  <version>4.8.6.0</version>
  <configuration>
    <plugins>
      <plugin>
        <groupId>com.h3xstream.findsecbugs</groupId>
        <artifactId>findsecbugs-plugin</artifactId>
        <version>1.13.0</version>
      </plugin>
    </plugins>
    <effort>Max</effort>
    <threshold>Low</threshold>
    <includeFilterFile>spotbugs-security-include.xml</includeFilterFile>
    <sarifOutput>true</sarifOutput>
  </configuration>
</plugin>
```

```bash
mvn compile spotbugs:check        # fail build on findings
mvn compile spotbugs:spotbugs     # generate report only
mvn compile spotbugs:gui          # interactive review UI
```

### Gradle

```groovy
plugins { id 'com.github.spotbugs' version '6.0.18' }
dependencies {
    spotbugsPlugins 'com.h3xstream.findsecbugs:findsecbugs-plugin:1.13.0'
}
spotbugs {
    effort = 'max'
    reportLevel = 'low'
}
spotbugsMain { reports { sarif.required = true } }
```

### CLI

```bash
spotbugs -pluginList findsecbugs-plugin-1.13.0.jar \
  -effort:max -low -sarif -output spotbugs.sarif target/classes
```

## Filter file (scope to security checks)

```xml
<!-- spotbugs-security-include.xml -->
<FindBugsFilter>
  <Match><Bug category="SECURITY"/></Match>
</FindBugsFilter>
```

## High-value FSB detectors

| Pattern | Class |
|---------|-------|
| SQL_INJECTION_JDBC / HIBERNATE / JPA / SPRING_JDBC | SQL injection variants |
| COMMAND_INJECTION | Runtime.exec with user input |
| XXE_SAXPARSER / XXE_DOCUMENT / XXE_XMLREADER | XML external entity |
| PATH_TRAVERSAL_IN / PATH_TRAVERSAL_OUT | File path taint |
| XSS_SERVLET / XSS_REQUEST_WRAPPER | Servlet XSS |
| LDAP_INJECTION | LDAP injection |
| WEAK_MESSAGE_DIGEST_MD5 / SHA1 | Weak hash |
| CIPHER_INTEGRITY / ECB_MODE / STATIC_IV | Crypto misuse |
| HARD_CODE_PASSWORD / KEY | Hardcoded secrets |
| INSECURE_COOKIE / HTTPONLY_COOKIE | Cookie flags |
| TRUST_BOUNDARY_VIOLATION | Session tainting |
| DESERIALIZATION_GADGET / OBJECT_DESERIALIZATION | Unsafe deserialization |
| URL_REWRITING | Session-in-URL |

## Suppression

```java
@edu.umd.cs.findbugs.annotations.SuppressFBWarnings(
    value = "SQL_INJECTION_JDBC",
    justification = "Query literal is constant; @varValue is validated allowlist"
)
```

## Known limits

- Requires compiled bytecode — cannot scan source-only.
- No Kotlin-specific patterns (analyze compiled Kotlin, but detector coverage is Java-centric).
- Deserialization gadget detection is pattern-based; pair with CodeQL Java suite.

## Pair with

- Semgrep `p/java p/spring` for source-level patterns.
- CodeQL Java suite for inter-procedural taint.
- Dependency-Check / OWASP DC for dependency CVEs — see sca-security.
