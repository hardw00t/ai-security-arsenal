# Java (Maven / Gradle) Reference

## Manifest + lockfile files

| File | Purpose |
|------|---------|
| `pom.xml` | Maven manifest |
| `build.gradle` / `build.gradle.kts` | Gradle manifest |
| `gradle.lockfile` | Gradle lockfile (opt-in) |
| `settings.gradle` | Gradle multi-project |
| `libs.versions.toml` | Gradle version catalog |
| `~/.m2/repository/` | local Maven cache |

Note: Maven has no true lockfile by default. Use `dependency:resolve` output or `versions-maven-plugin` pins, or `maven-lockfile` plugin.

## SBOM generation

```bash
# CycloneDX Maven plugin
mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom
# produces target/bom.json + target/bom.xml

# CycloneDX Gradle plugin
# In build.gradle:
#   plugins { id 'org.cyclonedx.bom' version '1.10.0' }
./gradlew cyclonedxBom
# produces build/reports/bom.json

# Syft
syft dir:. -o cyclonedx-json=sbom.cdx.json
```

## Vulnerability scanning

```bash
# OWASP Dependency-Check (Maven)
mvn org.owasp:dependency-check-maven:check
mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7

# OWASP Dependency-Check (Gradle)
./gradlew dependencyCheckAnalyze
./gradlew dependencyCheckAnalyze -PfailBuildOnCVSS=7

# Snyk
snyk test --file=pom.xml
snyk test --all-projects          # multi-module
snyk test --gradle-sub-project=app

# OSV-Scanner
osv-scanner --lockfile=pom.xml       # experimental
osv-scanner --lockfile=gradle.lockfile

# Trivy
trivy fs --scanners vuln pom.xml
trivy fs . --skip-dirs target
```

## Dependency tree inspection

```bash
# Maven
mvn dependency:tree
mvn dependency:tree -Dincludes=<groupId>:<artifactId>
mvn dependency:tree -Dverbose           # shows conflicts/overrides

# Why is this here?
mvn dependency:tree -Dincludes=org.apache.logging.log4j:*

# Gradle
./gradlew dependencies
./gradlew dependencies --configuration=runtimeClasspath
./gradlew dependencyInsight --dependency log4j-core --configuration runtimeClasspath
```

## Version pinning + lockfile

```bash
# Gradle lockfile (enable per-project)
# build.gradle:
#   dependencyLocking { lockAllConfigurations() }
./gradlew dependencies --write-locks
./gradlew dependencies --update-locks 'com.google.guava:*'

# Maven — use maven-lockfile plugin (third-party)
mvn io.github.chains-project:maven-lockfile:generate
mvn io.github.chains-project:maven-lockfile:validate
```

## License extraction

```bash
# Maven
mvn org.codehaus.mojo:license-maven-plugin:aggregate-third-party-report
mvn license:aggregate-add-third-party

# Gradle
./gradlew generateLicenseReport   # via com.github.jk1.dependency-license-report plugin
```

## Common vulnerability patterns

| Class | Example CVE | Scope |
|-------|-------------|-------|
| Log4Shell / JNDI injection | CVE-2021-44228 (log4j-core) | any Java |
| Spring4Shell | CVE-2022-22965 (spring-core) | Spring MVC |
| Jackson polymorphic deserialization | many CVEs jackson-databind | Jackson |
| Struts RCE | CVE-2017-5638 | Struts 2 |
| XXE | many (commons, jackson) | XML parsers |
| XStream deserialization | CVE-2021-39139 | XStream |

## Reachability hints specific to Java

- Framework-injected beans (Spring `@Autowired`, Jakarta CDI) — static call graphs miss these; treat as reachable.
- Jackson polymorphic type handling (`@JsonTypeInfo`) — if enabled anywhere, the whole class of deserialization vulns becomes reachable.
- Shaded/uber JARs bundle dependency bytecode — the SBOM must reflect shaded deps or scans miss vulns. Use `maven-shade-plugin`'s dependency-reduced pom.

## Gotchas

- `mvn dependency-check` downloads the NVD DB on first run (slow + rate-limited without API key). Set `NVD_API_KEY`.
- Gradle without lockfile: each build can resolve different versions. Always enable `dependencyLocking` for reproducible scans.
- Maven `<dependencyManagement>` without `<dependencies>` doesn't pull the dep — easy false positive.
- Transitive version overrides (`<dependency>` with explicit version) are easy to miss in dependency:tree output without `-Dverbose`.
- Test-only scopes (`<scope>test</scope>`) don't ship; filter by scope in scanners.

## Tool minimums (2026-04)

- Maven >= 3.9
- Gradle >= 8.10
- dependency-check-maven >= 10.0
- cyclonedx-maven-plugin >= 2.8
- Snyk CLI >= 1.1293
