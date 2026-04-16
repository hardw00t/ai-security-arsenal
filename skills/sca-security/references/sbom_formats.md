# SBOM Formats: CycloneDX vs SPDX

Both are OWASP/ISO-aligned and tool-interop targets. Use CycloneDX for security-centric workflows (vuln linking, VEX); use SPDX for license-centric and compliance-heavy workflows. Modern tooling supports both — generate one and convert if needed.

## Top-level document fields

| Concept | CycloneDX 1.6 | SPDX 2.3 |
|---------|---------------|----------|
| Format version | `specVersion: "1.6"` | `spdxVersion: "SPDX-2.3"` |
| Unique doc ID | `serialNumber` (urn:uuid:...) | `documentNamespace` (URI) |
| Doc name | `metadata.component.name` | `name` |
| Timestamp | `metadata.timestamp` (ISO-8601) | `creationInfo.created` |
| Tool that built it | `metadata.tools[]` | `creationInfo.creators[]` |
| License | `metadata.licenses[]` (of doc itself) | `dataLicense` (usually CC0-1.0) |

## Component / package fields

| Concept | CycloneDX | SPDX |
|---------|-----------|------|
| Package identity | `components[].purl` (Package URL) | `packages[].externalRefs[].referenceLocator` (with type=purl) |
| Name | `components[].name` | `packages[].name` |
| Version | `components[].version` | `packages[].versionInfo` |
| Type | `components[].type` (library/application/os/...) | `packages[].primaryPackagePurpose` |
| Declared license | `components[].licenses[].license.id` | `packages[].licenseDeclared` |
| Concluded license | (same field; distinguish via `.license.name` vs `.id`) | `packages[].licenseConcluded` |
| Copyright | `components[].copyright` | `packages[].copyrightText` |
| Hash | `components[].hashes[]` | `packages[].checksums[]` |
| Download URL | `components[].externalReferences[].type="distribution"` | `packages[].downloadLocation` |
| Supplier | `components[].supplier.name` | `packages[].supplier` |
| Author | `components[].author` | `packages[].originator` |
| Description | `components[].description` | `packages[].description` |
| VCS link | `components[].externalReferences[].type="vcs"` | `packages[].sourceInfo` (informal) |
| PURL | first-class | via externalRef with referenceCategory=PACKAGE-MANAGER |

## Relationships

| Concept | CycloneDX | SPDX |
|---------|-----------|------|
| Dependency graph | `dependencies[]` (array of `{ref, dependsOn: [...]}`) | `relationships[]` with `DEPENDS_ON`, `DEPENDENCY_OF`, etc. |
| Build-time only | `scope: "excluded"` / `"optional"` | `BUILD_DEPENDENCY_OF` |
| Container image of package | `components[].pedigree` | `CONTAINS` / `CONTAINED_BY` |

## Vulnerability / VEX

| Concept | CycloneDX | SPDX |
|---------|-----------|------|
| Inline vulns | `vulnerabilities[]` | No first-class; use external VEX |
| VEX | CycloneDX VEX (in same doc or separate) | OpenVEX or CSAF-VEX (separate) |
| Exploitability status | `vulnerabilities[].analysis.state` (exploitable, not_affected, ...) | OpenVEX `status` |

**CycloneDX wins for security workflows** because vuln + VEX are first-class in-format.

## When to pick which

Pick **CycloneDX** when:
- Security team owns the SBOM (vuln triage, VEX)
- Tools are Grype, Trivy, Snyk, Dependency-Track (native CDX)
- You need fast iteration + simpler JSON schema

Pick **SPDX** when:
- Legal / compliance team consumes it (license scrutiny, FOSSA, Fossology)
- Your procurement process or customer contract names SPDX
- You need ISO/IEC 5962:2021 citation

## Conversion

```bash
# cyclonedx-cli
cyclonedx convert --input-file sbom.spdx.json --input-format spdxjson \
  --output-file sbom.cdx.json --output-format json

# spdx-tools
pyspdxtools --input-file sbom.cdx.json --output-file sbom.spdx.json
```

Lossy conversions (common): VEX fields, CDX's `pedigree` (patching ancestry), CDX's `services` (for SaaS components).

## Validation

```bash
# CycloneDX
cyclonedx validate --input-file sbom.cdx.json

# SPDX
pyspdxtools --input-file sbom.spdx.json
# or: spdx-sbom-generator, tern
```

## Required minimum fields (NTIA "minimum elements")

Per NTIA (US EO 14028-derived baseline):
- Supplier name
- Component name
- Version
- Unique identifier (PURL or CPE)
- Dependency relationship
- SBOM author
- Timestamp

Both CDX and SPDX support all of these; neither **enforces** them by default. Validate before handoff.

## Versions (2026-04)

- CycloneDX: 1.6 current, 1.7 draft
- SPDX: 2.3 current, 3.0 adopted by some tools (major restructure)
