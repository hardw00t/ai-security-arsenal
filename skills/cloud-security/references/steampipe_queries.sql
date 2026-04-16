-- Steampipe SQL reference for multi-cloud security auditing.
-- These are patterns — adapt column filters to the exact schema of your plugin version.
-- Verify schemas with: `\d+ <table_name>` inside the steampipe shell.
--
-- Plugin install:
--   steampipe plugin install aws azure gcp
--
-- Invoke:
--   steampipe query "SELECT ..."
--   steampipe query ./file.sql --output json > findings.json
--
-- Frontier model tip: when a query returns nothing, introspect the schema and rewrite.
-- Steampipe column names follow the upstream API — read the plugin docs if unsure.

-- =============================================================================
-- AWS
-- =============================================================================

-- Public S3 buckets (by policy evaluation)
SELECT name, region, bucket_policy_is_public, block_public_acls, block_public_policy
FROM   aws_s3_bucket
WHERE  bucket_policy_is_public = true
   OR  block_public_acls       = false
   OR  block_public_policy     = false;

-- S3 buckets with public ACL grants
SELECT name, region, acl, grants
FROM   aws_s3_bucket,
       jsonb_array_elements(acl -> 'Grants') AS grants
WHERE  grants -> 'Grantee' ->> 'URI' IN (
         'http://acs.amazonaws.com/groups/global/AllUsers',
         'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
       );

-- Security group rules allowing 0.0.0.0/0
SELECT sg.group_id, sg.group_name, sg.vpc_id,
       rule.ip_protocol, rule.from_port, rule.to_port, rule.cidr_ipv4
FROM   aws_vpc_security_group_rule rule
JOIN   aws_vpc_security_group sg ON rule.group_id = sg.group_id
WHERE  rule.cidr_ipv4 = '0.0.0.0/0'
  AND  rule.is_egress = false
  AND  rule.from_port IN (22, 3389, 3306, 5432, 27017, 1433, 6379, 9200);

-- IAM users without MFA
SELECT name, create_date, password_last_used, mfa_enabled
FROM   aws_iam_user
WHERE  mfa_enabled = false;

-- Access keys older than 90 days
SELECT u.name, k.access_key_id, k.create_date, k.status,
       EXTRACT(DAY FROM now() - k.create_date) AS age_days
FROM   aws_iam_user u
JOIN   aws_iam_access_key k ON u.name = k.user_name
WHERE  k.status = 'Active'
  AND  k.create_date < now() - INTERVAL '90 days';

-- Policies granting * on *
SELECT name, arn, policy_std
FROM   aws_iam_policy,
       jsonb_array_elements(policy_std -> 'Statement') AS stmt
WHERE  stmt ->> 'Effect' = 'Allow'
  AND  stmt -> 'Action'   @> '["*"]'
  AND  stmt -> 'Resource' @> '["*"]';

-- Roles trusting overly broad principals
SELECT name, arn, assume_role_policy_std
FROM   aws_iam_role,
       jsonb_array_elements(assume_role_policy_std -> 'Statement') AS stmt
WHERE  stmt -> 'Principal' ->> 'AWS' IN ('*', 'arn:aws:iam::*:root');

-- RDS public + unencrypted
SELECT db_instance_identifier, engine, publicly_accessible, storage_encrypted
FROM   aws_rds_db_instance
WHERE  publicly_accessible = true
   OR  storage_encrypted   = false;

-- EBS volumes unencrypted
SELECT volume_id, size, state, encrypted, availability_zone, region
FROM   aws_ebs_volume
WHERE  encrypted = false;

-- CloudTrail: trails that are not multi-region or have logging disabled
SELECT name, home_region, is_multi_region_trail, is_logging, log_file_validation_enabled
FROM   aws_cloudtrail_trail
WHERE  is_multi_region_trail     = false
   OR  is_logging                = false
   OR  log_file_validation_enabled = false;

-- EC2 instances with IMDSv1 enabled (token optional)
SELECT instance_id, instance_type, region, metadata_options ->> 'HttpTokens' AS http_tokens
FROM   aws_ec2_instance
WHERE  metadata_options ->> 'HttpTokens' = 'optional';

-- =============================================================================
-- Azure
-- =============================================================================

-- Storage accounts allowing public blob access
SELECT name, resource_group, subscription_id, allow_blob_public_access,
       minimum_tls_version, enable_https_traffic_only
FROM   azure_storage_account
WHERE  allow_blob_public_access = true
   OR  minimum_tls_version     <> 'TLS1_2'
   OR  enable_https_traffic_only = false;

-- Key Vaults without purge protection or soft delete
SELECT name, resource_group, purge_protection_enabled, soft_delete_enabled,
       enable_rbac_authorization
FROM   azure_key_vault
WHERE  purge_protection_enabled = false
   OR  soft_delete_enabled     = false;

-- NSG rules exposing 22/3389 to Internet
SELECT nsg.name, nsg.resource_group,
       rule ->> 'name'                         AS rule_name,
       rule -> 'properties' ->> 'access'       AS access,
       rule -> 'properties' ->> 'direction'    AS direction,
       rule -> 'properties' ->> 'sourceAddressPrefix'      AS src,
       rule -> 'properties' ->> 'destinationPortRange'     AS dst_port
FROM   azure_network_security_group nsg,
       jsonb_array_elements(security_rules) AS rule
WHERE  rule -> 'properties' ->> 'access'    = 'Allow'
  AND  rule -> 'properties' ->> 'direction' = 'Inbound'
  AND  rule -> 'properties' ->> 'sourceAddressPrefix' IN ('*','Internet','0.0.0.0/0')
  AND  rule -> 'properties' ->> 'destinationPortRange' IN ('22','3389','*');

-- VMs without managed disk encryption
SELECT name, resource_group, location,
       os_disk -> 'managedDisk' ->> 'storageAccountType' AS disk_type
FROM   azure_compute_virtual_machine
WHERE  os_disk -> 'encryptionSettings' IS NULL;

-- Role assignments at subscription root with privileged role
SELECT ra.principal_id, ra.principal_type, rd.role_name, ra.scope
FROM   azure_role_assignment ra
JOIN   azure_role_definition rd ON ra.role_definition_id = rd.id
WHERE  rd.role_name IN ('Owner','Contributor','User Access Administrator')
  AND  ra.scope LIKE '/subscriptions/%'
  AND  ra.scope NOT LIKE '/subscriptions/%/resourceGroups/%';

-- =============================================================================
-- GCP
-- =============================================================================

-- Storage buckets world-readable
SELECT b.name, b.location, iam.member, iam.role
FROM   gcp_storage_bucket b,
       jsonb_to_recordset(b.iam_policy -> 'bindings') AS iam(role text, members jsonb),
       jsonb_array_elements_text(iam.members) AS member
WHERE  member IN ('allUsers','allAuthenticatedUsers');

-- Project-level IAM: owner/editor bindings (high privilege)
SELECT p.project_id, b.role, m AS member
FROM   gcp_project p,
       jsonb_to_recordset(p.iam_policy -> 'bindings') AS b(role text, members jsonb),
       jsonb_array_elements_text(b.members) AS m
WHERE  b.role IN ('roles/owner','roles/editor');

-- Service accounts with user-managed keys (long-lived)
SELECT sa.email, sa.project, k.name AS key_name, k.key_type, k.valid_after_time
FROM   gcp_service_account sa
JOIN   gcp_service_account_key k ON k.service_account_name = sa.name
WHERE  k.key_type = 'USER_MANAGED';

-- Compute instances with external IPs + default SA
SELECT name, zone, project,
       service_accounts,
       network_interfaces -> 0 -> 'accessConfigs' -> 0 ->> 'natIP' AS external_ip
FROM   gcp_compute_instance
WHERE  network_interfaces -> 0 -> 'accessConfigs' -> 0 ->> 'natIP' IS NOT NULL
  AND  EXISTS (
         SELECT 1 FROM jsonb_array_elements(service_accounts) sa
         WHERE sa ->> 'email' LIKE '%-compute@developer.gserviceaccount.com'
       );

-- Firewall rules allowing 0.0.0.0/0 on sensitive ports
SELECT name, network, direction, source_ranges, allowed
FROM   gcp_compute_firewall
WHERE  direction = 'INGRESS'
  AND  source_ranges @> '["0.0.0.0/0"]'
  AND  EXISTS (
         SELECT 1 FROM jsonb_array_elements(allowed) a
         WHERE a -> 'ports' @> '["22"]'
            OR a -> 'ports' @> '["3389"]'
            OR a -> 'ports' @> '["3306"]'
       );

-- Cloud SQL instances publicly accessible
SELECT name, database_version, region,
       settings -> 'ipConfiguration' ->> 'ipv4Enabled' AS public_ip,
       settings -> 'ipConfiguration' -> 'authorizedNetworks' AS auth_nets
FROM   gcp_sql_database_instance
WHERE  settings -> 'ipConfiguration' ->> 'ipv4Enabled' = 'true';

-- =============================================================================
-- Cross-cloud comparative queries (requires all three plugins installed)
-- =============================================================================

-- Count of public storage across clouds
SELECT 'aws'   AS cloud, count(*) AS public_buckets FROM aws_s3_bucket         WHERE bucket_policy_is_public = true
UNION ALL
SELECT 'azure' AS cloud, count(*) AS public_buckets FROM azure_storage_account WHERE allow_blob_public_access = true
UNION ALL
SELECT 'gcp'   AS cloud, count(*) AS public_buckets FROM gcp_storage_bucket b
WHERE EXISTS (
  SELECT 1 FROM jsonb_to_recordset(b.iam_policy -> 'bindings') AS bind(role text, members jsonb),
       jsonb_array_elements_text(bind.members) m
  WHERE m IN ('allUsers','allAuthenticatedUsers'));
