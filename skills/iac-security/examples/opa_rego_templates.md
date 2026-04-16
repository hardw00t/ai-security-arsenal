# Starter Rego Templates

Copy-paste starting points for common org controls. Pair each with a PASS/FAIL fixture per `workflows/policy_as_code_loop.md`.

All templates use the Conftest convention (`package main`, `deny[msg]`).

## Kubernetes

### Deny containers running as root
```rego
package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.runAsNonRoot
  msg := sprintf("Container %s must set runAsNonRoot=true", [container.name])
}
```

### Deny privileged containers
```rego
package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  container.securityContext.privileged == true
  msg := sprintf("Container %s must not be privileged", [container.name])
}
```

### Require CPU + memory limits
```rego
package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.cpu
  msg := sprintf("Container %s missing CPU limit", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.memory
  msg := sprintf("Container %s missing memory limit", [container.name])
}
```

### Deny hostNetwork / hostPID / hostIPC
```rego
package main

host_flags := {"hostNetwork", "hostPID", "hostIPC"}

deny[msg] {
  input.kind == "Deployment"
  flag := host_flags[_]
  input.spec.template.spec[flag] == true
  msg := sprintf("Deployment must not use %s", [flag])
}
```

### Require readOnlyRootFilesystem
```rego
package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.securityContext.readOnlyRootFilesystem
  msg := sprintf("Container %s must set readOnlyRootFilesystem=true", [container.name])
}
```

### Deny wildcard RBAC verbs/resources
```rego
package main

deny[msg] {
  input.kind == "ClusterRole"
  rule := input.rules[_]
  rule.verbs[_] == "*"
  msg := sprintf("ClusterRole %s uses wildcard verb", [input.metadata.name])
}

deny[msg] {
  input.kind == "ClusterRole"
  rule := input.rules[_]
  rule.resources[_] == "*"
  msg := sprintf("ClusterRole %s uses wildcard resource", [input.metadata.name])
}
```

### Deny :latest image tag
```rego
package main

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf("Container %s uses :latest tag", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not contains(container.image, ":")
  msg := sprintf("Container %s has unpinned image (no tag)", [container.name])
}
```

## Terraform (HCL parsed JSON)

Conftest parses HCL via `--parser hcl2`. Input shape: top-level `resource.<type>.<name>.<attrs>`.

### Enforce S3 encryption
```rego
package main

deny[msg] {
  bucket := input.resource.aws_s3_bucket[name]
  not bucket.server_side_encryption_configuration
  msg := sprintf("aws_s3_bucket.%s must configure server_side_encryption_configuration", [name])
}
```

### Enforce required tags on all AWS resources
```rego
package main

required_tags := {"Environment", "Owner", "DataClassification"}

deny[msg] {
  some resource_type, name
  resource := input.resource[resource_type][name]
  startswith(resource_type, "aws_")
  tags := object.get(resource, "tags", {})
  missing := required_tags - {t | tags[t]}
  count(missing) > 0
  msg := sprintf("%s.%s missing required tags: %v", [resource_type, name, missing])
}
```

### Deny public security group ingress on admin ports
```rego
package main

admin_ports := {22, 3389, 3306, 5432, 1433, 6379, 27017}

deny[msg] {
  sg := input.resource.aws_security_group[name]
  ingress := sg.ingress[_]
  ingress.cidr_blocks[_] == "0.0.0.0/0"
  port := admin_ports[_]
  port >= ingress.from_port
  port <= ingress.to_port
  msg := sprintf(
    "aws_security_group.%s exposes admin port %d to 0.0.0.0/0",
    [name, port]
  )
}
```

### Deny IAM policy with wildcard Action + Resource
```rego
package main

deny[msg] {
  policy := input.resource.aws_iam_policy[name]
  doc := json.unmarshal(policy.policy)
  statement := doc.Statement[_]
  statement.Effect == "Allow"
  statement.Action == "*"
  statement.Resource == "*"
  msg := sprintf("aws_iam_policy.%s allows *:* — wildcard privilege", [name])
}
```

## CloudFormation (JSON/YAML)

Conftest parses CFN YAML directly.

### Deny public S3 buckets
```rego
package main

deny[msg] {
  resource := input.Resources[name]
  resource.Type == "AWS::S3::Bucket"
  acl := object.get(resource.Properties, "AccessControl", "")
  acl == "PublicRead"
  msg := sprintf("S3 bucket %s has PublicRead ACL", [name])
}

deny[msg] {
  resource := input.Resources[name]
  resource.Type == "AWS::S3::Bucket"
  pab := object.get(resource.Properties, "PublicAccessBlockConfiguration", {})
  pab.BlockPublicAcls != true
  msg := sprintf("S3 bucket %s does not BlockPublicAcls", [name])
}
```

### Require RDS encryption
```rego
package main

deny[msg] {
  resource := input.Resources[name]
  resource.Type == "AWS::RDS::DBInstance"
  resource.Properties.StorageEncrypted != true
  msg := sprintf("RDS %s must set StorageEncrypted=true", [name])
}
```

## Tips for frontier models authoring new rules

1. Start from the closest template above; swap field paths and predicates.
2. Always write the PASS fixture first — it forces you to name the exact JSON shape.
3. Use `object.get(x, "k", default)` to avoid undefined-propagation bugs.
4. One concern per rule; compose with multiple `deny[msg]` blocks instead of `and`-chains inside one rule.
5. Name the rule's negative case in the `msg` — it doubles as documentation and remediation hint.
