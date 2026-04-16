# gRPC Testing Workflow

## 0 — Tooling

```bash
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
go install github.com/fullstorydev/grpcui/cmd/grpcui@latest
# protoc if you have .proto files
```

## 1 — Reflection-based discovery

If server reflection is enabled (often is in non-prod, sometimes leaks into prod):

```bash
grpcurl -plaintext target:50051 list
grpcurl -plaintext target:50051 list <service>
grpcurl -plaintext target:50051 describe <service>
grpcurl -plaintext target:50051 describe <service>.<Method>
grpcurl -plaintext -d '{"id":"123"}' target:50051 <service>/<Method>
```

Reflection itself is a finding if exposed externally (`API9:2023` — Improper Inventory Management).

## 2 — No-reflection path

Obtain `.proto` files from:
- Mobile app reverse engineering (APK / IPA resources)
- Public repos / open-source clients
- Docs / SDKs shipped to users

Then:

```bash
grpcurl -plaintext -import-path ./protos -proto user.proto \
        -d '{"id":"123"}' target:50051 user.UserService/GetUser
```

## 3 — Auth

- Metadata-based tokens: `-H "authorization: Bearer $TOKEN"` or `-rpc-header`.
- mTLS: obtain legitimate client cert, then test whether server enforces CN / SAN / OU.
- API keys in metadata: test scoping, rotation, tenant isolation.

## 4 — Authorization matrix

Same structure as REST (see `methodology/bola_bfla_matrix.md`) but issue calls via grpcurl:
- Unauth vs user-A vs user-B vs admin
- For every `Get*`, `Update*`, `Delete*` method, iterate resource IDs across tenants.

## 5 — Input validation

- Send oversized bytes fields (check `API4:2023` resource consumption).
- Send unexpected `oneof` combinations.
- Send negative numbers for counts/sizes.
- Send deeply nested messages if the schema allows recursion.
- Send `Any` type with unexpected packed type URLs.

## 6 — TLS

```bash
# Confirm TLS is actually enforced (fail closed)
grpcurl -plaintext target:50051 list       # should fail if TLS-only
# Cipher / protocol inspection
openssl s_client -connect target:50051 -alpn h2
nmap --script ssl-enum-ciphers -p 50051 target
```

## 7 — Reporting

Record per `schemas/finding.json` with `api_type: "grpc"`, `endpoint` set to
`<package>.<service>/<method>`, and `http_method: "N/A"`.
