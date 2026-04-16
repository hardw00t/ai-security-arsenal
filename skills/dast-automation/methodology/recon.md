# Phase 0: Reconnaissance

Passive and low-noise discovery of the target's attack surface. Most of these operations are independent and **should run in parallel**.

## Parallel track (run simultaneously)

```bash
# Subdomain enumeration (passive sources)
subfinder -d target.com -silent -o subs.txt &

# Service/version scan (authorized scope only)
nmap -sV -sC -p- -T4 target.com -oN nmap.txt &

# Technology fingerprinting
whatweb -a 3 https://target.com -q --log-json whatweb.json &

# Content discovery
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt \
     -mc 200,204,301,302,307,401,403 -o ffuf.json -of json &

# Nuclei exposure / panel / CVE sweep against the root
nuclei -u https://target.com -severity critical,high,medium \
       -t http/exposures/ -t http/cves/ -t http/misconfiguration/ \
       -jsonl -o nuclei-root.jsonl &

wait
```

## Exposed-file quick probes (sequential, cheap)

```bash
for p in .git/config .env .DS_Store robots.txt sitemap.xml \
         wp-config.php.bak backup.zip server-status .htaccess \
         actuator/env actuator/heapdump .well-known/security.txt; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://target.com/$p")
  [ "$code" != "404" ] && echo "$code $p"
done
```

## DNS / cert transparency sweep

```bash
# crt.sh via psql
psql -h crt.sh -p 5432 -U guest certwatch -c \
  "SELECT DISTINCT name_value FROM certificate_and_identities \
   WHERE plainto_tsquery('certwatch','target.com') @@ identities(certificate);"

# amass — deeper, slower, run in background
amass enum -passive -d target.com -o amass.txt &
```

## Output artifacts

Consolidate results into a single `recon.json` keyed by:

- `subdomains[]`
- `open_ports[]` (host, port, service, version)
- `technologies[]` (from whatweb + wappalyzer)
- `paths[]` with status code from ffuf + exposure probes
- `nuclei_findings[]` raw JSONL
- `certs[]` from CT logs

The crawl phase (`methodology/crawling.md`) seeds Playwright from `subdomains[]` + discovered `paths[]`.

## Don't

- Bypass WAF/rate-limit without written authorization.
- Scan every discovered subdomain with full nmap — triage to likely-in-scope hosts first.
- Skip recon for greybox scans; credentials do not replace surface mapping.
