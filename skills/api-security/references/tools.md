# API Security Tool Reference

Canonical command-line / install notes. Kept out of SKILL.md to stay under the
router line budget.

## HTTP & interception

| Tool       | Purpose                           | Install                                                     |
|------------|-----------------------------------|-------------------------------------------------------------|
| Burp Suite | HTTP intercept / repeater / intruder | https://portswigger.net/burp                            |
| mitmproxy  | Scriptable HTTP intercept         | `pip install mitmproxy`                                     |
| Postman    | Manual API testing / collections  | https://postman.com                                         |
| HTTPie     | Readable curl replacement         | `pip install httpie`                                        |

## Discovery / fuzzing

| Tool         | Purpose                       | Install                                                          |
|--------------|-------------------------------|------------------------------------------------------------------|
| ffuf         | Generic HTTP fuzzer           | `go install github.com/ffuf/ffuf/v2@latest`                      |
| kiterunner   | API-aware route discovery     | https://github.com/assetnote/kiterunner/releases                 |
| katana       | Crawler (JS-aware)            | `go install github.com/projectdiscovery/katana/cmd/katana@latest`|
| arjun        | HTTP parameter discovery      | `pip install arjun`                                              |
| feroxbuster  | Recursive content discovery   | `cargo install feroxbuster`                                      |

## Protocol-specific

| Tool         | Purpose                         | Install                                                         |
|--------------|---------------------------------|-----------------------------------------------------------------|
| graphql-cop  | GraphQL misconfig scan          | `pip install graphql-cop`                                       |
| clairvoyance | GraphQL schema w/o introspection| `pip install clairvoyance`                                      |
| inql         | Burp GraphQL extension          | Burp BApp store                                                 |
| grpcurl      | gRPC CLI                        | `go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest` |
| grpcui       | gRPC web UI                     | `go install github.com/fullstorydev/grpcui/cmd/grpcui@latest`   |
| wscat        | WebSocket CLI                   | `npm install -g wscat`                                          |

## JWT / auth

| Tool       | Purpose                       | Install                     |
|------------|-------------------------------|-----------------------------|
| jwt_tool   | JWT tampering / cracking      | `pip install jwt_tool`      |
| hashcat    | Offline JWT / PBKDF2 cracking | distro pkg or github releases |
| openssl    | Cert / key inspection         | distro pkg                  |

## Scanning

| Tool    | Purpose                    | Install                                                                 |
|---------|----------------------------|-------------------------------------------------------------------------|
| nuclei  | Template-based scanner     | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`    |
| sqlmap  | SQLi automation            | `pip install sqlmap` or distro                                          |
| nikto   | Legacy HTTP scanner        | distro pkg                                                              |

## Minimum validated versions (2026-04)

- nuclei >= 3.3
- ffuf >= 2.1
- grpcurl >= 1.9
- jwt_tool >= 2.2
- graphql-cop >= 1.13
- burp >= 2024.x
