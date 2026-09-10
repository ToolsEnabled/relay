# Relay transport lease renewal

The key-possession WebSocket edge can renew an admitted endpoint on its existing
socket. This preserves the connection identifier, pair slots, machine peer links,
queued opaque frames, and the encrypted browser session carried by that socket.
The encrypted session's own key/hello renewal remains a separate protocol.

## Wire exchange

1. Obtain a fresh signed `online-fra-lease.v1` lease from the account service.
2. Send the text frame `{"renew":"request"}` on the admitted socket.
3. Receive `{"challenge":"…","expiresAtMs":123,"renewal":true}`.
4. Sign the decoded base64url challenge bytes with the same Ed25519 identity key
   used at admission. Send exactly `{"renew":<fresh lease>,"publicKeySpki":"…",
   "nonce":"…","signature":"…"}`. Key, nonce and signature use base64url.
5. Receive `{"renewed":{"leaseId":"…","expiresAtMs":123}}`, or
   `{"renewalRefused":{"code":"ONLINE_FRA_…"}}`.

The client changes its renewal deadline only after the `renewed` receipt. A
refusal does not extend the original lease. If authorization expires or is
withdrawn, the connection closes under the existing rules. Binary traffic may
continue during the exchange.

Each challenge is single use, expires within the admission timeout, and is bound
to the specific connection and renewal purpose. Admission challenges cannot be
reused for renewal. Only one challenge may be outstanding per socket; new
challenge requests are limited to one per second. Closed sockets release their
pending challenge entries. Malformed control frames retain the edge's existing
protocol-violation close behavior.

The fresh lease must retain the pair, device, peer, role, generation and identity
key fingerprint. Its issuance cannot go backwards; its expiry must increase;
its lease identifier and nonce must change. All original signature, lifetime,
topology, current account authorization and durable pair-revocation checks still
apply. The existing SQLite transaction consumes the new nonce before the new
expiry is published. Replay protection survives process restart. Database or
audit failure cannot extend a connection.

## Account capability and rollout

The account service advertises support as a sibling of the signed lease:

```json
{"lease":{},"relay":{"renewal":"in-place"}}
```

This capability must remain disabled until the upgraded hosted relay is running.
The existing engine client and shell recognize this exact value. Omitted
capability retains their fresh-lease reconnect behavior. No fields are added to
the signed lease, and mTLS-only clients retain their existing reconnect path.

The relay accepts same-identity renewal for every role. The account service
should initially advertise it only for machine leases: the current browser
lease route mints a new web device identity/introduction per request. Browser
renewal needs a separate account/client change that preserves the current web
identity, key, session binding and session authorization deadline. It must not
silently rotate or extend an authenticated browser session.

## Verification

`node tests/run.js` includes `online-fra-lease-renewal.js`. It exercises the
production core, SQLite store, possession verifier and WebSocket adapter over
loopback only. It checks eight renewal cycles with unchanged socket identifiers
and binary traffic beyond initial expiry; solo and paired machines; queue
preservation; freshness and identity refusals; challenge replay and cross-socket
binding; current account and pair revocation; and storage/audit failure.

To include the shipped engine client in that same real-socket gate:

```bash
ENGINE_RELAY_CLIENT=/path/to/engine/src/lib/online-fra-relay-client.js \
  node tests/online-fra-lease-renewal.js
```

These checks use a controlled local clock. They establish protocol correctness
and expiry enforcement without consuming mobile data. A hosted authenticated
soak test remains necessary after deployment to verify the server, account
capability, desktop background process and phone together on their real network.
