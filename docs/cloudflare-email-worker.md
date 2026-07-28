# Cloudflare Email: bounce/complaint ingestion + suppression

This document explains how outbound email delivery and inbound bounce/complaint
handling work in ruxlog when `MAIL_PROVIDER=cloudflare`, and how to wire up the
reference Cloudflare Worker that feeds async delivery events into ruxlog.

## How it fits together

```
                         OUTBOUND (send)
handler ─► MailRouter::send ─► CloudflareMailProvider ─► CF Email Sending API
   ▲                              │                        │
   │                              │                        ▼
   │   1. validate recipient      │              {delivered, queued, permanent_bounces}
   │   2. suppression pre-check   │ ◄──────────────────────────┘
   │   3. rate-limit (Redis)      │   permanent_bounces → auto-upsert suppression (permanent)
   │   4. dedup (newsletter)      │
   │   5. delegate                │
   └─── enforced BEFORE every send, for every provider

                         INBOUND (async bounces/complaints)
CF Email Service ──queue──► CF Worker ──HMAC sign──► POST /mail/v1/webhook/cloudflare
                                                              │
                                verify secret (fail-closed) ──┤
                                dedup 24h                     │
                                BOUNCED/COMPLAINED → upsert suppression ──┘
```

### Two suppression sources

1. **Synchronous** — Cloudflare's send response returns `permanent_bounces[]`
   immediately. `MailRouter` upserts those as `permanent` suppression rows on
   every send. This is the robust, always-available path and needs no extra
   setup.
2. **Asynchronous** — delayed bounces and spam complaints. Cloudflare Email
   Service does **not** POST these to an HTTP URL with a signature. It publishes
   them to a **Cloudflare Queue**. To ingest them you deploy the reference
   Worker below, which consumes the Queue and re-POSTs to ruxlog under a shared
   HMAC secret that ruxlog verifies. This is optional; without it, suppression
   still works via the synchronous path + manual admin adds.

## ruxlog configuration

```env
MAIL_PROVIDER=cloudflare
MAIL_FROM_ADDRESS=no-reply@your-verified-domain.tld
CLOUDFLARE_EMAIL_ACCOUNT_ID=<account id>
CLOUDFLARE_EMAIL_API_TOKEN=<token with Email Sending permission>
CLOUDFLARE_EMAIL_WEBHOOK_SECRET=<random 32-byte hex; shared with the Worker>
# Optional pre-prod sandbox allowlist:
# CLOUDFLARE_EMAIL_ALLOWED_ADDRESSES=ops@example.com,qa@example.com
```

If `CLOUDFLARE_EMAIL_WEBHOOK_SECRET` is unset, the webhook receiver rejects every
event (fail-closed) — set it only if you deploy the Worker.

## The envelope contract (Worker → ruxlog)

The Worker POSTs a JSON body of this exact shape:

```json
{
  "event_type": "bounced",
  "recipient": "user@example.com",
  "message_id": "<optional>",
  "diagnostic": "<optional SMTP reply / reason>",
  "permanent": true,
  "ts": 1700000000
}
```

| field        | required | meaning                                                  |
|--------------|----------|----------------------------------------------------------|
| `event_type` | yes      | one of `bounced`, `complained`, `delivered`              |
| `recipient`  | yes      | the bounced/complaining address (canonicalized by ruxlog)|
| `permanent`  | no       | hard bounce? complaints are forced permanent by ruxlog   |
| `message_id` | no       | provider message id                                      |
| `diagnostic` | no       | diagnostic reason (stored server-side only)              |
| `ts`         | no       | unix seconds; if present, checked against a ±5 min window|

### Signing

The Worker sets two headers on every POST, and the timestamp is **required** and
**bound into the signed message** so a captured signed body cannot be replayed
(CWE-294):

- `X-Mail-Webhook-Timestamp: <unix seconds>` (required)
- `X-Mail-Webhook-Signature: <lowercase hex HMAC-SHA256(secret, "{ts}.{body}")>`

ruxlog recomputes the MAC over the exact `"{ts}.{body}"` bytes in constant time
(`subtle::ConstantTimeEq`) and rejects any request whose timestamp is absent,
non-numeric, more than ±5 min from the server clock, or whose signature does not
match. The secret is the same `CLOUDFLARE_EMAIL_WEBHOOK_SECRET` configured on
ruxlog.

## Reference Worker

`workers/ruxlog-mail-relay.js`:

```js
const ENDPOINT = "https://api.your-ruxlog.example/mail/v1/webhook/cloudflare";

export default {
  // `message` is one Cloudflare Email Service event from the Queue. Map CF's
  // fields to the ruxlog envelope; adjust the mapping to CF's actual schema.
  async queue(batch, env) {
    for (const msg of batch.messages) {
      const ev = msg.body; // CF Email Service event JSON
      const envelope = {
        // Map CF's event kind to ruxlog's vocabulary:
        //   delivery success -> "delivered", hard/permanent bounce -> "bounced",
        //   spam complaint -> "complained".
        event_type: mapEventType(ev),
        recipient: ev.to ?? ev.recipient ?? ev.rcpt,
        message_id: ev.messageId ?? ev.message_id,
        diagnostic: ev.reason ?? ev.diagnostic,
        permanent: isPermanent(ev),
        ts: Math.floor(Date.parse(ev.timestamp) / 1000) || undefined,
      };

      const body = JSON.stringify(envelope);
      // The timestamp is REQUIRED and bound into the signed message so a
      // captured body can't be replayed. ruxlog recomputes HMAC over "{ts}.{body}".
      const ts = String(Math.floor(Date.now() / 1000));
      const sig = await hmacHex(env.RUXLOG_WEBHOOK_SECRET, ts + "." + body);
      const resp = await fetch(ENDPOINT, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-mail-webhook-signature": sig,
          "x-mail-webhook-timestamp": ts,
        },
        body,
      });

      // Ack on 2xx so the message leaves the Queue; otherwise retry.
      if (resp.ok) msg.ack();
      else msg.retry();
    }
  },
};

async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function mapEventType(ev) {
  const t = (ev.type ?? ev.event ?? "").toLowerCase();
  if (t.includes("complaint") || t.includes("spam")) return "complained";
  if (t.includes("deliver")) return "delivered";
  return "bounced"; // default bounce/transient failures to "bounced"
}

function isPermanent(ev) {
  // 5xx / permanent SMTP codes are hard bounces; 4xx are transient.
  const code = ev.smtp ?? ev.code ?? 0;
  return code >= 500 || ev.permanent === true;
}
```

`wrangler.toml`:

```toml
name = "ruxlog-mail-relay"
main = "workers/ruxlog-mail-relay.js"
compatibility_date = "2024-09-01"

[[queues.producers]]
queue = "ruxlog-email-events"
binding = "EMAIL_QUEUE"

# Set with: wrangler secret put RUXLOG_WEBHOOK_SECRET
# (same value as ruxlog's CLOUDFLARE_EMAIL_WEBHOOK_SECRET)
```

## Setup steps

1. **Create the Queue** and bind the Cloudflare Email Service event
   subscription for your sending domain to it (Cloudflare dashboard → Email →
   your domain → event subscription → Queue).
2. Deploy the Worker (`wrangler deploy`) and set its
   `RUXLOG_WEBHOOK_SECRET` secret to the same value as ruxlog's
   `CLOUDFLARE_EMAIL_WEBHOOK_SECRET`.
3. Confirm ruxlog is reachable at `/mail/v1/webhook/cloudflare`. A signed POST
   with a `bounced` envelope should create an `email_suppression` row.
4. Verify end-to-end: send to a known-bad address; the synchronous response
   auto-suppresses it; a second send to that address is short-circuited.

## Admin suppression API (always-on)

The suppression list is managed at `/mail/v1/suppression` (admin role required).
This is **always available**, even on SMTP-only deployments, so a stale row can
be cleared:

```bash
# List (filter by reason/permanent/search)
curl /mail/v1/suppression?permanent=true&page=1

# Manually blacklist a recipient
curl -X POST /mail/v1/suppression \
  -H 'content-type: application/json' \
  -d '{"recipient":"spammer@example.com","reason":"manual","permanent":true}'

# Remove a recipient
curl -X DELETE '/mail/v1/suppression?recipient=spammer@example.com'
```

Suppression enforcement: a `permanent` row, or a non-permanent `bounce` row whose
`last_seen` is within `MAIL_SOFT_BOUNCE_COOLDOWN_SECS`, blocks the send before it
reaches any provider. Transactional sends (verification / password reset) to a
suppressed recipient are dropped silently with a counter (anti account
enumeration); the admin/manual path surfaces `EML_004 EmailSuppressed` (422).
