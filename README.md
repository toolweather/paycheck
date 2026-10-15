# PayCheck

PayCheck scores whether a domain, an https URL, or a `0x` wallet is safe to pay **before** an autonomous agent sends money.

It is part of the Toolweather suite, in the same family as Toolweather MCP health, Upstream, and SpendGate. SpendGate is for spend limits. PayCheck is only the payee trust check. It does not send payments, does not sign transactions, and does not hold wallet keys. A Toolweather bundle can front this API later with `x-tw-bundle-secret` and `x-tw-bundle-client`.

The score is deterministic. `amount_usd`, `category`, and any purpose text are discarded. Rewording them cannot fish for a better verdict.

## When to use it

Call PayCheck once per payee, immediately before a checkout, invoice, or transfer.

- Use `check_merchant` for a domain (`api.openai.com`), an https URL, or a `0x` address with 40 hex characters.
- Use `get_quota` to see how many free checks are left today.
- Use `get_api_key` **once** to mint a free `pc_live_…` key. Do not call it every turn.

Do not use PayCheck to send money, to hold keys, or to overturn a `block` by asking again with a friendlier category.

## Scoring (policy v1)

Full rules, the allowlist, and the penalty table: [`GET /v1/policy`](https://paycheck.toolweather.workers.dev/v1/policy) (or `http://127.0.0.1:8791/v1/policy` locally).

Start at 100 and subtract penalties. `policy_version` is `"1"`.

| Signal | Result |
| --- | --- |
| Allowlisted host, https, port 443 | `trusted`, score at least 92 |
| Mature domain that is not on the allowlist | `unknown` (never `trusted`) |
| RDAP age lookup failed | small penalty, age is **not** invented |
| Domain age under 30 days | `suspicious` |
| Domain age under 7 days | `suspicious` |
| Domain age under 2 days | `block` |
| Non-https, raw IP, localhost, private address, URL userinfo | `block` |
| Denylist, scam-name pattern, bad TLD, typosquat of an allowlist brand | `block` |
| Many hyphens, punycode, or brand impersonation | `suspicious` |
| `0x` wallet, invalid hex or burn / zero address | `block` |
| Any other `0x` wallet | `unknown`. No chain analysis in v1 |

`trusted` is only for the published allowlist (about 40 known AI and developer API hosts, including openai.com, anthropic.com, stripe.com, github.com, cloudflare.com, vercel.com, and supabase.com). A brand-new or random domain is never trusted.

Recommended actions: `proceed`, `verify_out_of_band`, `require_human_review`, `do_not_pay`.

Domain age uses public RDAP (`https://rdap.org`). Successful lookups are cached in D1 for 7 days. Failures are cached for 24 hours.

## Free tier

| Caller | Checks per UTC day | Price |
| --- | --- | --- |
| Anonymous IP | 100 | Free |
| Free `pc_live_…` key (`POST /v1/keys` or `get_api_key`) | 1,000 | Free |
| Bundle client, `x-tw-bundle-client` is hex (16+ chars) | 1,000 | Free |
| Bundle client, `anon` or `anon:…` (and any other non-hex id) | 100 | Free |
| Over the daily cap | per check | $0.001 USDC |

The same caller and the same target are idempotent for 60 seconds and do not consume a second free check.

Not billed: `get_quota`, `get_api_key`, `GET /v1/policy`, `GET /health`, docs, and MCP discovery.

Key minting is capped at 10 keys per IP per UTC day. PayCheck stores only a SHA-256 hash of the key.

### x402 overage

Over-cap checks cost **$0.001 USDC** (1000 atomic units) on Base (`eip155:8453`), scheme `exact`, asset `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, facilitator `https://facilitator.payai.network`.

`PAY_TO` is the receiving address. It is a Worker secret. If it is unset, over-cap calls return HTTP 402 with `error: "payment_not_configured"` and nothing is charged.

Bundle auth: header `x-tw-bundle-secret` must equal the Worker secret `BUNDLE_PROXY_SECRET`, and `x-tw-bundle-client` identifies the end caller.

## API

| Method | Path | |
| --- | --- | --- |
| `POST` | `/v1/check` | `{ "target", "amount_usd"?, "category"?, "api_key"? }` |
| `POST` | `/v1/keys` | Mint `pc_live_…` |
| `GET` | `/v1/quota` | Remaining free checks |
| `GET` | `/v1/policy` | Scoring policy v1 |
| `GET` | `/health` | Liveness |
| `GET` | `/openapi.json` | OpenAPI |
| `GET` | `/llms.txt`, `/llms-full.txt` | Agent docs |
| `POST` | `/mcp` | MCP streamable HTTP |
| `GET` | `/.well-known/mcp` and `/.well-known/mcp.json` | MCP discovery |
| `GET` | `/.well-known/x402` | Payment discovery |

MCP protocol versions: `2025-06-18` and `2025-03-26`. Stateless JSON responses (no session). `GET /mcp` returns 405.

Tools:

1. `check_merchant` — may write check history. `readOnlyHint: false`, `idempotentHint: true`, `openWorldHint: true`, `destructiveHint: false`.
2. `get_quota` — free. `readOnlyHint: true`, `idempotentHint: true`.
3. `get_api_key` — free, mints a key. Not read-only. Do not call every turn.

```bash
curl -s -X POST http://127.0.0.1:8791/v1/check \
  -H 'content-type: application/json' \
  -d '{"target":"https://api.openai.com"}'
```

```json
{
  "mcpServers": {
    "paycheck": {
      "type": "http",
      "url": "https://paycheck.toolweather.workers.dev/mcp"
    }
  }
}
```

Glama stdio entry, after `npm run build`:

```bash
node dist/stdio.js
```

The stdio process speaks newline-delimited JSON-RPC (one JSON object per line) and also accepts Content-Length frames on input. Its quota and keys are in memory. Production persistence is the Worker.

## Local

```bash
npm install
npx wrangler d1 migrations apply paycheck --local
npm run dev
npm test
npm run typecheck
```

`npm run dev` serves the API and the landing page on port **8791**.

Optional `.dev.vars` (gitignored; see `.dev.vars.example`):

```bash
# PAY_TO=0xYourReceivingAddress
# BUNDLE_PROXY_SECRET=replace-with-a-long-random-string
```

## Deploy

Production lives at [paycheck.toolweather.workers.dev](https://paycheck.toolweather.workers.dev). `wrangler.toml` already has the production D1 `database_id`. `PAY_TO` and `BUNDLE_PROXY_SECRET` are Worker secrets. Do not put them in `[vars]` or in git.

```bash
npx wrangler d1 migrations apply paycheck --remote
npx wrangler secret put PAY_TO
npx wrangler secret put BUNDLE_PROXY_SECRET
npx wrangler deploy
```

Check the bundle without deploying:

```bash
npm run dry-run
```

## Layout

- `src/score.ts` — pure scorer, covered by unit tests
- `src/http.ts` — Hono routes
- `src/mcp.ts` — streamable HTTP JSON-RPC
- `src/stdio.ts` — Glama stdio entry (`dist/stdio.js`)
- `migrations/` — D1 schema
- `public/` — landing page
- `lhm.plugin.json`, `glama.json` — directory listing metadata

## License

MIT. See [LICENSE](LICENSE).
