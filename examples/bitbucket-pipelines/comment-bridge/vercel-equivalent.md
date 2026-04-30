# Hosting the Bitbucket comment-suppress bridge on Vercel / Netlify / AWS Lambda

The Cloudflare Worker reference implementation in `worker.js` uses
only the standard Web Fetch API (`Request`, `Response`, `fetch`) and
`crypto.subtle` for HMAC verification. It ports to other edge-function
platforms with minimal adaptation:

- **Vercel Edge Functions** — drop `worker.js` in
  `api/bomdrift-bitbucket.js`, rename `export default { fetch }` to
  `export default async function handler(request)`. Configure env
  vars in the Vercel UI.
- **Netlify Edge Functions** — same shape; configure via
  `netlify.toml` and the Netlify UI.
- **AWS Lambda + API Gateway** — wrap the handler in the Lambda
  event/response envelope. **Do not** let API Gateway parse the
  body for you; configure the integration to pass the raw bytes
  through, or the HMAC check (which signs the byte-exact body) will
  fail.

The threat model (five guards) is the same on every host. Only these
change per host:

1. How env vars are injected.
2. How the **raw** body is read (the HMAC step is byte-sensitive).
3. The deploy command.

Cloudflare Workers is the recommended reference because its free
tier covers most webhook traffic and `wrangler deploy` is the
simplest deploy story. Vercel / Netlify are equally good if your
team already operates on those platforms.
