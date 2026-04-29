# Hosting the comment-suppress bridge on Vercel / Netlify / AWS Lambda

The Cloudflare Worker reference implementation in `worker.js` uses
only the standard Web Fetch API (`Request`, `Response`, `fetch`,
`FormData`). It ports to other edge-function platforms with minimal
adaptation:

- **Vercel Edge Functions** — drop `worker.js` in
  `api/bomdrift.js`, rename `export default { fetch }` to
  `export default async function handler(request)`. Configure env
  vars in the Vercel UI.
- **Netlify Edge Functions** — same shape; configure via
  `netlify.toml` and the Netlify UI.
- **AWS Lambda@Edge / Lambda + API Gateway** — wrap the handler in
  the Lambda event/response envelope; port `FormData` to
  `URLSearchParams`.

The threat model (five guards) is the same on every host. Only
these change per host:

1. How env vars are injected.
2. How the body is read.
3. The deploy command.

Recommend Cloudflare Workers as the reference because its free tier
(100k req/day) covers most webhook traffic and the deploy story
(`wrangler deploy`) is the simplest. Vercel / Netlify are equally
good if your team already operates on those platforms.
