# n8n: SSRF via workflow import endpoint (`/rest/workflows/from-url`), declined then silently patched

Date: 2026-06-26

Product:
- n8n

Affected versions:
- <= 2.19.x (validated on 2.19.0)

Fixed in:
- 2.20.0 (released 2026-05-05), via [PR #29178](https://github.com/n8n-io/n8n/pull/29178)
  / commit [`ecd0ba8eba`](https://github.com/n8n-io/n8n/commit/ecd0ba8eba)

Status:
- Reported privately to the n8n security team on 2026-04-29.
- On 2026-05-20 the vendor determined the report "does not qualify."
- The vulnerable code was in fact changed in commit `ecd0ba8eba` on
  2026-04-29 — the same day the report was filed — and shipped to users in
  2.20.0 on 2026-05-05, fifteen days *before* the report was declined.
- No CVE or security advisory was issued, and the follow-up hardening commits
  were merged as `no-changelog`.
- This disclosure documents a valid, fixed SSRF that was patched without
  acknowledgement or assignment.

## Summary

n8n exposed an authenticated server-side request forgery (SSRF) in the workflow
import endpoint `GET /rest/workflows/from-url`. The handler took a
user-controlled `url` query parameter and performed a direct
`axios.get(query.url)` with no hostname validation, no IP blocklist, and no
integration with n8n's own `SsrfProtectionService`.

Any authenticated user holding the standard member-level `workflow:create`
permission in any project could use this endpoint to make the n8n server issue
outbound HTTP requests to arbitrary destinations — including loopback
(`127.0.0.1`), link-local (`169.254.0.0/16`), and RFC1918 internal ranges — and
have the response body reflected back to the caller when it matched the expected
workflow JSON shape.

Critically, this path was **not** covered by n8n's `SsrfProtectionService`. Even
with `N8N_SSRF_PROTECTION_ENABLED=true`, the same destinations that were blocked
on the node-execution HTTP path were silently permitted on this endpoint.

## Relevant n8n behavior (pre-fix)

In `packages/cli/src/workflows/workflows.controller.ts`, the `getFromUrl`
handler:

- was reachable by any authenticated user with `workflow:create` in a project;
- read the user-controlled `query.url`;
- called `axios.get<IWorkflowResponse>(query.url)` directly;
- returned the fetched body to the caller if it parsed as workflow JSON, and a
  generic `400` otherwise — but only *after* the server-side request had fired.

n8n ships `SsrfProtectionService` specifically to validate user-controlled
outbound HTTP requests against loopback / link-local / RFC1918 ranges, including
redirect targets and DNS resolution. That service was wired only into the
workflow execution engine, not into this controller. The result was an
observable coverage gap: identical destinations blocked on one user-controlled
outbound path and permitted on another, despite the protection flag being on.

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

### Protection-bypass contrast

Launched with `-e N8N_SSRF_PROTECTION_ENABLED=true`:

- HTTP Request node pointed at `http://127.0.0.1:5678/rest/settings` — blocked,
  as expected.
- `GET /rest/workflows/from-url?url=http://127.0.0.1:5678/rest/settings` — the
  server-side request still fired, ignoring the flag entirely.

## Confirmed impact

- Arbitrary authenticated server-side fetch to attacker-chosen targets reachable
  from the n8n server, including loopback and RFC1918 addresses.
- Response reflection when the target returns workflow-shaped JSON; otherwise a
  boolean/timing oracle via response and error differences.
- Bypass of an existing security control (`N8N_SSRF_PROTECTION_ENABLED`) on a
  user-controlled outbound request path of the same class the control was built
  to protect.

On managed cloud deployments, an outbound-fetch primitive of this class is the
standard precondition for reaching internal services and cloud metadata
endpoints. Cloud metadata exfiltration was not independently validated and is
not claimed here as confirmed.

## The fix (public evidence)

The endpoint was remediated in:

- [PR #29178](https://github.com/n8n-io/n8n/pull/29178) — "fix(core): Validate workflow import URL requests"
- commit [`ecd0ba8eba`](https://github.com/n8n-io/n8n/commit/ecd0ba8eba), authored 2026-04-29
- first released in n8n 2.20.0 on 2026-05-05

The fix is exactly the remediation proposed in the private report: the handler
no longer calls `axios.get(query.url)` directly. It now routes the user-supplied
URL through `SsrfProtectionService` via a new `fetchWorkflowFromUrl()` method
that honors `N8N_SSRF_PROTECTION_ENABLED`, and adds a `findSsrfBlockedError()`
helper that walks the `AxiosError -> RedirectionError -> SsrfBlockedIpError`
cause chain to catch redirect-based bypasses.

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

Subsequent hardening (e.g. commit `ce43ec543d`, 2026-06-19, routing the import
through the shared HTTP client) was merged as `no-changelog`.

## Vendor position

The vendor declined the report on 2026-05-20 as not qualifying, citing in part a
shared-responsibility framing for self-hosted SSRF. That framing does not
explain why the same code path was changed — on the day of the report — to route
through the exact SSRF control the report identified as missing, nor why the fix
shipped to users before the report was declined.

This disclosure does not dispute that the bug is fixed. It documents that a
valid SSRF and SSRF-protection bypass was reported in good faith, silently
patched, and closed without acknowledgement, CVE, or credit.

## Timeline

- 2026-04-29: reported privately to the n8n security team.
- 2026-04-29: vendor commits the fix ([`ecd0ba8eba`](https://github.com/n8n-io/n8n/commit/ecd0ba8eba), [PR #29178](https://github.com/n8n-io/n8n/pull/29178)).
- 2026-05-05: fix released in n8n 2.20.0.
- 2026-05-20: vendor declines the report as "does not qualify."
- 2026-06-13, 2026-06-17: reporter follow-ups requesting status.
- 2026-06-26: public disclosure published.
