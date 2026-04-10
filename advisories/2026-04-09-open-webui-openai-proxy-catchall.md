# Open WebUI: Authenticated catch-all upstream proxy can expose privileged backend routes

Date: 2026-04-09

Product:
- Open WebUI

Affected versions:
- <= 0.8.10

Status:
- Vendor reviewed privately through GitHub Security Advisory `GHSA-xgpr-p799-gm8v`.
- Vendor closed the report on April 8, 2026 as not a vulnerability.
- This disclosure reflects a disputed classification.

## Summary

Open WebUI `v0.8.10` exposes a catch-all OpenAI-compatible proxy route at
`/openai/{path}` to any authenticated `get_verified_user` account. Before
forwarding the request upstream, the handler parses the JSON request body, uses
the user-controlled `model` field to resolve a configured backend index, and
then applies the upstream credential configured for that index.

In validated LiteLLM-backed setups, this allows a normal Open WebUI user to
invoke LiteLLM management endpoints through the passthrough route. In a stronger
two-index validation, the same user could steer the catch-all from a
low-privilege default backend index to a second backend index configured with a
management-capable key by supplying a model name that resolved to that stronger
credential.

The caller authenticates to Open WebUI with only a normal user JWT. The
privileged action occurs because Open WebUI applies the configured upstream
credential during proxying.

## Relevant Open WebUI Behavior

In `backend/open_webui/routers/openai.py`, the catch-all route:

- is exposed at `/{path:path}` for any `get_verified_user`
- parses the JSON request body before forwarding
- reads `payload["model"]`
- resolves that model to `OPENAI_MODELS[model_id]["urlIdx"]`
- selects `OPENAI_API_BASE_URLS[idx]` and `OPENAI_API_KEYS[idx]`
- constructs the upstream auth context with `get_headers_and_cookies()`

This means a normal JWT-authenticated user can influence which configured
upstream credential is used for a proxied request.

## Validated Impact: LiteLLM

Validated against:

- Open WebUI: `ghcr.io/open-webui/open-webui:v0.8.10`
- LiteLLM: `ghcr.io/berriai/litellm:main-latest`

### Single-key validation

With Open WebUI configured to use a LiteLLM management-capable key, a normal
Open WebUI `role=user` account successfully reached these LiteLLM management
paths through `/openai/{path}`:

- `/openai/key/generate`
- `/openai/key/list`
- `/openai/team/new`
- `/openai/key/delete`

This allowed the non-admin user to:

- mint a new LiteLLM API key
- enumerate existing LiteLLM-managed keys
- create a LiteLLM team
- delete a LiteLLM key

### Two-index validation

The stronger validation used two configured Open WebUI backend indices pointing
to the same LiteLLM server:

- `idx 0`: low-privilege LiteLLM key
- `idx 1`: management-capable LiteLLM key
- `idx 1` configured with `prefix_id = "admin"`

That caused the second backend’s model to appear in Open WebUI as
`admin.localmock`.

Observed behavior as a normal Open WebUI user:

Without `model`:

```bash
curl -s -o /tmp/default_idx.out -w '%{http_code}\n' \
  -X POST http://localhost:3010/openai/key/generate \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"key_alias":"default-path-test"}'
# 401
```

With `model = "admin.localmock"`:

```bash
curl -s -o /tmp/steered_idx.out -w '%{http_code}\n' \
  -X POST http://localhost:3010/openai/key/generate \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"admin.localmock","key_alias":"steered-admin-path"}'
# 200
```

Meaning:

- the request path stayed the same
- the caller stayed the same
- only the user-controlled `model` field changed
- Open WebUI therefore selected a different configured upstream credential
- the same LiteLLM management path succeeded under the stronger backend index

## Security Significance

The issue is not only that `/openai/{path}` forwards unmatched routes. The more
important behavior is:

1. any authenticated non-admin user can reach the catch-all route;
2. Open WebUI selects the backend index from the request body’s `model` field;
3. Open WebUI then applies the configured upstream credential for that backend;
4. if that credential authorizes privileged backend endpoints, the user can
   reach them through Open WebUI.

This is security-relevant because the effective upstream authority is determined
by Open WebUI’s proxy logic, not by the user’s own credential scope.

## CVSS Note

`AC:L` is defensible if the issue is scored as an Open WebUI authorization flaw,
because exploitation is straightforward once the deployment exists.

A conservative counterargument is `AC:H`, because the highest-impact outcomes
depend on deployment-specific upstream conditions, including a backend that
exposes privileged passthrough-reachable routes and a configured upstream
credential that authorizes them.

The dispute is about impact preconditions, not about whether the behavior
occurs.

## Vendor Position

The vendor stated that:

- `/openai/{path}` is an intended proxy feature
- exposure of provider-specific privileged routes is a deployment responsibility
- additional controls should be handled as feature work, not a security fix

I disagree with that classification. The validated LiteLLM PoC shows that a
normal Open WebUI user can trigger privileged backend actions through a
user-reachable catch-all route that applies configured upstream credentials.

## Timeline

- 2026-03-30: reported privately through GHSA
- 2026-04-03: vendor stated intended behavior / not a vulnerability
- 2026-04-08: GHSA closed
- 2026-04-09: public disclosure published
