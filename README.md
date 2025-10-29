---

title: Auth_Sess_JWT_OAuth_BAC_Methodology
tags: [security, pentest, OWASP, JWT, OAuth, session, access-control]
---------------------------------------------------------------------

# Part 1 — Broken Access Control (BAC) Testing Methodology

**Target Features:** Direct object references, role-based access, URL/parameter access, API endpoints, administrative interfaces.

---

## Basic Level

### WSTG-BAC-01 — Authorization enforcement

* **Question:** Are all resources protected by *server-side* authorization checks?
* **Test:** Request protected pages as unauthenticated or low-privilege users.
* **Expected:** `401` / `403` responses.

### WSTG-BAC-02 — Role separation

* **Question:** Can authenticated users access higher-privileged features (role escalation)?
* **Test:** Attempt admin-only actions as standard user.

### WSTG-BAC-03 — Direct Object Reference (IDOR)

* **Question:** Can attackers access others’ data by changing predictable identifiers (`id=123 → 124`)?
* **Test:** Modify resource IDs and verify ownership checks.

### WSTG-BAC-04 — Hidden Endpoints

* **Question:** Are administrative or debug URLs reachable by low-privilege users?
* **Test:** Probe paths like `/admin`, `/config`, `/console`, `/.env`.

---

## Intermediate Level

### WSTG-BAC-05 — Server-side authorization

* **Test:** Attempt privileged APIs as low-priv user.
* **Check:** Responses should `401/403` and server logs should record denied attempts.

### WSTG-BAC-06 — Role tampering

* **Test:** Manipulate client-controlled role claims (cookies, JWT, POST params) and re-submit to privileged endpoints.
* **Look for:** Endpoints that accept `role=admin`, `isAdmin=true`, or similar flags from the client.

### WSTG-BAC-07 — Insecure Direct Object Reference (IDOR) enumeration

* **Test:** Enumerate sequential or predictable identifiers and attempt access.
* **Check:** Server enforces ownership; use opaque IDs (UUIDs) where possible.

### WSTG-BAC-08 — Forced browsing / hidden endpoints

* **Test:** Fuzz common admin paths and API endpoints.
* **Check:** Any page returning sensitive information for unauth or low-priv users.

### WSTG-BAC-09 — Parameter & header based access control

* **Test:** Change `user_id`, `tenant_id`, `org_id`, or headers like `X-User-Role` and retry operations.

### WSTG-BAC-10 — Multi-tenant isolation

* **Test:** Request cross-tenant resources (change tenant identifier) and validate for leakage.

### WSTG-BAC-11 — Time/Action based privileges

* **Test:** Attempt actions that should be time-limited (e.g., cancel within 24h) beyond permitted window.
* **Check:** Server-side enforcement of business rules.

---

## Advanced Level

### WSTG-BAC-12 — Privilege escalation via chained requests

* **Test:** Combine multiple low-privilege operations to reach higher-privilege state (create resource → change owner → elevate privileges).

### WSTG-BAC-13 — Authorization logic flaws (complex conditions)

* **Test:** Find endpoints with complex boolean logic and attempt to manipulate inputs to bypass checks.

### WSTG-BAC-14 — Authorization bypass via alternative channels

* **Test:** Try APIs, mobile endpoints, or integration endpoints that may not share the same access control logic.

### WSTG-BAC-15 — Race conditions & TOCTOU

* **Test:** Perform concurrent requests to change resource ownership/permission and replay old operations.

### WSTG-BAC-16 — Logging & error disclosure

* **Test:** Inspect error messages for leakage of authorization decisions or internal role mappings.

---

## Evidence & Remediation (Template)

* **Evidence:** Request/response pairs, endpoint path, role used, manipulated param, HTTP status, Burp logs/screenshots.
* **Risk:** Data disclosure, privilege escalation, unauthorized actions.
* **Remediation:**

  * Enforce all authorization checks server-side, centrally where possible.
  * Use least privilege and explicit allow-lists.
  * Use opaque identifiers for objects (UUIDs, random tokens).
  * Validate tenant/owner on every access.
  * Harden admin endpoints (IP whitelisting, MFA, separate admin API).
  * Add logging/alerting for unusual access patterns and failed authz attempts.

---

# Part 2 — Cleaned & Standardized Methodology (Auth, Session, JWT, OAuth)

> This section is a normalized, ready-to-use Markdown checklist suitable for Obsidian and VSCode.

---

## Authentication Testing — WSTG (Basic → Advanced)

### WSTG-ATHN-01 — Transport security for credentials

**Objective:** Ensure credentials and tokens are always transported securely.
**Test:** Enumerate auth endpoints (login, register, reset, OAuth callbacks, API auth). Confirm HTTPS, HTTP→HTTPS redirects, HSTS header presence (`Strict-Transport-Security: max-age=...; includeSubDomains; preload`). Check for mixed-content and tokens in URLs or Referer headers.

### WSTG-ATHN-02 — Default / hard-coded credentials

**Objective:** Detect default credentials and exposed secrets.
**Test:** Scan for setup pages, installers, public repos, CI artifacts, `.env`, backup files. Check admin paths (`/admin`, `/wp-admin`, `/manage`) for default logins.

### WSTG-ATHN-03 — Account lockout & brute-force protection

**Objective:** Verify lockout/rate-limiting mechanisms.
**Test:** Test login failures and rate-limits (per-account, per-IP). Check progressive delays, CAPTCHAs, lockout thresholds, and recovery flow bypassability.

### WSTG-ATHN-04 — Authentication logic flaws

**Objective:** Find flaws allowing authentication bypass.
**Test:** Check for unauthenticated access to protected endpoints, parameter tampering (`loggedin=true`), JS-exposed auth logic, exposed debug/setup pages.

### WSTG-ATHN-05 — “Remember Me” and persistent auth

**Objective:** Ensure persistent login tokens are safe.
**Test:** Locate remember-me tokens (cookies, localStorage). Confirm long-lived tokens are signed, stored securely (HttpOnly cookie preferred), have rotation/expiry, and are bound to device.

### WSTG-ATHN-06 — Sensitive info cached client-side

**Objective:** Prevent secrets in cache/storage.
**Test:** Inspect cache-control headers on auth pages and sensitive responses. Check localStorage/sessionStorage/IndexedDB/service workers for tokens/PII. Ensure logout clears sensitive caches.

### WSTG-ATHN-07 — Password policy & reset security

**Objective:** Enforce strong password policies.
**Test:** Attempt weak passwords at registration/change flows. Inspect reset token randomness/expiry. Ensure server-side enforcement of complexity, history, and rate-limits.

### WSTG-ATHN-08 — Alternative channels parity

**Objective:** Ensure equivalent security across channels.
**Test:** Inventory alternate channels (API, mobile, admin, OAuth). Validate transport, token handling, rate-limits, and storage. Look for weaker protections than web UI.

---

## Token-Based Auth (JWT) — SCS-JWT (Basic → Advanced)

### SCS-JWT-01 — Algorithm handling (alg)

**Objective:** Prevent signature bypass (e.g., `alg: none`, alg confusion).
**Test:** Try `alg: none`, change alg (RS256↔HS256), verify server rejects or enforces allowed algorithms.

### SCS-JWT-02 — Token transport & interception

**Objective:** Ensure tokens are sent securely and not leaked.
**Test:** Confirm token endpoints use HTTPS/HSTS; tokens are not in URL/query/fragments. Check Referer leaks and analytics.

### SCS-JWT-03 — Storage & client-side safety

**Objective:** Tokens should not be stored insecurely.
**Test:** Inspect localStorage/sessionStorage/cookies. Cookies should be `Secure; HttpOnly; SameSite=Lax/Strict`. Prefer HttpOnly cookies for access tokens.

### SCS-JWT-04 — Claims & sensitive data

**Objective:** Claims must not include secrets/PII.
**Test:** Decode tokens and inspect payload for passwords, secrets, or over-privileged claims.

### SCS-JWT-05 — Signature & key management

**Objective:** Ensure robust key usage and rotation.
**Test:** Inspect JWKs/JWKS endpoints, key sizes, rotation policy, `kid` handling. Test attacker-supplied JWKS scenarios if dynamic JWKS used.

### SCS-JWT-06 — Refresh tokens & revocation

**Objective:** Ensure refresh tokens are rotated and revocable.
**Test:** Confirm refresh rotation, one-time use, revocation endpoint, and binding to client/device. Test token reuse behavior.

### SCS-JWT-07 — Expiry & audience checks

**Objective:** Enforce `exp`, `nbf`, `aud`, and `iss`.
**Test:** Craft tokens with modified `exp/aud/iss` values to see if server enforces checks and reasonable leeway for clock skew.

### Advanced Topics

* Alg confusion & signature bypass
* kid/JWKS attacks (key substitution)
* Claim manipulation & privilege escalation
* Token replay & reuse
* Refresh token rotation race conditions
* aud/iss/nbf/exp bypasses & clock drift
* Token leakage via logs/backups/analytics
* PKCE enforcement & public clients
* RedirectURI & open redirect chaining
* Scope escalation & introspection/revocation endpoint abuse

---

## OAuth Testing — SCS-OAUTH (Basic → Advanced)

### SCS-OAUTH-01 — Redirect URI validation & open redirect

**Test:** Tamper `redirect_uri` to external domains; validate strict whitelisting and `state` parameter presence and validation.

### SCS-OAUTH-02 — Authorization code randomness & expiry

**Test:** Check code entropy and one-time usage; attempt reuse and replay.

### SCS-OAUTH-03 — PKCE enforcement for public clients

**Test:** Initiate code flow without PKCE; server must require `code_verifier` on token exchange. Implicit flow should be disabled/deprecated.

### SCS-OAUTH-04 — Token scope & client binding

**Test:** Request elevated scopes and verify token scopes and client-bound usage.

### SCS-OAUTH-05 — Token handling & refresh policy

**Test:** Check refresh token rotation, storage location, lifetime, and client binding.

### SCS-OAUTH-06 — CSRF/CORS on OAuth endpoints

**Test:** Check CORS policies on `/authorize`, `/token`, `/introspect`. Ensure CSRF protections and SameSite cookie settings.

### Advanced checks include redirect chaining, race conditions on code reuse, JWKs manipulation, revocation/introspection abuses, PKCE downgrade testing, scope escalation, and implicit/hybrid flow misconfigurations.

---

## Session Management — WSTG-SESS (Basic → Advanced)

### WSTG-SESS-01 — Session ID unpredictability & entropy

**Test:** Collect session tokens and analyze entropy (length, randomness); use Burp Sequencer or similar.

### WSTG-SESS-02 — Session fixation prevention

**Test:** Attempt to set a session ID prior to login and see if that session becomes valid after auth. Verify session ID rotation on login.

### WSTG-SESS-03 — Session timeout & absolute lifetime

**Test:** Measure idle and absolute timeouts. Attempt to reuse expired tokens.

### WSTG-SESS-04 — Binding session to client attributes

**Test:** Replay session tokens from different IP/User-Agent; check if server invalidates or accepts.

### WSTG-SESS-05 — Secure cookie attributes

**Test:** Ensure cookies have `Secure`, `HttpOnly`, `SameSite=Strict/Lax` and proper `Max-Age`/`Expires`. Avoid tokens in URLs.

### WSTG-SESS-06 — Logout & revocation

**Test:** Confirm logout invalidates server-side session and prevents reuse.

### WSTG-SESS-07 — Data in cookies

**Test:** Check cookies for modifiable fields containing roles/privileges; server must not trust client-controlled cookie values for authorization.

### Advanced

* Reverse-engineer cookie format
* Test cookie brute-force/prediction
* Test session storage and regeneration on privilege change

---

## Reporting Template (Single Finding)

```
## Finding: <Short Title>
- **ID:** <WSTG-... or SCS-...>
- **Severity:** Critical/High/Medium/Low
- **Affected:** <URL / Endpoint / API Path>
- **Role used:** <unauth/low-priv user>
- **Request:** <method, path, manipulated params>
- **Response:** <HTTP status, key response details>
- **Steps to reproduce:**
  1. <step>
  2. <step>
- **Impact:** <what attacker can do>
- **Suggested remediation:**
  - <fix 1>
  - <fix 2>
- **Evidence:** (paste request/response pairs / Burp logs / screenshots)
```

---

## Quick Best-Practices 

* Enforce HTTPS + HSTS (`includeSubDomains; preload`).
* Use `Secure; HttpOnly; SameSite` cookies; avoid storing tokens in localStorage.
* Short-lived access tokens; rotate refresh tokens; support revocation.
* Enforce server-side authorization; centralize policy.
* Use PKCE for public clients; deprecate implicit flow.
* Harden admin endpoints (MFA, separate admin APIs, IP restrictions).
* Make object references opaque; validate ownership on every access.
* Log and alert on unusual auth/authz failures and repeated attempts.

---


