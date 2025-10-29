# SCS Shaker Methodology

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## VULNERABILITIES SELECTED

1. **BROKEN AUTHENTICATION (BA)** / Authentication testing
2. **BROKEN SESSION MANAGEMENT (BSESS)** / Session management testing
3. **BROKEN ACCESS CONTROL (BAC)**

---

## Authentication Testing Questions — Methodology

**Target features:** Authentication forms & mechanisms

### Basic level

- **WSTG-ATHN-01** — Are user credentials transmitted securely over HTTPS to prevent interception/tampering?
- **WSTG-ATHN-02** — Are there any default credentials in use that could be exploited to gain unauthorized access?
- **WSTG-ATHN-03** — Are there any weak lockout mechanisms that allow brute-force attacks to succeed?
- **WSTG-ATHN-04** — Are there flaws in the authentication process that allow an attacker to bypass authentication altogether?
- **WSTG-ATHN-05** — Is the “Remember Me” functionality implemented securely without exposing sensitive data that could aid unauthorized access?
- **WSTG-ATHN-06** — Is any sensitive information stored insecurely in the browser cache where attackers could retrieve it?
- **WSTG-ATHN-07** — Does the application's password policy enforce sufficient complexity and expiration requirements?
- **WSTG-ATHN-08** — Do alternative authentication channels (e.g., APIs, mobile apps) have weak or inconsistent security practices that could lead to account compromise?

### Intermediate level

- **WSTG-ATHN-01** — Are user credentials transmitted securely over HTTPS?
  - **Test:** Enumerate all auth-related endpoints (login, register, reset, OAuth callbacks, API auth) and confirm they use HTTPS.
  - **Check:** Redirects from HTTP → HTTPS; HSTS present.
  - **Inspect:** Any mixed content (scripts, images) on auth pages.
  - **Look for:** Plaintext credentials in request bodies/params or tokens sent over plain HTTP.

- **WSTG-ATHN-02** — Default credentials usage
  - **Test:** Scan public files, installers, setup pages, backups for default creds or dev/test accounts.
  - **Check:** Common admin endpoints (/admin, /wp-admin, /manage) for default logins.
  - **Inspect:** Exposed config files, CI/CD artifacts, or repos for hardcoded usernames/passwords.
  - **Look for:** Unchanged vendor defaults or well-known weak creds.

- **WSTG-ATHN-03** — Lockout mechanisms
  - **Test:** Observe login failure behavior and rate-limiting on login endpoints.
  - **Check:** Whether lockout is per-account, per-IP, or absent.
  - **Inspect:** Account recovery and change-password flows to see if they trigger lockouts.
  - **Look for:** Unlimited attempts, no progressive delay, or mechanisms that can be abused to avoid lockout.

- **WSTG-ATHN-04** — Auth bypass
  - **Test:** Enumerate endpoints that should be protected (admin pages, APIs, debug) for unauthenticated access.
  - **Check:** Parameter tampering (e.g., `loggedin`, `role`, `isAdmin`, `user_id`).
  - **Inspect:** Auth logic exposed in client JS or API responses.
  - **Look for:** Unauthenticated endpoints returning sensitive data, trust of client-supplied auth flags, or setup/config pages left accessible.

- **WSTG-ATHN-05** — Remember-me security
  - **Test:** Identify remember-me cookies/tokens and where they are set (cookie, localStorage, URL).
  - **Check:** Token lifecycle and where the token is sent (cookie headers or query).
  - **Inspect:** Long-lived tokens visible client-side or with predictable format.
  - **Look for:** Persistent tokens stored in insecure storage or included in requests/URLs.

- **WSTG-ATHN-06** — Browser cache
  - **Test:** Check pages after login for sensitive data in HTML, JS variables, or localStorage/sessionStorage.
  - **Check:** Cache-Control headers on auth pages and sensitive responses.
  - **Inspect:** Service workers, IndexedDB, and any client-side stores for creds/tokens.
  - **Look for:** Sensitive payloads cached, missing `no-store`/`no-cache`, tokens in JS files.

- **WSTG-ATHN-07** — Password policy
  - **Test:** Register & change-password endpoints for server-side enforcement (try weak/common passwords).
  - **Check:** Password reset token properties (length, expiry) and whether token reuse is possible.
  - **Inspect:** Any client-side-only checks that can be bypassed by sending raw requests.
  - **Look for:** Weak acceptance of common passwords, no password history, or very long-lived reset tokens.

- **WSTG-ATHN-08** — Alternative channels
  - **Test:** Inventory all auth channels (API endpoints, mobile apps, SSO/OAuth, admin consoles, third-party integrations).
  - **Check:** Token handling differences (refresh tokens, API keys), transport security, and rate limits per channel.
  - **Inspect:** Mobile app storage (if available) for tokens/credentials and OAuth redirect URIs for open redirects.
  - **Look for:** Channels with weaker protections than the main UI (no rate limits, verbose errors, insecure token storage).

### Advanced level

- Can users be enumerated in authentication channels? Test user enumeration via login and change-password forms.
- Test combined cases (WSTG-ATHN-07, WSTG-ATHN-03): password policy + lockout enforcement.

---

## Token-Based Authentication (JWT, OAuth, Bearer) — Methodology

**Target features:** Bearer tokens, JWTs, OAuth access/refresh tokens, token transport & storage, token endpoints.

### Token types

- **Bearer:** `Authorization: Bearer <token>` — can be vulnerable if mishandled.
- **JWT:** `header.payload.signature` — stored in cookies, localStorage, or headers; readable if not encrypted.
- **OAuth access/refresh tokens:** Mostly bearer tokens; JWT may be used as access token.
- **Query parameters:** `?access_token=<token>` — risky.
- **Request body:** `{ "token": "<token>" }` — not recommended for GET.
- **Cookies:** `Set-Cookie: auth_token=<token>; Secure; HttpOnly` — safe if configured properly.
- **Custom headers:** e.g., `X-Auth-Token: <token>` — can be vulnerable if mishandled.

### JWT structure

- **Structure:** `Header.Payload.Signature` (Base64 encoded parts)
- **Header:** Metadata about the token (e.g., `{ "alg": "HS256", "typ": "JWT" }`).
- **Payload:** Claims about the user/session (registered claims like `iss`, `exp`, `iat` and custom claims such as `role`, `email`).
- **Signature:** Ensures integrity and authenticity; created using a secret (symmetric) or private key (asymmetric).
- **Important:** Payload is base64 encoded, not encrypted — do not store secrets or passwords in claims.

---

## JWT Testing Questions — Methodology

### Basic

- **SCS-JWT-01** — Can an attacker use the `none` algorithm in the header and bypass signature verification?
- **SCS-JWT-02** — Is there sensitive information exposed in claims?

### Intermediate

- **SCS-JWT-01** — Can tokens be intercepted in transit? Test endpoints, HTTPS/HSTS, mixed content, Authorization headers, query params.
- **SCS-JWT-02** — Is token storage on the client secure? Check localStorage vs HttpOnly cookies, service workers, IndexedDB.
- **SCS-JWT-03** — Are JWT claims safe (no passwords/PII)? Check `exp`, `iat`, `nbf`, `aud`, `iss`.
- **SCS-JWT-04** — Is `alg` and signature handled properly? Test `RS256` ↔ `HS256` swaps and `alg: none`.
- **SCS-JWT-05** — Is key management robust? Inspect JWKS, key rotation, key lengths.
- **SCS-JWT-06** — Are refresh tokens used and handled safely? Check rotation and one-time usage.
- **SCS-JWT-07** — Is token revocation supported? Test revocation and introspection flows.

### Advanced

- **Alg confusion & signature bypass:** Craft tokens with `alg: none` or misuse HS/RS algorithms.
- **Kid/JWKS attacks:** Test JWKS injection, SSRF to JWKS, and `kid` handling.
- **Claim manipulation:** Modify role/admin claims and attempt escalation.
- **Token replay & reuse:** Capture and replay tokens across devices/IPs.
- **Refresh token abuse & rotation bypass:** Test concurrent refresh scenarios.
- **Aud/iss/nbf/exp bypasses & clock drift:** Test manipulated timestamps and audience checks.
- **Token leakage via logs/backups/analytics:** Search logs, error messages, telemetry for tokens.
- **PKCE & public clients:** Verify PKCE enforcement for public clients.
- **Redirect URI & open redirect chaining:** Test strict matching of redirect URIs and state parameter usage.
- **Scope escalation & CORS/CSRF around token endpoints:** Check scope enforcement and CORS policies.

---

## OAuth Testing Questions — Methodology

### Basic

- **SCS-OAUTH-01** — Are `redirect_uri` parameters validated to prevent token theft via open redirects?
- **SCS-OAUTH-02** — Do authorization codes have sufficient randomness?
- **SCS-OAUTH-03** — Do authorization codes expire and are they single-use?
- **SCS-OAUTH-04** — Can codes or refresh tokens be used across clients?
- **SCS-OAUTH-05** — Can attackers guess access/refresh tokens?
- **SCS-OAUTH-06** — Are there web-based vulnerabilities (SQL/NoSQLi) leading to token disclosure?
- **SCS-OAUTH-07** — Does the OAuth implementation have robust protections (XSS, CSRF, etc.)?

---

## Session Management Testing — Methodology

**Target features:** Sessions & account security mechanisms

### Basic

- **WSTG-SESS-01** — Are session identifiers generated and stored securely (unpredictable, non-reversible)?
- **WSTG-SESS-02** — Can an attacker set or fix a session ID prior to authentication, enabling session fixation?
- **WSTG-SESS-03** — Do sessions automatically expire after a defined timeout?
- **WSTG-SESS-04** — Are session tokens bound to user-specific attributes (IP, User-Agent, device fingerprint)?
- **WSTG-SESS-05** — Are secure cookie attributes (`HttpOnly`, `Secure`, `SameSite`) implemented?
- **WSTG-SESS-06** — Are session lifetimes reasonable (no long-lived sessions)?
- **WSTG-SESS-07** — Are session tokens never exposed in URLs, logs, or insecure storage?

---

> **Notes:**
> - This document is formatted as GitHub-ready Markdown. It preserves the original tone and structure while fixing typos and grammar.
> - Use it directly in your repo as `SCS Shaker Methodology.md`. If you want a downloadable `.md` file or additional repo files (LICENSE, README, issue templates), tell me and I'll add them to the canvas/repo.
