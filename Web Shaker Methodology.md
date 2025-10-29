
# SCS Shaker Methodology

**Vulnerabilities selected**
1. BROKEN AUTHENTICATION (BA) — Authentication testing  
2. BROKEN SESSION MANAGEMENT (BSESS) — Session management testing  
3. BROKEN ACCESS CONTROL (BAC)

---

## Authentication Testing — Questions & Methodology

**Target features:** Authentication forms & mechanisms.

### Basic Level

**WSTG-ATHN-01**  
Are user credentials transmitted securely over HTTPS to prevent interception or tampering?

**WSTG-ATHN-02**  
Are any default credentials in use that could be exploited to gain unauthorized access?

**WSTG-ATHN-03**  
Are there weak lockout mechanisms that allow brute-force attacks to succeed?

**WSTG-ATHN-04**  
Are there flaws in the authentication process that allow an attacker to bypass authentication altogether?

**WSTG-ATHN-05**  
Is the "Remember Me" functionality implemented securely without exposing sensitive data that could aid unauthorized access?

**WSTG-ATHN-06**  
Is any sensitive information stored insecurely in the browser cache where attackers could retrieve it?

**WSTG-ATHN-07**  
Does the application's password policy enforce sufficient complexity and expiration requirements?

**WSTG-ATHN-08**  
Do alternative authentication channels (APIs, mobile apps, etc.) have weak or inconsistent security practices that could lead to account compromise?

---

### Intermediate Level

**WSTG-ATHN-01 — Transport & pages**  
- Test: Enumerate all auth-related endpoints (login, register, reset, OAuth callbacks, API auth) and confirm they use HTTPS.  
- Check: Requests redirect from HTTP → HTTPS; HSTS present.  
- Inspect: Any mixed content (scripts, images) on auth pages that downgrade security.  
- Look for: Plaintext credentials in request bodies/params or tokens sent over plain HTTP.

**WSTG-ATHN-02 — Default credentials**  
- Test: Scan public files, installers, setup pages, backups for default creds or dev/test accounts.  
- Check: Common admin endpoints (`/admin`, `/wp-admin`, `/manage`) for default logins.  
- Inspect: Exposed config files, CI/CD artifacts, or repos for hardcoded usernames/passwords.  
- Look for: Unchanged vendor defaults or well-known weak credentials.

**WSTG-ATHN-03 — Lockouts & brute force**  
- Test: Observe login failure behavior and rate-limiting on login endpoints.  
- Check: Whether lockout is per-account, per-IP, or absent.  
- Inspect: Account recovery and change-password flows to see if they increment/trigger lockouts.  
- Look for: Unlimited attempts, no progressive delay, or mechanisms abused to avoid lockout.

**WSTG-ATHN-04 — Auth bypasses**  
- Test: Enumerate endpoints that should be protected (admin pages, APIs, debug) for unauth access.  
- Check: Parameter tampering (e.g., `loggedin`, `role`, `isAdmin`, `user_id`) on auth pages.  
- Inspect: Auth logic exposed in client JS or API responses.  
- Look for: Unauthenticated endpoints returning sensitive data or trust of client-supplied auth flags.

**WSTG-ATHN-05 — Remember Me**  
- Test: Identify remember-me cookies/tokens and where they are set (cookie, localStorage, URL).  
- Check: Token lifecycle (persistence across sessions) and where token is sent.  
- Inspect: Any long-lived tokens visible client-side or with predictable format.  
- Look for: Persistent tokens stored in insecure storage or included in requests/URLs.

**WSTG-ATHN-06 — Browser cache & client storage**  
- Test: Check pages after login for sensitive data in HTML, JS variables, or localStorage/sessionStorage.  
- Check: Cache-control headers on auth pages and sensitive responses.  
- Inspect: Service workers, IndexedDB, and any client-side stores for creds/tokens.  
- Look for: Sensitive payloads cached, lack of `no-store`/`no-cache`, or tokens in JS files.

**WSTG-ATHN-07 — Password policy**  
- Test: Register & change-password endpoints for server-side enforcement (try weak/common passwords).  
- Check: Password reset token properties (length, expiry) and whether token reuse is possible.  
- Inspect: Any client-side-only checks that can be bypassed by sending raw requests.  
- Look for: Weak acceptance of common passwords, no password history, or very long-lived reset tokens.

**WSTG-ATHN-08 — Alternative channels**  
- Test: Inventory all auth channels (API endpoints, mobile apps, SSO/OAuth, admin consoles, third-party integrations).  
- Check: Token handling differences (refresh tokens, API keys), transport security, and rate-limits per channel.  
- Inspect: Mobile app storage (if available) for tokens/credentials and OAuth redirect URIs for open redirects.  
- Look for: Channels with weaker protections than the main UI (no rate-limits, verbose errors, insecure token storage).

---

### Advanced Level

**WSTG-ATHN-08 — Alternative channels expanded**  
- Do alternative channels (e.g., WP-Login forms, admin-restricted login forms) have inconsistent security leading to compromise?

**User enumeration**  
- Test: User enumeration via login forms & change-password forms (supports tests WSTG-ATHN-07 & WSTG-ATHN-03 & WSTG-ATHN-04).

**CAPTCHA tests & lockout specifics**  
- Evaluate CAPTCHA types and bypass risk: arithmetic/text/image/reCAPTCHA v2/v3.  
- Test login lockout mechanisms and behavior with proxies, empty passwords, etc.

**WSTG-ATHN-07 — Password policy**
- Does the application's password policy enforces sufficient password complexity and expiration requirements in authentication channels?

**Can users set weak passwords or have weak password policy?**
- Test password setting mechanism -- Register Forms & Change Password Forms.

**Does the application enforce minimum standards (e.g., length, character types)?**
- Test password complexity. -- Register Forms & Login Forms.

**Does the application implement protections that limit login attempts?**
- Test account lockouts/rate limits. -- Login Forms.

**Are error messages generic or do they reveal information about password validity?**
- Test error messages. -- Login Forms & Change Password Forms.

**Are passwords overall set weak? can they be bruteforced?**
- Test passwords strength by brute-force attacks. -- Login Forms.

**WSTG-ATHN-03 — Lockout Mechanisms**
- Does the application enforce strong weak lockout mechanisms in authentication channels?

**Can CAPTCHAs authentication/verify mechanisms be vulnerable to bypass?**
- Test CAPTCHAs mechanisms. -- Login Forms, Verify Forms & any authentication channel requiring CAPTCHA.
Arithmetic Based - Weak (Vulnerable)
Text Based - Basic (Vulnerable)
Image Based - Intermediate (Somewhat)
reCAPTCHA v2 - Moderate to Strong (Somewhat)
reCAPTCHA v3 - Very Strong (not Vulnerable)

**Does the application enforce strong login lockout mechanism during login authentication form?**
- Test empty password with accounts in web proxies -- Login Forms.

**WSTG-ATHN-04 — Authentication Bypasses**
- Are there any flaws in the authentication process that allows attacker to bypass authentication altogether?

**Are there any endpoints that do not require authentication that are exposed that represent information disclosure or sensitive data exposure?**
- Test unprotected authentication endpoints -- server-info, server-status, .htaccess, etc.

**Are there any default/hardcored usernames or passwords or credentials overall, left in application code or configuration files or during setup phases without being changed representing information disclosure / sensitive data exposure?**
- Test default/hardcored credentials -- config files, app code, etc.

**Are there any pages/resources lacking proper access control checks? or any unauthenticated user / low privileged user can access them ? (BAC + BA)**
- Test weak/missing access controls -- any page/resource.

** Are there any vulnerable parameters in any authentication page allowing parameter manipulation (e.g., URL params, cookies, headers, POST data) that could involve modifying session tokens / tampering with params that control access levels / user roles?**
- Test parameter manipulation (e.g., loggedin=true, etc) -- any authentication page.

---

## Token-Based Authentication (JWT, OAuth, Bearer, etc.) — Testing & Questions Methodology

**Target features:** Bearer tokens, JWTs, OAuth access/refresh tokens, token transport & storage, token endpoints, etc.

**Token types:**  
- **Bearer:** `Authorization: Bearer <token>` — commonly used; can be vulnerable if mishandled.  
- **JWT:** `header.payload.signature` — may be stored in cookies, localStorage, or sent via API.  
- **OAuth tokens:** Access & refresh tokens — usually bearer tokens, sometimes JWTs.  
- **Query params:** `/api/v1/resource?access_token=<token>` — risky.  
- **Request body:** `{ "token": "<token>" }` — not recommended for GET requests.  
- **Cookies:** `Set-Cookie: auth_token=<token>; Secure; HttpOnly` — safer when configured correctly.  
- **Custom headers:** e.g., `X-Auth-Token: <token>`.

---

### JWT Structure (quick reference)

**Structure:** `Header.Payload.Signature`  
- **Header:** metadata about the token and algorithm, e.g. `{"alg":"HS256","typ":"JWT"}`.  
- **Payload:** claims about user/session, e.g. `{"sub":"12345","name":"John Doe","admin":true,"exp":1234567890}`. Claims are base64-encoded — not encrypted.  
- **Signature:** ensures integrity & authenticity; created using secret/private key.

**Notes:**  
- Claims should not include sensitive data like passwords.  
- Use registered claims where applicable: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`.  
- Public claims must be unique to avoid collisions; private claims are app-specific.

---

### JWT Testing — Questions & Methodology

**Basic**  
- **SCS-JWT-01:** Can an attacker use `alg: none` to bypass signature verification?  
- **SCS-JWT-02:** Is there sensitive info exposed in claims?

**Intermediate**  
- **SCS-JWT-01:** Can tokens be intercepted in transit?  
  - Test: enumerate token endpoints, check HTTPS/HSTS/no mixed content.  
  - Inspect: Authorization headers, query params, and response bodies.  
  - Look for: tokens sent in URLs or fragments, tokens in `Referer` headers.

- **SCS-JWT-02:** Is token storage on client secure?  
  - Inspect localStorage/sessionStorage, cookies, service workers, IndexedDB, mobile keystores.  
  - Check cookies for `Secure`, `HttpOnly`, and `SameSite` flags.

- **SCS-JWT-03:** Are JWT claims safe (no sensitive data)?  
  - Decode tokens and review claims, `exp`, `iat`, `nbf`, `aud`, `iss`.

- **SCS-JWT-04:** Is signature and algorithm handled properly?  
  - Test algorithm confusion (`RS256` ↔ `HS256`), `alg:none`.  
  - Inspect `kid` usage and JWKs endpoints.

- **SCS-JWT-05:** Is key management robust?  
  - Fetch JWKS if available, inspect key rotation and entropy.

- **SCS-JWT-06:** Are refresh tokens used and handled safely?  
  - Check rotation, one-time use, binding to client, and storage location.

- **SCS-JWT-07:** Is token revocation supported?  
  - Test revocation endpoints and attempt reuse after revocation.

**Advanced**  
- Algorithm confusion & signature bypass, kid/JWKS attacks, claim manipulation, token replay, refresh token race conditions, aud/iss/nbf/exp bypasses, token leakage via logs, PKCE enforcement, redirect URI open-redirects, scope escalation, CORS & CSRF around token endpoints, introspection abuse, and key rotation simulation.

---

## OAuth Testing — Questions & Methodology

### Basic Level

**SCS-OAUTH-01**  
Are redirect parameters validated to prevent open redirects and token theft?

**SCS-OAUTH-02**  
Do authorization codes have sufficient randomness?

**SCS-OAUTH-03**  
Do authorization codes expire and are they single-use?

**SCS-OAUTH-04**  
Can authorization codes or refresh tokens be reused across clients?

**SCS-OAUTH-05**  
Can attackers guess access or refresh tokens?

**SCS-OAUTH-06**  
Are there web vulnerabilities (SQL/NoSQL injection) that expose tokens?

**SCS-OAUTH-07**  
Does the OAuth implementation have weak spots (XSS, CSRF, etc.)?

### Intermediate Level

- Inspect OAuth flows (Authorization Code, Implicit, Hybrid).  
- Enforce HTTPS on `/authorize`, `/token`, `/callback`.  
- Test `redirect_uri` tampering and `state` parameter validation.  
- Verify PKCE enforcement for public clients.  
- Check token lifetimes, rotation, and scope enforcement.  
- Test CORS and CSRF protections on OAuth endpoints.

### Advanced Level

- Redirect chaining attacks, authorization code reuse / race conditions, cross-client leakage, `state` bypasses, PKCE downgrade, scope escalation, introspection/revocation abuse, token replay & binding failures, JWKs manipulation, and client registration flaws.

---

## Broken Session Management (BSESS) — Testing Questions & Methodology

**Target features:** Sessions & account security mechanisms.

### Basic Level

**WSTG-SESS-01**  
Are session identifiers generated and stored securely (unpredictable, non-reversible, resistant to guessing)?

**WSTG-SESS-02**  
Can an attacker set or fix a session ID prior to authentication (session fixation)?

**WSTG-SESS-03**  
Do sessions automatically expire after a defined timeout?

**WSTG-SESS-04**  
Are session tokens bound to user-specific attributes (IP, User-Agent, device fingerprint)?

**WSTG-SESS-05**  
Are secure cookie attributes (`HttpOnly`, `Secure`, `SameSite`) implemented?

**WSTG-SESS-06**  
Are reasonable session lifetimes configured to avoid long-lived sessions?

**WSTG-SESS-07**  
Are session tokens exposed in URLs, headers, logs, or other insecure storage?

### Intermediate Level

- Collect session tokens for analysis and test entropy (length, randomness).  
- Use tools like Burp Sequencer or OWASP ZAP to test randomness.  
- Test session ID rotation during login/logout to prevent fixation.  
- Replay session tokens from different devices/IPs to test binding.

### Advanced Level

- Gather many cookie samples and attempt reverse engineering (base64 decode, structures).  
- Test cookie forging and prediction attacks.  
- Verify regeneration of session tokens upon login/logout.  
- Check for XSS, CSRF, MITM, and session prediction vulnerabilities.  
- Confirm proper cookie attributes (`Max-Age`, `Expires`, `HttpOnly`, `Secure`, `SameSite`).

# Broken Access Control (BAC) — Testing Questions & Methodology

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