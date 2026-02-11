# Business Logic Flaws (BLF) – Testing Questions & Methodology

---

## Target Features to Manipulate

**Numeric fields:**  
price, quantity, amount, discount percentage, balance, credit, limit, threshold, stock, points  

**User identifiers:**  
username, email, user_id, account_id, verify, target_user, victim, temp-token, reset_token  

**Workflow tokens / state:**  
session, csrf, temp-forgot-password-token, notification cookie, order_id, transaction_id, state, step_id, confirmation_token  

**Mandatory / optional parameters:**  
current-password, old_password, verify, role, permission_level, is_admin, requires_2fa  

**Sequence indicators:**  
step, order-confirmation=true, checkout, confirm, complete, next, previous, finish  

**Privileged indicators:**  
email domain, role selector, stay-logged-in cookie, group_id, membership_type, vip_status, internal_flag  

**Additional high-value fields:**  
coupon_code, gift_card_code, referral_code, promo_id, invoice_total, tax_rate, shipping_cost, refund_amount  

---

## Core Manipulation Techniques (Use Burp Proxy / Repeater / Intruder)

Modify values -> price=1, quantity=-50, amount=999999999999, discount_percentage=100  
Set negative / oversized values -> quantity=-1000, quantity=2147483647+1, balance=-500000, limit=999999999999999  
Remove parameters entirely -> delete current-password, temp-forgot-password-token, verify, csrf, old_password  
Change user context -> username=administrator, verify=targetuser, email=admin@target.com, user_id=1, account_id=999  
Replay / skip steps -> resend /order-confirmation?confirmed=true or /complete without prior /checkout or /payment  
Alternate / repeat actions -> cycle between two coupon codes repeatedly, buy -> apply discount -> redeem gift card -> repeat  
Encrypt / craft tokens -> use encryption/decryption oracle to generate valid ciphertext for admin:timestamp or user:role  
Truncate / pad long inputs -> 255+ char emails with subdomain tricks (e.g., verylongstring@privileged-domain.com.attacker-controlled.com)  
Drop intermediate requests -> drop GET /role-selector or GET /mfa-verify; force default or elevated privilege  
Force parameter injection -> add unexpected parameters (is_admin=true, bypass_validation=1, role=admin)  
Parameter pollution -> duplicate keys (quantity=1&quantity=-100) or array injection ([quantity]=-50)  
Type confusion -> send string where number expected (quantity="NaN", price="999999999999999999999")  

---

# Bugmith-BLF-01 --- Understanding Logical Flaws

Business logic flaws arise from flawed assumptions about user behavior, input ranges, sequence enforcement, or state consistency, allowing attackers to trigger unintended business outcomes.

To spot them, map complete end-to-end workflows across multiple endpoints, paying attention to how data and state flow between requests — most serious bugs live in the gaps and transitions between endpoints, not inside single requests.

Exploit by systematically violating every visible and implicit assumption: send negative/zero/oversized values, remove “mandatory” fields, change user identifiers mid-flow, replay or skip steps, and force inconsistent application states.

Understand workflows by recording full proxy histories, annotating dependencies, and asking:
> “What happens if I break this link?”

Zoom out and think like an attacker with concrete goals (free items, account takeover, privilege escalation, infinite resources).

Test one deviation at a time and always finish the tampered workflow to observe the real business impact.

Document discovered assumptions and broken rules to recognize similar patterns in other parts of the application.

The more complex or multi-step the feature, the higher the probability of logic exposure.

**Summary:**  
Business logic vulnerabilities arise when an application makes incorrect assumptions about user behavior, input validity, workflow order, or state, allowing attackers to manipulate legitimate functionality to achieve unintended outcomes.

---

# Bugmith-BLF-02 --- Excessive Trust in Client-Side Controls

### Cart / Order Manipulation for Free Items (Price Tampering in Invoices)
Question: Does the server blindly trust values sent from the client?  
Manipulation: POST /cart or POST /order -> price=100 or amount=500 -> change to price=1 or amount=0 or total=0 or 1 -> complete checkout or payment  
Ready Exploit: POST /cart: price=0 or 1 / amount=0 or 1 / total=0 or 1  

### 2FA Broken Logic
Question: Can verification target another user (verify=anotheruser user-input trusted)?  
Manipulation: POST /login2 -> verify=targetuser -> brute-force code  

---

# Bugmith-BLF-03 --- Failing to Handle Unconventional Input

### Integer Overflow / Wrap-Around (High-level logic vulnerability)
Question: Are negative, zero, or extreme values rejected server-side?  
Manipulation: POST /cart or POST /transfer -> quantity=-150 or amount=-1000  
Ready Exploit: quantity=-100 in POST /cart  

### Failing to Handle Unconventional Input (Low-level logic flaw)
Question: Does large quantity × price exceed signed integer limits?  
Manipulation: Intruder on quantity=99 (null payloads 300–400x) -> watch total flip negative -> fine-tune final quantity  
Ready Exploit: Intruder: quantity=99, null payloads x300–400  

### Inconsistent Handling of Exceptional Input
Question: Does truncation / length limit allow spoofing privileged identifiers?  
Manipulation: Register with 200+ char email -> verylongstring@privileged-domain.com.attacker-controlled.com  
Ready Exploit: Long email with truncation abuse  

---

## Money Systems

### Negative Amount Inversion in Transfers
Question: Can negative amounts reverse transfers?  
Manipulation: POST /transfer -> amount=-5000  

### Negative Quantity Credit Abuse
Manipulation: POST /cart -> quantity=-1000  

### Balance Overflow in Deposits/Withdrawals
Question: Does large deposit cause wrap-around?  
Manipulation: Intruder deposit=2147483647+1 repeatedly  

---

# Bugmith-BLF-04 --- Making Flawed Assumptions About User Behavior

## Trusted users won’t always remain trustworthy

### Inconsistent Security Controls
Question: Are privilege checks applied only once? Can users after being trusted do unauthorized actions?  
Manipulation: Update email to admin@privileged-domain.com  

### Paid Feature Provisioning via Missing Authorization (Kong‑style scenario and across other applications)
Question: Are entitlement / subscription checks enforced server‑side when provisioning paid or enterprise‑only resources?  
Manipulation: Authenticate as free‑tier user -> call provisioning API directly -> set paid‑only capability flag (e.g. "cloud_gateway": true) -> observe backend provisions enterprise resource without validating subscription or payment status  

### Session Persistence After Account Revocation Trust Lifecycle Flaw (CI4MS-style scenario and across other applications)
Question: Does the application re‑validate account status (deleted / blacklisted / locked / deactivated) on every authenticated request, or only during login?  
Manipulation: Login as normal user -> while session is active, admin deletes / locks / blacklists account -> continue sending authenticated requests using existing session cookie -> check if access to account and protected resources still works  

---

## Users won’t always supply mandatory input

### Weak Isolation on Dual-Use Endpoint
Manipulation: Remove current-password during changing password; username=admin or any other user leading to session hijack and privesc  

### Password Reset Broken Logic
Manipulation: Delete temp-token or any token used during resetting pass without verification check; username=target_user  

### Bypass Recurring Billing Checks
Manipulation: POST /renew -> delete renewal-token and try to bypass verification  

---

## Users won’t always follow the intended sequence

### 2FA Simple Bypass
Manipulation: During logging into an account, when prompted for a 2fa code, skip the step and try to access/navigate to my-account and check if bypasses validation  

### Insufficient Workflow Validation
Manipulation: During adding items to cart and checking out, replay GET /order-confirmation?confirmed=true without completing checkout process and check if bypasses validation  

### Authentication Bypass via Flawed State Machine (Role Default Bypass)
Manipulation: When logging into an account, drop GET /role-selector or any role-selection request during the process and try to skip and access/navigate to my-account, check if bypasses validation as it may default to admin role or any dangerous role  

### Email Verification Bypass via Auth Surface Discrepancy (Kong‑style scenario and across other applications)
Question: Are email verification steps enforced server‑side and consistently across all authentication entry points (UI vs API)?  
Manipulation: During signin, drop or bypass email‑verification request -> complete authentication flow via API or alternate endpoint -> navigate to /my-account or other protected resources without completing email verification  

### Federated Authentication Sequence Bypass (Kong‑style scenario and across other applications)
Question: Are all required authentication steps (email verification, MFA, role selection) strictly enforced server-side across federated / alternate API entry points?  
Manipulation: Authenticate via federated endpoint -> drop or skip intermediate verification step (email‑verify / mfa‑verify / role‑selector) -> directly access /my-account or protected org endpoints -> check if authentication completes without enforcing required sequence  

---

# Business Logic Exploitation & Impact Escalation

## Bugmith-BLF-7 --- Financial Loss via Price Manipulation
Exploit: Negative totals + stacked discounts  

## Bugmith-BLF-8 --- Account Takeover via Reset/Change Bypass
Exploit scenarios:
- Resetting user's password without current_password leading to session hijacking  
- Password reset without verified email ownership (or via API) leading to session hijacking  
- Reusing / replaying password reset tokens across users leading to session hijacking  

## Bugmith-BLF-9 --- Admin Access via Escalation
Exploit scenarios:
- Forged cookies leading to Privilege Escalation / Admin‑Endpoints Access / Admin Session Hijacking  
- Escaping role selection and defaulting to admin roles leading to Privilege Escalation  
- Domain spoofing in user email leading to Privilege Escalation / Admin‑Endpoints Access  

## Bugmith‑BLF‑10 --- Denial‑of‑Wallet / Resource Exhaustion
Exploit scenarios:
- Provisioning paid or enterprise‑only resources from free / low‑tier accounts  
- Automating resource creation (gateways, instances, projects, workspaces) via vuln such as email ownership not validated  
- Triggering cloud‑side costs without billing enforcement  

## Bugmith‑BLF‑11 --- Unauthorized Data Access via Broken Authorization
Exploit scenarios:
- Accessing org‑scoped data without verified email  
- Switching account_id, org_id, or project_id mid‑flow  
- JWT / session trusting unverified identity claims  

## Bugmith‑BLF‑12 --- Identity Impersonation & Trust Abuse
Exploit scenarios:
- Registering with unverified or spoofed corporate email domains  
- Email normalization / parser discrepancies (user@gmail.com vs usér@gmail.com)  
- Appearing as internal staff, org owner, or trusted partner without email ownership  

## Bugmith‑BLF‑13 --- Authentication Bypass via State Machine Failure
Exploit scenarios:
- Skipping mandatory verification steps (email, 2FA)  
- Completing login via alternate auth surface (API vs UI)  
- Default role / default authenticated state assignment  

## Bugmith‑BLF‑14 --- Platform Abuse & Automation
Exploit scenarios:
- Mass account creation without verification  
- Abuse of free credits, coupons, trials, or referrals  
- Spam, phishing, and fake account operations  

---
