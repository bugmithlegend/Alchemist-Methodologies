# Broken Access Control (BAC) - Testing Questions & Methodology

---

## Target Features

Direct object references, role-based access, URL / parameter access, API endpoints, administrative interfaces, and privileged resources / functionalities / actions.

---

# AUTH BYPASSES

## Bugmith-BAC-01 --- Unprotected Functionalities
Question: Can I invoke privileged functionalities without being authenticated or with low privileges?  
Test: Invoke protected functionalities as an unauthenticated or low-privileged user  
Expected: 40X responses  
Vulnerable scenario: Privileged functionality invoked successfully as an unauthenticated or low-privileged user (200 / 302)

---

## Bugmith-BAC-02 --- Unprotected Resources
Question: Can I access privileged resources without being authenticated or with low privileges?  
Test: Request protected pages or resources as an unauthenticated or low-privileged user  
Expected: 40X responses  
Vulnerable scenario: Privileged resources accessed successfully as an unauthenticated or low-privileged user (200 / 302)

---

## Bugmith-BAC-03 --- Concealed Unprotected Functionalities (Hidden)
Question: Can I invoke hidden or obscured privileged functionalities without proper privileges?  
Test: Look in code, client-side scripts, or APIs for hidden sensitive functionalities and invoke them as an unauthenticated or low-privileged user  
Expected: 40X responses  
Vulnerable scenario: Obscured privileged functionality invoked successfully as an unauthenticated or low-privileged user (200 / 302)

---

## Bugmith-BAC-04 --- Concealed Unprotected Resources (Hidden)
Question: Can I access hidden or undocumented privileged resources without proper authorization?  
Test: Look in code, client-side scripts, or APIs for hidden sensitive resources or endpoints and request them as an unauthenticated or low-privileged user  
Expected: 40X responses  
Vulnerable scenario: Obscured privileged resources accessed successfully as an unauthenticated or low-privileged user (200 / 302)

---

## Bugmith-BAC-05 --- Authorization Bypass via Alternative Channels
Question: Can I access privileged functionality via alternative channels?  
Test: Try APIs, mobile endpoints, integration endpoints, or legacy interfaces  
Expected: 40X responses and blocked access  
Vulnerable scenario: Missing access control on alternative channels

---

## Bugmith-BAC-06 --- NoMore403
Use it to bypass 403 Forbidden pages in Linux.

---

## Bugmith-BAC-07 --- 403 Bypasser
Use it to bypass 403 Forbidden pages in Burp Suite.

---

# IDORs

## Bugmith-BAC-08 --- Insecure Direct Object References (IDOR)
Question: Can I access objects directly through user-supplied input without authorization?  
Test: Try to access resources/pages using client-side controlled parameters referencing other users’ data  
Expected: 40X responses and blocked access  
Vulnerable scenario: Direct object access via user-supplied input

---

## Bugmith-BAC-09 --- User Modifiable Roles Through Parameters (Role Escalation / Tampering & IDOR)
Question: Can I escalate privileges by modifying client-side parameters, cookies, headers, or role values?  
Test: Look for hidden fields, cookies, parameters, role claims, or numeric role values that allow client-side privilege escalation across all infrastructure  
Expected: 40X responses, roles and privilege data not modifiable on the client side, and proper access control across parameters  

Vulnerable scenario 1: A parameter such as ?admin=true accepts a boolean value resulting in privilege escalation  
Vulnerable scenario 2: A parameter such as ?role=1 accepts role modification via numeric values resulting in privilege escalation  

---

## Bugmith-BAC-10 --- User Modifiable Request Parameter Manipulating User ID (Predictable IDOR)
Question: Can I access other users’ data by changing predictable identifiers?  
Test: Modify resource identifiers (id=123 -> id=124) and attempt to access or invoke actions for other users  
Expected: 40X responses and blocked access  
Vulnerable scenario: Access to other users’ data by modifying predictable identifiers

---

## Bugmith-BAC-11 --- User Modifiable Request Parameter Manipulating GUIDs (Unpredictable IDOR)
Question: Can I abuse exposed GUIDs or indirect references to access other users’ data?  
Test: Search for GUIDs across all infrastructure and attempt to access user data via parameter manipulation  
Expected: 40X responses and blocked access  
Vulnerable scenario: Exposed GUIDs allow unauthorized access to other users’ data

---

## Bugmith-BAC-12 --- Redirected User Modifiable Request Parameter Manipulating User ID (IDOR)
Question: Can I get sensitive data before being redirected or blocked when abusing IDOR?  
Test: Manipulate identifiers and observe responses prior to redirection to a blocked page  
Expected: 40X responses and no sensitive information returned  
Vulnerable scenario: Sensitive data exposed before redirection

---

## Bugmith-BAC-13 --- User Modifiable Parameters & Headers
Question: Can I bypass authorization by manipulating parameters or headers?  
Test: Modify user_id, tenant_id, org_id, or headers like X-User-Role and retry operations  
Expected: 40X responses and proper server-side enforcement  
Vulnerable scenario: Authorization bypass via parameters or headers

---

## Bugmith-BAC-14 --- User Modifiable Tenants
Question: Can I access another tenant’s data by changing tenant identifiers?  
Test: Request cross-tenant resources by modifying tenant identifiers  
Expected: 40X responses and blocked access  
Vulnerable scenario: Cross-tenant data exposure

---

## Bugmith-BAC-15 --- Identifier Source Confusion (For Escalation from 1 Bug to 10+ Bugs)
Question: Can I control which duplicated identifier the backend actually trusts?  
Test: Send conflicting object IDs across URI, headers, body, cookies, or tokens (e.g. URI org_id=A, header org_id=B)  
Expected: All identifiers are cross-validated and mismatches are rejected  
Vulnerable scenario: Backend authorizes using one identifier while performing actions using another attacker-controlled identifier  

Mindset: 9 times out of 10 you will find the same bug somewhere else.

---

## Bugmith-BAC-16 --- User Modifiable Steps During Multi-Step Complex Processes
Question: Can I abuse a missing access control check in one step of a multi-step process?  
Test: Invoke each step independently or out of order using another user’s supplied input  
Expected: 40X responses and blocked access  
Vulnerable scenario: One step allows unauthorized access

---

# CIRCUMVENTIONS

## Bugmith-BAC-17 --- Circumvented URL-Based Access Controls
Question: Can I bypass URL-based access controls using non-standard HTTP headers?  
Test: Use non-standard HTTP headers such as X-Original-URL or X-Rewrite-URL to evade denied rules and access restricted resources or functionalities  
Expected: 40X responses and rejection of non-standard HTTP headers  
Vulnerable scenario: A URL accepts non-standard HTTP headers and grants access (200 / 302)

---

## Bugmith-BAC-18 --- Circumvented Method-Based Access Controls
Question: Can I bypass access controls by switching HTTP methods?  
Test: Switch HTTP methods (POST -> GET, POST -> PUT, POST -> DELETE, POST -> POSTX) using a web proxy or manual modification  
Expected: 40X responses and method rejection  
Vulnerable scenario: An endpoint rejects one method but accepts another unauthorized method allowing unauthorized access or actions

---

## Bugmith-BAC-19 --- Circumvented URL-Matching Discrepancies Access Controls
Question: Can I bypass access controls using URL-matching or path normalization discrepancies?  
Test: Append extensions or path segments to endpoints (e.g. /admin -> /admin.anything)  
Expected: 40X responses and discrepancy rejection  
Vulnerable scenario: A restricted endpoint blocks /admin but allows access to /admin.anything

---

## Bugmith-BAC-20 --- Circumvented Referer-Based Access Control
Question: Can I bypass access controls by forging the Referer header?  
Test: Visit restricted sub-pages with a forged Referer header including an authorized URL  
Expected: 40X responses and blocked access  
Vulnerable scenario: Access granted based on Referer header

---

## Bugmith-BAC-21 --- Circumvented Location-Based Access Control
Question: Can I bypass access controls by manipulating geographic location?  
Test: Use VPNs, proxies, or manipulate client-side geolocation mechanisms  
Expected: 40X responses and blocked access  
Vulnerable scenario: Location-based restrictions bypassed

---

# AUTHORIZATION LOGIC FLAWS

## Bugmith-BAC-22 --- Time / Action Based Privileges
Question: Can I perform actions outside permitted time or action limits?  
Test: Attempt actions beyond allowed time windows or limits  
Expected: 40X responses and enforcement of business rules  
Vulnerable scenario: Actions allowed outside limits

---

## Bugmith-BAC-23 --- Privilege Escalation via Chained Requests
Question: Can I chain low-privileged actions to gain higher privileges?  
Test: Chain legitimate low-privileged operations to escalate privileges  
Expected: 40X responses and blocked escalation  
Vulnerable scenario: Privilege escalation via chained requests

---

## Bugmith-BAC-24 --- Authorization Logic Flaws
Question: Can I bypass authorization due to flawed or complex logic?  
Test: Manipulate inputs in endpoints with complex boolean authorization logic  
Expected: 40X responses and correct enforcement  
Vulnerable scenario: Authorization bypass due to logic flaws

---

## Bugmith-BAC-25 --- Logging & Error Disclosure
Question: Can I extract sensitive authorization details from errors or logs?  
Test: Inspect error messages for leaked role mappings, access decisions, or internal identifiers  
Expected: Generic errors with no sensitive disclosure  
Vulnerable scenario: Authorization details leaked via errors or logs

---
