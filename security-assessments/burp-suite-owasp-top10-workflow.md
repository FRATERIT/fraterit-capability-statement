# Burp Suite Security Scan Workflow — OWASP Top 10
**Client Target:** `https://webservices.advanceware.net/gironbooksb2c/ShoppingCart.aspx`
**Prepared by:** FraterIT Enterprises
**Scope:** Web Application Penetration Test — OWASP Top 10 (2021)
**Tool:** Burp Suite Professional

---

## Pre-Engagement Checklist

- [ ] Written authorization / Rules of Engagement (RoE) signed by client
- [ ] Scope confirmation (URLs, IP ranges, excluded paths)
- [ ] Emergency contact established
- [ ] Testing window agreed upon
- [ ] Burp Suite Pro license active and updated

---

## Environment Setup

### 1. Configure Burp Suite Proxy
1. Launch Burp Suite Professional
2. Go to **Proxy → Options → Proxy Listeners**
3. Confirm listener on `127.0.0.1:8080`
4. Configure browser (or FoxyProxy) to route traffic through `127.0.0.1:8080`
5. Install Burp CA certificate in browser to intercept HTTPS traffic

### 2. Project Setup
1. **New Project → Save to disk** → name: `advanceware-gironbooks-<date>`
2. Set **Target → Scope**:
   - Include: `https://webservices.advanceware.net/gironbooksb2c/*`
   - Exclude: logout endpoints, password-reset triggers, destructive actions

### 3. Crawl / Spider the Target
1. Navigate to `https://webservices.advanceware.net/gironbooksb2c/ShoppingCart.aspx?Recalc=Yes`
2. Right-click in **Target → Site Map** → **Scan** (or use **Crawler**)
3. Manually browse: add items to cart, view cart, attempt checkout — capture all flows in Proxy History
4. Review **Target → Site Map** to confirm full coverage

---

## OWASP Top 10 (2021) Testing Procedures

---

### A01 — Broken Access Control

**Goal:** Verify users cannot access resources or perform actions beyond their privilege level.

**Steps:**
1. Log in as a low-privilege / guest user; capture session token.
2. Use **Burp Intruder / Repeater** to replay requests with:
   - Modified `OrderID`, `CartID`, `CustomerID` parameters (IDOR test)
   - Forced browsing to admin or account pages while unauthenticated
3. Test HTTP verbs: change `GET` to `POST`, `PUT`, `DELETE` on cart endpoints.
4. Check for direct object references in URL parameters (`?user=123`, `?order=456`).
5. Attempt to access another user's cart by manipulating session/cart cookies.

**Burp Tools:** Repeater, Intruder, Autorize extension (if installed)

---

### A02 — Cryptographic Failures

**Goal:** Ensure sensitive data is encrypted in transit and at rest (observable side).

**Steps:**
1. Confirm all traffic uses **TLS 1.2+** — check via Burp's **Logger** or browser dev tools.
2. In Burp **Target → Site Map**, flag any `http://` (non-TLS) resources or mixed content.
3. Inspect responses for sensitive data exposed in plain text:
   - Credit card numbers, CVV, full account numbers
   - Passwords or tokens in response bodies / cookies
4. Check cookies for `Secure` and `HttpOnly` flags (**Proxy → HTTP History → Response Headers**).
5. Review `ViewState` — right-click → **Send to Decoder** → decode Base64 → check if MAC-protected (`EnableViewStateMac`).

**Burp Tools:** Logger, Decoder, passive scan findings

---

### A03 — Injection (SQL, Command, LDAP, XPath)

**Goal:** Test all input fields and parameters for injection vulnerabilities.

**Steps:**
1. Identify injection points: URL params (`Recalc`, `ItemID`, `Qty`), POST body fields, cookies, headers.
2. **SQL Injection:**
   - Send requests to **Repeater**; inject payloads: `'`, `''`, `' OR '1'='1`, `; DROP TABLE--`
   - Use **Burp Scanner** (active scan) on form fields and URL parameters
   - Use **SQLMap** integration or Burp's active scanner for automated detection
3. **XPath / LDAP Injection:** Try `' or '1'='1` and `*)(uid=*))(|(uid=*` in username/search fields.
4. **Command Injection:** Test fields that may invoke server-side processes: `; whoami`, `| dir`.
5. Review all Burp **Active Scan** findings under **Dashboard → Issue Activity**.

**Burp Tools:** Scanner (Active Scan), Repeater, Intruder

---

### A04 — Insecure Design

**Goal:** Identify design-level flaws (rate limiting, business logic, workflow bypasses).

**Steps:**
1. **Shopping cart business logic:**
   - Set item quantity to `0`, `-1`, or very large numbers — observe server response.
   - Modify price parameters in POST requests (if present) to `0.01`.
   - Attempt to skip checkout steps (e.g., bypass payment page via direct URL).
   - Add items beyond stated inventory limits.
2. Test `Recalc=Yes` parameter — observe if recalculation can be manipulated.
3. Check for missing rate limiting on cart updates / coupon code fields (use **Intruder** in Sniper mode).

**Burp Tools:** Repeater, Intruder

---

### A05 — Security Misconfiguration

**Goal:** Identify misconfigurations in headers, error pages, and server banners.

**Steps:**
1. **HTTP Security Headers** — check responses for presence of:
   - `Content-Security-Policy`
   - `X-Frame-Options` (clickjacking)
   - `X-Content-Type-Options: nosniff`
   - `Strict-Transport-Security` (HSTS)
   - `Referrer-Policy`
   - `Permissions-Policy`
   Use Burp **Passive Scan** or manually inspect response headers in **HTTP History**.
2. Trigger error conditions (invalid input, 404s) — check if stack traces / server version leak.
3. Check for default/debug pages: `/elmah.axd`, `/trace.axd`, `/WebResource.axd`.
4. Verify `.aspx` pages don't expose viewable source or compilation errors.
5. Test for directory listing on known paths.

**Burp Tools:** Passive Scanner, Repeater, Content Discovery (Intruder with wordlist)

---

### A06 — Vulnerable and Outdated Components

**Goal:** Identify server-side and client-side components with known CVEs.

**Steps:**
1. Note `Server` and `X-Powered-By` response headers — record versions.
2. Check for ASP.NET version disclosure in headers (`X-AspNet-Version`, `X-AspNetMvc-Version`).
3. Inspect JavaScript includes — note jQuery, Bootstrap, and other library versions.
4. Cross-reference identified versions against:
   - [NIST NVD](https://nvd.nist.gov/)
   - [Snyk Vulnerability DB](https://security.snyk.io/)
5. Run Burp **Passive Scan** — flags outdated JS libraries automatically.

**Burp Tools:** Passive Scanner, Logger (header inspection)

---

### A07 — Identification and Authentication Failures

**Goal:** Verify authentication and session management are robust.

**Steps:**
1. **Session Token Analysis:**
   - Capture multiple session tokens (log in/out several times).
   - Send to **Sequencer** → analyze entropy.
2. **Cookie Attributes:** Confirm `Secure`, `HttpOnly`, `SameSite` flags on auth cookies.
3. **Session Fixation:** Set a known session ID before login — verify token rotates post-auth.
4. **Brute Force / Lockout:** Use **Intruder** (Sniper) on login — test if account lockout triggers after N attempts.
5. **Logout:** Verify session is invalidated server-side after logout (replay old token in Repeater).
6. **Password Policy:** Attempt weak passwords if a registration/account-change flow is in scope.
7. **Remember-Me Token:** Inspect for weak or predictable persistent tokens.

**Burp Tools:** Sequencer, Intruder, Repeater

---

### A08 — Software and Data Integrity Failures

**Goal:** Verify integrity of updates, critical data, and deserialization.

**Steps:**
1. **ViewState Deserialization:**
   - Capture `__VIEWSTATE` parameter from cart page.
   - Decode in **Burp Decoder** (Base64).
   - If MAC is not enforced (`EnableViewStateMac=false`), craft modified ViewState and submit.
   - Use **YSoSerial.NET** (out-of-band) to test for insecure deserialization if ViewState is unprotected.
2. Check for any auto-update mechanisms or CDN-loaded scripts without Subresource Integrity (SRI) hashes.
3. Verify that cart total / order data is validated server-side and cannot be tampered with client-side.

**Burp Tools:** Decoder, Repeater

---

### A09 — Security Logging and Monitoring Failures

**Goal:** Assess visibility (observable from the attacker's perspective).

**Steps:**
1. Perform intentional failed logins, invalid inputs, and access-control violations.
2. Observe whether the application returns detailed error messages that would aid an attacker.
3. Check if repeated attack patterns (SQLi probes, brute force) result in any observable defensive response (block, CAPTCHA, rate limit).
4. Document findings — note the **absence** of rate limiting or throttling as a finding.

> Note: Full logging assessment requires server-side access; document observable gaps only.

**Burp Tools:** Intruder (to generate volume), Repeater

---

### A10 — Server-Side Request Forgery (SSRF)

**Goal:** Test if the server can be tricked into making requests to internal/external resources.

**Steps:**
1. Identify parameters that accept URLs or resource paths (product images, redirects, webhooks).
2. In **Repeater**, replace URL values with:
   - `http://169.254.169.254/latest/meta-data/` (AWS metadata)
   - `http://127.0.0.1/` or `http://localhost/`
   - `http://<Burp Collaborator URL>` — confirm out-of-band interaction
3. Use **Burp Collaborator** (built-in) to detect blind SSRF.
4. Check any "share cart", "email receipt", or "load image from URL" features.

**Burp Tools:** Repeater, Burp Collaborator

---

## Automated Scan

After manual testing of the above, run a full active scan:

1. In **Target → Site Map**, right-click the target host → **Scan**
2. Select **Audit items with forms and parameters** — Full audit
3. Monitor **Dashboard → Issue Activity** for findings as scan progresses
4. When complete, triage all **High / Medium** findings manually in **Repeater** to confirm exploitability

---

## Reporting

### Finding Template (per issue)

| Field | Detail |
|---|---|
| **Title** | e.g., Reflected XSS in `ItemID` parameter |
| **OWASP Category** | e.g., A03 — Injection |
| **Severity** | Critical / High / Medium / Low / Informational |
| **CVSS Score** | (optional) |
| **URL / Parameter** | Exact endpoint and parameter affected |
| **Evidence** | Screenshot + Burp request/response |
| **Impact** | What an attacker could achieve |
| **Remediation** | Specific developer guidance |

### Export from Burp
1. **Dashboard → Issue Activity** → select all findings → **Report Selected Issues**
2. Format: **HTML** (for client) or **XML** (for import into defect tracker)
3. Supplement with manual findings documented outside the scanner

---

## Post-Engagement

- [ ] Confirm all active scan/attack traffic has stopped
- [ ] Deliver report to client with executive summary and technical detail
- [ ] Schedule remediation review / retest
- [ ] Archive Burp project file securely
- [ ] Destroy any credentials / test data created during engagement

---

*FraterIT Enterprises — Confidential Security Assessment Documentation*
