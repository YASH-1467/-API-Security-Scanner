R"""
API Security Scanner
----------------------
Tests a public API endpoint for common security misconfigurations:
missing authentication, verbose error leaks, exposed common paths,
and missing rate-limit indicators.

Tested safely against jsonplaceholder.typicode.com — a public API
built specifically for developers to practice against.

Author: Yash
"""

import requests

# Base URL of the API being tested.
# jsonplaceholder.typicode.com is a free, public, practice-safe API —
# no permission issues, built for exactly this kind of testing.
BASE_URL = "https://jsonplaceholder.typicode.com"


# ---------------------------------------------------------
# Check 1: Does the API return data without any authentication?
# ---------------------------------------------------------
def check_authentication(endpoint: str) -> dict:
    """
    Sends a plain request with no auth headers/token.
        If real data comes back with a 200 OK, that's worth flagging —
            a production API handling sensitive data should require auth.
    """
    url = f"{BASE_URL}{endpoint}"
    response = requests.get(url, timeout=10)

    return {
        "check": "Authentication",
        "url": url,
        "status_code": response.status_code,
        "flag": response.status_code == 200,
        "note": "Returned data with no authentication provided." if response.status_code == 200
        else "Did not return data without authentication (expected behavior).",
    }


# ---------------------------------------------------------
# Check 2: Does sending bad input leak internal error details?
# ---------------------------------------------------------
def check_error_leakage(endpoint: str) -> dict:
    """
    Sends a deliberately invalid request (bad ID format) and inspects
        the error response for leaked internal details like file paths,
            stack traces, or server/framework names.
    """
    url = f"{BASE_URL}{endpoint}/not-a-valid-id"
    response = requests.get(url, timeout=10)

    body_text = response.text.lower()
    leak_keywords = ["traceback", "stack trace", "exception", "/usr/", "c:\\", "sqlstate"]
    leaked = any(keyword in body_text for keyword in leak_keywords)

    return {
        "check": "Error Message Leakage",
        "url": url,
        "status_code": response.status_code,
        "flag": leaked,
        "note": "Response contains internal error details." if leaked
        else "No obvious internal details leaked in error response.",
    }


# ---------------------------------------------------------
# Check 3: Do common "hidden" endpoint paths respond with real data?
# ---------------------------------------------------------
def check_common_endpoints() -> list:
    """
    Tries a short list of commonly-used API paths to see if any
        sensitive-sounding endpoint responds unexpectedly.
    """
    common_paths = ["/admin", "/config", "/internal", "/debug"]
    results = []

    for path in common_paths:
        url = f"{BASE_URL}{path}"
        try:
            response = requests.get(url, timeout=10)
            exists = response.status_code == 200
            results.append({
                "check": "Common Endpoint Exposure",
                "url": url,
                "status_code": response.status_code,
                "flag": exists,
                "note": "Endpoint responded with data — worth investigating." if exists
                else "Not found / not exposed (expected for most of these).",
            })
        except requests.exceptions.RequestException as error:
            results.append({
                "check": "Common Endpoint Exposure",
                "url": url,
                "status_code": None,
                "flag": False,
                "note": f"Request failed: {error}",
            })

    return results


# ---------------------------------------------------------
# Check 4: Does the API include any rate-limiting headers?
# ---------------------------------------------------------
def check_rate_limiting(endpoint: str) -> dict:
    """
    Looks for standard rate-limit headers in the response.
        Their absence doesn't prove there's no rate limiting at all,
            but it's a reasonable signal worth flagging.
    """
    url = f"{BASE_URL}{endpoint}"
    response = requests.get(url, timeout=10)

    rate_limit_headers = [h for h in response.headers if "ratelimit" in h.lower()]

    return {
        "check": "Rate Limiting",
        "url": url,
        "status_code": response.status_code,
        "flag": len(rate_limit_headers) == 0,
        "note": "No rate-limit headers found in response." if len(rate_limit_headers) == 0
        else f"Rate-limit headers present: {rate_limit_headers}",
    }


# ---------------------------------------------------------
# Print a clean, readable report
# ---------------------------------------------------------
def print_report(results: list):
    print("\n" + "=" * 60)
    print(" API SECURITY SCAN REPORT")
    print("=" * 60)

    for item in results:
        symbol = "[FLAG]" if item["flag"] else "[OK]  "
        print(f"\n{symbol} {item['check']}")
        print(f"        URL    : {item['url']}")
        print(f"        Status : {item['status_code']}")
        print(f"        Note   : {item['note']}")

    flagged_count = sum(1 for item in results if item["flag"])
    print("\n" + "-" * 60)
    print(f" Total checks run : {len(results)}")
    print(f" Flags raised     : {flagged_count}")
    print("=" * 60 + "\n")


# ---------------------------------------------------------
# Run the scanner
# ---------------------------------------------------------
def main():
    test_endpoint = "/users"  # jsonplaceholder's users endpoint, used across checks

    results = []
    results.append(check_authentication(test_endpoint))
    results.append(check_error_leakage(test_endpoint))
    results.extend(check_common_endpoints())
    results.append(check_rate_limiting(test_endpoint))

    print_report(results)


if __name__ == "__main__":
    main()

