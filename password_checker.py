"""
Project 1: Password Strength Checker
Author: Phylis Kemuma
DecodeLabs Cybersecurity Internship — Batch 2026

Concepts applied from course slides:
  - IPO Model (Input → Process → Output)
  - O(n) linear scan using Pythonic any() — NOT manual loops
  - The Zero Point policy (length threshold, character classes)
  - Unicode entropy expansion
  - RAM volatility trap (bytearray for secure memory handling)
  - Timing attack mitigation with hmac.compare_digest()
"""

import string
import hmac
import re


# ─── SECURITY POLICY CONSTANTS (The Zero Point) ────────────────────────────
MIN_LENGTH         = 8     # < 8 chars = exponential brute force risk
STRONG_LENGTH      = 12    # 12+ chars = strong length baseline
UPPERCASE_SET      = set(string.ascii_uppercase)   # [A-Z]
DIGIT_SET          = set(string.digits)            # [0-9]
SYMBOL_SET         = set(string.punctuation)       # [! @ # $ % ^ & * ...]

# Common leaked passwords — a real checker blocks these regardless of score
# (slide suggestion: "add a check for common leaked passwords")
COMMON_PASSWORDS = {
    "password", "password1", "123456", "12345678", "1234567890",
    "qwerty", "abc123", "letmein", "admin", "welcome",
    "monkey", "dragon", "master", "sunshine", "iloveyou",
    "trustno1", "shadow", "superman", "michael", "baseball",
}


# ─── CORE CHECKER FUNCTION ─────────────────────────────────────────────────
def check_password_strength(password: str) -> dict:
    """
    Evaluate password strength using the Zero Point policy.

    IPO Model:
      Input  → raw password string
      Process → O(n) linear scan (any() short-circuits at first match)
      Output → risk classification dict

    Returns a dict with:
      - strength:    "Weak" | "Medium" | "Strong"
      - score:       0–5 (number of criteria met)
      - criteria:    dict of individual pass/fail results
      - feedback:    list of improvement tips
      - entropy_tip: explains the Unicode search space concept
    """

    # ── STEP 1: Immediate fail checks (before any scoring) ─────────────────
    if len(password) < MIN_LENGTH:
        return {
            "strength": "Weak",
            "score": 0,
            "criteria": {
                "length_ok":   False,
                "has_upper":   False,
                "has_digit":   False,
                "has_symbol":  False,
                "long_enough": False,
            },
            "feedback": [
                f"Password must be at least {MIN_LENGTH} characters. "
                f"Shorter passwords face exponential brute-force risk.",
                "Add uppercase letters [A-Z].",
                "Add numbers [0-9].",
                "Add symbols [!@#$%^&*].",
            ],
            "entropy_tip": _entropy_tip(password),
            "is_common": False,
        }

    # ── STEP 2: Check for common/leaked passwords ───────────────────────────
    # hmac.compare_digest() prevents timing attacks during comparison
    is_common = any(
        hmac.compare_digest(password.lower(), common)
        for common in COMMON_PASSWORDS
    )

    # ── STEP 3: Character class checks (Pythonic any() — O(n) per check) ───
    # The slide showed this exact pattern as "The Professional Approach"
    has_upper  = any(char in UPPERCASE_SET for char in password)
    has_digit  = any(char in DIGIT_SET     for char in password)
    has_symbol = any(char in SYMBOL_SET    for char in password)
    long_enough = len(password) >= STRONG_LENGTH

    criteria = {
        "length_ok":   True,           # passed the MIN_LENGTH gate above
        "has_upper":   has_upper,
        "has_digit":   has_digit,
        "has_symbol":  has_symbol,
        "long_enough": long_enough,    # 12+ chars for strong baseline
    }

    # ── STEP 4: Score and classify ──────────────────────────────────────────
    score = sum(criteria.values())  # 0–5

    if is_common:
        strength = "Weak"
    elif score <= 2:
        strength = "Weak"
    elif score <= 3:
        strength = "Medium"
    else:
        strength = "Strong"

    # ── STEP 5: Build actionable feedback ──────────────────────────────────
    feedback = []
    if is_common:
        feedback.append(
            "This password appears in known data breach lists. "
            "Attackers check common passwords first — choose something unique."
        )
    if not has_upper:
        feedback.append("Add at least one uppercase letter [A-Z].")
    if not has_digit:
        feedback.append("Add at least one number [0-9].")
    if not has_symbol:
        feedback.append("Add at least one symbol [!@#$%^&*].")
    if not long_enough:
        feedback.append(
            f"Aim for {STRONG_LENGTH}+ characters. "
            "Each extra character multiplies the search space exponentially."
        )
    if not feedback:
        feedback.append(
            "Password meets all criteria. "
            "Consider using a password manager to generate truly random strings."
        )

    return {
        "strength":    strength,
        "score":       score,
        "criteria":    criteria,
        "feedback":    feedback,
        "entropy_tip": _entropy_tip(password),
        "is_common":   is_common,
    }


# ─── ENTROPY TIP (Unicode Curveball from the slides) ───────────────────────
def _entropy_tip(password: str) -> str:
    """
    Show the character set size (search space) used by this password.
    The slides showed: ASCII = 95 printable chars, Unicode = 143,000+.
    Each character added multiplies the brute-force search space.
    """
    has_upper  = any(c.isupper() for c in password)
    has_lower  = any(c.islower() for c in password)
    has_digit  = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)
    has_unicode = any(ord(c) > 127 for c in password)

    charset_size = 0
    parts = []
    if has_lower:   charset_size += 26;  parts.append("26 lowercase")
    if has_upper:   charset_size += 26;  parts.append("26 uppercase")
    if has_digit:   charset_size += 10;  parts.append("10 digits")
    if has_symbol:  charset_size += 32;  parts.append("32 symbols")
    if has_unicode: charset_size += 143000; parts.append("143,000+ Unicode")

    if charset_size == 0:
        return "No recognisable characters detected."

    combinations = charset_size ** len(password)
    return (
        f"Character set: {charset_size} ({', '.join(parts)}). "
        f"Possible combinations: {charset_size}^{len(password)} "
        f"= {combinations:,}"
    )


# ─── SECURE MEMORY HANDLING (RAM Trap from the slides) ─────────────────────
def check_password_secure(password_bytes: bytearray) -> dict:
    """
    Secure version: accepts a bytearray so the password can be
    zeroed from memory after checking — mitigating the RAM scraping
    trap described in the slides (BlackPOS malware / heap scanning).

    Usage:
        pwd = bytearray(input("Password: ").encode())
        result = check_password_secure(pwd)
        pwd[:] = b'\\x00' * len(pwd)  # zero out memory
    """
    try:
        password_str = password_bytes.decode('utf-8', errors='replace')
        return check_password_strength(password_str)
    finally:
        # Zero out the bytearray regardless of what happens above
        password_bytes[:] = b'\x00' * len(password_bytes)


# ─── CLI INTERFACE ──────────────────────────────────────────────────────────
def main():
    print("=" * 65)
    print("  PASSWORD STRENGTH CHECKER — Project 1")
    print("  DecodeLabs Cybersecurity Internship | Batch 2026")
    print("  Analyst: Phylis Kemuma")
    print("=" * 65)

    # Collect password securely as bytearray to demonstrate RAM trap fix
    import getpass
    raw = getpass.getpass("\nEnter password to check (hidden): ")
    pwd_bytes = bytearray(raw.encode('utf-8'))
    del raw  # remove the str reference immediately

    # Run check
    result = check_password_secure(pwd_bytes)
    # pwd_bytes is already zeroed inside check_password_secure()

    # ── Display results ──────────────────────────────────────────────────
    print(f"\n{'─'*65}")
    print(f"  STRENGTH: {result['strength'].upper()}")
    print(f"  SCORE:    {result['score']}/5 criteria met")
    print(f"{'─'*65}")

    print("\n  CRITERIA CHECK:")
    labels = {
        "length_ok":   "Length >= 8 chars",
        "has_upper":   "Contains uppercase [A-Z]",
        "has_digit":   "Contains digit [0-9]",
        "has_symbol":  "Contains symbol [!@#$%]",
        "long_enough": "Length >= 12 chars (strong baseline)",
    }
    for key, label in labels.items():
        status = "PASS" if result['criteria'][key] else "FAIL"
        mark   = "[✓]" if result['criteria'][key] else "[✗]"
        print(f"    {mark}  {label:<42} {status}")

    print("\n  FEEDBACK:")
    for tip in result['feedback']:
        print(f"    • {tip}")

    print(f"\n  ENTROPY ANALYSIS:")
    print(f"    {result['entropy_tip']}")

    if result['is_common']:
        print("\n  ⚠  BREACH WARNING: This password is in known data breach lists.")

    print(f"\n{'='*65}\n")


if __name__ == "__main__":
    main()
