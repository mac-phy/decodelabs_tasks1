# Project 1 — Password Strength Checker

**DecodeLabs Cybersecurity Internship 2026**  
**Analyst:** Phylis Kemuma

---

## What This Project Does

A password strength checker that evaluates any password and classifies it as **Weak**, **Medium**, or **Strong** based on a security policy derived from real-world standards.

---

## Files

| File | Description |
|------|-------------|
| `password_checker.py` | Python backend — run in terminal |
| `password_checker.html` | Web interface — open in any browser |

---

## How to Run

**Python (terminal):**
```bash
python password_checker.py
```

**Web interface:**  
Just open `password_checker.html` in your browser. No server or installation needed.

---

## How It Works

The checker applies the **Zero Point Policy** — five criteria that determine password strength:

| Criterion | Rule |
|-----------|------|
| Minimum length | Must be at least 8 characters |
| Uppercase | Must contain at least one [A-Z] |
| Digit | Must contain at least one [0-9] |
| Symbol | Must contain at least one [!@#$%^&*] |
| Strong length | 12+ characters for a Strong rating |

**Scoring:**
- 0–2 criteria met → **Weak**
- 3 criteria met → **Medium**
- 4–5 criteria met → **Strong**
- Any password found in known breach lists → automatically **Weak**

---

## Key Concepts Applied

**IPO Model**
```
Input (password) → Process (O(n) scan) → Output (Weak / Medium / Strong)
```

**Pythonic approach — short-circuit evaluation**
```python
# The right way (any() stops at first match — fast)
has_digit = any(char.isdigit() for char in password)

# NOT this (manual loop — slow and verbose)
found = False
for i in range(len(password)):
    if password[i].isdigit():
        found = True
        break
```

**RAM security — zeroing memory after use**
```python
# Password stored as bytearray so it can be wiped from heap memory
pwd = bytearray(input().encode())
result = check_password_secure(pwd)
pwd[:] = b'\x00' * len(pwd)  # zero it out — RAM scraping mitigation
```

**Timing attack mitigation**
```python
# hmac.compare_digest() takes the same time regardless of where comparison fails
# Prevents attackers from guessing passwords by measuring response time
hmac.compare_digest(password.lower(), known_breach_password)
```

**Entropy / search space**
```
Lowercase only (26 chars):   26^8  =        208 billion combinations
+ Uppercase (52 chars):      52^8  =     53 trillion combinations  
+ Digits (62 chars):         62^8  =    218 trillion combinations
+ Symbols (94 chars):        94^8  =  6.1 quadrillion combinations
+ Unicode (143,000+ chars): huge   =  practically uncrackable
```
Each character class added multiplies the attacker's search space.

---

## Sample Output

```
Password: Hello1!
Strength: MEDIUM
Score:    3/5 criteria met

[✓] Length >= 8 chars
[✓] Contains uppercase [A-Z]
[✓] Contains digit [0-9]
[✓] Contains symbol [!@#$%]
[✗] Length >= 12 chars (strong baseline)

Feedback:
  → Aim for 12+ characters. Each extra character multiplies combinations.
```

---

*DecodeLabs Cybersecurity Internship  2026  Phylis Kemuma*