# 🔐 Password Strength Analyzer

A Python command-line tool that evaluates password strength using security best practices. Provides a detailed breakdown of length, complexity, entropy, and common vulnerability patterns — with actionable recommendations.

## Features

- **Entropy calculation** — estimates how hard the password is to crack (in bits)
- **Complexity check** — verifies use of lowercase, uppercase, digits, and symbols
- **Pattern detection** — flags sequential characters, keyboard walks, repeated chars
- **Common password check** — warns if the password is on a known weak-password list
- **Actionable feedback** — tells you exactly what to improve

## Usage

```bash
python password_analyzer.py
```

Your input is hidden (like a real login prompt) for security.

## Example Output

```
=======================================================
  Password Strength Analyzer  |  Rim Targuisti
=======================================================

  Strength  : 🟡  GOOD
  Entropy   : 52.4 bits  (Moderate)

─────────────────────────────────────────────────────
  LENGTH CHECK
  → Good length (11 chars)

─────────────────────────────────────────────────────
  COMPLEXITY CHECK
  ✔  Lowercase
  ✔  Uppercase
  ✔  Digits
  ✘  Symbols

─────────────────────────────────────────────────────
  RECOMMENDATIONS
  → Add: special characters (!@#$...)
  → Consider using a password manager to store this safely
=======================================================
```

## Concepts Demonstrated

- **Regular expressions** for pattern matching
- **Security math**: Shannon entropy for password strength estimation
- **Input handling**: masked password entry with `getpass`
- **Cybersecurity principles**: NIST password guidelines, common attack vectors

## Requirements

Python 3.6+ — No external libraries needed (uses standard library only)

## Background

Built to reinforce cybersecurity fundamentals from my coursework at NOVA — specifically around authentication security, threat modeling, and user-focused security design. Entropy-based scoring reflects real-world password auditing logic used in security operations.
