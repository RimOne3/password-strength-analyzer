"""
Password Strength Analyzer
Author: Rim Targuisti
Description: Analyzes the strength of a password based on security best
             practices. Checks length, complexity, common patterns, and
             provides actionable feedback to improve password security.
"""

import re
import math
import string
import getpass


# A sample of the most commonly used weak passwords
COMMON_PASSWORDS = {
    "password", "123456", "password123", "admin", "letmein",
    "qwerty", "abc123", "monkey", "1234567890", "password1",
    "iloveyou", "sunshine", "princess", "welcome", "shadow",
    "superman", "dragon", "master", "hello", "freedom",
    "whatever", "trustno1", "baseball", "football", "soccer",
    "starwars", "batman", "michael", "jessica", "donald",
}


def check_length(password):
    """Check password length and return a score and feedback."""
    length = len(password)
    if length < 6:
        return 0, "Too short (minimum 8 characters recommended)"
    elif length < 8:
        return 1, f"Short ({length} chars) — aim for 12+"
    elif length < 12:
        return 2, f"Acceptable length ({length} chars) — longer is stronger"
    elif length < 16:
        return 3, f"Good length ({length} chars)"
    else:
        return 4, f"Excellent length ({length} chars)"


def check_complexity(password):
    """Check character variety and return a score and list of feedback."""
    checks = {
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digits":    bool(re.search(r"\d", password)),
        "symbols":   bool(re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]", password)),
    }

    score = sum(checks.values())
    missing = []
    if not checks["lowercase"]: missing.append("lowercase letters (a-z)")
    if not checks["uppercase"]: missing.append("uppercase letters (A-Z)")
    if not checks["digits"]:    missing.append("numbers (0-9)")
    if not checks["symbols"]:   missing.append("special characters (!@#$...)")

    return score, checks, missing


def check_patterns(password):
    """Detect common weak patterns. Returns list of warnings."""
    warnings = []

    # Repeated characters (e.g. "aaaa", "1111")
    if re.search(r"(.)\1{2,}", password):
        warnings.append("Contains repeated characters (e.g. 'aaa' or '111')")

    # Sequential numbers
    sequences = ["0123456789", "9876543210"]
    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3] in password:
                warnings.append("Contains sequential numbers (e.g. '123' or '987')")
                break

    # Sequential letters
    alpha_seq = string.ascii_lowercase
    alpha_rev = alpha_seq[::-1]
    for seq in [alpha_seq, alpha_rev]:
        for i in range(len(seq) - 2):
            if seq[i:i+3] in password.lower():
                warnings.append("Contains sequential letters (e.g. 'abc' or 'xyz')")
                break

    # Keyboard walks
    keyboard_rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
    for row in keyboard_rows:
        for i in range(len(row) - 2):
            if row[i:i+3] in password.lower():
                warnings.append("Contains keyboard pattern (e.g. 'qwe' or 'asd')")
                break

    # Common words embedded
    common_words = ["password", "pass", "admin", "user", "login", "welcome"]
    for word in common_words:
        if word in password.lower():
            warnings.append(f"Contains common word: '{word}'")

    return list(set(warnings))  # deduplicate


def calculate_entropy(password):
    """Estimate password entropy in bits."""
    charset_size = 0
    if re.search(r"[a-z]", password): charset_size += 26
    if re.search(r"[A-Z]", password): charset_size += 26
    if re.search(r"\d", password):    charset_size += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset_size += 32

    if charset_size == 0:
        return 0
    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 1)


def get_strength_label(total_score, max_score=12):
    """Convert numeric score to a strength label."""
    ratio = total_score / max_score
    if ratio < 0.3:
        return "WEAK", "🔴"
    elif ratio < 0.55:
        return "FAIR", "🟠"
    elif ratio < 0.75:
        return "GOOD", "🟡"
    elif ratio < 0.90:
        return "STRONG", "🟢"
    else:
        return "VERY STRONG", "✅"


def analyze_password(password):
    """Run full analysis on a password and print a detailed report."""
    print("\n" + "=" * 55)
    print("  Password Strength Analyzer  |  Rim Targuisti")
    print("=" * 55)

    # Check if it's a known common password
    if password.lower() in COMMON_PASSWORDS:
        print("\n🚨 CRITICAL: This is one of the most commonly used passwords!")
        print("   It would be cracked instantly. Choose something unique.\n")

    # Run checks
    len_score, len_feedback     = check_length(password)
    comp_score, comp_checks, missing = check_complexity(password)
    pattern_warnings            = check_patterns(password)
    entropy                     = calculate_entropy(password)

    # Penalty for patterns
    pattern_penalty = min(len(pattern_warnings), 3)
    total_score = len_score + comp_score - pattern_penalty
    total_score = max(0, total_score)  # floor at 0
    max_score   = 8  # len(4) + comp(4)

    label, icon = get_strength_label(total_score, max_score)

    # --- Print Report ---
    print(f"\n  Strength  : {icon}  {label}")
    print(f"  Entropy   : {entropy} bits  ", end="")
    if entropy < 28:
        print("(Very low — easily cracked)")
    elif entropy < 36:
        print("(Low)")
    elif entropy < 60:
        print("(Moderate)")
    elif entropy < 80:
        print("(High)")
    else:
        print("(Excellent)")

    print(f"\n{'─' * 55}")
    print("  LENGTH CHECK")
    print(f"  → {len_feedback}")

    print(f"\n{'─' * 55}")
    print("  COMPLEXITY CHECK")
    for char_type, present in comp_checks.items():
        status = "✔" if present else "✘"
        print(f"  {status}  {char_type.capitalize()}")

    if pattern_warnings:
        print(f"\n{'─' * 55}")
        print("  ⚠️  PATTERN WARNINGS")
        for w in pattern_warnings:
            print(f"  → {w}")

    print(f"\n{'─' * 55}")
    print("  RECOMMENDATIONS")
    if missing:
        print(f"  → Add: {', '.join(missing)}")
    if len(password) < 12:
        print("  → Increase length to at least 12 characters")
    if not pattern_warnings:
        print("  → No common patterns detected — good!")
    if total_score >= 6 and not missing:
        print("  → Consider using a password manager to store this safely")
    print("=" * 55 + "\n")


def main():
    print("=" * 55)
    print("  Password Strength Analyzer")
    print("  Author: Rim Targuisti")
    print("=" * 55)
    print("\nEnter a password to analyze.")
    print("(Your input is hidden for security)\n")

    while True:
        password = getpass.getpass("Password: ")
        if not password:
            print("No password entered. Please try again.")
            continue
        analyze_password(password)

        again = input("Analyze another password? (y/n): ").strip().lower()
        if again != "y":
            print("\nStay secure! 🔐\n")
            break


if __name__ == "__main__":
    main()
