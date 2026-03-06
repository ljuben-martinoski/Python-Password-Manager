#!/usr/bin/env python3
"""
Secure Password Manager
A professional-grade local password manager with AES-256 encryption.

Features:
- Military-grade encryption (AES-256 via Fernet)
- Password generator with customization
- Password strength analysis
- Category organization
- Backup and restore functionality
- Completely local storage (no cloud)

Author: Built with security and ease-of-use in mind
"""

# flake8: noqa

import hmac
import json
import base64
import getpass
import secrets
import string
from datetime import datetime
from pathlib import Path

# Cryptography imports for secure encryption
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# For beautiful terminal interface
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    # Fallback for when colorama is not installed
    class _FallbackFore:
        RED = GREEN = YELLOW = CYAN = BLUE = MAGENTA = WHITE = RESET = ""

    class _FallbackStyle:
        BRIGHT = RESET_ALL = ""

    # Match the public API of colorama so rest of the script can use it
    Fore = _FallbackFore()
    Style = _FallbackStyle()

try:
    from tabulate import tabulate
    TABULATE_ENABLED = True
except ImportError:
    TABULATE_ENABLED = False


# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================

# File paths for storing encrypted data
DATA_DIR = Path.home() / ".password_manager"
PASSWORDS_FILE = DATA_DIR / "passwords.enc"
SALT_FILE = DATA_DIR / "salt.key"
BACKUP_DIR = DATA_DIR / "backups"

# Security settings - these make your passwords very hard to crack
PBKDF2_ITERATIONS = 480000  # Number of times we hash the master password
# Higher = more secure but slightly slower
# 480,000 is OWASP recommended minimum for 2024

# Available password categories for organization
CATEGORIES = [
    "Email",
    "Banking",
    "Social Media",
    "Shopping",
    "Work",
    "Gaming",
    "Entertainment",
    "Other"
]


# ============================================================================
# ENCRYPTION & SECURITY FUNCTIONS
# ============================================================================

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Convert a master password into an encryption key using PBKDF2.

    This is critical for security! We don't use the password directly.
    Instead, we use PBKDF2 (Password-Based Key Derivation Function 2) which:
    1. Adds a random salt (prevents rainbow table attacks)
    2. Runs 480,000+ iterations (prevents brute force attacks)
    3. Produces a strong 256-bit encryption key

    Args:
        password: Your master password (as string)
        salt: Random bytes unique to your installation

    Returns:
        A 32-byte encryption key suitable for AES-256
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA-256 hashing algorithm
        length=32,                   # Generate 32 bytes = 256 bits for AES-256
        salt=salt,  # Unique salt prevents pre-computed attacks
        iterations=PBKDF2_ITERATIONS # High iteration count slows down attackers
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)


def initialize_security():
    """
    Set up the security infrastructure on first run.

    Creates:
    - Main data directory (~/.password_manager/)
    - Backup directory for encrypted backups
    - Unique salt file (critical for security!)

    The salt is randomly generated once and stored. It ensures that even
    if two people use the same master password, their encryption keys
    will be completely different.
    """
    DATA_DIR.mkdir(exist_ok=True)
    BACKUP_DIR.mkdir(exist_ok=True)

    if not SALT_FILE.exists():
        # Generate a cryptographically secure random salt
        # This is created ONCE and never changes
        salt = secrets.token_bytes(32)  # 32 bytes = 256 bits of randomness
        SALT_FILE.write_bytes(salt)
        print(f"{Fore.GREEN}✓ Security initialized with unique encryption salt")


def get_salt() -> bytes:
    """
    Load the unique salt used for key derivation.

    Returns:
        32 bytes of salt data
    """
    if not SALT_FILE.exists():
        raise FileNotFoundError("Salt file not found. Run initialization first.")
    return SALT_FILE.read_bytes()


def encrypt_data(data: dict, key: bytes) -> bytes:
    """
    Encrypt password data using Fernet (AES-256 in CBC mode).

    Fernet provides:
    - AES-256 encryption (industry standard)
    - Authentication (detects tampering)
    - Timestamp (for key rotation)

    Args:
        data: Dictionary containing all passwords
        key: Encryption key derived from master password

    Returns:
        Encrypted bytes that can be safely stored on disk
    """
    fernet = Fernet(key)
    json_data = json.dumps(data, indent=2)
    encrypted = fernet.encrypt(json_data.encode())
    return encrypted


def decrypt_data(encrypted_data: bytes, key: bytes) -> dict:
    """
    Decrypt password data and verify integrity.

    Args:
        encrypted_data: Encrypted bytes from file
        key: Encryption key from master password

    Returns:
        Dictionary containing all passwords

    Raises:
        InvalidToken: If password is wrong or data is corrupted/tampered
    """
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data)
    return json.loads(decrypted.decode())


# ============================================================================
# PASSWORD STRENGTH CHECKER
# ============================================================================

def check_password_strength(password: str) -> dict:
    """
    Analyze a password and rate its strength.

    Checks for:
    - Length (longer is better)
    - Character variety (uppercase, lowercase, numbers, symbols)
    - Common patterns (repeated characters, sequences)

    Args:
        password: The password to analyze

    Returns:
        Dictionary with:
        - score: 0-100 strength score
        - level: "Weak", "Medium", "Strong", or "Very Strong"
        - feedback: List of suggestions to improve the password
    """
    score = 0
    feedback = []

    # Length is the most important factor
    length = len(password)
    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    else:
        score += 10
        feedback.append("Use at least 12 characters (16+ is better)")

    # Check for character variety
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    variety_score = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety_score * 10

    if not has_lower:
        feedback.append("Add lowercase letters")
    if not has_upper:
        feedback.append("Add uppercase letters")
    if not has_digit:
        feedback.append("Add numbers")
    if not has_symbol:
        feedback.append("Add symbols (!@#$%^&* etc.)")

    # Check for repeated characters (like "aaa" or "111")
    if len(set(password)) < len(password) * 0.5:
        score -= 10
        feedback.append("Avoid too many repeated characters")

    # Check for common sequences
    sequences = ["123", "abc", "qwerty", "password", "admin"]
    if any(seq in password.lower() for seq in sequences):
        score -= 15
        feedback.append("Avoid common sequences and words")

    # Bonus points for good length with variety
    if length >= 16 and variety_score == 4:
        score += 20

    # Cap score at 100
    score = min(100, max(0, score))

    # Determine strength level
    if score >= 80:
        level = "Very Strong"
        color = Fore.GREEN
    elif score >= 60:
        level = "Strong"
        color = Fore.CYAN
    elif score >= 40:
        level = "Medium"
        color = Fore.YELLOW
    else:
        level = "Weak"
        color = Fore.RED

    return {
        "score": score,
        "level": level,
        "color": color,
        "feedback": feedback
    }


def display_strength_analysis(password: str):
    """
    Show a visual analysis of password strength.

    Args:
        password: The password to analyze
    """
    analysis = check_password_strength(password)

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Password Strength Analysis")
    print(f"{Fore.CYAN}{'='*60}")
    print(f"Strength: {analysis['color']}{analysis['level']} ({analysis['score']}/100){Style.RESET_ALL}")

    # Visual strength bar
    bar_length = 30
    filled = int((analysis['score'] / 100) * bar_length)
    bar = "█" * filled + "░" * (bar_length - filled)
    print(f"Progress: {analysis['color']}{bar}{Style.RESET_ALL}")

    if analysis['feedback']:
        print(f"\n{Fore.YELLOW}💡 Suggestions to improve:")
        for suggestion in analysis['feedback']:
            print(f"   • {suggestion}")
    else:
        print(f"\n{Fore.GREEN}✓ Excellent password!")

    print(f"{Fore.CYAN}{'='*60}\n")


# ============================================================================
# PASSWORD GENERATOR
# ============================================================================

def generate_password(length=16, use_uppercase=True, use_lowercase=True,
                     use_digits=True, use_symbols=True) -> str:
    """
    Generate a cryptographically secure random password.

    Uses secrets module (not random!) for cryptographic security.
    The secrets module uses the OS's cryptographically secure random
    number generator, making passwords unpredictable.

    Args:
        length: Password length (8-64 characters)
        use_uppercase: Include A-Z
        use_lowercase: Include a-z
        use_digits: Include 0-9
        use_symbols: Include !@#$%^&* etc.

    Returns:
        A strong random password
    """
    # Build the character pool and guarantee at least one char from each enabled type
    char_pool = ""
    required = []

    if use_lowercase:
        char_pool += string.ascii_lowercase
        required.append(secrets.choice(string.ascii_lowercase))
    if use_uppercase:
        char_pool += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        char_pool += string.digits
        required.append(secrets.choice(string.digits))
    if use_symbols:
        char_pool += string.punctuation
        required.append(secrets.choice(string.punctuation))

    if not char_pool:
        # Fallback if user disabled everything
        char_pool = string.ascii_letters + string.digits

    # Fill remaining slots then shuffle securely
    remaining = [secrets.choice(char_pool) for _ in range(length - len(required))]
    password_chars = required + remaining
    secrets.SystemRandom().shuffle(password_chars)

    return ''.join(password_chars)


def password_generator_wizard():
    """
    Interactive wizard to generate a custom password.

    Returns:
        Generated password, or None if cancelled
    """
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}🔐 Password Generator")
    print(f"{Fore.CYAN}{'='*60}\n")

    # Get desired length
    while True:
        try:
            length_input = input(f"Password length (8-64) [{Fore.GREEN}16{Style.RESET_ALL}]: ").strip()
            if not length_input:
                length = 16
            else:
                length = int(length_input)

            if 8 <= length <= 64:
                break
            else:
                print(f"{Fore.RED}Please enter a number between 8 and 64")
        except ValueError:
            print(f"{Fore.RED}Please enter a valid number")

    # Get character preferences
    print(f"\n{Fore.CYAN}Include in password:")
    use_uppercase = input(f"  Uppercase letters (A-Z)? [{Fore.GREEN}Y{Style.RESET_ALL}/n]: ").strip().lower() != 'n'
    use_lowercase = input(f"  Lowercase letters (a-z)? [{Fore.GREEN}Y{Style.RESET_ALL}/n]: ").strip().lower() != 'n'
    use_digits = input(f"  Numbers (0-9)? [{Fore.GREEN}Y{Style.RESET_ALL}/n]: ").strip().lower() != 'n'
    use_symbols = input(f"  Symbols (!@#$%^&*)? [{Fore.GREEN}Y{Style.RESET_ALL}/n]: ").strip().lower() != 'n'

    # Generate and optionally regenerate without recursion
    while True:
        password = generate_password(length, use_uppercase, use_lowercase, use_digits, use_symbols)

        print(f"\n{Fore.GREEN}✓ Generated Password:")
        print(f"{Fore.WHITE}{Style.BRIGHT}{password}{Style.RESET_ALL}")

        display_strength_analysis(password)

        choice = input(f"Use this password? [{Fore.GREEN}Y{Style.RESET_ALL}/n/r=regenerate]: ").strip().lower()

        if choice == 'r':
            continue
        elif choice == 'n':
            return None
        else:
            return password


# ============================================================================
# PASSWORD STORAGE & MANAGEMENT
# ============================================================================

def load_passwords(key: bytes) -> dict:
    """
    Load and decrypt all passwords from disk.

    Args:
        key: Encryption key from master password

    Returns:
        Dictionary with structure:
        {
            "passwords": [
                {
                    "id": unique_id,
                    "site": "example.com",
                    "username": "user@email.com",
                    "password": "secret123",
                    "category": "Email",
                    "notes": "Optional notes",
                    "created": "2024-01-01 12:00:00",
                    "modified": "2024-01-01 12:00:00"
                },
                ...
            ]
        }
    """
    if not PASSWORDS_FILE.exists():
        return {"passwords": []}

    try:
        encrypted_data = PASSWORDS_FILE.read_bytes()
        return decrypt_data(encrypted_data, key)
    except InvalidToken as exc:
        raise ValueError("Invalid master password or corrupted data file") from exc


def save_passwords(data: dict, key: bytes):
    """
    Encrypt and save all passwords to disk.

    Args:
        data: Complete password database
        key: Encryption key from master password
    """
    encrypted_data = encrypt_data(data, key)
    PASSWORDS_FILE.write_bytes(encrypted_data)


def add_password(data: dict, key: bytes):
    """
    Add a new password entry with full details.

    Args:
        data: Current password database
        key: Encryption key (for saving)
    """
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}➕ Add New Password")
    print(f"{Fore.CYAN}{'='*60}\n")

    # Get site/service name
    site = input("Site/Service name (e.g., Gmail, Facebook): ").strip()
    if not site:
        print(f"{Fore.RED}Site name is required")
        return

    # Get username/email
    username = input("Username/Email: ").strip()
    if not username:
        print(f"{Fore.RED}Username is required")
        return

    # Get or generate password
    print(f"\n{Fore.CYAN}Password Options:")
    print("  1. Enter password manually")
    print("  2. Generate strong password")
    choice = input("Choose option [1-2]: ").strip()

    if choice == '2':
        password = password_generator_wizard()
        if password is None:
            print(f"{Fore.YELLOW}Cancelled")
            return
    else:
        password = getpass.getpass("Password (hidden): ")
        if not password:
            print(f"{Fore.RED}Password is required")
            return

        # Show strength analysis for manually entered passwords
        display_strength_analysis(password)
        confirm = input(f"Continue with this password? [{Fore.GREEN}Y{Style.RESET_ALL}/n]: ").strip().lower()
        if confirm == 'n':
            return

    # Select category
    print(f"\n{Fore.CYAN}Select Category:")
    for i, cat in enumerate(CATEGORIES, 1):
        print(f"  {i}. {cat}")

    try:
        cat_choice = input(f"Category [1-{len(CATEGORIES)}]: ").strip()
        category = CATEGORIES[int(cat_choice) - 1]
    except (ValueError, IndexError):
        category = "Other"
        print(f"{Fore.YELLOW}Invalid choice, using 'Other'")

    # Optional notes
    notes = input("Notes (optional, press Enter to skip): ").strip()

    # Create new entry
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_entry = {
        "id": secrets.token_hex(8),  # Unique 16-character hex ID
        "site": site,
        "username": username,
        "password": password,
        "category": category,
        "notes": notes,
        "created": now,
        "modified": now
    }

    data["passwords"].append(new_entry)
    save_passwords(data, key)

    print(f"\n{Fore.GREEN}✓ Password saved successfully!")
    print(f"{Fore.GREEN}  ID: {new_entry['id']}")


def view_passwords(data: dict, category_filter=None):
    """
    Display all passwords (or filtered by category) in a nice table.

    Args:
        data: Password database
        category_filter: Optional category to filter by
    """
    passwords = data["passwords"]

    if category_filter:
        passwords = [p for p in passwords if p["category"] == category_filter]
        header = f"Passwords in Category: {category_filter}"
    else:
        header = "All Passwords"

    if not passwords:
        print(f"\n{Fore.YELLOW}No passwords found")
        return

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}{header} ({len(passwords)} entries)")
    print(f"{Fore.CYAN}{'='*60}\n")

    if TABULATE_ENABLED:
        # Beautiful table format
        table_data = []
        for p in passwords:
            table_data.append([
                p['id'][:8] + "...",  # Shortened ID
                p['site'],
                p['username'],
                p['category'],
                p['modified'][:10]  # Just the date
            ])

        print(tabulate(
            table_data,
            headers=["ID", "Site", "Username", "Category", "Modified"],
            tablefmt="grid"
        ))
    else:
        # Fallback simple format
        for p in passwords:
            print(f"{Fore.WHITE}{Style.BRIGHT}{p['site']}{Style.RESET_ALL}")
            print(f"  ID: {p['id']}")
            print(f"  Username: {p['username']}")
            print(f"  Category: {p['category']}")
            print(f"  Modified: {p['modified']}")
            print()


def search_and_show_password(data: dict):
    """
    Search for a password and show its full details including the actual password.

    Args:
        data: Password database
    """
    search_term = input(f"\n{Fore.CYAN}Search (site name or username): ").strip().lower()

    if not search_term:
        return

    # Find matching passwords
    matches = [
        p for p in data["passwords"]
        if search_term in p['site'].lower() or search_term in p['username'].lower()
    ]

    if not matches:
        print(f"{Fore.YELLOW}No matches found")
        return

    if len(matches) == 1:
        show_password_details(matches[0])
    else:
        # Multiple matches - let user choose
        print(f"\n{Fore.CYAN}Found {len(matches)} matches:")
        for i, p in enumerate(matches, 1):
            print(f"  {i}. {p['site']} ({p['username']}) - {p['category']}")

        try:
            choice = int(input(f"\nSelect [1-{len(matches)}]: ")) - 1
            show_password_details(matches[choice])
        except (ValueError, IndexError):
            print(f"{Fore.RED}Invalid selection")


def show_password_details(entry: dict):
    """
    Show complete details of a password entry including the actual password.

    Args:
        entry: Single password entry dict
    """
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Password Details")
    print(f"{Fore.CYAN}{'='*60}")
    print(f"ID:       {entry['id']}")
    print(f"Site:     {Fore.WHITE}{Style.BRIGHT}{entry['site']}{Style.RESET_ALL}")
    print(f"Username: {entry['username']}")
    print(f"Password: {Fore.GREEN}{Style.BRIGHT}{entry['password']}{Style.RESET_ALL}")
    print(f"Category: {entry['category']}")
    if entry.get('notes'):
        print(f"Notes:    {entry['notes']}")
    print(f"Created:  {entry['created']}")
    print(f"Modified: {entry['modified']}")
    print(f"{Fore.CYAN}{'='*60}\n")


def update_password(data: dict, key: bytes):
    """
    Update an existing password entry.

    Args:
        data: Password database
        key: Encryption key (for saving)
    """
    search_term = input(f"\n{Fore.CYAN}Search for entry to update: ").strip().lower()

    matches = [
        p for p in data["passwords"]
        if search_term in p['site'].lower() or search_term in p['username'].lower() or search_term in p['id'].lower()
    ]

    if not matches:
        print(f"{Fore.YELLOW}No matches found")
        return

    if len(matches) > 1:
        print(f"\n{Fore.CYAN}Multiple matches found:")
        for i, p in enumerate(matches, 1):
            print(f"  {i}. {p['site']} ({p['username']})")
        try:
            choice = int(input(f"Select [1-{len(matches)}]: ")) - 1
            entry = matches[choice]
        except (ValueError, IndexError):
            print(f"{Fore.RED}Invalid selection")
            return
    else:
        entry = matches[0]

    # Show current details
    show_password_details(entry)

    print(f"{Fore.CYAN}What to update? (press Enter to keep current value)")

    # Update site
    new_site = input(f"Site [{entry['site']}]: ").strip()
    if new_site:
        entry['site'] = new_site

    # Update username
    new_username = input(f"Username [{entry['username']}]: ").strip()
    if new_username:
        entry['username'] = new_username

    # Update password
    change_pw = input("Change password? (y/N): ").strip().lower()
    if change_pw == 'y':
        print(f"\n{Fore.CYAN}Password Options:")
        print("  1. Enter new password manually")
        print("  2. Generate strong password")
        choice = input("Choose [1-2]: ").strip()

        if choice == '2':
            new_password = password_generator_wizard()
            if new_password:
                entry['password'] = new_password
        else:
            new_password = getpass.getpass("New password (hidden): ")
            if new_password:
                entry['password'] = new_password
                display_strength_analysis(new_password)

    # Update category
    print(f"\nCurrent category: {entry['category']}")
    print(f"{Fore.CYAN}Categories:")
    for i, cat in enumerate(CATEGORIES, 1):
        print(f"  {i}. {cat}")
    cat_input = input("New category [press Enter to keep current]: ").strip()
    if cat_input:
        try:
            entry['category'] = CATEGORIES[int(cat_input) - 1]
        except (ValueError, IndexError):
            pass

    # Update notes ('-' clears existing notes)
    new_notes = input(f"Notes [{entry.get('notes', '')}] (press Enter to keep, '-' to clear): ").strip()
    if new_notes == '-':
        entry['notes'] = ''
    elif new_notes:
        entry['notes'] = new_notes

    # Update modification time
    entry['modified'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    save_passwords(data, key)
    print(f"\n{Fore.GREEN}✓ Password updated successfully!")


def delete_password(data: dict, key: bytes):
    """
    Delete a password entry with confirmation.

    Args:
        data: Password database
        key: Encryption key (for saving)
    """
    search_term = input(f"\n{Fore.CYAN}Search for entry to delete: ").strip().lower()

    matches = [
        p for p in data["passwords"]
        if search_term in p['site'].lower() or search_term in p['username'].lower() or search_term in p['id'].lower()
    ]

    if not matches:
        print(f"{Fore.YELLOW}No matches found")
        return

    if len(matches) > 1:
        print(f"\n{Fore.CYAN}Multiple matches found:")
        for i, p in enumerate(matches, 1):
            print(f"  {i}. {p['site']} ({p['username']})")
        try:
            choice = int(input(f"Select [1-{len(matches)}]: ")) - 1
            entry = matches[choice]
        except (ValueError, IndexError):
            print(f"{Fore.RED}Invalid selection")
            return
    else:
        entry = matches[0]

    # Show what will be deleted
    show_password_details(entry)

    # Confirm deletion
    confirm = input(f"{Fore.RED}Delete this entry? Type 'DELETE' to confirm: ").strip()

    if confirm == 'DELETE':
        data["passwords"] = [p for p in data["passwords"] if p['id'] != entry['id']]
        save_passwords(data, key)
        print(f"\n{Fore.GREEN}✓ Password deleted successfully")
    else:
        print(f"{Fore.YELLOW}Deletion cancelled")


# ============================================================================
# CATEGORY & STATISTICS
# ============================================================================

def view_by_category(data: dict):
    """
    Show passwords organized by category.

    Args:
        data: Password database
    """
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}📁 View by Category")
    print(f"{Fore.CYAN}{'='*60}\n")

    # Count passwords per category
    category_counts = {}
    for cat in CATEGORIES:
        count = len([p for p in data["passwords"] if p["category"] == cat])
        if count > 0:
            category_counts[cat] = count

    if not category_counts:
        print(f"{Fore.YELLOW}No passwords stored yet")
        return

    print("Categories:")
    for i, (cat, count) in enumerate(category_counts.items(), 1):
        print(f"  {i}. {cat} ({count} passwords)")

    print("  0. View all categories statistics")

    choice = input(f"\nSelect category [0-{len(category_counts)}]: ").strip()

    if choice == '0':
        show_statistics(data)
    else:
        try:
            cat_name = list(category_counts.keys())[int(choice) - 1]
            view_passwords(data, cat_name)
        except (ValueError, IndexError):
            print(f"{Fore.RED}Invalid selection")


def show_statistics(data: dict):
    """
    Display statistics about stored passwords.

    Args:
        data: Password database
    """
    passwords = data["passwords"]
    total = len(passwords)

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}📊 Password Manager Statistics")
    print(f"{Fore.CYAN}{'='*60}\n")

    print(f"Total Passwords: {Fore.WHITE}{Style.BRIGHT}{total}{Style.RESET_ALL}")

    if total == 0:
        return

    # Category breakdown
    print(f"\n{Fore.CYAN}By Category:")
    category_counts = {}
    for cat in CATEGORIES:
        count = len([p for p in passwords if p["category"] == cat])
        if count > 0:
            category_counts[cat] = count
            percentage = (count / total) * 100
            bar = "█" * int(percentage / 5)
            print(f"  {cat:15} {count:3} ({percentage:5.1f}%) {bar}")

    # Strength analysis
    print(f"\n{Fore.CYAN}Password Strength Overview:")
    weak = medium = strong = very_strong = 0

    for p in passwords:
        analysis = check_password_strength(p['password'])
        if analysis['score'] >= 80:
            very_strong += 1
        elif analysis['score'] >= 60:
            strong += 1
        elif analysis['score'] >= 40:
            medium += 1
        else:
            weak += 1

    if weak > 0:
        print(f"  {Fore.RED}Weak:        {weak}")
    if medium > 0:
        print(f"  {Fore.YELLOW}Medium:      {medium}")
    if strong > 0:
        print(f"  {Fore.CYAN}Strong:      {strong}")
    if very_strong > 0:
        print(f"  {Fore.GREEN}Very Strong: {very_strong}")

    if weak > 0:
        print(f"\n{Fore.YELLOW}💡 Tip: You have {weak} weak password(s). Consider updating them!")

    print()


# ============================================================================
# BACKUP & RESTORE
# ============================================================================

def create_backup(data: dict, key: bytes):
    """
    Create an encrypted backup with timestamp.

    Args:
        data: Password database
        key: Encryption key
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = BACKUP_DIR / f"passwords_backup_{timestamp}.enc"

    # Create encrypted backup
    encrypted_data = encrypt_data(data, key)
    backup_file.write_bytes(encrypted_data)

    print(f"\n{Fore.GREEN}✓ Backup created successfully!")
    print(f"{Fore.GREEN}  Location: {backup_file}")
    print(f"{Fore.GREEN}  Size: {len(encrypted_data)} bytes")

    # Show existing backups
    list_backups()


def list_backups():
    """
    List all available backups.
    """
    backups = sorted(BACKUP_DIR.glob("passwords_backup_*.enc"), reverse=True)

    if not backups:
        print(f"\n{Fore.YELLOW}No backups found")
        return

    print(f"\n{Fore.CYAN}Available Backups:")
    for i, backup in enumerate(backups, 1):
        size_kb = backup.stat().st_size / 1024
        modified = datetime.fromtimestamp(backup.stat().st_mtime)
        print(f"  {i}. {backup.name}")
        print(f"     Created: {modified.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"     Size: {size_kb:.1f} KB")


def restore_from_backup(key: bytes) -> dict | None:
    """
    Restore password database from a backup file.

    Args:
        key: Encryption key

    Returns:
        Restored password database, or None if cancelled
    """
    backups = sorted(BACKUP_DIR.glob("passwords_backup_*.enc"), reverse=True)

    if not backups:
        print(f"\n{Fore.YELLOW}No backups found")
        return None

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}📦 Restore from Backup")
    print(f"{Fore.CYAN}{'='*60}\n")

    print(f"{Fore.CYAN}Available Backups:")
    for i, backup in enumerate(backups, 1):
        modified = datetime.fromtimestamp(backup.stat().st_mtime)
        print(f"  {i}. {backup.name}")
        print(f"     Created: {modified.strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        choice = int(input(f"\nSelect backup [1-{len(backups)}, 0 to cancel]: "))

        if choice == 0:
            return None

        backup_file = backups[choice - 1]

        # Confirm restoration
        print(f"\n{Fore.RED}⚠️  WARNING: This will replace your current passwords!")
        confirm = input("Type 'RESTORE' to confirm: ").strip()

        if confirm != 'RESTORE':
            print(f"{Fore.YELLOW}Restoration cancelled")
            return None

        # Load and decrypt backup
        encrypted_data = backup_file.read_bytes()
        restored_data = decrypt_data(encrypted_data, key)

        print(f"\n{Fore.GREEN}✓ Backup restored successfully!")
        print(f"{Fore.GREEN}  Restored {len(restored_data['passwords'])} passwords")

        return restored_data

    except IndexError:
        print(f"{Fore.RED}Invalid selection")
        return None
    except InvalidToken:
        print(f"{Fore.RED}❌ Cannot decrypt backup - wrong master password?")
        return None
    except ValueError:
        print(f"{Fore.RED}❌ Backup file is corrupted")
        return None


# ============================================================================
# MASTER PASSWORD MANAGEMENT
# ============================================================================

def setup_master_password() -> bytes:
    """
    Set up a new master password with strength validation.

    Returns:
        Encryption key derived from the master password
    """
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}🔐 Setup Master Password")
    print(f"{Fore.CYAN}{'='*60}\n")
    print(f"{Fore.YELLOW}This is the ONLY password you need to remember.")
    print(f"{Fore.YELLOW}If you forget it, your passwords CANNOT be recovered!\n")

    while True:
        password = getpass.getpass("Enter master password: ")

        if len(password) < 8:
            print(f"{Fore.RED}Master password must be at least 8 characters")
            continue

        # Check strength
        analysis = check_password_strength(password)
        print(f"\nMaster Password Strength: {analysis['color']}{analysis['level']} ({analysis['score']}/100)")

        if analysis['score'] < 60:
            print(f"{Fore.RED}⚠️  Your master password is too weak!")
            print(f"{Fore.YELLOW}Suggestions:")
            for suggestion in analysis['feedback']:
                print(f"  • {suggestion}")
            retry = input("\nTry a stronger password? [Y/n]: ").strip().lower()
            if retry != 'n':
                continue

        # Confirm password
        confirm = getpass.getpass("Confirm master password: ")

        if password != confirm:
            print(f"{Fore.RED}Passwords don't match. Try again.\n")
            continue

        # Generate encryption key
        salt = get_salt()
        key = derive_key_from_password(password, salt)

        print(f"\n{Fore.GREEN}✓ Master password set successfully!")
        return key


def verify_master_password() -> bytes | None:
    """
    Verify the master password and return encryption key.

    Returns:
        Encryption key, or None if verification fails
    """
    print(f"\n{Fore.CYAN}🔐 Enter your master password")

    for attempt in range(3):
        password = getpass.getpass("Master password: ")

        try:
            salt = get_salt()
            key = derive_key_from_password(password, salt)

            # Try to load passwords to verify key is correct
            load_passwords(key)

            print(f"{Fore.GREEN}✓ Access granted\n")
            return key

        except ValueError:
            remaining = 2 - attempt
            if remaining > 0:
                print(f"{Fore.RED}❌ Incorrect password. {remaining} attempts remaining.")
            else:
                print(f"{Fore.RED}❌ Too many failed attempts. Exiting for security.")
                return None

    return None


def change_master_password(old_key: bytes) -> bytes:
    """
    Change the master password and re-encrypt all data.

    Args:
        old_key: Current encryption key

    Returns:
        New encryption key, or old key if cancelled
    """
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}🔄 Change Master Password")
    print(f"{Fore.CYAN}{'='*60}\n")

    # Verify current password
    print("First, verify your current master password:")
    current = getpass.getpass("Current master password: ")

    salt = get_salt()
    verify_key = derive_key_from_password(current, salt)

    if not hmac.compare_digest(verify_key, old_key):
        print(f"{Fore.RED}❌ Current password is incorrect")
        return old_key

    # Get new password
    print(f"\n{Fore.CYAN}Enter new master password:")
    new_password = getpass.getpass("New master password: ")

    # Check strength
    analysis = check_password_strength(new_password)
    print(f"\nNew Password Strength: {analysis['color']}{analysis['level']} ({analysis['score']}/100)")

    if analysis['score'] < 60:
        print(f"{Fore.YELLOW}⚠️  Warning: This password is weak")
        proceed = input("Continue anyway? [y/N]: ").strip().lower()
        if proceed != 'y':
            print(f"{Fore.YELLOW}Cancelled")
            return old_key

    # Confirm new password
    confirm = getpass.getpass("Confirm new master password: ")

    if new_password != confirm:
        print(f"{Fore.RED}Passwords don't match")
        return old_key

    # Generate new key and re-encrypt everything
    new_key = derive_key_from_password(new_password, salt)

    try:
        # Load with old key, save with new key
        data = load_passwords(old_key)
        save_passwords(data, new_key)

        print(f"\n{Fore.GREEN}✓ Master password changed successfully!")
        print(f"{Fore.YELLOW}⚠️  Make sure to remember your new password!")

        return new_key

    except (ValueError, OSError) as e:
        print(f"{Fore.RED}❌ Error changing password: {e}")
        return old_key


# ============================================================================
# MAIN MENU & USER INTERFACE
# ============================================================================

def print_header():
    """Display the application header."""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}{Style.BRIGHT}          🔐 SECURE PASSWORD MANAGER 🔐")
    print(f"{Fore.CYAN}         Local Storage • AES-256 Encryption")
    print(f"{Fore.CYAN}{'='*60}\n")


def print_menu():
    """Display the main menu."""
    print(f"{Fore.CYAN}Main Menu:")
    print(f"  {Fore.WHITE}1.{Style.RESET_ALL} Add New Password")
    print(f"  {Fore.WHITE}2.{Style.RESET_ALL} View All Passwords")
    print(f"  {Fore.WHITE}3.{Style.RESET_ALL} Search & View Password")
    print(f"  {Fore.WHITE}4.{Style.RESET_ALL} Update Password")
    print(f"  {Fore.WHITE}5.{Style.RESET_ALL} Delete Password")
    print(f"  {Fore.WHITE}6.{Style.RESET_ALL} View by Category")
    print(f"  {Fore.WHITE}7.{Style.RESET_ALL} Generate Password")
    print(f"  {Fore.WHITE}8.{Style.RESET_ALL} Statistics")
    print(f"  {Fore.WHITE}9.{Style.RESET_ALL} Backup & Restore")
    print(f"  {Fore.WHITE}10.{Style.RESET_ALL} Change Master Password")
    print(f"  {Fore.WHITE}0.{Style.RESET_ALL} Exit")
    print()


def backup_restore_menu(data: dict, key: bytes) -> dict:
    """
    Backup and restore submenu.

    Args:
        data: Current password database
        key: Encryption key

    Returns:
        Updated password database (if restored)
    """
    while True:
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}Backup & Restore Menu")
        print(f"{Fore.CYAN}{'='*60}")
        print("  1. Create Backup")
        print("  2. Restore from Backup")
        print("  3. List Backups")
        print("  0. Back to Main Menu")

        choice = input(f"\n{Fore.WHITE}Choose option: ").strip()

        if choice == '1':
            create_backup(data, key)
        elif choice == '2':
            restored = restore_from_backup(key)
            if restored:
                # Save the restored data as current
                save_passwords(restored, key)
                data = restored
        elif choice == '3':
            list_backups()
        elif choice == '0':
            break
        else:
            print(f"{Fore.RED}Invalid option")

    return data


def main():
    """
    Main application loop.
    """
    try:
        # Initialize security infrastructure
        initialize_security()

        # Check if this is first run
        is_first_run = not PASSWORDS_FILE.exists()

        print_header()

        if is_first_run:
            print(f"{Fore.YELLOW}👋 Welcome to Secure Password Manager!")
            print(f"{Fore.YELLOW}This appears to be your first time using this application.\n")
            print(f"{Fore.CYAN}Setup Instructions:")
            print("  1. Create a strong master password")
            print("  2. Remember it! Cannot be recovered if forgotten")
            print("  3. All passwords encrypted with AES-256")
            print("  4. Data stored locally on your computer\n")

            key = setup_master_password()

            # Create initial empty database
            initial_data = {"passwords": []}
            save_passwords(initial_data, key)

            print(f"\n{Fore.GREEN}✓ Setup complete! You can now add passwords.")
            input(f"\n{Fore.CYAN}Press Enter to continue...")
        else:
            # Verify master password
            key = verify_master_password()
            if key is None:
                print(f"\n{Fore.RED}Exiting for security reasons.")
                return

        # Load password database
        data = load_passwords(key)

        # Main menu loop
        while True:
            print_header()
            print_menu()

            choice = input(f"{Fore.WHITE}Choose option [0-10]: ").strip()

            if choice == '1':
                add_password(data, key)
            elif choice == '2':
                view_passwords(data)
            elif choice == '3':
                search_and_show_password(data)
            elif choice == '4':
                update_password(data, key)
            elif choice == '5':
                delete_password(data, key)
            elif choice == '6':
                view_by_category(data)
            elif choice == '7':
                # Just generate a password for user to use elsewhere
                password = password_generator_wizard()
                if password:
                    print(f"\n{Fore.CYAN}💡 Tip: You can copy this password for use elsewhere")
            elif choice == '8':
                show_statistics(data)
            elif choice == '9':
                data = backup_restore_menu(data, key)
            elif choice == '10':
                key = change_master_password(key)
            elif choice == '0':
                print(f"\n{Fore.CYAN}👋 Goodbye! Your passwords are safe and encrypted.")
                break
            else:
                print(f"{Fore.RED}Invalid option. Please choose 0-10.")

            # Pause before showing menu again
            if choice != '0':
                input(f"\n{Fore.CYAN}Press Enter to continue...")

    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Interrupted by user. Exiting safely...")
    except (ValueError, OSError) as e:
        print(f"\n{Fore.RED}❌ Unexpected error: {e}")
        print(f"{Fore.YELLOW}Your data is still encrypted and safe.")
    finally:
        # Clear sensitive data from memory (Python will garbage collect)
        if 'key' in locals():
            del key
        if 'data' in locals():
            del data


if __name__ == "__main__":
    main()


