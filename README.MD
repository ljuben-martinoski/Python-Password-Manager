# 🔐 Secure Password Manager

A professional-grade, offline password manager with military-grade encryption. Keep all your passwords safe and organized on your local computer.

## ✨ Features

### Core Security
- **AES-256 Encryption** - Same encryption used by militaries and governments
- **PBKDF2 Key Derivation** - 480,000+ iterations to prevent brute force attacks
- **Local Storage Only** - Your passwords never leave your computer
- **Unique Salt** - Each installation has unique encryption parameters
- **Master Password Protection** - One password to rule them all

### Password Management
- ✅ **Add/View/Update/Delete** passwords with ease
- 🔍 **Search** by site name or username
- 📁 **Categories** - Organize by Email, Banking, Social Media, Shopping, Work, Gaming, etc.
- 📊 **Statistics** - See password strength distribution and category breakdown
- 🎲 **Password Generator** - Create strong random passwords (8-64 characters)
- 💪 **Strength Checker** - Analyze password security with actionable feedback

### Backup & Safety
- 💾 **Encrypted Backups** - Create timestamped backup files
- 🔄 **Restore** - Recover from backups if needed
- 🔐 **Master Password Change** - Update your master password anytime

### User Experience
- 🎨 **Beautiful Terminal UI** - Color-coded, easy to navigate
- 📋 **Table Views** - Professional password listings
- 🙈 **Hidden Input** - Passwords never show on screen when typing
- ⚠️ **Confirmations** - Double-check before deleting anything

---

## 📋 Requirements

- Python 3.7 or higher
- pip (Python package installer)
- Terminal/Command Prompt

---

## 🚀 Installation

### Step 1: Download the Files

Make sure you have these three files in the same folder:
```
password_manager.py
requirements.txt
README.md (this file)
```

### Step 2: Install Dependencies

Open your terminal/command prompt and navigate to the folder containing the files.

**On Windows:**
```bash
cd C:\path\to\password_manager
pip install -r requirements.txt
```

**On macOS/Linux:**
```bash
cd /path/to/password_manager
pip3 install -r requirements.txt
```

### Step 3: Run the Program

**On Windows:**
```bash
python password_manager.py
```

**On macOS/Linux:**
```bash
python3 password_manager.py
```

---

## 📖 Usage Guide

### First Time Setup

1. **Run the program** - You'll be greeted with a welcome screen
2. **Create master password** - Choose a strong password you'll remember
   - Minimum 8 characters
   - Program will rate its strength
   - **IMPORTANT:** This cannot be recovered if forgotten!
3. **Confirm password** - Enter it again to verify
4. **You're ready!** - Start adding passwords

### Adding a Password

1. Choose option `1` from the main menu
2. Enter site/service name (e.g., "Gmail", "Facebook")
3. Enter username/email
4. Choose to either:
   - **Enter password manually** - Program will check its strength
   - **Generate strong password** - Customize length and character types
5. Select a category
6. Add optional notes
7. Password is encrypted and saved!

### Viewing Passwords

**View All:**
- Option `2` - See all passwords in a nice table

**Search for Specific Password:**
- Option `3` - Search by site name or username
- Shows the actual password (in green)

**View by Category:**
- Option `6` - Browse passwords organized by category
- See statistics for each category

### Updating a Password

1. Option `4` - Update Password
2. Search for the password
3. Choose what to update (site, username, password, category, notes)
4. Press Enter to keep current values
5. Changes are encrypted and saved

### Deleting a Password

1. Option `5` - Delete Password
2. Search for the password
3. Review what will be deleted
4. Type `DELETE` to confirm (case-sensitive)
5. Password is permanently removed

### Generating Strong Passwords

1. Option `7` - Generate Password
2. Choose length (8-64 characters, default 16)
3. Select character types:
   - Uppercase (A-Z)
   - Lowercase (a-z)
   - Numbers (0-9)
   - Symbols (!@#$%^&*)
4. View the generated password and its strength
5. Choose to use it, regenerate, or cancel

### Statistics & Analysis

Option `8` shows:
- Total number of passwords
- Breakdown by category (with visual bars)
- Password strength distribution
- Warnings for weak passwords

---

## 💾 Backup & Restore

### Creating a Backup

1. Option `9` - Backup & Restore
2. Choose `1` - Create Backup
3. Backup is saved with timestamp in `~/.password_manager/backups/`
4. Format: `passwords_backup_YYYYMMDD_HHMMSS.enc`

**Backup files are encrypted** with your master password, so they're safe even if someone gets the file.

### Restoring from Backup

1. Option `9` - Backup & Restore
2. Choose `2` - Restore from Backup
3. Select which backup to restore
4. Type `RESTORE` to confirm
5. Your current passwords will be replaced

### Backup Best Practices

- ✅ Create backups regularly (weekly or after major changes)
- ✅ Keep backups on external drives or cloud storage
- ✅ Test restoring occasionally to ensure backups work
- ✅ Keep multiple backup versions (don't delete old ones immediately)

---

## 🔐 Security Features Explained

### Why This is Secure

**1. AES-256 Encryption (Fernet)**
- Same encryption used by governments and militaries
- Virtually unbreakable with current technology
- Your password file looks like random data without the master password

**2. PBKDF2 Key Derivation (480,000 iterations)**
- Your master password isn't used directly
- It's processed 480,000 times before creating the encryption key
- This means even with a supercomputer, brute force attacks would take centuries
- OWASP recommended minimum for 2024

**3. Unique Salt**
- A random 256-bit salt is generated on first run
- This ensures even identical master passwords create different encryption keys
- Prevents rainbow table and pre-computed attacks

**4. Local Storage**
- All data stays on YOUR computer
- No cloud services
- No internet connections
- No one can hack a server that doesn't exist

**5. Memory Protection**
- Sensitive data is cleared from memory after use
- Python's garbage collector handles cleanup

### What if Someone Gets Your Computer?

Without your master password, your encrypted password file is useless:
- They can't decrypt it (AES-256 with PBKDF2)
- They can't brute force it (480,000 iterations makes this take centuries)
- They can't tamper with it (Fernet detects modifications)

**Best practice:** Also use full-disk encryption on your computer (BitLocker, FileVault, LUKS)

---

## 🔄 Changing Your Master Password

1. Option `10` - Change Master Password
2. Enter current master password (for verification)
3. Enter new master password
4. Program checks strength
5. Confirm new password
6. All data is re-encrypted with new password

**Important:** You need to remember your current password to change it.

---

## 🆘 Troubleshooting

### "ModuleNotFoundError: No module named 'cryptography'"

**Solution:** Install dependencies
```bash
pip install -r requirements.txt
```

### "Invalid master password or corrupted data file"

**Causes:**
- Wrong master password
- Password file was tampered with
- File corruption

**Solutions:**
1. Double-check you're typing the password correctly
2. If you forgot it, you'll need to restore from backup
3. If backups also fail, data is unrecoverable (this is a security feature)

### "FileNotFoundError: Salt file not found"

**Solution:** Let the program initialize
```bash
python password_manager.py
```
The program creates necessary files automatically on first run.

### Forgot Master Password

**This is the one scenario we can't help with** - and that's by design for security.

**Options:**
1. If you have backups AND remember the password you used when creating them, restore from backup
2. If you truly forgot and have no backups, you'll need to start fresh (delete `~/.password_manager/` folder)

**Prevention:** 
- Write down your master password on paper and keep it in a safe
- Use a memorable passphrase (e.g., "MyDog!Loves#Pizza@Home7")
- Create regular backups

### Colors Not Showing

The program works fine without colors, but if you want them:
```bash
pip install colorama
```

### Table Format Not Pretty

Install tabulate for beautiful tables:
```bash
pip install tabulate
```

---

## 📁 File Locations

### Data Directory
```
~/.password_manager/
```

**On Windows:**
```
C:\Users\YourName\.password_manager\
```

**On macOS/Linux:**
```
/home/yourusername/.password_manager/
```

### Files Stored

```
~/.password_manager/
├── passwords.enc           # Your encrypted password database
├── salt.key               # Unique encryption salt (keep this safe!)
└── backups/               # Encrypted backup files
    ├── passwords_backup_20240101_120000.enc
    ├── passwords_backup_20240108_120000.enc
    └── ...
```

### Important Notes

- **passwords.enc** - Your encrypted passwords. Safe even if stolen.
- **salt.key** - Required for decryption. Back this up with your passwords!
- **backups/** - Old versions of your password database

---

## 🔒 Security Best Practices

### Strong Master Password

**Good Examples:**
- `MyFavoriteBook!Chapter7@Home` (35 chars, very strong)
- `Coffee&Sunshine2024#Morning!` (28 chars, very strong)
- `I!Eat3Pizzas@Midnight` (21 chars, strong)

**Bad Examples:**
- `password123` (too common)
- `12345678` (sequential)
- `mypassword` (no variety)

**Tips:**
- Use 16+ characters
- Mix letters, numbers, and symbols
- Make it memorable but unique
- Don't use it anywhere else

### Password Generator Settings

For maximum security:
- **Length:** 16-32 characters (20 is a good balance)
- **Include all character types:** Yes to everything
- Use generated passwords for all accounts

### Regular Maintenance

- 🔄 **Review weak passwords** monthly (check Statistics)
- 💾 **Create backups** weekly
- 🔐 **Update old passwords** especially for important accounts
- 🗑️ **Delete unused passwords** to keep things organized

### Backup Strategy

**The 3-2-1 Rule:**
- **3** copies of your data (original + 2 backups)
- **2** different storage types (computer + external drive)
- **1** offsite backup (cloud storage or different location)

### What to Back Up
- `passwords.enc` (your encrypted passwords)
- `salt.key` (required for decryption)
- All files in `backups/` folder

---

## ❓ FAQ

**Q: Is this really secure?**  
A: Yes! It uses the same encryption (AES-256) that governments use for top-secret data. The PBKDF2 with 480,000 iterations makes brute-force attacks infeasible.

**Q: What if someone steals my backup files?**  
A: Backups are encrypted with your master password. Without it, they're useless random data.

**Q: Can I use this for my team/family?**  
A: This is designed for individual use. Each person should have their own installation with their own master password.

**Q: Does it work offline?**  
A: Yes! It's 100% offline and local. No internet required.

**Q: Can I sync across devices?**  
A: Not automatically, but you can manually copy the `~/.password_manager/` folder. Use the same master password on all devices.

**Q: How do I uninstall?**  
A: Delete the folder `~/.password_manager/` and the program files. **MAKE SURE TO EXPORT YOUR PASSWORDS FIRST!**

**Q: What happens if I change my master password?**  
A: All your passwords are re-encrypted with the new master password. Old backups will still need the old password.

**Q: Is Python 2 supported?**  
A: No, use Python 3.7 or higher.

---

## 🛡️ Threat Model

### What This Protects Against

✅ **Physical theft of your computer** (if powered off)  
✅ **Malware scanning your files** (encrypted data is useless)  
✅ **Someone looking over your shoulder** (passwords hidden when typing)  
✅ **Accidental file sharing** (encrypted file is safe)  
✅ **Data breach if you share backups** (backups are encrypted)

### What This Doesn't Protect Against

❌ **Keyloggers** (records what you type, including master password)  
❌ **Screen recording malware** (can see passwords when displayed)  
❌ **Someone with your master password** (by design - that's the key)  
❌ **Physical access while program is running** (passwords visible in memory)  
❌ **Compromised operating system** (malware with admin access)

### Additional Protection

For maximum security:
- Use full-disk encryption (BitLocker/FileVault/LUKS)
- Keep your OS and antivirus updated
- Use a firewall
- Don't run unknown software
- Lock your computer when away
- Use a password manager for your master password reminder (securely!)

---

## 🎓 For Developers

### Code Structure

The code is extensively commented and organized into clear sections:

1. **Configuration** - Constants and file paths
2. **Encryption** - PBKDF2 and Fernet implementation
3. **Password Strength** - Analysis algorithm
4. **Password Generator** - Cryptographically secure random generation
5. **Storage** - Encrypted save/load functions
6. **CRUD Operations** - Add, view, update, delete passwords
7. **Categories** - Organization and statistics
8. **Backup/Restore** - Data safety features
9. **UI** - Menu system and user interaction

### Security Decisions

**Why PBKDF2?**
- Industry standard for password-based key derivation
- Configurable iteration count (future-proof)
- Built into Python's cryptography library

**Why Fernet?**
- High-level encryption primitive
- Handles IV, MAC, padding automatically
- Impossible to use incorrectly (unlike raw AES)
- Authenticated encryption (detects tampering)

**Why 480,000 iterations?**
- OWASP recommendation for 2024
- Makes brute force attacks extremely slow
- Good balance between security and performance

### Modifying the Code

Feel free to customize:
- Add more categories (CATEGORIES list)
- Change iteration count (PBKDF2_ITERATIONS)
- Modify password strength algorithm
- Add export to CSV/JSON features
- Create a GUI version

### Testing

To test backup/restore:
```bash
python password_manager.py
# Add some test passwords
# Create backup
# Add more passwords
# Restore backup
# Verify only original passwords remain
```

---

## 📜 License

This password manager is provided as-is for personal and educational use. Feel free to modify and distribute.

**No Warranty:** Use at your own risk. Always maintain backups.

---

## 🙏 Credits

Built with:
- [cryptography](https://cryptography.io/) - Encryption library
- [colorama](https://pypi.org/project/colorama/) - Cross-platform colored terminal text
- [tabulate](https://pypi.org/project/tabulate/) - Pretty table formatting

---

## 📞 Support

If you encounter issues:

1. **Check this README** - Most questions are answered here
2. **Verify installation** - Make sure all dependencies are installed
3. **Test with fresh start** - Try creating a new database
4. **Check Python version** - Must be 3.7+

---

## 🔄 Version History

**v1.0.0** - Initial Release
- AES-256 encryption with Fernet
- PBKDF2 key derivation (480,000 iterations)
- Password generator
- Password strength checker
- Category organization
- Backup and restore
- Statistics and analytics
- Beautiful terminal UI

---

**Stay secure! 🔐**

Remember: Your master password is the key to everything. Keep it safe, keep it secret, and keep it memorable!