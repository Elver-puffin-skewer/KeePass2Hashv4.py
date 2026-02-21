# KeePass2Hashv4.py
KeePass2John (Python Version)

A pure Python implementation of the keepass2john utility that extracts
password cracking hashes from KeePass .kdbx databases.

This script parses KeePass database headers and outputs hashes in the
keepass format compatible with:

-   John the Ripper
-   Hashcat (with conversion)
-   Custom cracking tools

It does NOT decrypt the database. It only extracts metadata required for
offline password analysis.

------------------------------------------------------------------------

Features

-   Supports KDBX 4.x
-   Supports AES, Twofish, and ChaCha20
-   Extracts:
    -   Master seed
    -   Transform seed*
    -   Transform rounds
    -   Argon2 parameters (KDBX 4)
    -   Header HMAC (KDBX 4)
-   No external dependencies beyond Python standard library

------------------------------------------------------------------------

Supported Applications

Works with databases created by: - KeePass 2.x - KeePassXC - KeePassDX

------------------------------------------------------------------------

Installation

Requires Python 3.8+

No external packages required.

Simply download the script:

    python3 keepass2john_py.py database.kdbx

------------------------------------------------------------------------

Example Output

database:keepass4600000ef636ddf1048576192*
*

------------------------------------------------------------------------

Output Format

KDBX 3.x:

keepass2

KDBX 4.x:

keepass4*
*

------------------------------------------------------------------------

Security Notice

This tool is intended for:

-   Password recovery
-   Security research
-   Penetration testing
-   Educational use

Do not use against databases you do not own or have explicit permission
to test.

Unauthorized cracking attempts may violate laws in your jurisdiction.

------------------------------------------------------------------------

Limitations

-   Keyfile support not implemented
-   KeePass 1.x (.kdb) not supported
-   Does not decrypt database
-   Does not validate passwords


------------------------------------------------------------------------

Legal

This project is for lawful security research only.

Use responsibly.

