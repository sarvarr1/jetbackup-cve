# JetBackup (WordPress) — CVE Writeup

A vulnerability I discovered in the **JetBackup** WordPress plugin (wordpress.org slug
`backup`) through source code review, reproduced in an isolated local lab, and
responsibly disclosed to the vendor. **Fixed in 3.1.24.10**; CVE assigned by VulnCheck,
credited to me.

| CVE | Class | Severity (CVSS 4.0) | Fixed in |
|---|---|---|---|
| [CVE-2026-104068](CVE-2026-104068-symlink-file-write/) | Symlink arbitrary file write via TAR restore (CWE-59) | High — 8.6 | 3.1.24.10 |

**→ Full writeup: [CVE-2026-104068-symlink-file-write/](CVE-2026-104068-symlink-file-write/)**

## Approach

1. **Source review** — trace the backup-archive extraction path and its symlink/path
   handling.
2. **Lab reproduction** — version-matched WordPress in Docker, reproduced end to end.
3. **Impact proof** — demonstrate the out-of-directory file write (escalatable to RCE).
4. **Disclosure** — report privately, verify the fix against 3.1.24.10.

## Responsible use

Published **after** the fix shipped. The PoC builder uses a **benign marker payload**
(a harmless canary string), not a drop-in webshell — the goal is to explain the root
cause and the fix. All testing was done only in my own authorized local lab.

## Contact

Sarvar Eshboyev — eshsarvar@gmail.com — [LinkedIn](https://www.linkedin.com/in/sarvar-eshboyev)
