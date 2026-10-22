# CVE-2026-104068 — JetBackup (WordPress): Symlink Arbitrary File Write via Backup Restore

- **Component:** JetBackup for WordPress (wordpress.org slug `backup`)
- **Affected:** < 3.1.24.10
- **Fixed in:** 3.1.24.10
- **Class:** CWE-59 (Link Following) → arbitrary file write
- **Severity:** High — CVSS 4.0 8.6 / CVSS 3.1 7.2 (`AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`)
- **CVE assigner:** VulnCheck (credited: Sarvar Eshboyev)
- **Status:** vendor-confirmed, fix verified

---

## Summary

When JetBackup restores a backup archive, a TAR member can be a **symbolic link**
whose target points outside the extraction directory. A following member with the
**same name** is then extracted, and the write *follows the symlink* — placing
attacker-controlled content at an arbitrary path, under the web-server user.

The plugin's existing `..` traversal protection does not help, because the escape
happens through **symlink resolution**, not through `..` in a filename.

## Root cause

The archive extraction routine:

- normalizes `..` sequences in member names (so classic path traversal is blocked), but
- **creates symlink members without verifying the link target stays inside the
  extraction root**, and
- opens regular-file members for writing **without `O_NOFOLLOW` / `lstat()`**, so a
  write to a name that is already a symlink follows it.

The escape chain, in order inside one archive:

1. `meta/meta.json` — a valid snapshot manifest (so the restore proceeds).
2. A symlink member, e.g. `jb-link` → `/var/www/html/<target>`.
3. A regular-file member **with the same name** `jb-link`, carrying the payload bytes.

When (3) is extracted on top of the symlink from (2), the bytes land at the symlink's
target, outside the intended directory.

### Why the existing checks miss it

| Existing check | Why it fails |
|---|---|
| `resolveRelativePath()` normalizes `..` | The malicious member name contains no `..`. |
| parent-directory `realpath()` inside root | The parent is a legitimate extraction subdir; only the final node is a symlink. |
| `symlink(link, output)` | No validation that the target stays inside the extraction root. |
| open for append/write | Follows symlinks; no `O_NOFOLLOW`, no `lstat()`. |

## Reproduction (lab)

Preconditions: Administrator, and **Cross Restore Domain** enabled (JetBackup →
Settings → Restore). Scored PR:H accordingly.

1. Build the crafted archive with the included benign builder:

   ```bash
   bash poc/build-archive.sh      # writes poc/jb-poc.tar
   ```

   The builder drops a harmless marker string (`JB-POC-CANARY`) at the target path —
   it is **not** a webshell.

2. In wp-admin: JetBackup → Backups → **Import & Restore** → upload `jb-poc.tar`.
   Let it reach the extraction stage (it need not finish).

3. Confirm the marker file was written **outside** the extraction directory, e.g.:

   ```
   /var/www/html/wp-content/jb-poc-canary.txt  →  JB-POC-CANARY
   ```

That write is outside the intended directory, under the web-server user — proving the
arbitrary file write primitive. In my private vendor report the same primitive was
escalated to code execution; that escalation is intentionally **omitted here**.

## Impact

Arbitrary file write as the web-server user. On a standard WordPress host this is
escalatable to remote code execution (write a PHP file into the web root). On shared
hosting the write can cross account boundaries.

## Remediation (shipped in 3.1.24.10)

1. Reject symlink/hardlink members unless the resolved target is verified inside the
   extraction root.
2. Do not follow symlinks when writing regular files — use `O_NOFOLLOW` or an
   equivalent safe-open.
3. Validate the **final** output path, not only its parent directory.
4. Reject archives containing two members with the same name.

## Timeline

- Reported privately to the vendor.
- Fixed in 3.1.24.10.
- CVE-2026-104068 published by VulnCheck.

## Files

- [`poc/build-archive.sh`](poc/build-archive.sh) — builds the crafted TAR with a benign marker payload.
- [`notes.md`](notes.md) — extra detail on the extraction logic.
