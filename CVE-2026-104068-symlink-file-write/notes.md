# Extra notes — CVE-2026-104068

- The web-reachable restore file is `jetbackup.restore.<random>.php`, where `<random>`
  is `random_bytes`-derived (96-bit), so the filename itself is the real access control
  and is not brute-forceable. Reaching the restore therefore requires Administrator
  access to the JetBackup Queue panel (PR:H).
- The manifest (`meta.json`) only needs a fresh, unused `name` / `job_identifier` on
  each import; JetBackup rejects snapshots whose identifier already exists.
- The restore does not need to complete. Once the extraction stage runs, the symlink +
  same-name-regular-file sequence has already performed the out-of-directory write.
- Patch check: diffing 3.1.24.5 → 3.1.24.10 confirmed the extraction path added the
  symlink-target containment check; the arbitrary write no longer occurs.
