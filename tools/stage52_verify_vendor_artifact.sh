#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'
import hashlib,json,pathlib,os
root=pathlib.Path("artifact/vendor/drand")
m=json.loads((root/"V6_VENDOR_MANIFEST.json").read_text(encoding="utf-8"))
assert m["schema"]=="V6_STAGE52_DRAND_VENDOR_MANIFEST_V1"
assert m["upstream_commit"]=="ef8c9260294f8699b5e8c27a6b764f8f0d768bea"
assert m["github_repository_id"]=="1469695205"
assert m["github_repository_owner_id"]=="360536248"
for f in m["files"]:
    p=root/f["name"]
    assert p.is_file() and not p.is_symlink()
    assert p.stat().st_size==f["bytes"]
    assert hashlib.sha256(p.read_bytes()).hexdigest()==f["sha256"]
PY
