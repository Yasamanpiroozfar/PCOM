"""Recover missing version manifests as separate, hashed JSON captures."""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
import sys
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcom01.io import SafeRedirect, now, read_json, save_json, sha256
from pcom01.npm import parse_timestamp, transform
from pcom01.schema import MONTH_WINDOWS


def acquire(root=ROOT):
    root = Path(root)
    original_path = root / "data/provenance/acquisition.json"
    original = read_json(original_path)
    selection = root / "config/packages.json"
    if original["selection_sha256"] != sha256(selection):
        raise ValueError("Original package selection binding failed")
    path = root / "data/provenance/release-manifests.json"
    inventory = {"schema_version": 1, "complete": False, "fetched_at": now(),
                 "selection_sha256": sha256(selection),
                 "original_acquisition_sha256": sha256(original_path),
                 "manifests": {}, "requests": [], "missing": [],
                 "source_type": "retained_public_registry_mirror_metadata",
                 "limitations": "A retained third-party registry mirror capture, not an immutable origin-time npm service response. Original publication timestamps remain sourced exclusively from the original npm registry capture."}
    save_json(path, inventory)
    lower = min(value[0] for value in MONTH_WINDOWS.values())
    upper = max(value[1] for value in MONTH_WINDOWS.values())
    opener = build_opener(SafeRedirect())
    for item in read_json(selection)["packages"]:
        package = item["name"]
        info = original["packages"].get(package, {}).get("registry", {})
        if "path" not in info:
            continue
        if sha256(root / info["path"]) != info["stored_sha256"]:
            raise ValueError("Original registry source changed")
        registry = read_json(root / info["path"])
        transformed = transform(registry, package)
        for exclusion in transformed["excluded"]:
            version = exclusion["version"]
            if exclusion["reason"] != "timestamp_without_version_manifest":
                continue
            published = registry["time"][version]
            if not lower <= parse_timestamp(published) < upper:
                continue
            recovered = False
            for host in ("registry.npmjs.org", "registry.npmmirror.com"):
                url = "https://" + host + "/" + quote(package, safe="@") + "/" + quote(version, safe="")
                requested = now()
                try:
                    with opener.open(Request(url, headers={"Accept": "application/json"}), timeout=30) as response:
                        raw = response.read(2 * 1024 * 1024 + 1)
                        status, final_url = response.status, response.url
                        content_type = response.headers.get("Content-Type")
                except HTTPError as exc:
                    body = exc.read(4096)
                    inventory["requests"].append({"package": package, "version": version, "url": url,
                        "requested_at": requested, "status": exc.code,
                        "error_body_sha256": hashlib.sha256(body).hexdigest(),
                        "error_body_prefix": body.decode("utf-8", errors="replace")})
                    save_json(path, inventory)
                    if exc.code == 404:
                        continue
                    raise
                if len(raw) > 2 * 1024 * 1024:
                    raise ValueError("Version metadata exceeds bounded JSON size")
                document = json.loads(raw)
                if document.get("name") != package or document.get("version") != version:
                    raise ValueError("Recovered manifest package/version identity mismatch")
                merged = {**registry, "versions": {**registry["versions"], version: document}}
                tested = transform(merged, package)
                if not any(row["purl"].endswith("@" + quote(version, safe="._-~")) for row in tested["records"]):
                    raise ValueError("Recovered manifest fails record eligibility")
                relative = "data/raw/release-manifests/" + quote(package, safe="") + "@" + quote(version, safe="") + ".json.gz"
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(gzip.compress(raw, mtime=0))
                entry = {"package": package, "version": version, "published_at": published,
                         "url": url, "final_url": final_url, "fetched_at": requested,
                         "http_status": status, "content_type": content_type,
                         "path": relative, "stored_sha256": sha256(target),
                         "response_sha256": hashlib.sha256(raw).hexdigest(),
                         "response_bytes": len(raw),
                         "source_kind": "npm_version_metadata" if host == "registry.npmjs.org" else "retained_npm_mirror_version_metadata"}
                inventory["manifests"].setdefault(package, {})[version] = entry
                inventory["requests"].append({"package": package, "version": version,
                    "url": url, "requested_at": requested, "status": status,
                    "response_sha256": entry["response_sha256"]})
                save_json(path, inventory)
                print(json.dumps({"package": package, "version": version, "status": status,
                                  "source": host, "response_bytes": len(raw)}), flush=True)
                recovered = True
                break
            if not recovered:
                inventory["missing"].append({"package": package, "version": version})
    inventory["complete"] = not inventory["missing"]
    save_json(path, inventory)
    return 0 if inventory["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(acquire())
