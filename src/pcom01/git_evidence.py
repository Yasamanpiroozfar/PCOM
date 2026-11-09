"""Verify retained Git objects and complete reviewed-subtree inventories."""
from __future__ import annotations

import base64
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import lru_cache, wraps
import gzip
import hashlib
import json
from pathlib import Path
import re

from .io import read_json, sha256

SOURCE_KIND = "git_reviewed_tree"
OID = re.compile(r"[a-f0-9]{40}\Z")
_SESSION = ContextVar("git_verification_session", default=None)
_INVENTORY_FILES = {}


def checked_file(path, expected):
    # Keep the live path for each stat/read, including symlink-target changes.
    # Resolving every ancestor repeatedly is expensive on Windows.
    path = Path(path).absolute()
    stat = path.stat()
    fingerprint = (stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size)
    session = _SESSION.get()
    previous = session.get(str(path)) if session is not None else None
    if previous != (expected, fingerprint):
        if sha256(path) != expected:
            raise ValueError("Git source file hash mismatch: " + path.name)
        if session is not None:
            session[str(path)] = (expected, fingerprint)


def verification_session(function):
    """Use fresh proofs per public operation, with file-change checks on reuse."""
    @wraps(function)
    def wrapped(*args, **kwargs):
        outermost = _SESSION.get() is None
        if outermost:
            clear_inventory_cache()
        token = _SESSION.set({})
        try:
            result = function(*args, **kwargs)
            # A final content pass also catches edits whose timestamps were
            # deliberately restored while this operation was running.
            for path, (digest, _) in _SESSION.get().items():
                if sha256(Path(path)) != digest:
                    raise ValueError("Git source changed during verification: " + Path(path).name)
            return result
        finally:
            _SESSION.reset(token)
            if outermost:
                clear_inventory_cache()
    return wrapped


def verified_source_hashes(root):
    base = Path(root).resolve()
    session = _SESSION.get()
    if session is None:
        raise ValueError("Git source hashes require an active verification session")
    return {Path(path).relative_to(base).as_posix(): value[0]
            for path, value in sorted(session.items()) if base in Path(path).parents}


def object_id(kind, raw):
    return hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def tree_entries(raw):
    entries, offset = {}, 0
    while offset < len(raw):
        space, zero = raw.index(b" ", offset), raw.index(b"\0", offset)
        mode = raw[offset:space].decode("ascii")
        name = raw[space + 1:zero].decode("utf-8")
        oid = raw[zero + 1:zero + 21].hex()
        if len(oid) != 40 or name in entries or not name or "/" in name:
            raise ValueError("Malformed Git tree entry")
        entries[name] = (mode, oid)
        offset = zero + 21
    return entries


def inventory_tree_id(entries):
    """Reconstruct the Git tree from every relative path, mode and blob ID."""
    directories = {"": {}}
    for item in entries:
        path, mode, oid = item["path"], item["mode"], item["blob_sha"]
        if (not isinstance(path, str) or path.startswith("/") or "\\" in path
                or any(part in ("", ".", "..") for part in path.split("/"))
                or mode not in ("100644", "100755", "120000") or not OID.fullmatch(oid)):
            raise ValueError("Invalid reviewed Git inventory entry")
        parts = path.split("/")
        for index in range(len(parts) - 1):
            parent, child = "/".join(parts[:index]), "/".join(parts[:index + 1])
            existing = directories.setdefault(parent, {}).get(parts[index])
            if existing and existing != ("40000", child):
                raise ValueError("Git inventory file/directory conflict")
            directories[parent][parts[index]] = ("40000", child)
            directories.setdefault(child, {})
        parent = "/".join(parts[:-1])
        if parts[-1] in directories.setdefault(parent, {}):
            raise ValueError("Duplicate reviewed Git inventory path")
        directories[parent][parts[-1]] = (mode, oid)
    computed = {}
    for path in sorted(directories, key=lambda value: value.count("/") + bool(value), reverse=True):
        entries_here = directories[path]
        parts = []
        for name, (mode, value) in sorted(entries_here.items(), key=lambda pair: (pair[0] + ("/" if pair[1][0] == "40000" else "")).encode()):
            oid = computed[value] if mode == "40000" else value
            parts.append(mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid))
        computed[path] = object_id("tree", b"".join(parts))
    return computed[""]


@lru_cache(maxsize=1024)
def _inventory(root_string, tree_sha, digest):
    root = Path(root_string)
    path = root / "data/raw/git-reviewed-trees" / (tree_sha + ".json.gz")
    if sha256(path) != digest:
        raise ValueError("Reviewed tree inventory hash mismatch")
    document = read_json(path)
    if document.get("tree_sha") != tree_sha:
        raise ValueError("Reviewed tree inventory identity mismatch")
    if document.get("base_tree_sha"):
        inherited = _inventory(root_string, document["base_tree_sha"], document["base_sha256"])
        dependencies = dict(_INVENTORY_FILES[(root_string, document["base_tree_sha"], document["base_sha256"])])
        entries = {item["path"]: item for item in inherited}
        for deleted in document.get("deleted", []):
            if deleted not in entries:
                raise ValueError("Reviewed tree delta deletes absent path")
            del entries[deleted]
        for item in document.get("entries", []):
            entries[item["path"]] = item
        result = tuple(entries[key] for key in sorted(entries))
    else:
        dependencies = {}
        result = tuple(document["entries"])
    if inventory_tree_id(result) != tree_sha:
        raise ValueError("Reviewed inventory does not reconstruct its Git tree")
    dependencies[str(path)] = digest
    _INVENTORY_FILES[(root_string, tree_sha, digest)] = dependencies
    return result


def clear_inventory_cache():
    _inventory.cache_clear()
    _shard.cache_clear()
    _blob_fact.cache_clear()
    _INVENTORY_FILES.clear()


@lru_cache(maxsize=256)
def _shard(root_string, prefix, digest):
    path = Path(root_string) / "data/raw/git-blob-shards" / (prefix + ".json.gz")
    if sha256(path) != digest:
        raise ValueError("Original Git object shard hash mismatch")
    document = read_json(path)
    if document.get("schema_version") != 1 or not isinstance(document.get("objects"), dict):
        raise ValueError("Malformed original Git object shard")
    return document["objects"]


@lru_cache(maxsize=100000)
def _blob_fact(root_string, oid, shard_digest):
    objects = _shard(root_string, oid[:2], shard_digest)
    raw = base64.b64decode(objects[oid], validate=True)
    if object_id("blob", raw) != oid:
        raise ValueError("Original advisory Git blob digest mismatch")
    original = json.loads(raw)
    if not isinstance(original, dict):
        raise ValueError("Original advisory Git blob is not a JSON object")
    affected = original.get("affected", [])
    if not isinstance(affected, list):
        raise ValueError("Original advisory affected field is malformed")
    names = set()
    for item in affected:
        if not isinstance(item, dict) or not isinstance(item.get("package", {}), dict):
            raise ValueError("Original advisory package mapping is malformed")
        package = item.get("package", {})
        if package.get("ecosystem") == "npm":
            if not isinstance(package.get("name"), str) or not package["name"]:
                raise ValueError("Original advisory npm mapping lacks a package name")
            names.add(package["name"])
    from .advisories import RETAINED_OSV_FIELDS
    projection = {key: original[key] for key in RETAINED_OSV_FIELDS if key in original}
    digest = hashlib.sha256(json.dumps(original, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return original.get("id"), frozenset(names), digest, projection


def verify_git_source(root, info, bundle):
    """Bind a selected projection to real commit/tree/blob objects offline."""
    if _SESSION.get() is None:
        # Direct source checks must never inherit a previous operation's cache.
        clear_inventory_cache()
    proof = bundle["provenance"]
    if info.get("source_kind") != SOURCE_KIND or proof.get("source_kind") != SOURCE_KIND:
        raise ValueError("Git source kind is inconsistent")
    if info.get("archive_sha256") is not None or proof.get("archive_sha256") is not None:
        raise ValueError("Git source cannot claim an HTTP archive digest")
    source = proof.get("git_source")
    if source != info.get("git_source") or not isinstance(source, dict):
        raise ValueError("Git source binding differs between bundle and manifest")
    if source.get("selection_sha256") != sha256(Path(root) / "config/packages.json"):
        raise ValueError("Git projection selected-package binding mismatch")
    selected = sorted(item["name"] for item in read_json(Path(root) / "config/packages.json")["packages"])
    if proof.get("selected_packages") != selected:
        raise ValueError("Git snapshot package coverage differs from the complete selection")
    commit_raw = base64.b64decode(source["commit_object_base64"], validate=True)
    if object_id("commit", commit_raw) != info["commit"]["sha"]:
        raise ValueError("Commit object digest mismatch")
    headers = commit_raw.split(b"\n\n", 1)[0].splitlines()
    tree_header = next(line for line in headers if line.startswith(b"tree "))
    root_sha = tree_header[5:].decode("ascii")
    committer = next(line for line in headers if line.startswith(b"committer ")).rsplit(b" ", 2)
    committed_at = datetime.fromtimestamp(int(committer[-2]), timezone.utc)
    from .advisories import utc
    if committed_at != utc(info["commit"]["committed_at"]):
        raise ValueError("Commit timestamp does not match its Git object")
    root_raw = base64.b64decode(source["root_tree_base64"], validate=True)
    advisory_raw = base64.b64decode(source["advisories_tree_base64"], validate=True)
    if object_id("tree", root_raw) != root_sha:
        raise ValueError("Root tree object digest mismatch")
    advisory_sha = tree_entries(root_raw).get("advisories")
    if advisory_sha != ("40000", object_id("tree", advisory_raw)):
        raise ValueError("Advisories tree is not part of the recorded commit")
    reviewed_sha = source["reviewed_tree_sha"]
    if tree_entries(advisory_raw).get("github-reviewed") != ("40000", reviewed_sha):
        raise ValueError("Reviewed tree is not part of the advisory tree")
    expected_path = "data/raw/git-reviewed-trees/" + reviewed_sha + ".json.gz"
    if source.get("inventory_path") != expected_path:
        raise ValueError("Reviewed inventory path is not bound to its Git tree")
    inventory = _inventory(str(Path(root).resolve()), reviewed_sha, source["inventory_sha256"])
    for path, digest in _INVENTORY_FILES[(str(Path(root).resolve()), reviewed_sha, source["inventory_sha256"])].items():
        checked_file(path, digest)
    entries = {item["path"]: item for item in inventory if item["path"].endswith(".json")}
    ids = [path.rsplit("/", 1)[-1][:-5] for path in entries]
    if (proof.get("reviewed_files_scanned") != len(entries)
            or proof.get("all_ghsa_ids") != sorted(set(ids)) or len(ids) != len(set(ids))):
        raise ValueError("Complete reviewed inventory disagrees with the source Git tree")
    index_path = Path(root) / "data/provenance/git-blob-shards.json"
    checked_file(index_path, source.get("blob_index_sha256"))
    shard_index = read_json(index_path)["shards"]
    for prefix, item in shard_index.items():
        if not re.fullmatch(r"[a-f0-9]{2}", prefix) or item["path"] != "data/raw/git-blob-shards/" + prefix + ".json.gz":
            raise ValueError("Git shard identity/path mismatch")
        checked_file(Path(root) / item["path"], item["sha256"])
    expected_paths = set()
    selected_set = set(selected)
    facts = {}
    root_string = str(Path(root).resolve())
    for path, item in entries.items():
        oid = item["blob_sha"]
        fact = _blob_fact(root_string, oid, shard_index[oid[:2]]["sha256"])
        if fact[0] != path.rsplit("/", 1)[-1][:-5]:
            raise ValueError("Original advisory ID differs from reviewed Git filename")
        if fact[1] & selected_set or "*" in fact[1]:
            expected_paths.add("advisories/github-reviewed/" + path)
            facts[path] = fact
    actual_paths = [item["source_path"] for item in bundle["records"]]
    if len(set(actual_paths)) != len(actual_paths) or set(actual_paths) != expected_paths:
        raise ValueError("Projection omits or duplicates a matching historical advisory")
    for retained in bundle["records"]:
        prefix = "advisories/github-reviewed/"
        path = retained["source_path"]
        if not path.startswith(prefix) or path[len(prefix):] not in entries:
            raise ValueError("Retained document is absent from the reviewed Git tree")
        _, _, digest, projected = facts[path[len(prefix):]]
        if projected != retained["document"] or digest != retained.get("source_document_sha256"):
            raise ValueError("Retained advisory projection differs from its original Git blob")
    return inventory
