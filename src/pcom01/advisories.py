"""Count package-wide GHSAs from immutable historical advisory-database trees.

No live advisory response is accepted as a historical snapshot. Source timestamps
are checked in addition to the commit boundary; unknown evidence raises instead
of being silently represented as a count of zero. See docs/advisory-history.md.
"""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

SEVERITIES = ("low", "moderate", "high", "critical", "unknown")
GHSA_RE = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\Z")
SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
RETAINED_OSV_FIELDS = ("schema_version", "id", "published", "modified", "withdrawn", "aliases", "severity", "affected", "database_specific")


class HistoricalEvidenceError(ValueError):
    """The supplied evidence cannot support historical counts for a package."""


def utc(value: str | datetime) -> datetime:
    """Parse a timezone-aware instant, accepting the source's RFC3339 precision."""
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HistoricalEvidenceError(f"Invalid source timestamp: {value!r}") from exc
    else:
        raise HistoricalEvidenceError(f"Timestamp must be a string: {value!r}")
    if result.tzinfo is None or result.utcoffset() is None:
        raise HistoricalEvidenceError(f"Timezone missing from {value!r}")
    return result.astimezone(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def severity_category(value: Any) -> str:
    """Use GitHub's qualitative category, without inventing a CVSS conversion."""
    category = value.strip().lower() if isinstance(value, str) else "unknown"
    return category if category in SEVERITIES[:-1] else "unknown"


def month_window(index: int, cutoff: str | datetime) -> tuple[datetime, datetime]:
    """M0 is the complete calendar month immediately before the cutoff."""
    end = utc(cutoff)
    if end.day != 1 or any((end.hour, end.minute, end.second, end.microsecond)):
        raise HistoricalEvidenceError("Monthly cutoff must be the start of a UTC month")
    if type(index) is not int or not 0 <= index <= 11:
        raise HistoricalEvidenceError("Month index must be an integer in M0..M11")
    number = end.year * 12 + end.month - 1 - index
    upper_year, upper_month = divmod(number, 12)
    lower_year, lower_month = divmod(number - 1, 12)
    return (
        datetime(lower_year, lower_month + 1, 1, tzinfo=timezone.utc),
        datetime(upper_year, upper_month + 1, 1, tzinfo=timezone.utc),
    )


def _npm_packages(document: Mapping[str, Any]) -> frozenset[str]:
    affected = document.get("affected", [])
    if not isinstance(affected, list):
        raise HistoricalEvidenceError("OSV affected must be an array")
    names = set()
    for item in affected:
        if not isinstance(item, dict) or not isinstance(item.get("package", {}), dict):
            raise HistoricalEvidenceError("Malformed OSV affected package")
        package = item.get("package", {})
        if package.get("ecosystem") == "npm":
            name = package.get("name")
            if not isinstance(name, str) or not name:
                raise HistoricalEvidenceError("npm mapping has no package name")
            names.add(name)
    return frozenset(names)


@dataclass(frozen=True)
class Advisory:
    ghsa_id: str
    packages: frozenset[str]
    published: datetime
    modified: datetime
    severity: str
    reviewed_at: datetime | None
    withdrawn: datetime | None
    source_path: str
    document: dict[str, Any] = field(repr=False)

    def active_before(self, boundary: datetime) -> bool:
        # All boundaries are exclusive; a withdrawal at the boundary is not
        # present in the permitted strictly-earlier snapshot.
        return self.withdrawn is None or self.withdrawn >= boundary


@dataclass
class AdvisorySnapshot:
    observed_before: datetime
    commit_sha: str
    committed_at: datetime
    selected_packages: frozenset[str]
    advisories: dict[str, Advisory]
    all_ghsa_ids: frozenset[str]
    reviewed_files_scanned: int
    archive_sha256: str | None
    issues: dict[str, list[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    rejected_records: list[dict[str, Any]] = field(default_factory=list)
    source_document_hashes: dict[str, str] = field(default_factory=dict)

    def require_package(self, package: str) -> None:
        if package not in self.selected_packages:
            raise HistoricalEvidenceError(f"Package was not included in complete scan: {package}")
        if self.issues.get(package):
            raise HistoricalEvidenceError(f"Unresolved historical evidence for {package}: {self.issues[package]}")
        if self.reviewed_files_scanned < 1:
            raise HistoricalEvidenceError("No complete reviewed advisory corpus was scanned")

    def provenance(self) -> dict[str, Any]:
        return {
            "source": "https://github.com/github/advisory-database",
            "method": "commit-pinned reviewed Git mirror snapshot",
            "observed_before": iso(self.observed_before),
            "commit_sha": self.commit_sha,
            "committed_at": iso(self.committed_at),
            "snapshot_lag_seconds": (self.observed_before - self.committed_at).total_seconds(),
            "archive_sha256": self.archive_sha256,
            "reviewed_files_scanned": self.reviewed_files_scanned,
            "all_ghsa_ids": sorted(self.all_ghsa_ids),
            "selected_packages": sorted(self.selected_packages),
            "retained_advisories": len(self.advisories),
            "rejected_records_retained": len(self.rejected_records),
            "issues": self.issues,
            "warnings": self.warnings,
            "source_document_hashes": self.source_document_hashes,
            "record_projection": "Count-relevant OSV fields only; narrative/references/credits omitted to avoid redistributing unrelated signed URLs. source_document_hashes hash the original complete canonical JSON (sorted keys, compact separators, ensure_ascii=True).",
        }

    def raw_records(self) -> list[dict[str, Any]]:
        records = sorted([
            {"source_path": item.source_path, "document": item.document}
            for _, item in sorted(self.advisories.items())
        ] + self.rejected_records, key=lambda item: item["source_path"])
        return [{"source_path": item["source_path"],
                 "source_document_sha256": self.source_document_hashes[item["document"]["id"]],
                 "document": {key: item["document"][key] for key in RETAINED_OSV_FIELDS if key in item["document"]}}
                for item in records]


def _build_snapshot(
    entries: Iterable[tuple[str, dict[str, Any]]],
    packages: Iterable[str],
    observed_before: str | datetime,
    commit_sha: str,
    committed_at: str | datetime,
    archive_sha256: str | None,
) -> AdvisorySnapshot:
    boundary, commit_date = utc(observed_before), utc(committed_at)
    if not SHA_RE.fullmatch(commit_sha):
        raise HistoricalEvidenceError("A full immutable 40-character commit SHA is required")
    if commit_date >= boundary:
        raise HistoricalEvidenceError("Snapshot commit must be strictly before its observation boundary")
    selected = frozenset(packages)
    if not selected or any(not isinstance(name, str) or not name for name in selected):
        raise HistoricalEvidenceError("At least one explicit package must be selected")
    snapshot = AdvisorySnapshot(boundary, commit_sha, commit_date, selected, {}, frozenset(), 0, archive_sha256)
    all_ids: set[str] = set()
    seen: dict[str, str] = {}
    for path, document in entries:
        snapshot.reviewed_files_scanned += 1
        if not isinstance(document, dict):
            raise HistoricalEvidenceError(f"Advisory is not an object: {path}")
        ghsa_id = document.get("id")
        if not isinstance(ghsa_id, str) or not GHSA_RE.fullmatch(ghsa_id):
            raise HistoricalEvidenceError(f"Invalid GHSA identifier in {path}")
        if Path(path).stem != ghsa_id:
            raise HistoricalEvidenceError(f"Advisory filename/id mismatch: {path}")
        digest = hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if ghsa_id in seen:
            if seen[ghsa_id] != digest:
                raise HistoricalEvidenceError(f"Conflicting duplicate GHSA in one snapshot: {ghsa_id}")
            continue
        seen[ghsa_id] = digest
        all_ids.add(ghsa_id)
        names = _npm_packages(document)
        matched = names & selected
        if "*" in names:
            # Explicit wildcard is not silently treated as an exact name.
            matched = selected
        if not matched:
            continue
        snapshot.source_document_hashes[ghsa_id] = digest
        try:
            if "*" in names:
                raise HistoricalEvidenceError("Wildcard npm mapping requires manual interpretation")
            specific = document.get("database_specific")
            if not isinstance(specific, dict) or specific.get("github_reviewed") is not True:
                raise HistoricalEvidenceError("Reviewed path lacks explicit github_reviewed=true")
            published, modified = utc(document.get("published")), utc(document.get("modified"))
            reviewed_at = utc(specific["github_reviewed_at"]) if specific.get("github_reviewed_at") else None
            withdrawn = utc(document["withdrawn"]) if document.get("withdrawn") else None
            for label, timestamp in (("published", published), ("modified", modified), ("reviewed_at", reviewed_at), ("withdrawn", withdrawn)):
                if timestamp is not None and timestamp >= boundary:
                    raise HistoricalEvidenceError(f"{label} is not before snapshot boundary")
            if modified < published:
                # OSV defines these independently and does not require this
                # ordering. The pinned pre-boundary tree establishes existence;
                # neither field supplies future information. Preserve the fact.
                snapshot.warnings.append(f"{ghsa_id}: modified={iso(modified)} precedes published={iso(published)}; both precede boundary; historical Git tree retained without changing timestamps")
            if reviewed_at is None:
                snapshot.warnings.append(f"{ghsa_id}: review timestamp absent; reviewed flag and historical tree establish review state")
            snapshot.advisories[ghsa_id] = Advisory(
                ghsa_id, names, published, modified,
                severity_category(specific.get("severity")), reviewed_at,
                withdrawn, path, document,
            )
        except HistoricalEvidenceError as exc:
            snapshot.rejected_records.append({"source_path": path, "document": document})
            for name in sorted(matched):
                snapshot.issues.setdefault(name, []).append(f"{ghsa_id}: {exc}")
    snapshot.all_ghsa_ids = frozenset(all_ids)
    if not snapshot.reviewed_files_scanned:
        raise HistoricalEvidenceError("Archive contains no github-reviewed advisory JSON files")
    return snapshot


def load_snapshot_archive(
    path: str | Path,
    packages: Iterable[str],
    observed_before: str | datetime,
    commit_sha: str,
    committed_at: str | datetime,
) -> AdvisorySnapshot:
    """Stream a complete GitHub tar/tar.gz archive; never extract its paths."""
    archive_path = Path(path)
    with archive_path.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()

    def entries() -> Iterable[tuple[str, dict[str, Any]]]:
        try:
            with tarfile.open(archive_path, mode="r|*") as archive:
                for member in archive:
                    top_level = member.name.split("/", 1)[0]
                    if top_level != f"advisory-database-{commit_sha}":
                        raise HistoricalEvidenceError("Archive root does not match the pinned full commit SHA")
                    if "/advisories/github-reviewed/" not in "/" + member.name or not member.name.endswith(".json"):
                        continue
                    if not member.isfile() or member.size > 16 * 1024 * 1024:
                        raise HistoricalEvidenceError(f"Unexpected advisory archive member: {member.name}")
                    handle = archive.extractfile(member)
                    if handle is None:
                        raise HistoricalEvidenceError(f"Unreadable advisory member: {member.name}")
                    with handle:
                        try:
                            record = json.load(handle)
                        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                            raise HistoricalEvidenceError(f"Malformed advisory JSON: {member.name}") from exc
                    yield member.name, record
        except (tarfile.TarError, EOFError, OSError) as exc:
            raise HistoricalEvidenceError(f"Cannot read complete advisory archive: {exc}") from exc

    return _build_snapshot(entries(), packages, observed_before, commit_sha, committed_at, digest)


def restore_snapshot(records: list[dict[str, Any]], provenance: Mapping[str, Any]) -> AdvisorySnapshot:
    """Replay retained source records with the complete-scan provenance manifest.

    The caller must verify committed file hashes before trusting this manifest.
    It preserves the original full corpus's ID set to distinguish truly new IDs.
    """
    snapshot = _build_snapshot(
        ((item["source_path"], item["document"]) for item in records),
        provenance["selected_packages"], provenance["observed_before"],
        provenance["commit_sha"], provenance["committed_at"], provenance.get("archive_sha256"),
    ) if records else AdvisorySnapshot(
        utc(provenance["observed_before"]), provenance["commit_sha"], utc(provenance["committed_at"]),
        frozenset(provenance["selected_packages"]), {}, frozenset(), 0, provenance.get("archive_sha256"),
    )
    # A complete original scan is required even when no selected package has a GHSA.
    count = provenance.get("reviewed_files_scanned")
    ids = provenance.get("all_ghsa_ids")
    if type(count) is not int or count < 1 or not isinstance(ids, list) or not ids:
        raise HistoricalEvidenceError("Replay is missing complete-scan evidence")
    if any(not isinstance(value, str) or not GHSA_RE.fullmatch(value) for value in ids):
        raise HistoricalEvidenceError("Replay manifest contains invalid GHSA IDs")
    if len(set(ids)) > count or not set(snapshot.advisories).issubset(ids):
        raise HistoricalEvidenceError("Replay ID inventory conflicts with scanned records")
    if not SHA_RE.fullmatch(snapshot.commit_sha) or snapshot.committed_at >= snapshot.observed_before:
        raise HistoricalEvidenceError("Invalid replay snapshot boundary or commit")
    snapshot.reviewed_files_scanned = count
    snapshot.all_ghsa_ids = frozenset(ids)
    for package, messages in provenance.get("issues", {}).items():
        existing = snapshot.issues.setdefault(package, [])
        existing.extend(message for message in messages if message not in existing)
    snapshot.warnings = sorted(set(snapshot.warnings) | set(provenance.get("warnings", [])))
    hashes = provenance.get("source_document_hashes", {})
    if any(not re.fullmatch(r"[a-f0-9]{64}", digest) for digest in hashes.values()):
        raise HistoricalEvidenceError("Invalid original document digest")
    snapshot.source_document_hashes.update(hashes)
    return snapshot


def _check_boundaries(history: AdvisorySnapshot, outcome: AdvisorySnapshot, cutoff: str | datetime) -> tuple[datetime, datetime]:
    start = utc(cutoff)
    end = start + timedelta(days=90)
    month_window(0, start)
    if history.observed_before != start or outcome.observed_before != end:
        raise HistoricalEvidenceError("Snapshots do not match the prediction cutoff and exact 90-day outcome end")
    if history.committed_at >= start or outcome.committed_at >= end:
        raise HistoricalEvidenceError("Snapshot commits contain future information")
    return start, end


def package_evidence(package: str, history: AdvisorySnapshot, outcome: AdvisorySnapshot, cutoff: str | datetime) -> dict[str, Any]:
    """Return exact GHSA membership so every count can be traced to source IDs."""
    start, end = _check_boundaries(history, outcome, cutoff)
    history.require_package(package)
    outcome.require_package(package)
    historical = [item for item in history.advisories.values() if package in item.packages and item.published < start and item.active_before(start)]
    targets = [item for item in outcome.advisories.values() if package in item.packages and start <= item.published < end and item.active_before(end) and item.ghsa_id not in history.all_ghsa_ids]
    monthly: dict[str, dict[str, list[str]]] = {}
    for index in range(12):
        lower, upper = month_window(index, start)
        monthly[f"M{index}"] = {
            severity: sorted(item.ghsa_id for item in historical if item.severity == severity and lower <= item.published < upper)
            for severity in SEVERITIES
        }
    return {
        "package": package,
        "prediction_cutoff": iso(start),
        "outcome_end_exclusive": iso(end),
        "history_commit": history.commit_sha,
        "outcome_commit": outcome.commit_sha,
        "history": {severity: sorted(item.ghsa_id for item in historical if item.severity == severity) for severity in SEVERITIES},
        "monthly": monthly,
        "targets": {severity: sorted(item.ghsa_id for item in targets if item.severity == severity) for severity in SEVERITIES},
    }


def derive_features(package: str, history: AdvisorySnapshot, outcome: AdvisorySnapshot, cutoff: str | datetime) -> dict[str, int]:
    """Build the 5 lifetime + 60 monthly + 5 outcome fields in schema order."""
    evidence = package_evidence(package, history, outcome, cutoff)
    result = {f"ghsa_{severity}_count": len(evidence["history"][severity]) for severity in SEVERITIES}
    for severity in SEVERITIES:
        for index in range(12):
            result[f"ghsa_{severity}_count_M{index}"] = len(evidence["monthly"][f"M{index}"][severity])
    result.update({f"target_ghsa_{severity}_count_90d": len(evidence["targets"][severity]) for severity in SEVERITIES})
    return result
