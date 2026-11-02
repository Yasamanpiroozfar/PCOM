"""Deterministic storage and bounded, auditable public HTTP acquisition."""
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, HTTPRedirectHandler, build_opener


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old, new = urlparse(req.full_url), urlparse(newurl)
        if new.scheme != "https" or new.username or new.password:
            raise AcquisitionError("Unsafe HTTP redirect rejected")
        if req.has_header("Authorization") and new.netloc != old.netloc:
            raise AcquisitionError("Cross-host authenticated redirect rejected")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


urlopen = build_opener(SafeRedirect()).open


def reject_constant(value):
    raise ValueError(f"Non-JSON numeric constant: {value}")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def save_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json_bytes(value)
    temporary = path.with_suffix(path.suffix + ".part")
    temporary.write_bytes(gzip.compress(raw, mtime=0) if path.suffix == ".gz" else raw)
    temporary.replace(path)


def read_json(path: Path):
    raw = path.read_bytes()
    return json.loads(gzip.decompress(raw) if path.suffix == ".gz" else raw, parse_constant=reject_constant)


def sha256(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class AcquisitionError(RuntimeError):
    pass


class PublicClient:
    """GET only; bounded retries; credentials never appear in provenance.

    Complete npm documents and complete Git archives need no pagination.
    ``pages`` implements GitHub Link-header pagination for list endpoints.
    GitHub commit resolution deliberately requests the one most recent commit.
    """
    def __init__(self, *, attempts=5, timeout=90, sleeper=time.sleep):
        self.attempts, self.timeout, self.sleep = attempts, timeout, sleeper
        self.events = []

    @staticmethod
    def retry_delay(headers, attempt):
        value = headers.get("Retry-After")
        if value:
            try:
                return max(float(value), min(2 ** attempt, 32))
            except ValueError:
                try:
                    return max(0.0, parsedate_to_datetime(value).timestamp() - time.time())
                except (ValueError, TypeError):
                    pass
        if headers.get("X-RateLimit-Remaining") == "0":
            try:
                return max(1.0, float(headers.get("X-RateLimit-Reset", "0")) - time.time() + 1)
            except ValueError:
                pass
        return min(2 ** attempt, 32)

    def get(self, url, *, destination: Path | None = None):
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.username or parsed.password:
            raise AcquisitionError("Only credential-free HTTPS source URLs are allowed")
        headers = {"User-Agent": "PCOM01-Homework3-reproducible-research/1.0", "Accept": "application/json"}
        if parsed.hostname == "api.github.com":
            headers.update({"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
            token = os.getenv("GITHUB_TOKEN")
            if token:
                headers["Authorization"] = "Bearer " + token
        for attempt in range(1, self.attempts + 1):
            stamp = now()
            try:
                with urlopen(Request(url, headers=headers), timeout=self.timeout) as response:
                    metadata = {key.lower(): value for key, value in response.headers.items()
                                if key.lower() in {"etag", "last-modified", "content-type", "date", "link", "x-ratelimit-remaining", "x-ratelimit-reset"}}
                    digest, size = hashlib.sha256(), 0
                    if destination:
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        temporary = destination.with_suffix(destination.suffix + ".part")
                        with temporary.open("wb") as stream:
                            for block in iter(lambda: response.read(1024 * 1024), b""):
                                stream.write(block)
                                digest.update(block)
                                size += len(block)
                        temporary.replace(destination)
                        body = None
                    else:
                        body = response.read()
                        digest.update(body)
                        size = len(body)
                    evidence = {"url": url, "fetched_at": stamp, "status": response.status,
                                "body_sha256": digest.hexdigest(), "bytes": size,
                                "headers": metadata, "attempt": attempt}
                    self.events.append(evidence)
                    return body, evidence
            except (HTTPError, URLError, TimeoutError, OSError) as exc:
                status = exc.code if isinstance(exc, HTTPError) else None
                source_headers = exc.headers if isinstance(exc, HTTPError) else {}
                self.events.append({"url": url, "fetched_at": stamp, "status": status,
                                    "attempt": attempt, "error_type": type(exc).__name__})
                transient = status is None or status in {408, 429, 500, 502, 503, 504} or (
                    status == 403 and (source_headers.get("X-RateLimit-Remaining") == "0" or source_headers.get("Retry-After")))
                delay = self.retry_delay(source_headers, attempt)
                if not transient or attempt == self.attempts or delay > 60:
                    raise AcquisitionError(f"GET failed for {url}: {type(exc).__name__}; status={status}; suggested_retry_seconds={delay}") from None
                self.sleep(delay)
        raise AssertionError("unreachable")

    def json(self, url):
        raw, evidence = self.get(url)
        try:
            return json.loads(raw, parse_constant=reject_constant), evidence
        except (ValueError, UnicodeError) as exc:
            raise AcquisitionError(f"Invalid JSON response from {url}") from exc

    def pages(self, url, *, max_pages=1000):
        seen = set()
        for _ in range(max_pages):
            if url in seen:
                raise AcquisitionError("Repeated pagination URL")
            seen.add(url)
            data, evidence = self.json(url)
            if not isinstance(data, list):
                raise AcquisitionError("Paginated endpoint did not return an array")
            yield data, evidence
            match = re.search(r'<([^>]+)>;\s*rel="next"', evidence["headers"].get("link", ""))
            if not match:
                return
            candidate = match.group(1)
            if urlparse(candidate).netloc != urlparse(url).netloc or urlparse(candidate).scheme != "https":
                raise AcquisitionError("Cross-host pagination rejected")
            url = candidate
        raise AcquisitionError("Pagination limit reached before completion")
