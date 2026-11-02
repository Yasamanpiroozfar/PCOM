"""Offline HTTP/storage tests. All mocked responses are explicitly synthetic."""

from contextlib import contextmanager
from email.message import Message
import gzip
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from pcom01.io import AcquisitionError, PublicClient, json_bytes, read_json, save_json, sha256


URL = "https://api.github.com/repos/example/project/commits"


class Response(io.BytesIO):
    def __init__(self, body=b"{}", *, headers=None, status=200):
        super().__init__(body)
        self.headers = headers or {}
        self.status = status


def http_error(status, headers=None, reason="synthetic error"):
    message = Message()
    for key, value in (headers or {}).items():
        message[key] = value
    return HTTPError(URL, status, reason, message, None)


class HttpTests(unittest.TestCase):
    def test_zero_retry_after_still_uses_backoff(self):
        self.assertGreaterEqual(PublicClient.retry_delay({"Retry-After": "0"}, 3), 8)
    def setUp(self):
        self.sleeper = Mock()
        self.client = PublicClient(sleeper=self.sleeper, attempts=3)

    @patch("pcom01.io.urlopen")
    def test_429_retry_after_then_success(self, open_url):
        open_url.side_effect = [http_error(429, {"Retry-After": "3"}), Response(b'{"ok":true}')]
        value, evidence = self.client.json(URL)
        self.assertEqual(value, {"ok": True})
        self.sleeper.assert_called_once_with(3)
        self.assertEqual(evidence["attempt"], 2)
        self.assertEqual([item["status"] for item in self.client.events], [429, 200])

    @patch("pcom01.io.time.time", return_value=100)
    @patch("pcom01.io.urlopen")
    def test_rate_limit_reset_then_success(self, open_url, _clock):
        open_url.side_effect = [http_error(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "105"}), Response()]
        self.client.get(URL)
        self.sleeper.assert_called_once_with(6)

    @patch("pcom01.io.urlopen")
    def test_hard_404_is_not_retried(self, open_url):
        open_url.side_effect = http_error(404)
        with self.assertRaises(AcquisitionError):
            self.client.get(URL)
        self.assertEqual(open_url.call_count, 1)
        self.sleeper.assert_not_called()

    @patch("pcom01.io.urlopen")
    def test_unprivileged_403_is_not_retried(self, open_url):
        open_url.side_effect = http_error(403)
        with self.assertRaises(AcquisitionError):
            self.client.get(URL)
        self.assertEqual(open_url.call_count, 1)

    @patch("pcom01.io.urlopen")
    def test_long_rate_wait_fails_explicitly(self, open_url):
        open_url.side_effect = http_error(429, {"Retry-After": "120"})
        with self.assertRaisesRegex(AcquisitionError, "suggested_retry_seconds=120"):
            self.client.get(URL)
        self.sleeper.assert_not_called()

    @patch("pcom01.io.urlopen")
    def test_retries_are_bounded(self, open_url):
        open_url.side_effect = URLError("synthetic network interruption")
        with self.assertRaises(AcquisitionError):
            self.client.get(URL)
        self.assertEqual(open_url.call_count, 3)
        self.assertEqual([call.args[0] for call in self.sleeper.call_args_list], [2, 4])

    @patch("pcom01.io.urlopen")
    def test_invalid_json_is_an_explicit_error(self, open_url):
        open_url.return_value = Response(b"{not json}")
        with self.assertRaisesRegex(AcquisitionError, "Invalid JSON"):
            self.client.json(URL)

    @patch("pcom01.io.urlopen")
    def test_nonstandard_nonfinite_json_is_rejected(self, open_url):
        for body in [b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}']:
            with self.subTest(body=body):
                open_url.return_value = Response(body)
                with self.assertRaisesRegex(AcquisitionError, "Invalid JSON"):
                    self.client.json(URL)

    @patch.dict("os.environ", {"GITHUB_TOKEN": "synthetic-test-token"}, clear=False)
    @patch("pcom01.io.urlopen")
    def test_token_only_sent_to_github_and_not_provenance(self, open_url):
        open_url.side_effect = [Response(headers={"Authorization": "hidden", "Set-Cookie": "hidden", "ETag": "known"}), Response()]
        self.client.get(URL)
        self.client.get("https://registry.npmjs.org/sample")
        github_request = open_url.call_args_list[0].args[0]
        npm_request = open_url.call_args_list[1].args[0]
        self.assertEqual(github_request.get_header("Authorization"), "Bearer synthetic-test-token")
        self.assertIsNone(npm_request.get_header("Authorization"))
        serialized = json.dumps(self.client.events)
        self.assertNotIn("synthetic-test-token", serialized)
        self.assertNotIn("hidden", serialized)
        self.assertEqual(self.client.events[0]["headers"]["etag"], "known")

    @patch.dict("os.environ", {"GITHUB_TOKEN": "synthetic-test-token"}, clear=False)
    @patch("pcom01.io.urlopen")
    def test_token_echoed_in_error_is_not_logged(self, open_url):
        open_url.side_effect = http_error(401, reason="rejected Bearer synthetic-test-token")
        with self.assertRaises(AcquisitionError) as result:
            self.client.get(URL)
        self.assertNotIn("synthetic-test-token", json.dumps(self.client.events))
        self.assertNotIn("synthetic-test-token", str(result.exception))

    @patch("pcom01.io.urlopen")
    def test_non_https_and_embedded_credentials_rejected(self, open_url):
        for url in ["http://api.github.com/x", "https://user:secret@api.github.com/x"]:
            with self.subTest(url=url), self.assertRaises(AcquisitionError):
                self.client.get(url)
        open_url.assert_not_called()

    @patch("pcom01.io.urlopen")
    def test_body_hash_and_download_file(self, open_url):
        body = b"synthetic\x00archive\xff"
        open_url.return_value = Response(body)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "nested" / "archive.bin"
            returned, evidence = self.client.get(URL, destination=target)
            self.assertIsNone(returned)
            self.assertEqual(target.read_bytes(), body)
            self.assertEqual(evidence["bytes"], len(body))
            self.assertEqual(evidence["body_sha256"], hashlib.sha256(body).hexdigest())
            self.assertFalse(target.with_suffix(".bin.part").exists())

    @patch("pcom01.io.time.time", return_value=0)
    def test_http_date_retry_after(self, _clock):
        self.assertEqual(PublicClient.retry_delay({"Retry-After": "Thu, 01 Jan 1970 00:00:05 GMT"}, 1), 5)
        self.assertEqual(PublicClient.retry_delay({"Retry-After": "invalid"}, 2), 4)


class PaginationTests(unittest.TestCase):
    @patch("pcom01.io.urlopen")
    def test_sequential_pages(self, open_url):
        next_url = URL + "?page=2"
        open_url.side_effect = [Response(b"[1,2]", headers={"Link": f'<{next_url}>; rel="next"'}), Response(b"[3]")]
        pages = list(PublicClient().pages(URL))
        self.assertEqual([data for data, _ in pages], [[1, 2], [3]])
        self.assertEqual([call.args[0].full_url for call in open_url.call_args_list], [URL, next_url])

    @patch("pcom01.io.urlopen")
    def test_cycle_rejected(self, open_url):
        open_url.return_value = Response(b"[]", headers={"Link": f'<{URL}>; rel="next"'})
        with self.assertRaisesRegex(AcquisitionError, "Repeated pagination"):
            list(PublicClient().pages(URL))

    @patch("pcom01.io.urlopen")
    def test_cross_host_rejected(self, open_url):
        open_url.return_value = Response(b"[]", headers={"Link": '<https://example.invalid/a>; rel="next"'})
        with self.assertRaisesRegex(AcquisitionError, "Cross-host|Cross-origin"):
            list(PublicClient().pages(URL))
        self.assertEqual(open_url.call_count, 1)

    @patch("pcom01.io.urlopen")
    def test_same_hostname_different_port_rejected(self, open_url):
        open_url.return_value = Response(b"[]", headers={"Link": '<https://api.github.com:444/a>; rel="next"'})
        with self.assertRaisesRegex(AcquisitionError, "Cross-host|Cross-origin"):
            list(PublicClient().pages(URL))
        self.assertEqual(open_url.call_count, 1)

    @patch("pcom01.io.urlopen")
    def test_limit_is_not_silent_truncation(self, open_url):
        open_url.return_value = Response(b"[]", headers={"Link": f'<{URL}?page=2>; rel="next"'})
        with self.assertRaisesRegex(AcquisitionError, "Pagination limit"):
            list(PublicClient().pages(URL, max_pages=1))

    @patch("pcom01.io.urlopen")
    def test_nonarray_response_rejected(self, open_url):
        open_url.return_value = Response(b"{}")
        with self.assertRaisesRegex(AcquisitionError, "array"):
            list(PublicClient().pages(URL))


class StorageTests(unittest.TestCase):
    def test_deterministic_gzip_and_roundtrip(self):
        value = {"sample": [0, None, 12], "note": "Unicode \u00e9"}
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "one.json.gz", Path(directory) / "two.json.gz"
            save_json(first, value)
            save_json(second, value)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(gzip.decompress(first.read_bytes()), json_bytes(value))
            self.assertEqual(read_json(first), value)
            self.assertEqual(sha256(first), hashlib.sha256(first.read_bytes()).hexdigest())

    def test_plain_json_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data.json"
            save_json(path, {"value": 0})
            self.assertEqual(read_json(path), {"value": 0})

    def test_serialization_rejects_nonfinite_numbers(self):
        with self.assertRaises(ValueError):
            json_bytes({"value": float("nan")})


if __name__ == "__main__":
    unittest.main()
