import csv
import json
import math
import tempfile
import unittest
from pathlib import Path

from predict import (HERE, SEVERITIES, TARGETS, expected_counts, features,
                     package_version, predict, read_packages)


class PredictionTests(unittest.TestCase):
    def test_semver(self):
        self.assertGreater(package_version('pkg:npm/a@1.10.0')[1],
                           package_version('pkg:npm/a@1.9.0')[1])
        self.assertEqual(package_version('pkg:npm/%40scope/a@1.2.3'),
                         ('@scope/a', (1, 2, 3)))
        with self.assertRaises(ValueError):
            package_version('pkg:npm/a@1.2.3-beta.1')

    def test_real_example(self):
        model = json.loads((HERE / 'model.json').read_text())
        version, row = next(iter(read_packages(HERE / 'example_input.csv').values()))
        values = expected_counts(features(row, version), model)
        reference = [0.08695830936664146, 7.3574907259981135,
                     1.6255946784463282, 0.10291043390536796, 0]
        for actual, expected in zip(values, reference):
            self.assertTrue(math.isclose(actual, expected, rel_tol=1e-9, abs_tol=1e-10))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'result.csv'
            self.assertEqual(predict(HERE / 'example_input.csv', path), [0, 7, 2, 0, 0])
            with path.open(newline='') as f:
                self.assertEqual(list(csv.reader(f)), [list(TARGETS), ['0','7','2','0','0']])
            self.assertEqual(predict(HERE / 'example_input.csv', path, include_unknown=False), [0,7,2,0])
            self.assertEqual(predict(HERE / 'example_input.csv', path, method='zero'), [0,0,0,0,0])

    def test_highest_version_not_latest_date(self):
        with (HERE / 'example_input.csv').open(newline='') as f:
            row = next(csv.DictReader(f))
        lower = dict(row, purl='pkg:npm/axios@0.99.0', published_at='2026-06-30T12:00:00.000Z')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input.csv'
            with path.open('w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=list(row))
                writer.writeheader()
                writer.writerows([lower, row])
            self.assertEqual(read_packages(path)['axios'][0], (1,18,1))


    def test_targets_not_required(self):
        with (HERE / 'example_input.csv').open(newline='') as f:
            rows = list(csv.DictReader(f))
        for row in rows:
            for target in TARGETS:
                row.pop(target, None)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input.csv'
            out = Path(tmp) / 'out.csv'
            with path.open('w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
            self.assertEqual(predict(path, out), [0, 7, 2, 0, 0])

    def test_reject_mixed_packages(self):
        with (HERE / 'example_input.csv').open(newline='') as f:
            row = next(csv.DictReader(f))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input.csv'
            with path.open('w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=list(row))
                writer.writeheader()
                writer.writerows([row, dict(row, purl='pkg:npm/other@1.0.0')])
            with self.assertRaises(ValueError):
                predict(path, Path(tmp) / 'output.csv')


if __name__ == '__main__':
    unittest.main()
