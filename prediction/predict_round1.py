"""Run the submitted Poisson model on an anonymized, single-package input."""
import argparse
import csv
import json
from pathlib import Path

import predict


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    with args.input.open(newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        if 'purl' in (reader.fieldnames or []):
            raise ValueError('Use predict.py for input with PURLs.')
        rows = list(reader)
    if not rows or any(None in r or any(v is None for v in r.values()) for r in rows):
        raise ValueError('Empty or malformed input CSV.')
    # The anonymous input does not identify semantic versions. Use the latest
    # publication as a proxy, assuming the rows belong to one package.
    row = max(rows, key=lambda r: predict.timestamp(r['published_at']))
    x = predict.features(row, (0, 0, 0))
    # Do not treat the placeholder major version as observed: use the model's
    # training median through its existing missing-feature preprocessing.
    x[predict.FEATURES.index('log_version_major')] = None
    model = json.loads((predict.HERE / 'model.json').read_text(encoding='utf-8'))
    counts = predict.expected_counts(x, model)
    with args.output.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(predict.TARGETS)
        writer.writerow(counts)
    print('Selected publication:', row['published_at'])
    print('Missing version-major feature: training-median imputation')
    print('Predictions:', counts)


if __name__ == '__main__':
    main()
