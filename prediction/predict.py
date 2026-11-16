"""Predict the 90-day advisory counts for one npm package."""
import argparse
import csv
import json
import math
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

HERE = Path(__file__).resolve().parent
SEVERITIES = ('low', 'moderate', 'high', 'critical', 'unknown')
TARGETS = tuple(f'target_ghsa_{s}_count_90d' for s in SEVERITIES)
FEATURES = ('log_age_days', 'log_version_major', 'log_dependency_count',
            'log_dev_dependency_count', 'log_file_count', 'log_unpacked_size',
            'log_stable_releases', 'log_downloads_per_day', 'download_coverage',
            'log_prior_low', 'log_prior_moderate', 'log_prior_high',
            'log_prior_critical', 'log_prior_unknown', 'log_recent_ghsa')


def package_version(purl):
    if not purl.startswith('pkg:npm/'):
        raise ValueError(f'Not an npm PURL: {purl}')
    name, version = purl[8:].rsplit('@', 1)
    match = re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\+[0-9A-Za-z.-]+)?', version)
    if not name or not match:
        raise ValueError(f'Expected a stable semantic version: {purl}')
    return unquote(name), tuple(map(int, match.groups()))


def timestamp(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00'))


def number(row, key, required=False):
    if key not in row:
        raise ValueError(f'Missing column: {key}')
    value = row[key]
    if value is None or value.strip().lower() in ('', 'null'):
        if required:
            raise ValueError(f'Missing required value: {key}')
        return None
    value = float(value)
    if not math.isfinite(value) or value < 0 or not value.is_integer():
        raise ValueError(f'Invalid count for {key}: {value}')
    return value


def month_sum(row, prefix, months=12, required=False):
    values = [number(row, f'{prefix}_M{i}', required) for i in range(months)]
    observed = [x for x in values if x is not None]
    return sum(observed) if observed else None


def read_packages(path):
    """Keep the highest stable SemVer, not the most recent timestamp."""
    packages = {}
    seen = set()
    with open(path, newline='', encoding='utf-8-sig') as f:
        for row in csv.DictReader(f):
            if None in row or any(v is None for v in row.values()):
                raise ValueError('Malformed CSV row')
            purl = row['purl']
            if purl in seen:
                raise ValueError(f'Duplicate PURL: {purl}')
            seen.add(purl)
            name, version = package_version(purl)
            old = packages.get(name)
            if old is None or version > old[0]:
                packages[name] = (version, row)
            elif version == old[0]:
                raise ValueError(f'Ambiguous highest semantic version: {name}')
    if not packages:
        raise ValueError('Input CSV has no package records')
    return packages


def features(row, version):
    def log(value):
        return None if value is None else math.log1p(value)

    age = (timestamp(row['published_at']) - timestamp(row['package_created_at'])).total_seconds() / 86400
    if age < 0:
        raise ValueError('Package creation is after version publication')
    downloads = month_sum(row, 'package_downloads')
    days = month_sum(row, 'package_download_days_observed')
    recent = sum(month_sum(row, f'ghsa_{s}_count', 3, True) for s in SEVERITIES)
    return [log(age), log(version[0]),
            log(number(row, 'dependency_count', True)),
            log(number(row, 'dev_dependency_count', True)),
            log(number(row, 'file_count')), log(number(row, 'unpacked_size')),
            log(month_sum(row, 'package_stable_release_count')),
            log(downloads / days) if downloads is not None and days else None,
            days / 365 if days is not None else None,
            *[log(number(row, f'ghsa_{s}_count', True)) for s in SEVERITIES],
            log(recent)]


def expected_counts(x, model):
    if model['feature_names'] != list(FEATURES) or model['severities'] != list(SEVERITIES):
        raise ValueError('Model does not match the feature or output schema')
    z = [1.0] + [((m if v is None else v) - u) / s
                 for v, m, u, s in zip(x, model['medians'], model['means'], model['scales'])]
    return [0.0 if w is None else math.exp(sum(a * b for a, b in zip(w, z)))
            for w in model['weights']]


def predict(input_path, output_path, model_path=HERE / 'model.json',
            method='poisson', include_unknown=True, fractional=False):
    packages = read_packages(input_path)
    if len(packages) != 1:
        raise ValueError('Prediction input must contain exactly one package')
    version, row = next(iter(packages.values()))
    x = features(row, version)  # Target columns are never read.
    if method == 'zero':
        counts = [0.0] * len(SEVERITIES)
    else:
        model = json.loads(Path(model_path).read_text(encoding='utf-8'))
        counts = expected_counts(x, model)
    if not fractional:
        counts = [math.floor(v + 0.5) for v in counts]
    n = 5 if include_unknown else 4
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(TARGETS[:n])
        writer.writerow(counts[:n])
    return counts[:n]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--model', type=Path, default=HERE / 'model.json')
    parser.add_argument('--method', choices=['poisson', 'zero'], default='poisson')
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument('--include-unknown', dest='include_unknown', action='store_true',
                              help='Write all five official Prediction Goal columns (default)')
    output_group.add_argument('--four-severities', dest='include_unknown', action='store_false',
                              help='Compatibility mode for a four-field competition form')
    parser.set_defaults(include_unknown=True)
    parser.add_argument('--fractional', action='store_true')
    args = parser.parse_args()
    predict(args.input, args.output, args.model, args.method,
            args.include_unknown, args.fractional)


if __name__ == '__main__':
    main()
