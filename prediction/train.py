"""Fit and evaluate the first PCOM prediction model, one row per package."""
import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
from sklearn.linear_model import PoissonRegressor

from predict import (FEATURES, HERE, SEVERITIES, TARGETS, features, number,
                     read_packages)


def stable_hash(name):
    # FNV-1a gives a reproducible order without depending on Python's hash seed.
    h = 2166136261
    for char in name:
        h = ((h ^ ord(char)) * 16777619) & 0xffffffff
    return h


def split_packages(packages):
    splits = [[], [], []]
    for positive in (False, True):
        group = sorted((p for p in packages if any(p[2][:4]) == positive),
                       key=lambda p: (stable_hash(p[0]), p[0]))
        a, b = int(len(group) * .7 + .5), int(len(group) * .85 + .5)
        for target, part in zip(splits, (group[:a], group[a:b], group[b:])):
            target.extend(part)
    return splits


def evaluate(y, pred):
    error = pred[:, :4] - y[:, :4]
    return {'mae': float(np.mean(np.abs(error))),
            'rmse': float(np.sqrt(np.mean(error ** 2)))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('data', type=Path)
    parser.add_argument('--model', type=Path, default=HERE / 'model.json')
    parser.add_argument('--report', type=Path, default=HERE / 'evaluation.json')
    args = parser.parse_args()
    records = read_packages(args.data)
    packages = [(name, features(row, version), [number(row, t, True) for t in TARGETS])
                for name, (version, row) in records.items()]
    train, val, test = split_packages(packages)
    if not all((train, val, test)):
        raise ValueError('Not enough packages for train/validation/test')
    x = [np.array([p[1] for p in part], dtype=float) for part in (train, val, test)]
    y = [np.array([p[2] for p in part], dtype=float) for part in (train, val, test)]
    medians = np.array([np.median(col[np.isfinite(col)]) if np.isfinite(col).any() else 0
                        for col in x[0].T])
    x = [np.where(np.isnan(a), medians, a) for a in x]
    means, scales = x[0].mean(axis=0), x[0].std(axis=0)
    scales[scales == 0] = 1
    x = [(a - means) / scales for a in x]

    def fit(alpha):
        models = []
        for k in range(len(SEVERITIES)):
            if not y[0][:, k].any():
                models.append(None)
            else:
                model = PoissonRegressor(alpha=alpha, max_iter=5000, tol=1e-10)
                model.fit(x[0], y[0][:, k])
                models.append(model)
        return models

    def predict(models, a):
        return np.column_stack([np.zeros(len(a)) if m is None else m.predict(a)
                                for m in models])

    candidates = []
    for alpha in (.01, .1, 1., 10.):
        models = fit(alpha)
        pred = predict(models, x[1])
        candidates.append((alpha, models, evaluate(y[1], pred),
                           evaluate(y[1], np.floor(pred + .5))))
    alpha, models, _, _ = min(candidates, key=lambda c: c[3]['rmse'])
    test_pred = predict(models, x[2])
    model = {'feature_names': list(FEATURES), 'severities': list(SEVERITIES),
             'medians': medians.tolist(), 'means': means.tolist(), 'scales': scales.tolist(),
             'alpha': alpha, 'weights': [None if m is None else
                                        [float(m.intercept_), *m.coef_.tolist()] for m in models]}
    report = {'dataset_sha256': hashlib.sha256(args.data.read_bytes()).hexdigest(),
              'splits': [{'packages': len(p), 'positive': sum(any(a[2][:4]) for a in p),
                          'target_totals': b.sum(axis=0).astype(int).tolist()}
                         for p, b in zip((train, val, test), y)],
              'validation': [{'alpha': a, 'raw': raw, 'rounded': rounded}
                             for a, _, raw, rounded in candidates],
              'validation_zero': evaluate(y[1], np.zeros_like(y[1])),
              'selected_alpha': alpha,
              'test': {'poisson': evaluate(y[2], test_pred),
                       'rounded': evaluate(y[2], np.floor(test_pred + .5)),
                       'zero': evaluate(y[2], np.zeros_like(y[2]))}}
    args.model.write_text(json.dumps(model, indent=2) + '\n', encoding='utf-8')
    args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
