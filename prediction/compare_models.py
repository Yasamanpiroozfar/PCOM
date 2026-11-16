"""Compare count predictors on package-level train/validation data."""
import argparse
import json
import math
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression, PoissonRegressor
from sklearn.preprocessing import StandardScaler
from xgboost import XGBRegressor

from predict import HERE, SEVERITIES, TARGETS, read_packages, number, month_sum, timestamp, features

COMPACT_FEATURES = ('prior_ghsa', 'prior_high_critical', 'recent_ghsa_M0_M2',
                    'stable_releases', 'dependencies', 'log_daily_downloads', 'log_age_days')


def stable_hash(name):
    h = 2166136261
    for char in name:
        h = ((h ^ ord(char)) * 16777619) & 0xffffffff
    return h


def compact_features(row):
    age = (timestamp(row['published_at']) - timestamp(row['package_created_at'])).total_seconds() / 86400
    downloads = month_sum(row, 'package_downloads')
    days = month_sum(row, 'package_download_days_observed')
    def hundredth(value):
        return math.floor(100 * math.log1p(value) + .5) / 100
    return [sum(number(row, f'ghsa_{s}_count', True) for s in SEVERITIES),
            sum(number(row, f'ghsa_{s}_count', True) for s in ('high', 'critical')),
            sum(month_sum(row, f'ghsa_{s}_count', 3, True) for s in SEVERITIES),
            month_sum(row, 'package_stable_release_count'), number(row, 'dependency_count', True),
            hundredth(downloads / days) if days and downloads is not None else None,
            hundredth(age)]


def arrays(path, feature_mode="compact"):
    packages = [(name, (compact_features(row) if feature_mode == "compact" else features(row, version)),
                 [number(row, t, True) for t in TARGETS])
                for name, (version, row) in read_packages(path).items()]
    split = [[], [], []]
    for positive in (False, True):
        group = sorted((p for p in packages if any(p[2][:4]) == positive),
                       key=lambda p: (stable_hash(p[0]), p[0]))
        a, b = int(.7 * len(group) + .5), int(.85 * len(group) + .5)
        for dst, part in zip(split, (group[:a], group[a:b], group[b:])):
            dst.extend(part)
    return [(np.asarray([p[1] for p in part], dtype=float),
             np.asarray([p[2] for p in part], dtype=float)) for part in split]


def score(y, p):
    p = np.maximum(p, 0)
    def metrics(e):
        return {'mae': float(np.abs(e).mean()), 'rmse': float(np.sqrt((e ** 2).mean()))}
    return {'four_raw': metrics(p[:, :4] - y[:, :4]),
            'four_integer': metrics(np.floor(p[:, :4] + .5) - y[:, :4]),
            'five_integer': metrics(np.floor(p + .5) - y)}


def compare(parts, feature_mode="compact"):
    # Test data stays out of this comparison; the earlier holdout was already inspected.
    (x, y), (v, vy), _ = parts
    med = np.nanmedian(x, axis=0)
    med = np.where(np.isfinite(med), med, 0)
    def transform(a):
        a = np.where(np.isfinite(a), a, med).copy()
        if feature_mode == "compact":
            a[:, :5] = np.log1p(a[:, :5])
        return a
    x, v = transform(x), transform(v)
    scaler = StandardScaler().fit(x)
    z, vz = scaler.transform(x), scaler.transform(v)
    results = []
    def add(name, params, p):
        results.append({'model': name, 'params': params, **score(vy, p)})
    add('zero', {}, np.zeros_like(vy))
    add('training_mean', {}, np.broadcast_to(y.mean(0), vy.shape))
    for alpha in (.01, .1, 1., 10.):
        p = []
        for k in range(5):
            m = PoissonRegressor(alpha=alpha, max_iter=5000, tol=1e-10)
            p.append(m.fit(z, y[:, k]).predict(vz) if y[:, k].any() else np.zeros(len(v)))
        add('poisson_7_features' if feature_mode == 'compact' else 'poisson_15_features', {'alpha': alpha}, np.column_stack(p))
    for depth, trees, child, reg in [(1, 50, 1, 1), (2, 50, 1, 1), (2, 100, 1, 1),
                                     (2, 100, 5, 10), (3, 100, 5, 10)]:
        p = []
        for k in range(5):
            if not y[:, k].any():
                p.append(np.zeros(len(v)))
                continue
            m = XGBRegressor(objective='count:poisson', n_estimators=trees, max_depth=depth,
                             learning_rate=.05, min_child_weight=child, reg_lambda=reg,
                             base_score=float(y[:, k].mean()), n_jobs=1, random_state=17,
                             tree_method='hist', verbosity=0)
            p.append(m.fit(x, y[:, k]).predict(v))
        add('xgboost_poisson', {'depth': depth, 'trees': trees, 'min_child_weight': child,
                                'reg_lambda': reg}, np.column_stack(p))
    for c in (.1, 1., 10.):
        # Separate occurrence probability from the conditional severity counts.
        positive = y[:, :4].sum(1) > 0
        prob = LogisticRegression(C=c, max_iter=2000).fit(z, positive).predict_proba(vz)[:, 1]
        conditional_mean = y[positive].mean(0)
        add('hurdle_any', {'C': c}, prob[:, None] * conditional_mean[None, :])
        predictions = []
        for k in range(5):
            positive = y[:, k] > 0
            if not positive.any():
                predictions.append(np.zeros(len(v)))
                continue
            prob = LogisticRegression(C=c, max_iter=2000).fit(z, positive).predict_proba(vz)[:, 1]
            predictions.append(prob * y[positive, k].mean())
        add('hurdle_per_severity', {'C': c}, np.column_stack(predictions))
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('data', type=Path)
    parser.add_argument('--report', type=Path, default=HERE / 'model_comparison.json')
    parser.add_argument('--features', choices=['compact', 'full'], default='compact')
    args = parser.parse_args()
    results = compare(arrays(args.data, args.features), args.features)
    args.report.write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
