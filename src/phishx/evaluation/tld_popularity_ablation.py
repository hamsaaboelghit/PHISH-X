"""Ablation: effect of removing tld_popularity on Logistic Regression.

Uses the fixed Group Split (primary evaluation) with preprocessing fit
on train only. Compares all-16-features vs without-tld_popularity.
Positive class is Phishing (0); Legitimate is 1. Correlation is
reported separately and is NOT treated as proof of data leakage; the
ablation measures model reliance on the feature.

NOTE: this experiment uses sklearn Logistic Regression on all 16
stored features. It is different from Norhan's 5-feature baseline in
the AI Model Core and is NOT a direct evaluation of the app model.

Run: PYTHONPATH=src python -m phishx.evaluation.tld_popularity_ablation
Writes docs/tld_popularity_ablation.json. No dataset/split writes.
"""
import json
from pathlib import Path

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[3]
CLEANED = ROOT / "data" / "processed" / "cleaned_dataset.csv"
TRAIN_MANIFEST = ROOT / "data" / "processed" / "splits" / "group_train.csv"
TEST_MANIFEST = ROOT / "data" / "processed" / "splits" / "group_test.csv"
OUT = ROOT / "docs" / "tld_popularity_ablation.json"

FEATURES = [
    "url_length",
    "has_ip_address",
    "dot_count",
    "https_flag",
    "url_entropy",
    "token_count",
    "subdomain_count",
    "query_param_count",
    "tld_length",
    "path_length",
    "has_hyphen_in_domain",
    "number_of_digits",
    "tld_popularity",
    "suspicious_file_extension",
    "domain_name_length",
    "percentage_numeric_chars",
]


def load_group_split():
    cleaned = pd.read_csv(CLEANED)
    train_m = pd.read_csv(TRAIN_MANIFEST)
    test_m = pd.read_csv(TEST_MANIFEST)
    train = train_m.merge(
        cleaned, on="URL", how="left", validate="one_to_one",
        suffixes=("_manifest", ""),
    )
    test = test_m.merge(
        cleaned, on="URL", how="left", validate="one_to_one",
        suffixes=("_manifest", ""),
    )
    if train[FEATURES + ["ClassLabel"]].isna().any().any():
        raise ValueError("Missing values in group train.")
    if test[FEATURES + ["ClassLabel"]].isna().any().any():
        raise ValueError("Missing values in group test.")
    return train, test


def evaluate(train, test, features):
    scaler = StandardScaler()
    X_train = scaler.fit_transform(train[features])
    X_test = scaler.transform(test[features])
    y_train = train["ClassLabel"].astype(int)
    y_test = test["ClassLabel"].astype(int)
    model = LogisticRegression(max_iter=1000, random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    # Positive class is Phishing (0). With labels=[0, 1] the matrix is:
    #   [[TP (0,0), FN (0,1)],
    #    [FP (1,0), TN (1,1)]]
    # where TP=phishing correct, FN=phishing as legitimate,
    # FP=legitimate as phishing, TN=legitimate correct.
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tp, fn, fp, tn = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    precision = float(
        precision_score(y_test, y_pred, pos_label=0, zero_division=0)
    )
    recall = float(
        recall_score(y_test, y_pred, pos_label=0, zero_division=0)
    )
    f1 = float(f1_score(y_test, y_pred, pos_label=0, zero_division=0))
    # Consistency: sklearn metrics must match matrix-derived values.
    matrix_precision = tp / (tp + fp) if (tp + fp) else 0.0
    matrix_recall = tp / (tp + fn) if (tp + fn) else 0.0
    matrix_f1 = (
        2 * matrix_precision * matrix_recall
        / (matrix_precision + matrix_recall)
        if (matrix_precision + matrix_recall)
        else 0.0
    )
    assert abs(precision - matrix_precision) < 1e-9, "precision mismatch"
    assert abs(recall - matrix_recall) < 1e-9, "recall mismatch"
    assert abs(f1 - matrix_f1) < 1e-9, "F1 mismatch"
    return {
        "features": features,
        "n_train": int(len(train)),
        "n_test": int(len(test)),
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "phishing_precision": precision,
        "phishing_recall": recall,
        "phishing_f1": f1,
        # Legitimate FPR: legitimate predicted as phishing / all legitimate.
        "legitimate_false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "confusion_matrix": {
            "tn_legit_correct": tn,
            "fp_legit_as_phishing": fp,
            "fn_phishing_as_legit": fn,
            "tp_phishing_correct": tp,
        },
    }


def main():
    train, test = load_group_split()
    baseline = evaluate(train, test, FEATURES)
    ablated_features = [f for f in FEATURES if f != "tld_popularity"]
    ablated = evaluate(train, test, ablated_features)

    # Correlation reported separately (not a leakage proof).
    full = pd.read_csv(CLEANED)
    corr = float(full[["tld_popularity", "ClassLabel"]].corr().iloc[0, 1])
    crosstab = pd.crosstab(full["tld_popularity"], full["ClassLabel"])

    result = {
        "split": "Group Split by Host (fixed; train/test manifests)",
        "positive_class": "Phishing (0); Legitimate is 1",
        "model": (
            "sklearn LogisticRegression(max_iter=1000, random_state=42) "
            "+ StandardScaler (fit on train only) on all 16 stored "
            "features. This differs from Norhan's 5-feature baseline "
            "in the AI Model Core and is not a direct evaluation of "
            "the app model."
        ),
        "baseline_all_16": baseline,
        "ablated_without_tld_popularity": ablated,
        "delta_ablated_minus_baseline": {
            k: ablated[k] - baseline[k]
            for k in (
                "accuracy",
                "phishing_precision",
                "phishing_recall",
                "phishing_f1",
                "legitimate_false_positive_rate",
            )
        },
        "tld_popularity_correlation_with_label": corr,
        "tld_popularity_by_label_counts": {
            str(k): {str(c): int(v) for c, v in row.items()}
            for k, row in crosstab.iterrows()
        },
        "interpretation": (
            "Correlation alone does not prove data leakage. The ablation "
            "measures how much the model relies on tld_popularity under "
            "the fixed Group Split; a large drop indicates reliance "
            "(shortcut risk), not by itself a leakage verdict."
        ),
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
