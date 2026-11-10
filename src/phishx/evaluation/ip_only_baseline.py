
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)


# ============================================================
# PHISH-X | IP-ONLY BASELINE AUDIT
# ============================================================

ROOT = Path(__file__).resolve().parents[3]

DATA_PATH = ROOT / "data" / "processed" / "cleaned_dataset.csv"


def main():

    print("=" * 65)
    print("PHISH-X | IP-ONLY BASELINE AUDIT")
    print("=" * 65)

    # 1. Load cleaned dataset
    df = pd.read_csv(DATA_PATH)

    print(f"\n[1] Dataset records: {len(df):,}")

    # 2. Validate required features
    required = ["has_ip_address", "ClassLabel"]

    missing = [col for col in required if col not in df.columns]

    if missing:
        raise ValueError(f"Missing columns: {missing}")

    df = df[required].copy()

    df["has_ip_address"] = pd.to_numeric(
        df["has_ip_address"], errors="coerce"
    )

    df["ClassLabel"] = pd.to_numeric(
        df["ClassLabel"], errors="coerce"
    )

    if df.isna().any().any():
        raise ValueError("Missing or invalid values detected.")

    if not set(df["has_ip_address"].unique()).issubset({0, 1}):
        raise ValueError("has_ip_address must contain only 0 and 1.")

    if not set(df["ClassLabel"].unique()).issubset({0, 1}):
        raise ValueError("ClassLabel must contain only 0 and 1.")

    y_true = df["ClassLabel"].astype(int)

    # 3. Apply the IP-only prediction rule
    # 0 = Phishing
    # 1 = Legitimate

    y_pred = df["has_ip_address"].map({
        1: 0,
        0: 1
    }).astype(int)

    # 4. Calculate evaluation metrics

    accuracy = accuracy_score(y_true, y_pred)

    precision = precision_score(
        y_true, y_pred, pos_label=0, zero_division=0
    )

    recall = recall_score(
        y_true, y_pred, pos_label=0, zero_division=0
    )

    f1 = f1_score(
        y_true, y_pred, pos_label=0, zero_division=0
    )

    # 5. Display results

    print("\n[2] Prediction rule:")
    print("IP Address  -> Phishing")
    print("Domain      -> Legitimate")

    print("\n[3] Evaluation metrics:")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-score:  {f1:.4f}")

    print("\n[4] Confusion Matrix")
    print("Rows = Actual | Columns = Predicted")
    print("Order: Phishing, Legitimate")

    matrix = confusion_matrix(
        y_true, y_pred, labels=[0, 1]
    )

    print(matrix)

    print("\n[5] Detailed Classification Report")

    print(
        classification_report(
            y_true,
            y_pred,
            labels=[0, 1],
            target_names=["Phishing", "Legitimate"],
            zero_division=0
        )
    )

    # 6. Compare with majority-class baseline

    majority_class = y_true.mode()[0]

    majority_predictions = [
        majority_class
    ] * len(y_true)

    majority_accuracy = accuracy_score(
        y_true, majority_predictions
    )

    print("\n[6] Majority-class baseline:")
    print(f"Majority class: {majority_class}")
    print(f"Majority accuracy: {majority_accuracy:.4f}")

    print("\n" + "=" * 65)
    print("IP-ONLY BASELINE AUDIT COMPLETED")
    print("NO DATASET MODIFICATIONS WERE MADE")
    print("=" * 65)


if __name__ == "__main__":
    main()
