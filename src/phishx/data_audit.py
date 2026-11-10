
import pandas as pd

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)

print("=" * 55)
print("PHISH-X | DUPLICATE & LABEL AUDIT")
print("=" * 55)

# 1. Separate rows with known labels
valid_df = df.dropna(subset=["ClassLabel"]).copy()

# 2. Group repeated URLs
url_groups = (
    valid_df.groupby("URL")
    .agg(
        occurrences=("ClassLabel", "size"),
        unique_labels=("ClassLabel", "nunique"),
        labels=("ClassLabel", lambda x: sorted(x.unique().tolist()))
    )
)

duplicate_groups = url_groups[url_groups["occurrences"] > 1]

print("\n[1] Duplicate URL Groups")
print("Number of repeated URL groups:", len(duplicate_groups))

# 3. URLs with conflicting labels
conflicts = duplicate_groups[
    duplicate_groups["unique_labels"] > 1
]

print("\n[2] Conflicting Labels")
print("Number of URLs with conflicting labels:", len(conflicts))

if not conflicts.empty:
    print(conflicts.head(10).to_string())

# 4. Repeated URLs with the same label
same_label_duplicates = duplicate_groups[
    duplicate_groups["unique_labels"] == 1
]

print("\n[3] Same-Label Duplicate Groups")
print("Number of groups:", len(same_label_duplicates))
print(same_label_duplicates.head(10).to_string())

# 5. Rows with missing labels
missing_labels = df[df["ClassLabel"].isna()]

print("\n[4] Rows with Missing Labels")
print("Number of rows:", len(missing_labels))

if not missing_labels.empty:
    print(missing_labels.to_string(index=False))

# 6. Check unexpected labels
print("\n[5] Unexpected Labels")

unexpected = valid_df[
    ~valid_df["ClassLabel"].isin([0, 1])
]

print("Unexpected label rows:", len(unexpected))

print("\nAudit completed.")
