
import pandas as pd

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)

# Features only (exclude URL and target)
feature_columns = [
    col for col in df.columns
    if col not in ["URL", "ClassLabel"]
]

print("=" * 60)
print("PHISH-X | FEATURE AUDIT")
print("=" * 60)

# 1. Statistical summary
print("\n[1] Feature Statistics")

summary = df[feature_columns].describe().T

print(
    summary[
        ["min", "max", "mean", "std"]
    ].round(3).to_string()
)

# 2. Binary feature validation
binary_features = [
    "has_ip_address",
    "https_flag",
    "has_hyphen_in_domain",
    "suspicious_file_extension"
]

print("\n[2] Binary Feature Values")

for feature in binary_features:
    print(f"{feature}: {sorted(df[feature].dropna().unique())}")

# 3. Negative values
print("\n[3] Negative Values")

for feature in feature_columns:
    count = (df[feature] < 0).sum()

    if count > 0:
        print(f"{feature}: {count} negative values")

# 4. Percentage feature validation
print("\n[4] Percentage Validation")

percentage = df["percentage_numeric_chars"]

print("Minimum:", percentage.min())
print("Maximum:", percentage.max())
print("Values outside 0-100:", 
      ((percentage < 0) | (percentage > 100)).sum())

# 5. Constant features
print("\n[5] Constant Features")

constant_features = [
    col for col in feature_columns
    if df[col].nunique() <= 1
]

print(constant_features)

print("\nFeature audit completed.")



# 6. Investigate suspicious values

print("\n[6] Investigating Negative Subdomain Count")

negative_rows = df[df["subdomain_count"] < 0]

print("Negative rows:", len(negative_rows))

print(
    negative_rows[
        ["URL", "subdomain_count", "domain_name_length",
         "dot_count", "token_count"]
    ].head(15).to_string(index=False)
)

# 7. Investigate zero values

zero_features = [
    "tld_length",
    "path_length",
    "domain_name_length"
]

print("\n[7] Zero Value Analysis")

for feature in zero_features:
    zero_rows = df[df[feature] == 0]

    print(f"\n{feature}: {len(zero_rows)} zero values")

    print(
        zero_rows[
            ["URL", feature]
        ].head(5).to_string(index=False)
    )

# 8. Query parameter analysis

print("\n[8] Query Parameter Distribution")

print(df["query_param_count"].value_counts().sort_index())

print("\nInvestigation completed.")



# 9. Investigate Offline records

print("\n[9] Offline Records")

offline = df[df["URL"].str.lower() == "offline"]

print("Offline records:", len(offline))
print(offline[["URL", "ClassLabel"]].to_string(index=False))


# 10. Feature analysis by class

print("\n[10] Feature Analysis by Class")

features_to_check = [
    "subdomain_count",
    "tld_length",
    "domain_name_length",
    "query_param_count"
]

print(
    df.groupby("ClassLabel")[features_to_check]
    .agg(["min", "max", "mean"])
    .round(2)
    .to_string()
)


# 11. Query parameter consistency

print("\n[11] Query Parameter Consistency")

has_query = df["URL"].str.contains("?", regex=False)

print("URLs containing ?:")
print(has_query.sum())

print("\nQuery count distribution for URLs without ?:")

print(
    df.loc[~has_query, "query_param_count"]
    .value_counts()
    .sort_index()
)

print("\nQuery count distribution for URLs with ?:")

print(
    df.loc[has_query, "query_param_count"]
    .value_counts()
    .sort_index()
)

print("\nQuality investigation completed.")
