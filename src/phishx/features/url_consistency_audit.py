
import pandas as pd
from urllib.parse import urlsplit, parse_qsl

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)


def count_query_parameters(url):
    if not isinstance(url, str) or url.strip().lower() == "offline":
        return None

    try:
        value = url.strip()

        if "://" not in value and not value.startswith("//"):
            value = "//" + value

        parsed = urlsplit(value)

        return len(
            parse_qsl(
                parsed.query,
                keep_blank_values=True
            )
        )

    except ValueError:
        return None


df["calculated_query_count"] = df["URL"].apply(
    count_query_parameters
)

valid = df.dropna(subset=["calculated_query_count"]).copy()

valid["query_mismatch"] = (
    valid["query_param_count"]
    != valid["calculated_query_count"]
)

print("=" * 60)
print("PHISH-X | URL CONSISTENCY AUDIT")
print("=" * 60)

print("\n[1] URLs containing query parameters (?)")
print(valid["URL"].str.contains(r"\?", regex=True).sum())

print("\n[2] Dataset query_param_count distribution")
print(valid["query_param_count"].value_counts().sort_index())

print("\n[3] Independently calculated query count distribution")
print(valid["calculated_query_count"].value_counts().sort_index())

print("\n[4] Total mismatches")
print(valid["query_mismatch"].sum())

print("\n[5] Mismatch percentage")
print(
    round(valid["query_mismatch"].mean() * 100, 2),
    "%"
)

print("\n[6] Examples of mismatched URLs")

examples = valid[valid["query_mismatch"]][
    ["URL", "query_param_count", "calculated_query_count"]
].head(15)

print(examples.to_string(index=False))



print("\n[7] Analysis of URLs containing ?")

with_query = valid[
    valid["URL"].str.contains(r"\?", regex=True, na=False)
].copy()

print("Total URLs containing ?:", len(with_query))

print("\nDataset feature distribution:")
print(
    with_query["query_param_count"]
    .value_counts()
    .sort_index()
)

print("\nCalculated feature distribution:")
print(
    with_query["calculated_query_count"]
    .value_counts()
    .sort_index()
)

print("\nMismatches among URLs containing ?:")

query_mismatches = with_query[
    with_query["query_mismatch"]
][
    ["URL", "query_param_count", "calculated_query_count"]
]

print("Count:", len(query_mismatches))
print(query_mismatches.head(20).to_string(index=False))


print("\nAudit completed.")



print("\n[8] Testing the ampersand-count hypothesis")

valid["ampersand_count_plus_one"] = (
    valid["URL"].str.count("&") + 1
)

valid["ampersand_mismatch"] = (
    valid["query_param_count"]
    != valid["ampersand_count_plus_one"]
)

print("\nAmpersand-based distribution:")
print(
    valid["ampersand_count_plus_one"]
    .value_counts()
    .sort_index()
)

print("\nTotal mismatches:")
print(valid["ampersand_mismatch"].sum())

print("\nMismatch percentage:")
print(
    round(valid["ampersand_mismatch"].mean() * 100, 2),
    "%"
)

print("\nExamples of remaining mismatches:")

print(
    valid[valid["ampersand_mismatch"]][
        ["URL", "query_param_count", "ampersand_count_plus_one"]
    ].head(15).to_string(index=False)
)



print("\n[9] Investigating the remaining 38 mismatches")

remaining = valid[valid["ampersand_mismatch"]].copy()


def inspect_ampersands(url):
    before_query, separator, after_query = str(url).partition("?")

    return pd.Series({
        "has_question_mark": bool(separator),
        "ampersands_before_question": before_query.count("&"),
        "ampersands_after_question": after_query.count("&"),
        "total_ampersands": str(url).count("&"),
        "contains_html_amp": "&amp;" in str(url)
    })


details = remaining["URL"].apply(inspect_ampersands)

remaining = pd.concat(
    [remaining, details],
    axis=1
)

print("\nRemaining mismatch count:")
print(len(remaining))

print("\nQuestion mark distribution:")
print(remaining["has_question_mark"].value_counts())

print("\nHTML ampersand encoding:")
print(remaining["contains_html_amp"].value_counts())

print("\nDetailed examples:")
print(
    remaining[
        [
            "URL",
            "query_param_count",
            "ampersands_before_question",
            "ampersands_after_question",
            "contains_html_amp"
        ]
    ].head(20).to_string(index=False)
)
