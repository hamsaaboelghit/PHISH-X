"""Parity of the extractor with the shared dataset.

For every row of ``data/raw/url_features_extracted1.csv`` the extractor must
reproduce the stored feature values. This is what guarantees that the model
trained on the dataset and the extractor used at inference time agree.
"""

import math
from pathlib import Path

import pytest

pd = pytest.importorskip("pandas")

from phishx.features.url_features import FEATURE_NAMES, extract_features

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / "url_features_extracted1.csv"

pytestmark = pytest.mark.skipif(not RAW.exists(), reason="dataset not present")


@pytest.fixture(scope="module")
def dataset():
    df = pd.read_csv(RAW)
    return df[df["URL"].notna() & df["URL"].astype(str).str.strip().ne("")]


@pytest.fixture(scope="module")
def extracted(dataset):
    """Extract every URL once; shared by all per-feature tests."""
    return [extract_features(url) for url in dataset["URL"]]


def test_dataset_has_all_feature_columns(dataset):
    assert set(FEATURE_NAMES) <= set(dataset.columns)


def test_every_row_extracts_ok(dataset, extracted):
    failed = [r.url for r in extracted if not r.ok]
    assert not failed, f"{len(failed)} rows failed, first: {failed[:3]}"


@pytest.mark.parametrize("feature", FEATURE_NAMES)
def test_feature_matches_dataset(dataset, extracted, feature):
    mismatches = []
    for url, expected, result in zip(
        dataset["URL"], dataset[feature], extracted
    ):
        got = result.features[feature]
        if not math.isclose(got, float(expected), rel_tol=0, abs_tol=1e-6):
            mismatches.append((url, expected, got))
    assert not mismatches, (
        f"{feature}: {len(mismatches)} mismatches, first: {mismatches[:3]}"
    )
