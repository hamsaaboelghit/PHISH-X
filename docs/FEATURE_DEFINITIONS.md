# PHISH-X — Dataset Feature Definitions (for AI Model Core)

Date: 2026-11-12
Dataset: `data/processed/cleaned_dataset.csv` (100,872 rows; raw
`data/raw/url_features_extracted1.csv` has identical stored feature values
for kept rows — cleaning only filtered rows).
SHA256 (cleaned): `ed8d830fba05688b5f57f7e7deacb8f377268898cb6f36da50bde1eebd8d95ec`

## Important: original extraction code

The original LegitPhish feature-extraction code is **not in this
repository**. The protocol (`docs/DATASET_AND_EVALUATION_PROTOCOL.md`)
states that stored features "have not yet been validated against our own
extraction definitions" and lists "Define the final feature extraction
contract" as a future task. The definitions below were therefore
**reverse-engineered from the data** by testing hypotheses against all
100,872 rows. Where a formula reproduces the stored values with **0
mismatches**, it is marked **CONFIRMED**. Where no tested hypothesis
reproduces the stored values, it is marked **UNKNOWN** — do not invent a
definition. Existing audit scripts under `src/phishx/features/` contain
*hypotheses* (re-calculations for comparison), not ground truth; see
"Conflicts / clarifications" below. Shawky's security audit
(`docs/SECURITY_DATASET_AUDIT.md`, `src/phishx/security_dataset_audit.py`)
is preserved unchanged; this document adds precision to it.

Common parsing used by the confirmed formulas (reproduces stored values
exactly): `urlsplit` netloc with userinfo stripped
(`netloc.split("@")[-1]`), split on `"."`. Ports are **not** stripped —
they remain part of the last dot-part (40,918 URLs have ports; this
matters for Q5/Q7). There are no IPv6 hosts and no uppercase hosts in
the dataset, so IPv6 and case handling are **unconfirmed** (see
Limitations).

---

## 1. `query_param_count` — CONFIRMED (exact)

**Answer:** It is **not** the number of parsed query parameters. It is a
lexical count:

```python
query_param_count = (url.split("?", 1)[1].count("&") + 1) if "?" in url else 1
```

i.e. number of `&` characters **after the first `?`**, plus 1; `1` when
there is no `?`. Minimum stored value is therefore `1` (100,075 URLs
without `?` all store `1`).

**Evidence:** 0 mismatches on 100,872 rows. By contrast, parsed-params
(`parse_qsl`) mismatches on 99.39% of rows, and whole-URL `&`+1
mismatches on 38 rows (those with `&` in the path before `?`).

**Edge cases:** `&amp;` counts as one `&` (92 URLs, consistent). Blank
values, duplicates and encoding are irrelevant — only `&` characters
after `?` are counted.

**For the model:** recompute with the formula above if you need
training/serving consistency; do not use `parse_qsl` length.

## 2. `subdomain_count` — CONFIRMED for non-sentinel rows (exact)

**Answer:** For all rows except the sentinel cohort (below):

```python
subdomain_count = len(netloc.split(".")) - 2
```

where `netloc` is the `urlsplit` netloc (userinfo stripped, port kept —
ports add no dots so they do not affect the count). There is **no IP
special case** and **no Public Suffix List**: IPv4 hosts (4 labels) get
`2`; a 2-label host gets `0`; 3 labels → `1`, etc. No IPv6 hosts exist
in the dataset.

**Evidence:** 0 mismatches on 99,564 non-sentinel rows (perfect
`nlabels` × stored crosstab). Stored distribution: `{-1: 1308, 0: 2455,
1: 41014, 2: 55534, 3: 502, 4: 55, 5: 4}`.

**Sentinel cohort (exception):** 1,308 rows store `-1` regardless of
their label count (their `labels-2` values range over 0–18). 1,300 of
them also store `tld_length=0, domain_name_length=0` (see Q7); 8 store
`(5, 5)` (double-scheme `http://http://…` URLs). The single `Offline`
row is in this cohort. Treat `-1` as a **missing-value sentinel**, not
a literal count. This confirms Shawky's finding that the cohort is not
simply malformed URLs.

**Conflict / clarification (preserved, not deleted):**
`src/phishx/features/subdomain_audit.py::analyze_subdomain` returns `0`
for IPs and is explicitly a *preliminary, non-PSL audit hypothesis*. It
does **not** match the stored definition (IPs: stored `2` vs audit `0`).
Do **not** use `analyze_subdomain` for training/serving; use the stored
column or the formula above.

## 3. `has_ip_address` — CONFIRMED (exact): anywhere in URL, not hostname-only

**Answer:** It detects an IPv4-like pattern **anywhere in the full URL
string**, not only in the hostname:

```python
import re
has_ip_address = int(bool(re.search(r"(?:\d{1,3}\.){3}\d{1,3}", url)))
```

No word boundaries, no 0–255 octet-range validation, searched over the
whole URL (scheme/host/path/query). Stored positives: 48,916.

**Evidence:** 0 mismatches on 100,872 rows. Hostname-only strict IP
(`ipaddress.ip_address(parse_hostname(url))`) mismatches on 22 rows —
all stored-only (IP in path, in a subdomain label such as
`162.19.214.220.sslip.io`, or in a nested `http://http://…` URL), plus
2 version-string cases (`AutoHotkey_1.1.37.02`, `v0.4.5.10`) that the
`\d{1,3}` pattern correctly captures. A looser `(\d+\.){3}\d+` pattern
has 10 false positives (e.g. `6.1.6206.0`), confirming the `{1,3}`
octet-length limit.

**Clarification vs Shawky's audit (both true):** Shawky's
`ip_flag_vs_parsed` compares stored vs *strict hostname* IP (both
48,894; stored-only 22; parsed-only 0). That comparison is correct and
preserved. The answer to "hostname only or anywhere?" is: **anywhere**
(the stored definition). For the model, use the stored column as-is; if
you recompute a hostname-only variant, expect the 22-row difference and
do not conflate the two.

## 4. `token_count` — UNKNOWN (not reproducible; do not recompute)

**Answer:** The original tokenization is **unknown**. The original
extraction code is not in the repo, and no tested hypothesis reproduces
the stored values:

| Hypothesis | Mismatches |
|---|---:|
| Audit hypothesis `re.split(r"[/?:&=._\-#]")`, drop empties (`token_count_audit.py`) | 48.13% |
| Same +1 for `https://` URLs | 16.29% (best found; likely spurious correlation, not exact) |
| Non-alphanumeric split / `findall` variants | 48–58% |
| `urlsplit`-component tokenization | 88.38% |

Stored `token_count` (mean 6.88, range 1–48) is close to the audit
hypothesis (mostly equal or +1) but never exact. Raw vs cleaned stored
values are identical, so this is not a cleaning artifact.

**For the model:** use the **stored** `token_count` as-is. Do **not**
use `token_count_audit.calculate_token_count` as ground truth — it is a
rejected hypothesis (48% mismatch). If a serving-time tokenizer is
needed, it must be agreed as a *new* contract (see Eiad handoff), not
presented as the original definition.

## 5. `tld_popularity` — CONFIRMED (exact)

**Answer:** Binary flag based on the last dot-part of the netloc
(**including port**) and the sentinel cohort:

```python
POPULAR_TLDS = {"com", "org", "net", "edu", "gov"}
tld_popularity = int(
    netloc.split(".")[-1] in POPULAR_TLDS and subdomain_count != -1
)
```

Stored: 33,070 ones / 67,802 zeros. `edu` and `gov` are always 1 (when
not sentinel); `com`/`org`/`net` are mostly 1; every other final label
(611 of them, including `xyz`, `dev`, `mil`, numerics) is always 0. IP
hosts and the `Offline` row are 0.

**Evidence:** 0 mismatches on 100,872 rows. The popular-list alone
(without the sentinel condition) mismatches on 717 rows — all sentinel
rows whose netloc TLD is popular but stored `0` (e.g. `docs.google.com`
appears both as sentinel/`0` and normal/`1`). Port URLs (e.g.
`com:8888`) correctly yield `0` because the port is part of the final
part. Note the leakage-relevant association: `1` → 25,777 legitimate /
7,293 phishing; `0` → 11,603 / 56,199 (see Shawky's ablation
recommendation).

## 6. `suspicious_file_extension` — CONFIRMED (exact, observed list)

**Answer:** `1` iff the URL **path** (before `?`/`#`) ends with one of:

```python
SUSPICIOUS = ("exe", "zip", "bin", "apk", "cmd", "js")
suspicious_file_extension = int(
    any(path.endswith(s) for s in SUSPICIOUS)
)
```

No dot is required before the suffix (hence `…/bin` with no dot and
`….1exe` both count). Query-string extensions do **not** count
(e.g. `?name=mixthree.exe` → `0`). Stored positives: 14,810
(`exe` 14,091; `zip` 484; `bin` 166; `apk` 24; `cmd` 14; `js` 12).

**Evidence:** 0 mismatches on 100,872 rows (dot-required variant has 19
mismatches). Observed **not** suspicious: `dll`, `scr`, `bat`, `ps1`,
`vbs`, `jar`, `rar`, `7z`, `tar`, `gz`, `lnk`, `php`, `txt`, `html`,
`sh` (as path extension). Case handling is **unconfirmed** — the dataset
contains no uppercase extensions, so case-sensitive and
case-insensitive variants both reproduce the data.

## 7. `domain_name_length` and `tld_length` — CONFIRMED (exact)

**Answer:** Lengths of the last two dot-parts of the netloc (**port
included**):

```python
parts = netloc.split(".")          # e.g. "host.com:8888" -> ["host", "com:8888"]
tld_length = len(parts[-1])        # "com:8888" -> 8
domain_name_length = len(parts[-2])  # "host" -> 4
```

So `tld_length` is the length of the final label **plus** `:port` when
present (e.g. `cn:8988` → 7, `biz:11455` → 9), and
`domain_name_length` is the length of the second-level label (the label
before the final one). IP hosts follow the same rule with no special
case (e.g. `59.183.116.177:55504` → tld `177:55504` len 9, domain
`116` len 3). This is consistent with Q2 (`subdomain_count =
len(parts) - 2` uses the same parts).

**Evidence:** 0 mismatches on 99,564 non-sentinel rows for both
features. **Sentinel exception:** the 1,300-row `-1` bundle stores
`(0, 0)`; the 8 double-scheme rows store `(5, 5)` (netloc `http:`).
The `Offline` row stores `(0, 0)`.

---

## Summary table

| Feature | Status | Formula (stored) |
|---|---|---|
| `query_param_count` | CONFIRMED | `&` after first `?` + 1, else 1 |
| `subdomain_count` | CONFIRMED* | `len(netloc.split('.')) - 2`; `-1` sentinel cohort excepted |
| `has_ip_address` | CONFIRMED | IPv4-like regex anywhere in URL |
| `token_count` | **UNKNOWN** | No tested hypothesis reproduces; use stored as-is |
| `tld_popularity` | CONFIRMED | Netloc final part in `{com,org,net,edu,gov}` and not sentinel |
| `suspicious_file_extension` | CONFIRMED | Path ends with `exe/zip/bin/apk/cmd/js` |
| `domain_name_length` | CONFIRMED* | `len(parts[-2])` (port in `parts[-1]`) |
| `tld_length` | CONFIRMED* | `len(parts[-1])` incl. `:port` |

\* Except the 1,308-row sentinel cohort (`-1` / `0` / `0`), which is a
source-specific bundle, not computed by these formulas.

## Conflicts / clarifications (Shawky's work preserved)

1. **`analyze_subdomain` (IP→0) vs stored (IP→2):** audit-only
   hypothesis; do not use for training. Stored formula above governs.
2. **`has_ip_address` stored (anywhere) vs strict hostname:** Shawky's
   22-row discrepancy is correct and now explained — stored is the
   anywhere-regex. Do not conflate.
3. **`token_count_audit` hypothesis rejected:** 48% mismatch; stored
   definition unknown. Audit file retained for history; do not use its
   calculator as ground truth.
4. **`tld_popularity` + sentinel bundle:** popularity, `-1`, and
   zero-lengths move together (all-phishing cohort). The
   `tld_popularity` ablation is now done (see below); stored-IP and
   sentinel-bundle ablations remain proposed, not results.

## `tld_popularity` ablation (Group Split)

Script: `src/phishx/evaluation/tld_popularity_ablation.py`
Results: `docs/tld_popularity_ablation.json`
Model: sklearn Logistic Regression + StandardScaler (fit on train
only) on all 16 stored features, fixed Group Split (81,165 train /
19,707 test). Positive class is Phishing (0). This differs from
Norhan's 5-feature baseline in the AI Model Core and is **not** a
direct evaluation of the app model.

| Metric | All 16 | Without `tld_popularity` | Delta |
|---|---|---|---|
| Accuracy | 99.69% | 99.65% | −0.04 pp |
| Phishing precision | 99.91% | 99.91% | ~0 |
| Phishing recall | 99.59% | 99.53% | −0.07 pp |
| Phishing F1 | 99.75% | 99.72% | −0.03 pp |
| Legitimate FPR | 0.15% | 0.15% | 0 |

Correlation between `tld_popularity` and the label is 0.59 (strong),
but removing the feature barely changes performance: the model does
**not** heavily rely on it given the other features. Correlation alone
is **not** proof of data leakage; this ablation measures reliance, not
a leakage verdict. The near-perfect scores with and without the feature
indicate other shortcuts (notably `has_ip_address`) dominate — see
Shawky's audit for the IP-shortcut and sentinel-bundle findings.

## Stored values vs re-extraction at prediction (Eiad agreement needed)

| Feature | Training (now) | Serving / re-extraction |
|---|---|---|
| `query_param_count` | Use stored | Formula confirmed; serving use needs Eiad input-contract agreement (HTTP(S), invalid handling) |
| `subdomain_count` | Use stored (incl. `-1` sentinel as-is) | Formula confirmed for non-sentinel; sentinel emission for new URLs needs agreement — do not invent |
| `has_ip_address` | Use stored (anywhere-regex) | Formula confirmed; do not silently switch to hostname-only |
| `token_count` | Use stored | **Blocked:** original tokenizer unknown; needs new agreed tokenizer (Eiad) |
| `tld_popularity` | Use stored | Formula confirmed incl. port/sentinel rules; serving use needs Eiad agreement |
| `suspicious_file_extension` | Use stored | Formula confirmed (observed list); case handling unconfirmed |
| `domain_name_length`, `tld_length` | Use stored | Formulas confirmed incl. port; serving must not strip ports without agreement |

Rule: stored values are ground truth for training. Any serving-time
re-extraction must match these definitions **and** be agreed with Eiad
(input contract, invalid-URL behavior, sentinel/port/case policies)
before it is treated as the production extractor.

## Feature names and order contract (Dataset Loader / Model / URL Investigation)

Dataset column order (`data/processed/cleaned_dataset.csv`, after `URL`,
before `ClassLabel`):

1. `url_length`
2. `has_ip_address`
3. `dot_count`
4. `https_flag`
5. `url_entropy`
6. `token_count`
7. `subdomain_count`
8. `query_param_count`
9. `tld_length`
10. `path_length`
11. `has_hyphen_in_domain`
12. `number_of_digits`
13. `tld_popularity`
14. `suspicious_file_extension`
15. `domain_name_length`
16. `percentage_numeric_chars`

Norhan's AI Model Core loader (`origin/norhan/ai-model-core`,
`src/phishx/data/dataset.py`) currently uses a 5-feature baseline subset
in this order: `url_length`, `number_of_digits`, `url_entropy`,
`dot_count`, `path_length`, with `StandardScaler` fit on train only.
That subset order differs from dataset order — the single agreed
contract (names, order, types, scaling) between Dataset Loader, Model,
and URL Investigation is **pending confirmation** with Norhan and Eiad
and is not claimed here. Until agreed, each component must document
which names/order it uses and must not silently reorder or rename.

## Limitations

- No original extraction code in repo; CONFIRMED means exact
  reproduction on this dataset, not proof of the original implementation.
- No uppercase hosts/extensions and no IPv6 hosts in data: case and IPv6
  handling unconfirmed.
- No DNS/redirects, no browser differential, no source provenance, no
  label correction, no model training (per security audit limitations).
- `token_count` remains unknown; any serving tokenizer needs a new
  agreed contract (Eiad handoff), not a retrofitted claim.
