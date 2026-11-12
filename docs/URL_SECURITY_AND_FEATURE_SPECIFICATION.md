# PHISH-X — URL Security & Feature Specification

| | |
|---|---|
| **Spec version** | `1.0-legacy` (`FEATURE_SPEC_VERSION` in code) |
| **Owner** | Eiad — Security Lead & URL Feature Engineering |
| **Status** | **IMPLEMENTED — aligned with the requirements supplied for this task** |
| **Code** | `src/phishx/features/url_parser.py`, `url_features.py`, `url_signals.py` |
| **Tests** | `tests/` (202 passed, 0 skipped, 136 subtests on this branch after the review follow-up; including full-dataset parity and the enabled production contract) |
| **Network access** | None. All analysis is local string processing. No URL is ever visited, resolved or requested. |

Evidence tags used in this document:

* **[D]** — measured by us on `data/raw/url_features_extracted1.csv` / `data/processed/cleaned_dataset.csv`.
* **[R#]** — claim supported by an external reference listed in section 13.
* **[A]** — an assumption or design decision that the data cannot confirm. Listed again in section 3.3 so the team can accept or reject it.

---

## 1. Summary

1. The 16 numerical features of the dataset were **reverse-engineered and reproduced exactly**: for all 101,219 raw rows and all 16 features the extractor returns the stored value (0 mismatches), verified in this delivery environment on Python 3.13.5. Other Python versions are not claimed as tested in this package. [D]
2. The original extraction code is not in the repository. The definitions below are therefore *inferred from the data*, not copied from the author's code. They are exact on every observed row, but behaviour on inputs that do not occur in the dataset (e.g. uppercase TLDs, IPv6 hosts) is [A].
3. The definitions are **legacy**: several are naive (no Public Suffix List, port text counted inside the TLD, empty host for URLs without a scheme). They were **not changed**, because a model trained on the dataset must be fed the same definitions. Weak spots are reported at run time through `warnings`, and documented here.
4. Several features are **shortcuts** that identify *how the dataset was collected* rather than phishing behaviour (section 9): `has_ip_address`, `https_flag`, port-in-TLD (`tld_length`), `tld_popularity`, `suspicious_file_extension`, and the scheme-less rows. Accuracy on this dataset must be interpreted accordingly (consistent with the IP-only baseline of 85.55 % in `DATASET_AND_EVALUATION_PROTOCOL.md`).
5. The datasets and the fixed train/test splits were not modified. The Streamlit page (`app/main.py`) **was** modified in this delivery (URL Investigation page and display helpers); see section 10.1 for the app integration contract. An earlier draft of this document incorrectly stated that `app/main.py` was unmodified.

---

## 2. How the definitions were established

Method: for each feature, candidate definitions were generated from the feature's name and the observed values, evaluated on every row, and refined until **zero mismatches** remained. A definition is accepted only at 0 mismatches. Where several definitions agree on all rows (e.g. for the extension list), the *simplest* one is used and the ambiguity is recorded.

Result:

| Check | Result |
|---|---|
| Rows compared | 101,219 raw rows (cleaned file: 100,872) |
| Features compared | 16 |
| Mismatches | **0** |
| Python version verified for this delivery | 3.13.5 (original delivery); 3.13.16 (review follow-up). Other versions require separate CI evidence (GitHub Actions matrix: 3.10–3.13) |
| Reproduce | `python -m pytest tests/test_dataset_parity.py` |

The parser is a self-contained re-implementation of `urllib.parse.urlparse` as it behaved when the dataset was built (`legacy_split`). It does **not** call `urllib.parse`, because `urlparse` changed behaviour across Python versions (e.g. scheme detection, control-character stripping, bracket validation), which would silently change feature values. One raw row (`64.233.14.37.dynamic.jazztel.es:84/`) already differs between Python 3.13's `urlparse` and the original; `legacy_split` reproduces the original. [D]

### 2.1 Raw-data observations that matter for extraction [D]

| Observation | Count |
|---|---:|
| URLs without any `://` (scheme-less) — **all labelled phishing** | 1,300 |
| `http://http://…` double-scheme URLs | 7 |
| Raw rows whose host carries a `:port` | 41,087 |
| Cleaned rows whose host carries a `:port` (all phishing) | 40,926 |
| Rows with an IPv4 pattern but a non-IP host (path / version number) | 22 |
| URLs with `%xx` escapes / `xn--` / `@` / `[` | 570 / 15 / 5 / 1 |
| Non-ASCII URLs, URLs with leading/trailing whitespace | 0 / 0 |
| Literal `Offline` URL (retained; `ClassLabel=0`) | 1 |
| URL with missing label (`https://www.chocolatleroux.com`) | 1 |

---

## 3. Answers to Norhan's questions

| # | Question | Exact answer (all verified at 0 mismatches [D]) |
|---|---|---|
| 1 | `query_param_count` | `len(query.split("&"))`, where `query` is the text after the first `?` and before `#`. **Not** the number of parsed key=value pairs. An empty or missing query gives `1` (not 0), so the minimum is 1. `a=1&&b=2` → 3 (empty segments count). Equal to `count("&") + 1` **only** when there is no `&` before the `?` — 38 rows differ from the naive `&`-count (e.g. `…/webscrcmd=_home-customer&nav=1/…` has an `&` but no `?`, so the value is 1). |
| 2 | `subdomain_count` | `len(netloc.split(".")) - 2`, with no Public Suffix List. `netloc` is the text after `//` up to the first `/ ? #`, **including** any `user@` and `:port`. `www` counts as a subdomain. **IP hosts** are not special-cased: `1.2.3.4` → 2; `1.2.3.4:80` → 2. **URL without a scheme** (empty netloc) → `-1`. **Single-label host** (e.g. `localhost`) → `-1`. So the range is −1…. |
| 3 | `has_ip_address` | 1 if the regex `(\d{1,3}\.){3}\d{1,3}` matches **anywhere in the URL string** (host, userinfo, path, query, version numbers). Not host-only. It does not recognise IPv6 or decimal/hex/octal IPv4. On this data it differs from a strict "host is an IP" check in only 22 rows (0.02 %). |
| 4 | `token_count` | `1 + number of characters in "./?=&"` in the whole URL, i.e. `len(re.split(r"[./?=&]", url))` with **empty tokens kept**. Hyphen, underscore, colon and `#` are *not* separators. (Shawky's `token_count_audit.py` assumed `[/?:&=._\-#]` with empties dropped → 48,722 mismatches; the definition above has 0.) |
| 5 | `tld_popularity` | 1 iff the **last dot-separated label of the netloc** is one of `com`, `org`, `net`, `edu`, `gov`; else 0. Exactly these five values are 1 in the data; every other TLD seen is 0. Because the label comes from the netloc, `example.com:8080` → label `com:8080` → 0. Case handling is not observable (no uppercase TLDs in the data); the extractor lower-cases [A]. |
| 6 | `suspicious_file_extension` | 1 iff `path.lower().endswith(("exe","zip","bin","apk","cmd","js"))`. **No leading dot**, so `/bin` and `…-for-js` also match, and `.1exe` matches. Only the URL *path* is tested (not query/fragment; `;params` are excluded). Extensions that occur in the data but are **not** flagged: `sh`, `bat`, `dll`, `scr`, `msi`, `jar`, `vbs`, `ps1`, `rar`, `7z`, `iso`, `dmg`, `lnk`, `pif`. Extensions that never occur in the data cannot be confirmed either way. |
| 7a | `domain_name_length` | Length of the **second-to-last** dot-separated label of the netloc (no PSL). If the netloc has one label, the length of that label; if the netloc is empty, 0. For `www.example.com` → 7; for `a.b.co.uk` → 2 (`co`); for `192.168.0.1:8080` → 1 (third octet `0`). |
| 7b | `tld_length` | Length of the **last** dot-separated label of the netloc, port included. `example.com` → 3; `example.com:8080` → 8; `192.168.0.1:8080` → 6 (`1:8080`); `…//` empty netloc → 0. |
| — | Original code | Not available in the repository. This document and `url_features.py` are the executable, test-verified reference for all rows present in the supplied dataset. Behaviour on unseen input formats is defined by the documented parser contract. |

**Why the IP counts differ:** the protocol's 48,894 count refers to rows whose parsed host is an IP address. The `has_ip_address` feature is intentionally legacy-compatible: its IPv4-looking regex scans the entire URL, including path and version strings. It therefore reports 48,916 rows, including 22 matches outside the host. These are different definitions, not a data inconsistency.

### 3.1 Other features (not asked, but now pinned down)

`url_length` = `len(url)`; `dot_count` = `url.count(".")`; `https_flag` = scheme (lower-cased) equals `https`; `url_entropy` = Shannon entropy of the characters of the URL, log base 2 (max abs error vs stored 5·10⁻¹⁰); `path_length` = `len(path)` after removing `?query`, `#fragment` and `;params` (for a URL without a scheme the "path" is the whole string up to `?`); `has_hyphen_in_domain` = `"-"` in the netloc; `number_of_digits` = count of characters where `str.isdigit()` is true; `percentage_numeric_chars` = `digits / len(url) × 100`, as an unrounded float in 0–100.

### 3.2 Names that do not match their behaviour (kept as is)

| Name | Actually is |
|---|---|
| `token_count` | number of `./?=&` separators + 1 |
| `tld_length` | length of last netloc label, includes `:port` |
| `domain_name_length` | length of the second-to-last netloc label (not the registrable domain) |
| `has_hyphen_in_domain` | hyphen anywhere in netloc (includes user-info and port) |
| `query_param_count` | number of `&`-separated segments, minimum 1 |

### 3.3 Compatibility assumptions and implementation boundaries

| ID | Decision | Default in code | Compatibility note |
|---|---|---|---|
| A1 | TLD list matched case-insensitively | yes | no uppercase TLD in the data |
| A2 | Leading/trailing whitespace stripped before extraction | yes | none in the data; users paste whitespace |
| A3 | Failed extraction returns `ok=False` and NaN features; `to_vector()` raises | yes | defensive API behaviour; source-extractor error handling is not recoverable from dataset rows |
| A4 | Inputs over 8,192 characters rejected (`too_long`) | yes | data max is 474 chars; bounds work on hostile input |
| A5 | Keep legacy definitions for model v1; any "fix" is a separate, versioned change | yes | changing definitions without retraining silently invalidates the model |
| A6 | Whether leakage-prone features (section 9) are kept in the training matrix | outside this extractor scope | model-training/evaluation policy; the 16-feature extraction contract remains unchanged |

---

## 4. Output contract

```python
from phishx.features.url_features import extract_features, FEATURE_NAMES

r = extract_features("http://192.168.0.1:8080/login.exe")
r.ok            # True
r.status        # "ok" | "invalid_type" | "empty" | "too_long" | "malformed"
r.features      # dict, ALWAYS the 16 keys of FEATURE_NAMES in this order
r.warnings      # tuple of reliability codes (section 8); never changes a value
r.to_vector()   # list[float] in FEATURE_NAMES order; raises if not r.ok
r.as_dict()     # JSON-safe (NaN -> None)
```

* The function **never raises**; a bad input gives `ok=False` and all-NaN features, so a failed extraction cannot be mistaken for a "clean" URL and cannot reach the model.
* Pure standard library; no pandas/numpy needed (usable from Streamlit without extra imports).
* Feature order = dataset column order: `url_length, has_ip_address, dot_count, https_flag, url_entropy, token_count, subdomain_count, query_param_count, tld_length, path_length, has_hyphen_in_domain, number_of_digits, tld_popularity, suspicious_file_extension, domain_name_length, percentage_numeric_chars`.
* Batch helper: `extract_features_batch(urls)`.

### 4.1 Production feature contract (Eiad-confirmed)

The shared production extractor is `phishx.features.url_features` with the interface above. The contract, confirmed by Eiad's review of `origin/eyad` and asserted by `test_production_feature_contract` in `tests/test_url_security_cases.py`, is:

* **Module:** `src/phishx/features/url_features.py` (imports without starting the UI or accessing data/network).
* **Interface:** `extract_features(url) -> UrlFeatures`, `extract_features_batch(urls) -> list[UrlFeatures]`, `FEATURE_NAMES`, `FEATURE_SPEC_VERSION = "1.0-legacy"`.
* **Feature order/semantics:** the 16 dataset features in `FEATURE_NAMES` order (section 5). The extractor **always returns all 16**; `to_vector()` emits them in that order.
* **16-feature extractor vs 5-feature baseline:** the extractor contract is 16 features. A model-side subset (e.g. a 5-feature baseline) is a training-time selection **by name** from `FEATURE_NAMES` — it is not a competing extractor and must not redefine any feature. Which subset the AI team trains on remains a model decision outside this contract; no second extractor exists.
* **Failure contract:** invalid input gives `ok=False` (never a legitimate-looking vector); `to_vector()` raises on failure. Invalid must not mean legitimate.
* **Offline:** pure string processing; no network, DNS, or file access. Network is blocked in every test (`setUp` patches `socket`).

---

## 5. Feature specification

Legend — **Status**: ✅ keep as defined · ⚠ keep, interpret with caution · 🚩 shortcut / leakage-prone (see section 9). Class statistics are from `cleaned_dataset.csv` (63,492 phishing / 37,380 legitimate). [D]

| # | Feature | Exact definition | Type / range | Why it matters for security | Status |
|---|---|---|---|---|---|
| 1 | `url_length` | `len(url)` | int ≥ 1 | Long URLs can hide the real host and pad deceptive paths; length is a standard lexical feature [R1][R2]. | ⚠ median 34 (phishing) vs 27 (legit) in this dataset; sensitive to how each class was sampled |
| 2 | `has_ip_address` | regex `(\d{1,3}\.){3}\d{1,3}` anywhere | {0,1} | A raw IP instead of a name avoids registration cost, hides brand and defeats domain reputation [R1][R2][R3]. | 🚩 48,916 rows =1, **100 % phishing**; no legit row =1 |
| 3 | `dot_count` | `url.count(".")` | int ≥ 0 | Many dots indicate stacked subdomains or dotted look-alike paths (`paypal.com.example/…`) [R3][R14]. | ⚠ counts dots in IP octets, path, query |
| 4 | `https_flag` | scheme == `https` | {0,1} | TLS proves encryption, **not** legitimacy: certificates are issued free and automatically [R8]. | 🚩 `https=0` → 99.995 % phishing (59,981 rows, 3 legit) |
| 5 | `url_entropy` | Shannon entropy, bits/char, over all URL characters [R7] | float ≈ 2.5–5.9 | Randomly generated names/tokens (kit IDs, hashes, DGA-like hosts) have flatter character distributions. | ⚠ depends on length; hashes/base64 occur in legit URLs |
| 6 | `token_count` | `1 + count of "./?=&"` | int ≥ 1 | Proxy for structural complexity (depth, number of parameters). Token-level lexical features are standard [R2]. | ⚠ counts empty tokens; name is misleading |
| 7 | `subdomain_count` | `len(netloc.split(".")) − 2` | int ≥ −1 | Attackers place a trusted brand in the left-most labels so the real registrable domain is easy to miss [R14][R13]. | ⚠ no PSL; `www` counted; IP → 2; no scheme → −1 (all 1,308 `−1` rows are phishing) |
| 8 | `query_param_count` | `len(query.split("&"))`, min 1 | int ≥ 1 | Parameters carry tracking IDs, tokens and redirect targets used in credential-harvesting flows. | ⚠ 99.5 % of rows =1; "1" means "zero or one" |
| 9 | `tld_length` | `len(last netloc label)` incl. `:port` | int ≥ 0 | Intended: unusual / long TLDs. | 🚩 ≥ 6 in 40,947 rows, 99.7 % of them because a port is attached; 99.8 % phishing |
| 10 | `path_length` | `len(path)`; no query/fragment/params | int ≥ 0 | Long deep paths are typical of uploaded kits/CMS abuse (`/wp-content/…`). | ⚠ for scheme-less URLs the "path" is the whole string |
| 11 | `has_hyphen_in_domain` | `"-"` in netloc | {0,1} | Hyphenated look-alikes (`brand-secure-login.example`) are a classic impersonation pattern [R3][R14]. | ✅ (includes port/userinfo text) |
| 12 | `number_of_digits` | count of `isdigit()` characters | int ≥ 0 | Digit-heavy hosts/paths: IPs, generated IDs, character-substitution (`paypa1`). | ⚠ IP octets always add digits; Unicode digits counted |
| 13 | `tld_popularity` | last netloc label ∈ {com, org, net, edu, gov} | {0,1} | Intended as a reputation proxy for the TLD. | 🚩 P(legit)=77.9 % if 1, 17.1 % if 0; list is not data-sourced; `.com` is itself heavily abused |
| 14 | `suspicious_file_extension` | `path.lower().endswith(exe,zip,bin,apk,cmd,js)` | {0,1} | Direct links to executables, archives and scripts indicate malware delivery or kit download. | 🚩 14,810 rows =1, 99.97 % phishing; mostly malware-feed URLs; list omits `bat,dll,scr,msi,jar,vbs,ps1,sh` |
| 15 | `domain_name_length` | len of 2nd-to-last netloc label | int ≥ 0 | Very long or hyphen-chained registrable names are typical of impersonation / generated domains. | ⚠ not eTLD+1; for IPs it is an octet length; for scheme-less rows 0 |
| 16 | `percentage_numeric_chars` | `digits / len(url) × 100` | float 0–100 | Normalised version of #12; compares digit density across URL lengths. | ⚠ redundant with #1 and #12 (collinearity risk for Newton's method) |

---

## 6. Parsing rules and edge cases

Two parsers exist on purpose (see module docstring):

* **Legacy split** (`legacy_split`) → used only for the 16 model features. Reproduces the dataset.
* **Strict parse** (`parse_url`) → used for warnings and `url_signals`; a security-oriented, browser-aware reading (not a full WHATWG implementation — see section 11.8). Never used for model features.

| Input | Legacy split (model features) | Strict parse (diagnostics) |
|---|---|---|
| `https://www.example.com/a?x=1#f` | scheme `https`, netloc `www.example.com`, path `/a`, query `x=1`, fragment `f` | same; host `www.example.com` |
| **No scheme** `example.com/login` | scheme `""`, **netloc `""`**, path = whole string → host-derived features become `-1/0/0` + warning `no_authority` | `authority_source="implied"`, host `example.com`, path `/login` |
| **No scheme + port** `example.com:8080/p` | scheme `example.com`, path `8080/p` (rest is not all digits) | host `example.com`, port 8080 |
| `localhost:8080` | no scheme (rest is all digits) | host `localhost`, port 8080 |
| **Protocol-relative** `//example.com/a` | scheme `""`, netloc `example.com` | `is_protocol_relative=True`, host `example.com` |
| `HTTPS://Example.COM/` | scheme lower-cased; host text untouched, TLD matched lower-case [A1] | host lower-cased |
| `http:/example.com`, `http:\\evil.com\x` | no netloc (single slash) / backslash not a delimiter | browser-aware repair: host `example.com` / `evil.com`, path `/x` [R5] |
| **IPv4** `http://192.168.0.1:8080/x` | netloc `192.168.0.1:8080`; last label `1:8080`; `has_ip_address=1` | host_kind `ipv4`, port 8080 |
| **IPv6** `http://[2001:db8::1]:8080/` | netloc `[2001:db8::1]:8080` (no dots → 1 label); `has_ip_address=0`; warning `ipv6_not_detected` | host `2001:db8::1`, host_kind `ipv6` [R6] |
| **Obfuscated IPv4** `http://2130706433/`, `0x7f.1`, `0177.0.0.1` | `has_ip_address=0`; warning `obfuscated_ipv4_not_detected` | host_kind `ipv4_obfuscated` (WHATWG IPv4 parser) [R5] |
| **User-info trick** `http://paypal.com@evil.example/` | netloc keeps `paypal.com@evil.example`; `tld_length` from `example`; warning `host_contains_userinfo` | `userinfo="paypal.com"`, host `evil.example`, signal `userinfo_contains_dot` [R4] |
| Ports `:8080`, `:99999`, `:` | port text stays in last label; warning `host_contains_port` | valid port int; `99999` → `port_valid=False`, signal `has_invalid_port=True` (never read as a safe default); empty port valid |
| Query / fragment / params | `#` split first, then `?`; `;params` split off the last path segment for http(s)/ftp… | `#` then `?` |
| **Trailing-dot host** `example.com.` | last label is `""` → `tld_length=0` | host `example.com`, `host_had_trailing_dot=True` |
| **Double scheme** `http://http://x/a.exe` | netloc `http:` → single label → `subdomain_count=-1`, `tld_length=5` | host `http`; signal `double_scheme` |
| **IDN (Unicode)** `http://bücher.example/` | counts code points (`bücher` = 6) | `host_ascii = xn--bcher-kva.example` (IDNA 2003 codec) [R9][R10] |
| **Punycode** `xn--…` | counted as ASCII text | signal `has_punycode_label` |
| Percent-escapes `%41` | **never decoded** (3 chars each) | counted in `percent_escape_count`; `%` in host flagged |
| Opaque scheme `javascript:`, `mailto:`, `data:` | scheme set, empty netloc → `no_authority` | `is_opaque_scheme=True`, no host |
| Opaque scheme with digits `javascript:123`, `data:123` | no scheme (rest is all digits, so the legacy rule treats the whole string as path) | `is_opaque_scheme=True`, no host (known opaque schemes win over the host:port reading) |
| Schemeless host:port `example.com:8080`, `localhost:8080` | `example.com` is read as a scheme (rest not all digits); `localhost` is not (rest all digits) | `authority_source="implied"`, host + port |
| Embedded URL `?u=http://other` | no special handling (`://` just adds separators) | signal `embedded_url_in_path_or_query` |
| Leading/trailing whitespace | stripped at API boundary [A2] | stripped |
| Tabs, CR, LF **inside** the URL | deleted (as `urllib` does) [R11] | deleted |
| Leading C0 controls / spaces | removed by `legacy_split` (CVE-2023-24329 class of bypass) [R11] | stripped |
| **Empty / blank** | `status="empty"` | `UrlParseError` |
| **Non-string** (None, int, bytes, list) | `status="invalid_type"` | `UrlParseError` |
| Unbalanced `[` or `]` in netloc | `status="malformed"` | `UrlParseError` |
| > 8,192 chars | `status="too_long"` [A4] | n/a |
| Lone surrogates, NUL, emoji, RTL override `U+202E` | processed as ordinary characters, no crash | no crash |

---

## 7. Phishing URL structures (Phase 2 analysis)

Everything below was analysed offline, on text only.

| Structure | Why attackers use it [R-tag] | How the model features see it | Advisory signal (`url_signals`) |
|---|---|---|---|
| IP address instead of domain | no registration, no brand name, throw-away hosting [R1][R3] | `has_ip_address=1`, `subdomain_count=2`, port glued into `tld_length` | `host_kind=ipv4` |
| Obfuscated IP (decimal / hex / octal) | evades naive IP regexes and blocklists [R5] | **missed** (0) | `ipv4_obfuscated` |
| Brand in a subdomain or path | victim reads the left-most label [R14] | `subdomain_count`, `dot_count`, `path_length` | `label_count` |
| `brand.com@evil.example` | everything before `@` is user-info, not the host [R4] | host-derived features computed on the whole netloc | `has_userinfo`, `userinfo_contains_dot` |
| Hyphenated / digit-substituted brands | look-alike registration | `has_hyphen_in_domain`, `number_of_digits` | — |
| IDN homographs / punycode | visually confusable characters [R9][R10][R12] | length of Unicode text; no script analysis | `has_punycode_label`, `has_non_ascii_host` |
| Uncommon ports | self-hosted kits, malware C2/droppers | port text inside last label | `has_nondefault_port` |
| Open redirect / embedded URL | launder reputation through a trusted site | extra separators in `token_count` | `embedded_url_in_path_or_query` |
| Double scheme / malformed prefixes | break naive parsers | `subdomain_count=-1`, `tld_length=5` | `double_scheme` |
| Executable / archive payload links | direct malware delivery | `suspicious_file_extension` | — |
| Excess percent-encoding | hides characters from filters | not decoded | `percent_escape_count` |
| Trailing dot, extra whitespace/control chars | filter evasion [R11] | last label empty → `tld_length=0` | `has_trailing_dot_host` |
| URL shorteners, brand keywords, newly registered domains | hide destination / reputation | **not representable offline** (needs lists or WHOIS/DNS) | not implemented |

---

## 8. Warning codes (`UrlFeatures.warnings`)

A warning marks a result whose *legacy value is structurally unreliable*. It never changes a feature value.

| Code | Meaning |
|---|---|
| `no_authority` | no `//` authority (usually no scheme): `subdomain_count=-1`, `tld_length=0`, `domain_name_length=0`, `tld_popularity=0`, `has_hyphen_in_domain=0` (1,300 dataset rows, all phishing) |
| `host_contains_port` | `:port` is part of the last label (40,926 rows, all phishing) |
| `host_contains_userinfo` | `user@` is part of the netloc |
| `ip_pattern_outside_host` | `has_ip_address=1` but the host is not an IP (22 rows: paths, version numbers like `v0.4.5.10`) |
| `ipv6_not_detected` | host is an IPv6 literal; `has_ip_address=0` |
| `obfuscated_ipv4_not_detected` | browser-accepted IPv4 form; `has_ip_address=0` |
| `single_label_host` | no dot in host (e.g. `localhost`, `http:`): `subdomain_count=-1` |

---

## 9. Features to exclude or treat with caution

These are **findings, not decisions**. Removing or redefining a feature is a team decision (A5, A6); the code does not do it.

### 9.1 Shortcuts that reflect data collection, not phishing behaviour [D]

| Feature / pattern | Evidence | Risk |
|---|---|---|
| `has_ip_address` | 48,916 rows =1, all phishing; 0 legit | Alone gives 85.55 % accuracy (protocol §5). Model learns "IP ⇒ phishing". |
| `https_flag` | `https=0`: 59,981 rows, 3 legit (99.995 % phishing); `https=1`: 91.4 % legit; 94.5 % of phishing rows are plain `http` | TLS is not a trust signal [R8]; in this dataset it almost encodes the label. |
| `tld_length`, `tld_popularity` as port proxies | 40,926 rows carry a port, all phishing; `tld_length ≥ 6` (40,947 rows) ⇒ 99.8 % phishing, 40,826 of them with a port | The "TLD length" is really "has a port". |
| Scheme-less URLs | 1,300 rows, all phishing, all with `subdomain_count=-1`, `tld_length=0`, `domain_name_length=0` | A missing `://` identifies a data source, not behaviour. A legitimate scheme-less input at inference time looks like phishing. |
| `suspicious_file_extension` | 14,810 rows =1, 99.97 % phishing | Captures malware-delivery URLs (the dataset mixes malware and phishing sources); list is incomplete and uses suffix matching without a dot. |
| `tld_popularity` | P(legit) 77.9 % vs 17.1 % | Already flagged in the protocol. List `{com, org, net, edu, gov}` has no documented source. |
| `subdomain_count` distribution (cleaned data) | `0`: 2,303 phishing vs 152 legit; `1`: 9,267 vs 31,747; `2`: 50,552 vs 4,982; `3`: 21 vs 481; `4`: 37 vs 18; `5`: 4 vs 0 | Strong class structure driven by IP hosts (always 2) and by `www.`-style legit hosts (1). Not a behavioural signal. |
| Group effects (64,001 hosts, `github.com` in both classes) | protocol §4 | Use the **group split** as primary evaluation (as already decided). |

### 9.2 Low-information or redundant

* `query_param_count`: 99.5 % of rows equal 1.
* `percentage_numeric_chars` vs `number_of_digits` vs `url_length`: deterministic ratio of the other two; expect strong collinearity (relevant to the Hessian in Newton's method; consider checking the condition number).
* `dot_count`, `token_count`: both counts of separator characters in the same string; correlated.

### 9.3 Modelling notes for Norhan (not changes)

* Feature scales differ by orders of magnitude (`url_length` up to 474, `url_entropy` ≈ 4, `percentage_numeric_chars` up to 66) — standardise with **training-split** statistics and persist them with the model.
* `subdomain_count` can be −1; `to_vector()` returns it unchanged.
* Never impute failed extractions with zeros: `ok=False` means *no prediction*.

### 9.4 Proposals — NOT approved, NOT in the model contract

If the team later wants security features that survive these biases, candidates that need no external lists are: strict host-is-IP (v4/v6/obfuscated), user-info presence, non-default port as a separate binary (instead of inside `tld_length`), punycode/non-ASCII host, embedded URL, registrable-domain length via the Public Suffix List [R13]. All are already available as advisory facts in `url_signals.py`. Adding any of them requires: team agreement → new spec version (e.g. `2.0`) → dataset regeneration → retraining. They must not be mixed into the current 16-feature vector.

---

## 10. Overlap with existing work

### 10.1 `extract_basic_signals()` in `app/main.py` — app integration contract

`app/main.py` **was** modified in this delivery (URL Investigation page, display helpers, and related UI). An earlier draft of this document incorrectly stated that it was unmodified. The integration contract is:

* `extract_basic_signals()` in `app/main.py` is a **display helper only**. It is separate from the production extractor and its output must never be fed to a model. (A clarifying comment was added at the function in the review follow-up; no UI/logic was changed.)
* The **production extractor** is `phishx.features.url_features.extract_features` (16 features in `FEATURE_NAMES` order). Anything shown as "model input" must come from it.
* **Security diagnostics** (`phishx.features.url_signals.analyze_url_security`) are kept **separate** from the model feature vector. They may be shown as explanations, but must not be mixed into model input.
* The production extractor is **not yet wired into prediction** in the app. Wiring it in is a separate, reviewed step; until then the URL Investigation page shows preliminary structural signals only and states that they are not a classification.

| Streamlit signal | Compared with dataset definition | Consequence |
|---|---|---|
| URL length, HTTPS, dots, digits | same definitions | consistent |
| IP address in hostname | strict `ipaddress` check on `parsed.hostname` | differs from the regex-anywhere feature on 22 dataset rows (IP pattern in path / version number) |
| Hyphen in hostname | `parsed.hostname` (no port/userinfo) | tiny differences |
| Path length | **prepends `http://` to scheme-less input** | differs from the dataset for every scheme-less URL (dataset path = whole string) |
| Query parameters | counts **non-empty** `&` segments → 0 when no query | dataset minimum is 1 |
| Hostname length | not a dataset feature | dataset uses `domain_name_length` (2nd-to-last label) |
| Coverage | 9 display signals, 7 of the 16 features missing (entropy, tokens, subdomains, TLD length/popularity, extension, % digits) | cannot feed the model |

Recommendation: keep it as a *display helper*; the URL Investigation page should call `extract_features()` for anything shown as "model input" and `analyze_url_security()` for explanations. Note: `app/utils/url_helpers.py` duplicates the same helpers as standalone functions, but `app/main.py` currently uses its inline copies and does not import `url_helpers`; deduplication is a future cleanup, not part of this delivery.

### 10.2 Shawky's audit scripts (not modified)

| Script | Hypothesis | Measured against dataset | Resolved definition |
|---|---|---|---|
| `token_count_audit.py` | split on `[/?:&=._\-#]`, drop empties | 48,722 mismatches | split on `[./?=&]`, keep empties — 0 |
| `subdomain_audit.py` | strict hostname, IP → 0, `//` prefixed | 49.77 % mismatch | `len(netloc.split(".")) − 2` — 0 |
| `url_consistency_audit.py` | `parse_qsl(keep_blank_values=True)` | 99.38 % mismatch | `len(query.split("&"))` — 0 |
| `ip_address_audit.py` | strict hostname IP | 22 mismatches | regex anywhere — 0 |

These scripts remain valid as audit tooling; this document supersedes their *hypotheses*.

---

## 11. Known limitations

1. **Definitions are inferred**, exact on the observed data, unverified elsewhere (A1–A4).
2. **No Public Suffix List**: `co.uk`, `com.au`, hosting platforms (`github.io`, `pages.dev`) are mis-split. `subdomain_count`/`domain_name_length` are therefore approximations of the intended concepts.
3. **Legacy parser quirks** are reproduced on purpose (scheme-less → empty netloc; port/userinfo inside labels). They are surfaced via warnings, not fixed.
4. **IPv6, obfuscated IPv4 and IDN homographs** are not detected by the model features. Script mixing / confusable analysis (UTS #39 [R12]) is not implemented.
5. **Percent-encoding is never decoded**, and Unicode is not normalised (NFKC/IDNA 2008) for the model features.
6. **No reputation data**: no blocklists, shortener lists, brand lists, WHOIS/DNS or certificate data — all would require network or external data and are excluded by the offline rule.
7. **Dataset bias dominates** (section 9). A correct extractor cannot repair a biased label source; reported accuracy must be read with the group split and the IP-only baseline in mind.
8. **Behaviour tied to `urlparse` semantics** of the dataset generator can differ from what modern browsers do (backslashes, single slashes, whitespace). The strict parser is a security-oriented, browser-aware parser — it covers the browser-like readings that matter for diagnostics but is not a full WHATWG implementation and must not be described as browser-equivalent (no full IPv6 canonicalisation, no IDNA 2008/UTS #46 processing — it uses Python's IDNA 2003 codec).
9. **Extraction speed** is ~100 k URLs in a few seconds (pure Python); not optimised for millions.
10. The extension list is fixed at the six observed suffixes; absence of other types from the dataset flags is observed, not intended.

---

## 12. How to run and verify

```bash
python -m pip install pytest pandas
python -m pytest tests -q                      # 202 passed, 0 skipped, 136 subtests, ~4 s
python -m compileall -q src tests app          # includes app/
```

GitHub Actions workflow: `.github/workflows/tests.yml` runs the suite on Python 3.10–3.13 after push / pull request. This branch was locally verified on Python 3.13.16 (202 passed, 0 skipped, 136 subtests); the other matrix results will be available in GitHub Actions after push. The 28 synthetic cases in `tests/cases/url_security_cases.json` exercise the old audit helpers, not the production parser; production acceptance is asserted by `test_production_feature_contract` and the `test_url_*` suites.

```bash
python -m pytest tests/test_dataset_parity.py  # full-dataset parity only
```

```python
import sys; sys.path.insert(0, "src")
from phishx.features.url_features import extract_features
from phishx.features.url_signals import analyze_url_security

print(extract_features("//Example.COM/a?x=1&y=2").as_dict())
print(analyze_url_security("http://paypal.com@evil.example:8081/login").as_dict())
```

---

## 13. References

Standards and specifications

* **[R5]** WHATWG. *URL Standard* (host parsing, IPv4 parser, special-scheme repair, backslash handling). <https://url.spec.whatwg.org/>
* **[R6]** Hinden, R., Deering, S. *RFC 4291 — IP Version 6 Addressing Architecture* (2006); Kawamura, S., Kawashima, M. *RFC 5952 — A Recommendation for IPv6 Address Text Representation* (2010). <https://www.rfc-editor.org/rfc/rfc4291>, <https://www.rfc-editor.org/rfc/rfc5952>
* **[R4]** Berners-Lee, T., Fielding, R., Masinter, L. *RFC 3986 — Uniform Resource Identifier (URI): Generic Syntax* (2005): §3.2 authority, §3.2.1 user-info (deprecated `user:password`), §7.6 semantic attacks. <https://www.rfc-editor.org/rfc/rfc3986>
* **[R9]** Klensin, J. *RFC 5890/5891 — Internationalized Domain Names for Applications (IDNA)* (2010); Costello, A. *RFC 3492 — Punycode* (2003). <https://www.rfc-editor.org/rfc/rfc5890>, <https://www.rfc-editor.org/rfc/rfc3492>
* **[R10]** Unicode Consortium. *UTS #46 — Unicode IDNA Compatibility Processing.* <https://www.unicode.org/reports/tr46/>
* **[R12]** Unicode Consortium. *UTS #39 — Unicode Security Mechanisms* (confusables, mixed-script detection). <https://www.unicode.org/reports/tr39/>
* **[R13]** Mozilla Foundation. *Public Suffix List.* <https://publicsuffix.org/>
* **[R8]** Barnes, R. et al. *RFC 8555 — Automatic Certificate Management Environment (ACME)* (2019): free, automated certificate issuance, which is why HTTPS alone is not a trust signal. <https://www.rfc-editor.org/rfc/rfc8555>
* **[R11]** Python Software Foundation. `urllib.parse` documentation <https://docs.python.org/3/library/urllib.parse.html>; **CVE-2023-24329** — `urllib.parse` mishandles URLs beginning with blank characters, enabling blocklist bypass. <https://nvd.nist.gov/vuln/detail/CVE-2023-24329>
* **[R7]** Shannon, C. E. "A Mathematical Theory of Communication." *Bell System Technical Journal* 27 (1948).

Research on URL-based phishing / malicious-URL detection

* **[R1]** Sahoo, D., Liu, C., Hoi, S. C. H. "Malicious URL Detection using Machine Learning: A Survey." arXiv:1701.07179 (2017). <https://arxiv.org/abs/1701.07179>
* **[R2]** Ma, J., Saul, L. K., Savage, S., Voelker, G. M. "Beyond Blacklists: Learning to Detect Malicious Web Sites from Suspicious URLs." *KDD 2009.* <https://dblp.org/rec/conf/kdd/MaSSV09.html>
* **[R3]** Garera, S., Provos, N., Chew, M., Rubin, A. D. "A Framework for Detection and Measurement of Phishing Attacks." *ACM WORM 2007.*
* **[R14]** McGrath, D. K., Gupta, M. "Behind Phishing: An Examination of Phisher Modi Operandi." *USENIX LEET 2008.* <https://www.usenix.org/legacy/event/leet08/tech/full_papers/mcgrath/mcgrath_html/mcgrath_gupta.html>

**Verification note.** For [R1]–[R3], [R14] and [R11] (CVE) the existence, title and venue were confirmed by web search on the day this document was written; the claims attributed to them are deliberately general (lexical/host features are standard in URL classifiers; IP-literal hosts, deceptive subdomains and user-info are known obfuscation devices). Page-level citations must be checked against the papers before they are quoted in the final report. Standards ([R4]–[R10], [R12], [R13]) were not re-fetched for this document; check section numbers against the originals before quoting them.
